#!/usr/bin/env python3
# This file is part of Xpra.
# Copyright (C) 2026 Yan Shoshitaishvili <yans@pwn.college>
# Xpra is released under the terms of the GNU GPL v2, or, at your option, any
# later version. See the file COPYING for details.

import unittest

from xpra.keyboard.common import KeyEvent
from xpra.keyboard.mask import MODIFIER_MAP, DEFAULT_MODIFIER_MEANINGS

try:
    from xpra.client.terminal import keyboard as terminal_keyboard
except ImportError:
    terminal_keyboard = None

# every method `KeyboardHelper` calls on the keyboard object:
KEYBOARD_METHODS = (
    "mask_to_names", "set_modifier_mappings", "get_keymap_modifiers", "get_keymap_spec",
    "get_x11_keymap", "get_layout_spec", "get_keyboard_repeat", "update_modifier_map",
    "process_key_event", "cleanup", "has_bell",
)


@unittest.skipIf(terminal_keyboard is None, "the terminal client component is not available")
class TerminalKeyboardTest(unittest.TestCase):

    def test_contract(self):
        keyboard = terminal_keyboard.TerminalKeyboard()
        for method in KEYBOARD_METHODS:
            self.assertTrue(callable(getattr(keyboard, method, None)), f"no {method!r} method")
        self.assertEqual(repr(keyboard), "TerminalKeyboard")

    def test_keymap_modifiers(self):
        keyboard = terminal_keyboard.TerminalKeyboard()
        mod_meanings, mod_managed, mod_pointermissing = keyboard.get_keymap_modifiers()
        self.assertEqual(mod_managed, [])
        # the terminal reports the lock modifiers with every event:
        self.assertEqual(mod_pointermissing, [])
        self.assertTrue(mod_meanings)
        for keyname, modifier in mod_meanings.items():
            self.assertEqual(DEFAULT_MODIFIER_MEANINGS.get(keyname), modifier)
            self.assertIn(modifier, MODIFIER_MAP)
        for keyname in ("Shift_L", "Control_R", "Alt_L", "Caps_Lock", "Num_Lock", "Super_L"):
            self.assertIn(keyname, mod_meanings, f"{keyname!r} is missing")
        # `Mode_switch` is not a key the terminal can report:
        self.assertNotIn("Mode_switch", mod_meanings)
        # the caller gets a copy it can modify:
        mod_meanings["Shift_L"] = "mod5"
        self.assertEqual(keyboard.get_keymap_modifiers()[0]["Shift_L"], "shift")

    def test_layout_spec(self):
        keyboard = terminal_keyboard.TerminalKeyboard()
        model, layout, layouts, variant, variants, options = keyboard.get_layout_spec()
        self.assertEqual(model, "pc105")
        self.assertEqual(layout, "us")
        self.assertEqual(list(layouts), ["us"])
        self.assertEqual(variant, "")
        self.assertEqual(list(variants), [])
        self.assertEqual(options, "")

    def test_no_local_keymap(self):
        keyboard = terminal_keyboard.TerminalKeyboard()
        # no key repeat: each repeat is delivered as a new key press,
        # which is also what keeps `keyboard_sync` disabled:
        self.assertIsNone(keyboard.get_keyboard_repeat())
        self.assertEqual(keyboard.get_keymap_spec(), {})
        self.assertEqual(keyboard.get_x11_keymap(), {})
        self.assertEqual(keyboard.mask_to_names(MODIFIER_MAP["control"] | MODIFIER_MAP["shift"]),
                         ["shift", "control"])

    def test_process_key_event(self):
        keyboard = terminal_keyboard.TerminalKeyboard()
        key_event = KeyEvent()
        key_event.keyname = "a"
        sent = []
        keyboard.process_key_event(lambda wid, event: sent.append((wid, event)), 1, key_event)
        # the default is to send the event as-is:
        self.assertEqual(sent, [(1, key_event)])


@unittest.skipIf(terminal_keyboard is None, "the terminal client component is not available")
class TerminalKeyboardHelperTest(unittest.TestCase):

    def make_helper(self):
        packets = []
        helper = terminal_keyboard.TerminalKeyboardHelper(lambda *packet: packets.append(packet))
        self.addCleanup(helper.cleanup)
        return helper, packets

    def test_keyboard_class(self):
        helper = self.make_helper()[0]
        self.assertIsInstance(helper.keyboard, terminal_keyboard.TerminalKeyboard)
        self.assertEqual(repr(helper), "TerminalKeyboardHelper")
        # the platform keyboard class must be left alone:
        from xpra.platform import keyboard as platform_keyboard
        self.assertIsNot(platform_keyboard.Keyboard, terminal_keyboard.TerminalKeyboard)
        # no key repeat value means no keyboard synchronization:
        self.assertEqual((helper.key_repeat_delay, helper.key_repeat_interval), (-1, -1))

    def test_keymap_properties(self):
        helper = self.make_helper()[0]
        props = helper.get_keymap_properties()
        self.assertEqual(props.get("layout"), "us")
        self.assertEqual(list(props.get("layouts")), ["us"])
        self.assertEqual(props.get("mod_meanings"), terminal_keyboard.MOD_MEANINGS)
        # we have no keycodes to send: the server maps the key names we send instead
        self.assertNotIn("keycodes", props)
        self.assertNotIn("x11_keycodes", props)
        self.assertNotIn("query_struct", props)
        # what the `keyboard` subsystem skips when the keyboard data is delayed:
        self.assertEqual(helper.get_keymap_properties(("layout", )).get("layout"), None)

    def test_send_key_action(self):
        helper, packets = self.make_helper()
        key_event = KeyEvent()
        key_event.keyname = "Return"
        key_event.pressed = True
        key_event.modifiers = ["control"]
        helper.process_key_event(1, key_event)
        self.assertEqual(len(packets), 1)
        packet = packets[0]
        self.assertIn(packet[0], ("key-action", "keyboard-event"))
        self.assertEqual(packet[1], 1)
        self.assertEqual(packet[2], "Return")


def main():
    unittest.main()


if __name__ == '__main__':
    main()
