#!/usr/bin/env python3
# This file is part of Xpra.
# Copyright (C) 2026 Yan Shoshitaishvili <yans@pwn.college>
# Xpra is released under the terms of the GNU GPL v2, or, at your option, any
# later version. See the file COPYING for details.

import os
import fcntl
import termios
import tempfile
import unittest
from io import BytesIO
from collections.abc import Sequence

from xpra.exit_codes import ExitCode
from xpra.util.env import OSEnvContext
from xpra.util.objects import typedict
from xpra.client.base import client as base_client
from xpra.client.gui import ui_client_base
from unit.test_util import silence_info, silence_warn

try:
    from xpra.client.terminal import graphics
    from xpra.client.terminal import client as terminal_client
    from xpra.client.terminal import tty as terminal_tty
    from xpra.client.terminal.tty import TerminalOutput
    from xpra.client.terminal.input import KeyEvent, MouseEvent, GraphicsResponse, KeyboardFlagsResponse
    from xpra.client.terminal.subsystem.display import TerminalDisplayClient
except ImportError:
    graphics = None
    terminal_client = None
    terminal_tty = None
    TerminalOutput = None
    KeyEvent = MouseEvent = GraphicsResponse = KeyboardFlagsResponse = None
    TerminalDisplayClient = None

# the terminal geometry these tests pretend to run in: (columns, rows, width, height)
TERMINAL_SIZE = (100, 30, 1000, 600)

# `GLib.IO_IN`, spelled out so that this test package never imports `gi`:
IO_IN = 1


class FakeWindow:
    """ the little of a `ClientWindow` that the client's input routing looks at """

    def __init__(self, wid: int, pos=(0, 0), size=(100, 100), override_redirect=False):
        self.wid = wid
        self._pos = pos
        self._size = size
        self._mapped = True
        self._metadata = typedict()
        self._override_redirect = override_redirect
        self.placements = 0

    def is_OR(self) -> bool:
        return self._override_redirect

    def refresh_placement(self) -> None:
        self.placements += 1


class FakeWindowSubsystem:
    """ replaces the composed `window` subsystem, recording what the client sends it """

    def __init__(self):
        # the real subsystem exposes the registry under this name:
        self.windows: dict[int, FakeWindow] = {}
        self._id_to_window = self.windows
        self.focus_events: list[tuple] = []
        self.buttons: list[tuple] = []
        self.wheels: list[tuple] = []
        self._window_with_grab = 0

    def cleanup(self) -> None:
        """ the client cleans up every subsystem """

    def get_window(self, wid: int):
        return self.windows.get(wid)

    def update_focus(self, wid: int, gotit: bool) -> None:
        self.focus_events.append((wid, gotit))

    def send_button(self, device_id, wid, button, pressed, pointer, modifiers, buttons, props) -> None:
        self.buttons.append((device_id, wid, button, pressed, pointer, tuple(modifiers), tuple(buttons)))

    def wheel_event(self, device_id, wid, deltax, deltay, pointer) -> None:
        self.wheels.append((device_id, wid, deltax, deltay, pointer))


class FakePointerSubsystem:
    def __init__(self):
        self.positions: list[tuple] = []

    def cleanup(self) -> None:
        """ the client cleans up every subsystem """

    def send_mouse_position(self, device_id, wid, pos, modifiers=None, buttons=None, props=None) -> None:
        self.positions.append((device_id, wid, pos, tuple(modifiers or ()), tuple(buttons or ())))


class FakeKeyboardSubsystem:
    def __init__(self):
        self.actions: list[tuple] = []

    def cleanup(self) -> None:
        """ the client cleans up every subsystem """

    def handle_key_action(self, window, key_event) -> bool:
        self.actions.append((window, key_event.keyname, key_event.pressed, tuple(key_event.modifiers)))
        return False


class FakeEncodingSubsystem:
    def __init__(self, encodings=("png", "rgb")):
        self.encodings = encodings

    def get_encodings(self):
        return self.encodings


@unittest.skipIf(terminal_client is None, "the terminal client component is not available")
class TerminalClientTest(unittest.TestCase):
    """
    Composition test for `XpraTerminalClient`: the real client object, with the
    terminal size injected so that no tty is ever needed.
    """

    def setUp(self):
        super().setUp()
        # the terminal client never has an X11 display source, and the platform
        # queries used when the client starts up must not go looking for one:
        env_context = OSEnvContext(XPRA_NOX11="1")
        env_context.__enter__()
        self.addCleanup(env_context.__exit__)

    def make_client(self, terminal_size=TERMINAL_SIZE):
        with silence_info(ui_client_base):
            client = terminal_client.XpraTerminalClient()
        self.addCleanup(client.cleanup)
        client.terminal_size = terminal_size
        return client

    def make_output(self, client):
        buf = BytesIO()
        client.terminal_output = TerminalOutput(buf)
        return buf

    ######################################################################
    # composition

    def test_subsystem_substitution(self):
        client = self.make_client()
        display = client.get_subsystem("display")
        self.assertIsNotNone(display, "no `display` subsystem composed")
        self.assertIsInstance(display, TerminalDisplayClient)
        # every substitution must keep the subsystem prefix:
        self.assertEqual(type(display).PREFIX, "display")
        if clipboard := client.get_subsystem("clipboard"):
            from xpra.client.terminal.subsystem.clipboard import TerminalClipboardClient
            self.assertIsInstance(clipboard, TerminalClipboardClient)
            self.assertEqual(type(clipboard).PREFIX, "clipboard")

    def test_keyboard_helper_class_is_installed(self):
        client = self.make_client()
        from xpra.client.terminal.keyboard import TerminalKeyboardHelper
        kb = client.get_subsystem("keyboard")
        self.assertIsNotNone(kb, "no `keyboard` subsystem composed")
        # it must be set before `init_ui` instantiates it:
        self.assertIs(kb.helper_class, TerminalKeyboardHelper)

    def test_client_identity(self):
        client = self.make_client()
        self.assertEqual(client.client_toolkit(), "terminal")
        self.assertEqual(client.client_type, "terminal")
        self.assertEqual(repr(client), "XpraTerminalClient")

    def test_scheduler_is_the_glib_one(self):
        client = self.make_client()
        # the base class' stubs return `None` silently, which would hang the client:
        for name in ("idle_add", "timeout_add", "source_remove"):
            self.assertTrue(callable(getattr(client, name)))
        timer = client.timeout_add(10000, print)
        self.assertTrue(timer)
        client.source_remove(timer)

    ######################################################################
    # display subsystem

    def test_display_real_values(self):
        client = self.make_client()
        display = client.get_subsystem("display")
        self.assertEqual(display.get_root_size(), (1000, 600))
        self.assertEqual(tuple(display.get_screen_sizes()), ((1000, 600), ))
        self.assertEqual(tuple(display.get_screen_sizes(2, 2)), ((500, 300), ))
        monitors = display.get_monitors_info()
        self.assertIsInstance(monitors, dict)
        self.assertEqual(monitors[0]["geometry"], (0, 0, 1000, 600))
        self.assertEqual(monitors[0]["name"], "terminal")
        self.assertTrue(display.has_transparency())

    def test_default_terminal_geometry(self):
        # a terminal which does not report its pixel size:
        client = self.make_client((80, 24, 0, 0))
        self.assertEqual(client.cell_size(),
                         (terminal_client.DEFAULT_CELL_WIDTH, terminal_client.DEFAULT_CELL_HEIGHT))
        self.assertEqual(client.terminal_pixel_size(),
                         (80 * terminal_client.DEFAULT_CELL_WIDTH, 24 * terminal_client.DEFAULT_CELL_HEIGHT))
        # nothing known at all:
        client.terminal_size = (0, 0, 0, 0)
        self.assertEqual(client.get_subsystem("display").get_root_size(), (800, 480))

    def test_cell_size(self):
        client = self.make_client()
        self.assertEqual(client.cell_size(), (10, 20))
        self.assertEqual(client.terminal_pixel_size(), (1000, 600))

    ######################################################################
    # encodings

    def test_get_encodings(self):
        client = self.make_client()
        # `xpra.scripts.main.handle_client_encoding_option` calls this:
        self.assertIsInstance(client.get_encodings(), Sequence)
        client.subsystems["encoding"] = FakeEncodingSubsystem()
        self.assertEqual(tuple(client.get_encodings()), ("png", "rgb"))
        client.subsystems.pop("encoding")
        self.assertEqual(tuple(client.get_encodings()), ())

    ######################################################################
    # the rest of the frontend contract

    def test_frontend_contract(self):
        client = self.make_client()
        self.assertIsNone(client.get_group_leader(1, typedict(), False))
        self.assertEqual(tuple(client.get_notifier_classes()), ())
        self.assertEqual(tuple(client.get_tray_classes()), ())
        self.assertEqual(tuple(client.get_system_tray_classes()), ())
        self.assertIsNone(client.get_menu_helper())
        self.assertIsNone(client.get_menu_helper_class())
        self.assertEqual(client.get_gl_client_window_module("yes"), ({}, None))
        self.assertEqual(client.get_xdpi(), 96)
        self.assertEqual(client.get_ydpi(), 96)
        self.assertEqual(client.get_mouse_position(), (0, 0))
        self.assertEqual(client.get_raw_mouse_position(), (0, 0))
        self.assertEqual(tuple(client.get_current_modifiers()), ())

    def test_client_window_classes(self):
        client = self.make_client()
        from xpra.client.terminal.window import ClientWindow
        self.assertEqual(tuple(client.get_client_window_classes((0, 0, 1, 1), typedict(), False)),
                         (ClientWindow, ))

    def test_grabs_are_recorded_only(self):
        client = self.make_client()
        window = client.subsystems["window"] = FakeWindowSubsystem()
        client.window_grab(5, None)
        self.assertEqual(window._window_with_grab, 5)
        client.window_ungrab()
        self.assertEqual(window._window_with_grab, 0)

    def test_get_info(self):
        client = self.make_client()
        # `merge_dicts` warns because two composed subsystems both use a "network" key,
        # which is a pre-existing quirk of `XpraClientBase.get_info`, not of this client:
        from xpra.util import io as util_io
        util_io.get_util_logger()
        with silence_warn(util_io, "util_logger"):
            info = client.get_info()
        self.assertEqual(info["terminal"]["size"], TERMINAL_SIZE)
        self.assertEqual(info["terminal"]["cell-size"], (10, 20))
        self.assertFalse(info["terminal"]["graphics"])

    ######################################################################
    # the terminal is left alone until we enter terminal mode

    def test_terminal_untouched_before_terminal_mode(self):
        client = self.make_client()
        self.assertIsNone(client.terminal_output)
        self.assertIsNone(client.terminal_context)
        # nothing may be written, and nothing may raise:
        client.write_terminal(b"hello")
        client.write_osc52(b"hello")
        client.window_bell(None, 0, 0, 0, 0, 0, 0, "")
        client.update_cursor()

    def test_write_osc52_and_bell(self):
        client = self.make_client()
        buf = self.make_output(client)
        client.write_osc52(b"\x1b]52;c;YQ==\x07")
        client.window_bell(None, 0, 100, 1000, 100, 0, 0, "TerminalBell")
        self.assertEqual(buf.getvalue(), b"\x1b]52;c;YQ==\x07\x07")

    ######################################################################
    # the kitty graphics protocol probe

    def test_graphics_probe_accepted(self):
        client = self.make_client()
        buf = self.make_output(client)
        client.subsystems["window"] = FakeWindowSubsystem()
        client.handle_graphics_response(GraphicsResponse(terminal_client.PROBE_IMAGE_ID, True, "OK"))
        self.assertTrue(client.graphics_ok)
        # the test image is freed again:
        self.assertIn(b"a=d,d=I", buf.getvalue())

    def test_graphics_response_for_another_image_is_ignored(self):
        client = self.make_client()
        self.make_output(client)
        client.handle_graphics_response(GraphicsResponse(1, True, "OK"))
        self.assertFalse(client.graphics_ok)

    def test_graphics_probe_timeout_quits(self):
        client = self.make_client()
        self.make_output(client)
        client.probe_timer = 0
        with silence_warn(base_client):
            client.graphics_probe_timeout()
        self.assertEqual(client.exit_code, ExitCode.UNSUPPORTED)
        self.assertFalse(client.graphics_ok)
        # quitting restores the terminal:
        self.assertIsNone(client.terminal_output)

    def test_graphics_probe_rejected_quits(self):
        client = self.make_client()
        self.make_output(client)
        with silence_warn(base_client):
            client.handle_graphics_response(GraphicsResponse(terminal_client.PROBE_IMAGE_ID, False, "ENOTSUP:nope"))
        self.assertEqual(client.exit_code, ExitCode.UNSUPPORTED)

    ######################################################################
    # input routing

    def test_keyboard_flags_response(self):
        client = self.make_client()
        self.assertFalse(client.kitty_keyboard)
        client.process_input_events([KeyboardFlagsResponse(15)])
        self.assertTrue(client.kitty_keyboard)
        client.process_input_events([KeyboardFlagsResponse(1)])
        self.assertFalse(client.kitty_keyboard)

    def make_input_client(self):
        client = self.make_client()
        self.make_output(client)
        window_sub = FakeWindowSubsystem()
        client.subsystems["window"] = window_sub
        client.subsystems["pointer"] = FakePointerSubsystem()
        client.subsystems["keyboard"] = FakeKeyboardSubsystem()
        return client, window_sub

    def add_window(self, client, window_sub, wid, pos, size, override_redirect=False):
        window = FakeWindow(wid, pos, size, override_redirect)
        window_sub.windows[wid] = window
        client._new_window(None, window)
        return window

    def test_key_events_go_to_the_focused_window(self):
        client, window_sub = self.make_input_client()
        kb = client.subsystems["keyboard"]
        # no window exists yet, so the event is dropped:
        client.process_input_events([KeyEvent(ord("a"), text="a")])
        self.assertEqual(kb.actions, [])
        # the first regular window takes the focus as soon as it is created,
        # so the keyboard works without requiring a click first:
        window = self.add_window(client, window_sub, 1, (0, 0), (100, 100))
        self.assertEqual(client._focused, 1)
        client.kitty_keyboard = True
        client.process_input_events([KeyEvent(ord("a"), mods=4, event_type=1, text="a")])
        self.assertEqual(kb.actions, [(window, "a", True, ("control", ))])
        # the modifiers reported with the event are cached for the subsystems:
        self.assertEqual(tuple(client.get_current_modifiers()), ("control", ))

    def test_legacy_key_press_synthesizes_a_release(self):
        client, window_sub = self.make_input_client()
        window = self.add_window(client, window_sub, 1, (0, 0), (100, 100))
        client.focus_window(1)
        kb = client.subsystems["keyboard"]
        # the terminal does not report key releases (no kitty keyboard protocol):
        self.assertFalse(client.kitty_keyboard)
        client.process_input_events([KeyEvent(ord("a"), text="a")])
        self.assertEqual(kb.actions, [(window, "a", True, ()), (window, "a", False, ())])
        # with the protocol enabled, the terminal sends the release itself:
        kb.actions = []
        client.kitty_keyboard = True
        client.process_input_events([KeyEvent(ord("a"), event_type=1, text="a"),
                                     KeyEvent(ord("a"), event_type=3, text="a")])
        self.assertEqual([a[2] for a in kb.actions], [True, False])

    def test_mouse_motion(self):
        client, window_sub = self.make_input_client()
        self.add_window(client, window_sub, 1, (20, 40), (100, 100))
        pointer = client.subsystems["pointer"]
        # SGR pixel coordinates are 1-based:
        client.process_input_events([MouseEvent(31, 51, 0, "motion", 0)])
        self.assertEqual(client.get_raw_mouse_position(), (30, 50))
        self.assertEqual(pointer.positions, [(-1, 1, (30, 50, 10, 10), (), ())])

    def test_mouse_motion_outside_any_window(self):
        client, window_sub = self.make_input_client()
        self.add_window(client, window_sub, 1, (20, 40), (10, 10))
        pointer = client.subsystems["pointer"]
        client.process_input_events([MouseEvent(500, 500, 0, "motion", 0)])
        self.assertEqual(pointer.positions, [(-1, 0, (499, 499, 499, 499), (), ())])

    def test_mouse_buttons_are_paired_and_focus(self):
        client, window_sub = self.make_input_client()
        self.add_window(client, window_sub, 1, (0, 0), (100, 100))
        client.process_input_events([MouseEvent(11, 21, 1, "press", 0)])
        self.assertEqual(client._buttons, [1])
        self.assertEqual(window_sub.focus_events, [(1, True)])
        client.process_input_events([MouseEvent(11, 21, 1, "release", 0)])
        self.assertEqual(client._buttons, [])
        self.assertEqual([(b[2], b[3]) for b in window_sub.buttons], [(1, True), (1, False)])
        # the held buttons are reported with the press:
        self.assertEqual(window_sub.buttons[0][6], (1, ))
        self.assertEqual(window_sub.buttons[1][6], ())

    def test_mouse_button_outside_any_window_is_dropped(self):
        client, window_sub = self.make_input_client()
        self.add_window(client, window_sub, 1, (0, 0), (10, 10))
        client.process_input_events([MouseEvent(500, 500, 1, "press", 0)])
        self.assertEqual(window_sub.buttons, [])
        self.assertEqual(client._buttons, [])

    def test_wheel(self):
        client, window_sub = self.make_input_client()
        self.add_window(client, window_sub, 1, (0, 0), (100, 100))
        client.process_input_events([MouseEvent(11, 21, 4, "wheel", 0),
                                     MouseEvent(11, 21, 5, "wheel", 0),
                                     MouseEvent(11, 21, 6, "wheel", 0),
                                     MouseEvent(11, 21, 7, "wheel", 0)])
        self.assertEqual([(w[2], w[3]) for w in window_sub.wheels],
                         [(0, 1), (0, -1), (-1, 0), (1, 0)])
        # an unknown wheel button is dropped rather than sent as a delta of 0:
        window_sub.wheels = []
        client.process_input_events([MouseEvent(11, 21, 9, "wheel", 0)])
        self.assertEqual(window_sub.wheels, [])
        # and so is a wheel event which is not over any window:
        client.process_input_events([MouseEvent(500, 500, 4, "wheel", 0)])
        self.assertEqual(window_sub.wheels, [])

    def test_unknown_events_are_ignored(self):
        client = self.make_client()
        client.process_input_events([object(), None])

    ######################################################################
    # cursor

    def cursor_data(self, width=4, height=4, xhot=1, yhot=2, serial=77):
        pixels = bytes((1, 2, 3, 255)) * (width * height)
        return ("raw", 0, 0, width, height, xhot, yhot, serial, pixels, "default")

    def test_cursor_is_transmitted_and_placed_at_the_hotspot(self):
        client = self.make_client()
        buf = self.make_output(client)
        client._pointer_pos = (105, 63)
        client.set_windows_cursor((), self.cursor_data())
        data = buf.getvalue()
        image_id = graphics.CURSOR_IMAGE_ID
        self.assertIn(b"a=t,q=2,i=%i,f=32,s=4,v=4" % image_id, data)
        # (105-1, 63-2) with 10x20 cells: row 4, column 11, offsets (4, 1)
        self.assertIn(b"\x1b[4;11H", data)
        self.assertIn(b"a=p,q=2,i=%i,p=1,z=%i,C=1,X=4,Y=1" % (image_id, graphics.CURSOR_Z), data)

    def test_cursor_follows_the_pointer_without_a_new_image(self):
        client = self.make_client()
        buf = self.make_output(client)
        client.set_windows_cursor((), self.cursor_data())
        buf.seek(0)
        buf.truncate()
        client._pointer_pos = (200, 100)
        client.update_cursor()
        data = buf.getvalue()
        # the image is already in the terminal, only the placement moves:
        self.assertNotIn(b"a=t", data)
        self.assertIn(b"\x1b[5;20H", data)

    def test_empty_cursor_removes_the_placement(self):
        client = self.make_client()
        buf = self.make_output(client)
        client.set_windows_cursor((), self.cursor_data())
        buf.seek(0)
        buf.truncate()
        client.set_windows_cursor((), ())
        self.assertIn(b"a=d,d=i,i=%i,p=1" % graphics.CURSOR_IMAGE_ID, buf.getvalue())
        # and nothing is emitted for a cursor which is already gone:
        buf.seek(0)
        buf.truncate()
        client.update_cursor()
        self.assertEqual(buf.getvalue(), b"")

    def test_invalid_cursor_data_is_dropped(self):
        client = self.make_client()
        buf = self.make_output(client)
        # the pixel buffer is too small for the size claimed:
        with silence_warn(terminal_client, "cursorlog"):
            client.set_windows_cursor((), ("raw", 0, 0, 40, 40, 0, 0, 1, b"\0" * 16, "default"))
        self.assertEqual(client._cursor_data, ())
        buf.seek(0)
        buf.truncate()
        client.update_cursor()
        self.assertEqual(buf.getvalue(), b"")

    def test_cursor_is_recorded_on_the_cursor_subsystem(self):
        client = self.make_client()
        self.make_output(client)
        cursor = client.get_subsystem("cursor")
        if cursor is None:
            self.skipTest("no `cursor` subsystem composed")
        window = FakeWindow(1)
        data = self.cursor_data()
        client.set_windows_cursor((window, ), data)
        self.assertEqual(cursor._cursors[window], data)
        client.set_windows_cursor((window, ), ())
        self.assertNotIn(window, cursor._cursors)

    ######################################################################
    # cleanup

    def test_cleanup_twice(self):
        client = self.make_client()
        client.cleanup()
        client.cleanup()

    def test_cleanup_after_terminal_output(self):
        client = self.make_client()
        buf = self.make_output(client)
        client._zorder = {1: 10, 2: 12}
        client.cleanup()
        # every image we uploaded is freed:
        self.assertIn(b"a=d,d=I,i=1", buf.getvalue())
        self.assertIn(b"a=d,d=I,i=2", buf.getvalue())
        self.assertIsNone(client.terminal_output)
        client.cleanup()

    def test_quit_before_run(self):
        client = self.make_client()
        # `GObjectClientAdapter.quit` would dereference a main loop which does not exist yet:
        client.quit(ExitCode.OK)
        self.assertEqual(client.exit_code, ExitCode.OK)


@unittest.skipIf(terminal_client is None, "the terminal client component is not available")
class TerminalModeTest(unittest.TestCase):
    """
    Enters and leaves terminal mode for real, on a pty created by this test:
    the terminal modes, the escape sequences we emit and the input we read back
    all go through the same code paths as on a real terminal.
    """

    def setUp(self):
        super().setUp()
        log_dir = tempfile.TemporaryDirectory()
        self.addCleanup(log_dir.cleanup)
        # the client redirects its own log output away from the terminal,
        # keep whatever it writes inside the temporary directory:
        env_context = OSEnvContext(XPRA_NOX11="1", XPRA_LOG_DIRS=log_dir.name)
        env_context.__enter__()
        self.addCleanup(env_context.__exit__)
        self.master, self.slave = os.openpty()
        self.outputs: list = []
        # registered before the client, so it runs after `client.cleanup()`:
        self.addCleanup(self.close_pty)
        # so that reading what the client wrote never blocks:
        flags = fcntl.fcntl(self.master, fcntl.F_GETFL)
        fcntl.fcntl(self.master, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        self.saved_mode = termios.tcgetattr(self.slave)
        with silence_info(ui_client_base):
            self.client = terminal_client.XpraTerminalClient()
        self.addCleanup(self.client.cleanup)
        self.client.terminal_fd = self.slave
        self.client.terminal_size = TERMINAL_SIZE
        self.client.make_terminal_output = self.make_terminal_output

    def make_terminal_output(self):
        # the client owns the terminal device, the test plays the terminal emulator:
        fileobj = os.fdopen(os.dup(self.slave), "wb", buffering=0)
        self.outputs.append(fileobj)
        return TerminalOutput(fileobj)

    def close_pty(self) -> None:
        for fileobj in self.outputs:
            fileobj.close()
        for fd in (self.master, self.slave):
            try:
                os.close(fd)
            except OSError:
                pass

    def read_terminal(self) -> bytes:
        data = b""
        while True:
            try:
                chunk = os.read(self.master, 65536)
            except BlockingIOError:
                return data
            except OSError:
                return data
            if not chunk:
                return data
            data += chunk

    def write_terminal(self, data: bytes) -> None:
        os.write(self.master, data)
        self.client.handle_terminal_input(None, IO_IN)

    def test_enter_and_leave_terminal_mode(self):
        client = self.client
        client.start_terminal_mode()
        self.assertIsNotNone(client.terminal_output)
        self.assertTrue(client.terminal_context.active)
        # the terminal is now in raw mode:
        self.assertFalse(termios.tcgetattr(self.slave)[3] & termios.ECHO)
        data = self.read_terminal()
        for expected in (
            b"\x1b[?1049h",         # alternate screen
            b"\x1b[?25l",           # hide the cursor
            b"\x1b[>",              # push the kitty keyboard flags
            b"\x1b[?1016h",         # SGR pixel mouse reports
            b"\x1b[?u",             # query the keyboard flags
            b"a=q,i=%i" % terminal_client.PROBE_IMAGE_ID,   # the graphics probe
        ):
            self.assertIn(expected, data)
        # the log output has been redirected away from the terminal:
        self.assertIsNotNone(client.saved_log_handlers)

        client.cleanup()
        data = self.read_terminal()
        for expected in (
            b"\x1b[?1016l",         # mouse reports off
            b"\x1b[<u",             # pop the keyboard flags
            b"\x1b[?25h",           # show the cursor
            b"\x1b[?1049l",         # back to the main screen
        ):
            self.assertIn(expected, data)
        self.assertIsNone(client.terminal_output)
        self.assertIsNone(client.terminal_context)
        self.assertIsNone(client.saved_log_handlers)
        # the terminal modes have been restored:
        self.assertEqual(termios.tcgetattr(self.slave), self.saved_mode)

    def test_start_terminal_mode_is_idempotent(self):
        client = self.client
        client.start_terminal_mode()
        output = client.terminal_output
        self.read_terminal()
        client.start_terminal_mode()
        self.assertIs(client.terminal_output, output)
        self.assertEqual(self.read_terminal(), b"")

    def test_input_is_parsed_from_the_terminal(self):
        client = self.client
        client.start_terminal_mode()
        self.read_terminal()
        window_sub = FakeWindowSubsystem()
        client.subsystems["window"] = window_sub
        client.subsystems["pointer"] = FakePointerSubsystem()
        client.subsystems["keyboard"] = FakeKeyboardSubsystem()
        window = FakeWindow(1, (0, 0), (500, 500))
        window_sub.windows[1] = window
        client._new_window(None, window)
        client.focus_window(1)
        # the terminal answers our two queries:
        self.write_terminal(b"\x1b[?15u")
        self.assertTrue(client.kitty_keyboard)
        self.write_terminal(b"\x1b_Gi=%i;OK\x1b\\" % terminal_client.PROBE_IMAGE_ID)
        self.assertTrue(client.graphics_ok)
        # a key press, then a mouse move:
        self.write_terminal(b"\x1b[97;1:1u")
        self.assertEqual(client.subsystems["keyboard"].actions,
                         [(window, "a", True, ())])
        self.write_terminal(b"\x1b[<35;101;51M")
        self.assertEqual(client.get_raw_mouse_position(), (100, 50))
        self.assertEqual(client.subsystems["pointer"].positions,
                         [(-1, 1, (100, 50, 100, 50), (), ())])

    def test_closed_terminal_quits(self):
        client = self.client
        client.start_terminal_mode()
        self.read_terminal()
        os.close(self.master)
        # writing to a pty whose other end is gone fails, which is the point:
        with silence_warn(base_client), silence_warn(terminal_tty):
            self.assertFalse(client.handle_terminal_input(None, IO_IN))
        self.assertEqual(client.input_watch, 0)


def main():
    unittest.main()


if __name__ == '__main__':
    main()
