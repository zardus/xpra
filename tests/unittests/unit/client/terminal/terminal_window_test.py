#!/usr/bin/env python3
# This file is part of Xpra.
# Copyright (C) 2026 Yan Shoshitaishvili <yans@pwn.college>
# Xpra is released under the terms of the GNU GPL v2, or, at your option, any
# later version. See the file COPYING for details.

import os
import unittest
from io import BytesIO

# `XPRA_UNIT_TEST` is read at import time by the client window modules:
os.environ.setdefault("XPRA_UNIT_TEST", "1")

from xpra.util.objects import typedict                                  # noqa: E402
from xpra.net.packet_type import WINDOW_MAP, WINDOW_UNMAP, WINDOW_CONFIGURE   # noqa: E402

try:
    from xpra.client.terminal import graphics
    from xpra.client.terminal.tty import TerminalOutput
    from xpra.client.terminal.backing import TerminalBacking
    from xpra.client.terminal.window import ClientWindow, cell_position
except ImportError:
    graphics = None
    TerminalOutput = None
    TerminalBacking = None
    ClientWindow = None
    cell_position = None

APC = b"\x1b_G"
ST = b"\x1b\\"


def parse_output(data: bytes) -> list:
    """
    Decode a terminal byte stream into commands:
    `("graphics", {key: value}, payload)`, `("cup", (row, col))`, `("save",)`, `("restore",)`
    """
    commands = []
    pos = 0
    while pos < len(data):
        if data[pos] != 0x1b:
            raise ValueError(f"unexpected data at offset {pos}: {data[pos:pos + 8]!r}")
        if data[pos:pos + 3] == APC:
            end = data.index(ST, pos)
            control, _, payload = data[pos + 3:end].partition(b";")
            keys = {}
            for kv in control.decode("ascii").split(","):
                if kv:
                    key, _, value = kv.partition("=")
                    keys[key] = value
            commands.append(("graphics", keys, payload))
            pos = end + len(ST)
        elif data[pos:pos + 2] == b"\x1b[":
            end = pos + 2
            while end < len(data) and not 0x40 <= data[end] <= 0x7E:
                end += 1
            body = data[pos + 2:end].decode("ascii")
            if chr(data[end]) == "H":
                row, _, col = body.partition(";")
                commands.append(("cup", (int(row), int(col))))
            pos = end + 1
        elif data[pos:pos + 2] == b"\x1b7":
            commands.append(("save",))
            pos += 2
        elif data[pos:pos + 2] == b"\x1b8":
            commands.append(("restore",))
            pos += 2
        else:
            raise ValueError(f"unexpected escape sequence at offset {pos}: {data[pos:pos + 8]!r}")
    return commands


def actions(commands) -> list:
    return [cmd[1].get("a") for cmd in commands if cmd[0] == "graphics"]


def graphics_keys(commands, action: str) -> list:
    return [cmd[1] for cmd in commands if cmd[0] == "graphics" and cmd[1].get("a") == action]


class FakeWindowSubsystem:
    def __init__(self):
        self.focus_events = []

    def update_focus(self, wid: int, focused=True) -> None:
        self.focus_events.append((wid, focused))


class FakeClient:
    """ the minimal client surface a terminal `ClientWindow` reaches through """
    readonly = False
    # a title template with a variable, so the metadata title is used:
    title = "@title@"
    headerbar = "no"
    frame_edits = True

    def __init__(self, cell=(10, 20), pixel_size=(800, 480)):
        self.packets = []
        self.buffer = BytesIO()
        self.terminal_output = TerminalOutput(self.buffer)
        self.subsystems = {"window": FakeWindowSubsystem()}
        self._focused = 0
        self.zorder = {}
        self.raised = []
        self.restacked = []
        self._cell = cell
        self._pixel_size = pixel_size

    def send(self, *args) -> None:
        self.packets.append(args)

    def get_subsystem(self, name: str):
        return self.subsystems.get(name)

    def idle_add(self, fn, *args) -> int:
        fn(*args)
        return 0

    def timeout_add(self, timeout: int, fn, *args) -> int:
        return 0

    def source_remove(self, timer: int) -> None:
        """ no timers are ever started """

    def cell_size(self) -> tuple:
        return self._cell

    def terminal_pixel_size(self) -> tuple:
        return self._pixel_size

    def window_z(self, wid: int) -> int:
        return self.zorder.get(wid, 10)

    def raise_window(self, wid: int) -> None:
        self.raised.append(wid)
        self.zorder[wid] = 42

    def restack_window(self, wid: int, other_wid: int, above: int) -> None:
        self.restacked.append((wid, other_wid, above))
        self.zorder[wid] = 44

    def focus_window(self, wid: int) -> None:
        # this mirrors `XpraTerminalClient.focus_window`:
        # the client's own focus state is what key events are routed with
        if self._focused == wid:
            return
        self._focused = wid
        self.subsystems["window"].update_focus(wid, True)

    # test helpers:
    def drain(self) -> bytes:
        data = self.buffer.getvalue()
        self.buffer.seek(0)
        self.buffer.truncate()
        return data

    def commands(self) -> list:
        return parse_output(self.drain())

    def packet_types(self) -> list:
        return [packet[0] for packet in self.packets]

    def last_packet(self, packet_type: str):
        for packet in reversed(self.packets):
            if packet[0] == packet_type:
                return packet
        raise AssertionError(f"no {packet_type!r} packet in {self.packet_types()}")


@unittest.skipIf(ClientWindow is None, "the terminal client is not installed")
class CellPositionTest(unittest.TestCase):

    def test_origin(self):
        self.assertEqual(cell_position(0, 0, 10, 20), (1, 1, 0, 0))

    def test_exact_cell(self):
        self.assertEqual(cell_position(30, 40, 10, 20), (3, 4, 0, 0))

    def test_intra_cell_offsets(self):
        self.assertEqual(cell_position(25, 45, 10, 20), (3, 3, 5, 5))
        self.assertEqual(cell_position(9, 19, 10, 20), (1, 1, 9, 19))

    def test_negative_is_clamped_to_the_origin(self):
        self.assertEqual(cell_position(-100, -1, 10, 20), (1, 1, 0, 0))

    def test_clamped_to_the_terminal_area(self):
        self.assertEqual(cell_position(1000, 1000, 10, 20, 100, 100), (5, 10, 9, 19))
        # without a known terminal size, nothing is clamped:
        self.assertEqual(cell_position(1000, 1000, 10, 20), (51, 101, 0, 0))

    def test_invalid_cell_size(self):
        for cell in ((0, 20), (10, 0), (-1, 20)):
            with self.assertRaises(ValueError):
                cell_position(0, 0, *cell)


@unittest.skipIf(ClientWindow is None, "the terminal client is not installed")
class TerminalWindowTest(unittest.TestCase):

    def make_window(self, client=None, wid=1, geom=(20, 40, 64, 32), override_redirect=False, metadata=None):
        client = client or FakeClient()
        md = typedict({"has-alpha": True})
        md.update(metadata or {})
        window = ClientWindow(client, None, wid, geom, geom[2:],
                              md, override_redirect, typedict(),
                              None, (0, 0), 24, "no")
        # the paints are normally deferred to the GLib main loop, run them inline:
        window._backing.with_gfx_context = lambda function, *args: function(None, *args)
        return client, window

    def paint(self, window, x=0, y=0, width=4, height=4, flush=0):
        calls = []

        def record(success, message="") -> None:
            calls.append((success, message))

        data = bytes((1, 2, 3, 255)) * (width * height)
        options = typedict({"rgb_format": "RGBA", "flush": flush})
        window.draw_region(x, y, width, height, "rgb32", data, width * 4, options, [record])
        return calls

    ######################################################################
    # construction

    def test_backing_class(self):
        client, window = self.make_window()
        self.assertEqual(window.get_backing_class(), TerminalBacking)
        self.assertIsInstance(window._backing, TerminalBacking)
        self.assertEqual(window._backing.size, (64, 32))
        self.assertEqual(window._backing.render_size, (64, 32))

    def test_attributes(self):
        client, window = self.make_window()
        self.assertEqual(window._pos, (20, 40))
        self.assertEqual(window._size, (64, 32))
        self.assertEqual(window.get_size(), (64, 32))
        self.assertEqual(window._resize_counter, 0)
        self.assertFalse(window._override_redirect)
        self.assertEqual(window.sp(10, 20), (10, 20))
        self.assertFalse(window.is_OR())
        self.assertFalse(window.is_tray())
        self.assertIn("64", repr(window) + str(window.get_info()))

    def test_client_properties_include_rgb_formats(self):
        client, window = self.make_window()
        props = window._client_properties
        self.assertEqual(tuple(props["encodings.rgb_formats"]), tuple(TerminalBacking.RGB_MODES))
        self.assertEqual(props["encoding.render-size"], (64, 32))

    def test_nothing_written_before_mapping(self):
        client, window = self.make_window()
        self.assertEqual(client.drain(), b"")
        window.repaint(0, 0, 10, 10)
        self.assertEqual(client.drain(), b"")

    ######################################################################
    # map

    def test_show_sends_map_packet(self):
        client, window = self.make_window()
        window.show_all()
        packet = client.last_packet(WINDOW_MAP)
        self.assertEqual(packet[1], 1)
        self.assertEqual(packet[2:6], (20, 40, 64, 32))
        props = packet[6]
        self.assertEqual(tuple(props["encodings.rgb_formats"]), tuple(TerminalBacking.RGB_MODES))
        self.assertEqual(packet[7], {})
        # the properties have been consumed:
        self.assertEqual(dict(window._client_properties), {})

    def test_override_redirect_does_not_send_map(self):
        # the server maps override-redirect windows itself and rejects map packets for them:
        client, window = self.make_window(override_redirect=True)
        window.show_all()
        self.assertNotIn(WINDOW_MAP, client.packet_types())
        # the client properties are delivered without any geometry instead:
        config = client.last_packet(WINDOW_CONFIGURE)[2]
        self.assertNotIn("geometry", config)
        props = config["properties"]
        self.assertEqual(tuple(props["encodings.rgb_formats"]), tuple(TerminalBacking.RGB_MODES))
        self.assertEqual(props["encoding.render-size"], (64, 32))
        self.assertEqual(dict(window._client_properties), {})
        # the window is still shown:
        self.assertEqual(actions(client.commands()), ["t", "p"])

    def test_override_redirect_does_not_send_unmap(self):
        client, window = self.make_window(override_redirect=True)
        window.show_all()
        client.drain()
        client.packets = []
        window.hide()
        self.assertEqual(client.packet_types(), [])
        # the placement is still removed:
        self.assertEqual(actions(client.commands()), ["d"])

    def test_override_redirect_resize_sends_the_client_properties(self):
        client, window = self.make_window(override_redirect=True)
        window.show_all()
        client.drain()
        client.packets = []
        window.resize(100, 50)
        config = client.last_packet(WINDOW_CONFIGURE)[2]
        self.assertNotIn("geometry", config)
        self.assertEqual(config["properties"]["encoding.render-size"], (100, 50))

    def test_show_transmits_and_places(self):
        client, window = self.make_window()
        window.show_all()
        commands = client.commands()
        self.assertEqual(actions(commands), ["t", "p"])
        transmit = graphics_keys(commands, "t")[0]
        self.assertEqual(transmit["i"], "1")
        self.assertEqual(transmit["s"], "64")
        self.assertEqual(transmit["v"], "32")
        self.assertEqual(transmit["f"], "32")
        place = graphics_keys(commands, "p")[0]
        self.assertEqual(place["i"], "1")
        self.assertEqual(place["z"], "10")
        self.assertEqual(place["C"], "1")
        # (20, 40) with 10x20 cells: row 3, column 3, no intra-cell offset
        self.assertEqual(place["X"], "0")
        self.assertEqual(place["Y"], "0")
        self.assertIn(("cup", (3, 3)), commands)
        # the cursor position is saved and restored around the placement:
        self.assertEqual(commands[1], ("save",))
        self.assertEqual(commands[-1], ("restore",))

    def test_placement_offsets(self):
        client, window = self.make_window(geom=(25, 45, 64, 32))
        window.show_all()
        place = graphics_keys(client.commands(), "p")[0]
        self.assertEqual((place["X"], place["Y"]), ("5", "5"))

    def test_z_index_from_client(self):
        client = FakeClient()
        client.zorder[1] = 16
        client, window = self.make_window(client)
        window.show_all()
        self.assertEqual(graphics_keys(client.commands(), "p")[0]["z"], "16")

    def test_default_z_without_client_support(self):
        client, window = self.make_window()
        client.window_z = None
        window.show_all()
        self.assertEqual(graphics_keys(client.commands(), "p")[0]["z"], str(graphics.WINDOW_Z_BASE))

    def test_default_z_for_override_redirect(self):
        client, window = self.make_window(override_redirect=True)
        client.window_z = None
        window.show_all()
        expected = graphics.WINDOW_Z_BASE + graphics.OVERRIDE_REDIRECT_Z_OFFSET
        self.assertEqual(graphics_keys(client.commands(), "p")[0]["z"], str(expected))

    ######################################################################
    # paint / present

    def test_draw_region_emits_a_patch(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        calls = self.paint(window, 2, 3, 4, 4)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0])
        commands = client.commands()
        self.assertEqual(actions(commands), ["f"])
        patch = graphics_keys(commands, "f")[0]
        self.assertEqual((patch["x"], patch["y"], patch["s"], patch["v"]), ("2", "3", "4", "4"))
        self.assertEqual(patch["r"], "1")
        self.assertEqual(patch["X"], "1")

    def test_no_frame_edits_retransmits_the_image(self):
        # a terminal without `a=f` support gets the whole image again instead of a patch:
        client, window = self.make_window()
        window.show_all()
        client.drain()
        client.frame_edits = False
        calls = self.paint(window, 2, 3, 4, 4)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0])
        commands = client.commands()
        self.assertEqual(actions(commands), ["t", "p"])
        self.assertNotIn("f", actions(commands))

    def test_draw_region_flush_defers_the_patch(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        calls = self.paint(window, 0, 0, 4, 4, flush=1)
        self.assertEqual(len(calls), 1)
        # nothing is presented until the last packet of the group:
        self.assertEqual(client.drain(), b"")
        calls = self.paint(window, 8, 8, 4, 4, flush=0)
        self.assertEqual(len(calls), 1)
        commands = client.commands()
        # both rectangles are presented, they do not overlap:
        self.assertEqual(actions(commands), ["f", "f"])
        rects = [(k["x"], k["y"], k["s"], k["v"]) for k in graphics_keys(commands, "f")]
        self.assertIn(("0", "0", "4", "4"), rects)
        self.assertIn(("8", "8", "4", "4"), rects)

    def test_overlapping_damage_is_merged_into_one_patch(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        self.paint(window, 0, 0, 8, 8, flush=1)
        self.paint(window, 4, 4, 8, 8, flush=0)
        commands = client.commands()
        self.assertEqual(actions(commands), ["f"])
        patch = graphics_keys(commands, "f")[0]
        self.assertEqual((patch["x"], patch["y"], patch["s"], patch["v"]), ("0", "0", "12", "12"))

    def test_repaint_clips_to_the_backing(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        window.repaint(60, 30, 100, 100)
        patch = graphics_keys(client.commands(), "f")[0]
        self.assertEqual((patch["x"], patch["y"], patch["s"], patch["v"]), ("60", "30", "4", "2"))

    def test_repaint_outside_the_backing_emits_nothing(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        window.repaint(1000, 1000, 10, 10)
        self.assertEqual(client.drain(), b"")

    def test_redraw_does_not_re_encode_unchanged_pixels(self):
        # `redraw_windows()` calls this at 10Hz whilst the server is unresponsive:
        client, window = self.make_window()
        window.show_all()
        client.drain()
        window.redraw()
        window.redraw()
        self.assertEqual(client.drain(), b"")

    def test_redraw_presents_the_pending_damage(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        # a paint that is part of a group is not presented yet:
        self.paint(window, 2, 3, 4, 4, flush=1)
        self.assertEqual(client.drain(), b"")
        window.redraw()
        patch = graphics_keys(client.commands(), "f")[0]
        self.assertEqual((patch["x"], patch["y"], patch["s"], patch["v"]), ("2", "3", "4", "4"))
        # and it is not sent twice:
        window.redraw()
        self.assertEqual(client.drain(), b"")

    def test_redraw_retransmits_a_reallocated_buffer(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        window.freeze()
        window.resize(100, 50)
        client.drain()
        window._frozen = False
        window.redraw()
        self.assertEqual(actions(client.commands()), ["t", "p"])

    def test_paint_reaches_the_backing(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        self.paint(window, 1, 1, 2, 2)
        self.assertEqual(window._backing.pixels_for(1, 1, 2, 2), bytes((1, 2, 3, 255)) * 4)

    def test_void_encoding_is_short_circuited(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        calls = []
        window.draw_region(0, 0, 4, 4, "void", b"", 0, typedict({"flush": 0}),
                           [lambda success, message="": calls.append((success, message))])
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0])

    ######################################################################
    # geometry

    def test_move_emits_a_placement_and_a_configure(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        window.move_resize(30, 60, 64, 32, 7)
        self.assertEqual(window._pos, (30, 60))
        self.assertEqual(window._resize_counter, 7)
        commands = client.commands()
        # the image did not change, only its placement:
        self.assertEqual(actions(commands), ["p"])
        self.assertIn(("cup", (4, 4)), commands)
        packet = client.last_packet(WINDOW_CONFIGURE)
        self.assertEqual(packet[1], 1)
        self.assertEqual(packet[2]["geometry"], (30, 60, 64, 32))
        self.assertEqual(packet[2]["resize-counter"], 7)

    def test_resize_reinitialises_the_backing_and_retransmits(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        serial = window._backing.buffer_serial
        window.resize(100, 50, 3)
        self.assertEqual(window._size, (100, 50))
        self.assertEqual(window._backing.size, (100, 50))
        self.assertEqual(window._backing.render_size, (100, 50))
        self.assertGreater(window._backing.buffer_serial, serial)
        commands = client.commands()
        self.assertEqual(actions(commands), ["t", "p"])
        transmit = graphics_keys(commands, "t")[0]
        self.assertEqual((transmit["s"], transmit["v"]), ("100", "50"))
        config = client.last_packet(WINDOW_CONFIGURE)[2]
        self.assertEqual(config["geometry"], (20, 40, 100, 50))
        self.assertEqual(config["resize-counter"], 3)
        # the new render size is sent with the configure packet:
        self.assertEqual(config["properties"]["encoding.render-size"], (100, 50))

    def test_unchanged_geometry_emits_no_graphics(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        window.move_resize(20, 40, 64, 32)
        self.assertEqual(client.drain(), b"")
        self.assertEqual(client.last_packet(WINDOW_CONFIGURE)[2]["geometry"], (20, 40, 64, 32))

    def test_override_redirect_does_not_send_configure(self):
        client, window = self.make_window(override_redirect=True)
        window.show_all()
        client.packets = []
        window.move_resize(0, 0, 64, 32)
        self.assertEqual(client.packet_types(), [])

    def test_send_configure(self):
        client, window = self.make_window()
        window.show_all()
        client.packets = []
        window.send_configure()
        packet = client.last_packet(WINDOW_CONFIGURE)
        self.assertEqual(packet[2]["geometry"], (20, 40, 64, 32))

    ######################################################################
    # stacking and focus

    def test_present_raises_and_replaces(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        window.present()
        self.assertEqual(client.raised, [1])
        commands = client.commands()
        self.assertEqual(actions(commands), ["p"])
        self.assertEqual(graphics_keys(commands, "p")[0]["z"], "42")
        self.assertEqual(client.subsystems["window"].focus_events, [(1, True)])

    def test_present_focuses_the_window_in_the_client(self):
        # the client's focus state is what key events are routed with,
        # leaving it stale sends the keystrokes to the previously focused window:
        client, window = self.make_window()
        other_client, other = self.make_window(client, wid=2, geom=(0, 0, 10, 10))
        client._focused = 2
        window.show_all()
        window.present()
        self.assertEqual(client._focused, 1)
        self.assertTrue(window.has_toplevel_focus())
        self.assertFalse(other.has_toplevel_focus())

    def test_present_falls_back_to_the_window_subsystem(self):
        client, window = self.make_window()
        client.focus_window = None
        window.show_all()
        window.present()
        self.assertEqual(client.subsystems["window"].focus_events, [(1, True)])

    def test_restack(self):
        client, window = self.make_window()
        other_client, other = self.make_window(client, wid=2, geom=(0, 0, 10, 10))
        window.show_all()
        client.drain()
        window.restack(other, 1)
        self.assertEqual(client.restacked, [(1, 2, 1)])
        self.assertEqual(graphics_keys(client.commands(), "p")[0]["z"], "44")

    def test_has_toplevel_focus(self):
        client, window = self.make_window()
        self.assertFalse(window.has_toplevel_focus())
        client._focused = 1
        self.assertTrue(window.has_toplevel_focus())

    ######################################################################
    # unmap / destroy / freeze

    def test_hide_removes_the_placement(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        window.hide()
        commands = client.commands()
        self.assertEqual(actions(commands), ["d"])
        delete = graphics_keys(commands, "d")[0]
        self.assertEqual(delete["d"], "i")
        self.assertEqual(delete["i"], "1")
        self.assertEqual(client.last_packet(WINDOW_UNMAP), (WINDOW_UNMAP, 1))
        # hiding twice is a no-op:
        client.packets = []
        window.hide()
        self.assertEqual(client.drain(), b"")
        self.assertEqual(client.packet_types(), [])

    def test_hidden_window_does_not_paint(self):
        client, window = self.make_window()
        window.show_all()
        window.hide()
        client.drain()
        calls = self.paint(window)
        self.assertEqual(len(calls), 1)
        self.assertEqual(client.drain(), b"")

    def test_destroy_deletes_the_image(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        window.destroy()
        commands = client.commands()
        self.assertEqual(actions(commands), ["d", "d"])
        self.assertEqual([k["d"] for k in graphics_keys(commands, "d")], ["i", "I"])
        self.assertIsNone(window._backing)

    def test_destroy_is_idempotent(self):
        client, window = self.make_window()
        window.show_all()
        window.destroy()
        client.drain()
        window.destroy()
        self.assertEqual(client.drain(), b"")

    def test_freeze_and_unfreeze(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        window.freeze()
        self.assertEqual([k["d"] for k in graphics_keys(client.commands(), "d")], ["i"])
        # a frozen window paints into its buffer but emits nothing:
        calls = self.paint(window)
        self.assertEqual(len(calls), 1)
        self.assertEqual(client.drain(), b"")
        window.unfreeze()
        # the placement comes back, followed by the damage that accumulated while frozen:
        self.assertEqual(actions(client.commands()), ["p", "f"])

    ######################################################################
    # metadata

    def test_update_icon_is_recorded(self):
        client, window = self.make_window()
        icon = object()
        window.update_icon(icon)
        self.assertIs(window._current_icon, icon)
        window.reset_icon()
        self.assertIs(window._current_icon, icon)

    def test_transient_for_is_recorded(self):
        client, window = self.make_window()
        window.update_metadata(typedict({"transient-for": 12}))
        self.assertEqual(window._transient_for, 12)

    def test_update_metadata(self):
        client, window = self.make_window()
        window.update_metadata(typedict({
            "title": "hello",
            "icon-title": "icon",
            "modal": True,
            "decorations": False,
            "role": "dialog",
            "maximized": True,
            "above": True,
            "sticky": True,
            "skip-taskbar": True,
            "window-type": ("DIALOG", ),
        }))
        self.assertEqual(window._title, "hello")
        self.assertEqual(window._icon_name, "icon")
        self.assertTrue(window.get_modal())
        self.assertFalse(window.get_decorated())
        self.assertEqual(window._role, "dialog")
        self.assertEqual(window._metadata.strget("title"), "hello")

    def test_alert_state(self):
        client, window = self.make_window(metadata={"window-type": ("NORMAL", )})
        window.set_alert_state(True)
        self.assertTrue(window._backing.alert_state)

    def test_initiate_moveresize_is_a_noop(self):
        client, window = self.make_window()
        window.show_all()
        client.drain()
        window.initiate_moveresize(0, 0, 1, 1, 1)
        self.assertEqual(client.drain(), b"")

    def test_eos(self):
        client, window = self.make_window()
        window.eos()


def main():
    unittest.main()


if __name__ == '__main__':
    main()
