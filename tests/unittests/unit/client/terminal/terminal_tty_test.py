#!/usr/bin/env python3
# This file is part of Xpra.
# Copyright (C) 2026 Yan Shoshitaishvili <yans@pwn.college>
# Xpra is released under the terms of the GNU GPL v2, or, at your option, any
# later version. See the file COPYING for details.

import os
import fcntl
import struct
import termios
import unittest
from io import BytesIO

from unit.test_util import silence_error

try:
    from xpra.client.terminal import tty as tty_module
except ImportError:
    tty_module = None

# the exact byte sequences the terminal context is contracted to emit:
ENTER = b"\x1b[?1049h\x1b[?25l\x1b[>15u\x1b[?1002h\x1b[?1003h\x1b[?1006h\x1b[?1016h"
EXIT = b"\x1b[?1016l\x1b[?1006l\x1b[?1003l\x1b[?1002l\x1b[<u\x1b[?25h\x1b[?1049l"


class RecordingFile:
    """ minimal stand-in for a buffered binary file object """

    def __init__(self, fail=False):
        self.data = b""
        self.flushes = 0
        self.fail = fail

    def write(self, data: bytes) -> None:
        if self.fail:
            raise OSError(5, "Input/output error")
        self.data += data

    def flush(self) -> None:
        if self.fail:
            raise OSError(5, "Input/output error")
        self.flushes += 1


@unittest.skipIf(tty_module is None, "the terminal client tty module is not available")
class TestTerminalOutput(unittest.TestCase):

    def test_write_and_flush(self):
        buf = BytesIO()
        output = tty_module.TerminalOutput(buf)
        output.write(b"hello")
        output.write(b" world")
        output.flush()
        self.assertEqual(buf.getvalue(), b"hello world")

    def test_write_empty_is_a_noop(self):
        recorder = RecordingFile()
        output = tty_module.TerminalOutput(recorder)
        output.write(b"")
        self.assertEqual(recorder.data, b"")

    def test_flush_is_forwarded(self):
        recorder = RecordingFile()
        output = tty_module.TerminalOutput(recorder)
        output.flush()
        output.flush()
        self.assertEqual(recorder.flushes, 2)

    def test_write_failure_is_not_fatal(self):
        recorder = RecordingFile(fail=True)
        output = tty_module.TerminalOutput(recorder)
        with silence_error(tty_module):
            output.write(b"hello")
            # the writer gives up after the first failure:
            output.write(b"more")
            output.flush()
        self.assertTrue(output.failed)
        self.assertEqual(recorder.data, b"")
        self.assertEqual(recorder.flushes, 0)

    def test_flush_failure_is_not_fatal(self):
        recorder = RecordingFile()
        output = tty_module.TerminalOutput(recorder)
        recorder.fail = True
        with silence_error(tty_module):
            output.flush()
        self.assertTrue(output.failed)

    def test_repr(self):
        self.assertIn("TerminalOutput", repr(tty_module.TerminalOutput(BytesIO())))


@unittest.skipIf(tty_module is None, "the terminal client tty module is not available")
class TestMakeRaw(unittest.TestCase):

    def setUp(self):
        self.master, self.slave = os.openpty()
        self.addCleanup(os.close, self.master)
        self.addCleanup(os.close, self.slave)

    def test_make_raw_clears_the_expected_flags(self):
        mode = termios.tcgetattr(self.slave)
        tty_module.make_raw(mode)
        self.assertEqual(mode[tty_module.IFLAG] & tty_module.IFLAG_RAW_MASK, 0)
        self.assertEqual(mode[tty_module.OFLAG] & termios.OPOST, 0)
        self.assertEqual(mode[tty_module.LFLAG] & tty_module.LFLAG_RAW_MASK, 0)
        self.assertEqual(mode[tty_module.CFLAG] & termios.CSIZE, termios.CS8)
        self.assertEqual(mode[tty_module.CFLAG] & termios.PARENB, 0)
        self.assertEqual(mode[tty_module.CC][termios.VMIN], 1)
        self.assertEqual(mode[tty_module.CC][termios.VTIME], 0)

    def test_make_raw_does_not_touch_the_terminal(self):
        before = termios.tcgetattr(self.slave)
        mode = termios.tcgetattr(self.slave)
        tty_module.make_raw(mode)
        self.assertEqual(termios.tcgetattr(self.slave), before)


@unittest.skipIf(tty_module is None, "the terminal client tty module is not available")
class TestTerminalContext(unittest.TestCase):

    def setUp(self):
        self.master, self.slave = os.openpty()
        self.addCleanup(os.close, self.master)
        self.addCleanup(os.close, self.slave)
        self.buf = BytesIO()
        self.output = tty_module.TerminalOutput(self.buf)
        self.context = tty_module.TerminalContext(self.slave, self.output)

    def written(self) -> bytes:
        return self.buf.getvalue()

    def test_defaults(self):
        self.assertEqual(tty_module.KEYBOARD_FLAGS, 15)
        self.assertEqual(tty_module.MOUSE_MODES, (1002, 1003, 1006, 1016))

    def test_enter_sequence(self):
        self.assertFalse(self.context.active)
        self.context.enter()
        self.assertTrue(self.context.active)
        self.assertEqual(self.written(), ENTER)

    def test_enter_ordering(self):
        self.context.enter()
        data = self.written()
        expected_order = (
            b"\x1b[?1049h",     # alternate screen first
            b"\x1b[?25l",       # then hide the cursor
            b"\x1b[>15u",       # then push the kitty keyboard flags
            b"\x1b[?1002h",     # then the mouse modes, in ascending order
            b"\x1b[?1003h",
            b"\x1b[?1006h",
            b"\x1b[?1016h",
        )
        positions = [data.index(seq) for seq in expected_order]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(len(positions), len(set(positions)))

    def test_enter_switches_to_raw_mode(self):
        self.context.enter()
        mode = termios.tcgetattr(self.slave)
        self.assertEqual(mode[tty_module.LFLAG] & (termios.ECHO | termios.ICANON | termios.ISIG), 0)
        self.assertEqual(mode[tty_module.OFLAG] & termios.OPOST, 0)
        self.assertEqual(mode[tty_module.IFLAG] & (termios.ICRNL | termios.IXON), 0)
        self.assertEqual(mode[tty_module.CC][termios.VMIN], 1)

    def test_enter_is_idempotent(self):
        self.context.enter()
        self.context.enter()
        self.assertEqual(self.written(), ENTER)

    def test_exit_sequence(self):
        self.context.enter()
        self.context.exit()
        self.assertEqual(self.written(), ENTER + EXIT)
        self.assertFalse(self.context.active)

    def test_exit_ordering_is_the_reverse_of_enter(self):
        self.context.enter()
        expected_order = (
            b"\x1b[?1016l",     # mouse modes off first, in reverse order
            b"\x1b[?1006l",
            b"\x1b[?1003l",
            b"\x1b[?1002l",
            b"\x1b[<u",         # pop the kitty keyboard flags
            b"\x1b[?25h",       # show the cursor
            b"\x1b[?1049l",     # back to the main screen last
        )
        self.context.exit()
        data = self.written()[len(ENTER):]
        positions = [data.index(seq) for seq in expected_order]
        self.assertEqual(positions, sorted(positions))

    def test_exit_restores_termios(self):
        saved = termios.tcgetattr(self.slave)
        self.context.enter()
        self.assertNotEqual(termios.tcgetattr(self.slave), saved)
        self.context.exit()
        self.assertEqual(termios.tcgetattr(self.slave), saved)

    def test_exit_is_idempotent(self):
        self.context.enter()
        self.context.exit()
        expected = self.written()
        self.context.exit()
        self.context.exit()
        self.assertEqual(self.written(), expected)

    def test_exit_without_enter_is_a_noop(self):
        self.context.exit()
        self.assertEqual(self.written(), b"")
        self.assertFalse(self.context.active)

    def test_enter_after_exit(self):
        self.context.enter()
        self.context.exit()
        self.context.enter()
        self.assertEqual(self.written(), ENTER + EXIT + ENTER)
        self.assertTrue(self.context.active)
        self.context.exit()

    def test_repr(self):
        self.assertIn("TerminalContext", repr(self.context))

    def test_non_terminal_fd_still_emits_the_escape_sequences(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        buf = BytesIO()
        context = tty_module.TerminalContext(read_fd, tty_module.TerminalOutput(buf))
        with silence_error(tty_module):
            context.enter()
            self.assertTrue(context.active)
            self.assertEqual(buf.getvalue(), ENTER)
            context.exit()
        self.assertEqual(buf.getvalue(), ENTER + EXIT)


@unittest.skipIf(tty_module is None, "the terminal client tty module is not available")
class TestTerminalSize(unittest.TestCase):

    def setUp(self):
        self.master, self.slave = os.openpty()
        self.addCleanup(os.close, self.master)
        self.addCleanup(os.close, self.slave)

    def set_size(self, rows: int, cols: int, width_px: int, height_px: int) -> None:
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, width_px, height_px))

    def test_size(self):
        self.set_size(24, 80, 640, 480)
        self.assertEqual(tty_module.get_terminal_size(self.slave), (80, 24, 640, 480))

    def test_size_changes(self):
        self.set_size(50, 132, 1584, 1100)
        self.assertEqual(tty_module.get_terminal_size(self.slave), (132, 50, 1584, 1100))
        self.set_size(24, 80, 640, 480)
        self.assertEqual(tty_module.get_terminal_size(self.slave), (80, 24, 640, 480))

    def test_size_from_the_master_side(self):
        self.set_size(24, 80, 640, 480)
        self.assertEqual(tty_module.get_terminal_size(self.master), (80, 24, 640, 480))

    def test_no_pixel_size_reported(self):
        self.set_size(24, 80, 0, 0)
        self.assertEqual(tty_module.get_terminal_size(self.slave), (80, 24, 0, 0))

    def test_large_values(self):
        self.set_size(1000, 2000, 40000, 50000)
        self.assertEqual(tty_module.get_terminal_size(self.slave), (2000, 1000, 40000, 50000))

    def test_not_a_terminal(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        self.assertEqual(tty_module.get_terminal_size(read_fd), (0, 0, 0, 0))

    def test_invalid_fd(self):
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        os.close(write_fd)
        self.assertEqual(tty_module.get_terminal_size(read_fd), (0, 0, 0, 0))


def main():
    unittest.main()


if __name__ == '__main__':
    main()
