# This file is part of Xpra.
# Copyright (C) 2026 Yan Shoshitaishvili <yans@pwn.college>
# Xpra is released under the terms of the GNU GPL v2, or, at your option, any
# later version. See the file COPYING for details.

import os
import sys
import select
import signal
import logging
from typing import Any, Final
from collections.abc import Sequence

from xpra.os_util import gi_import
from xpra.exit_codes import ExitCode, ExitValue
from xpra.platform.paths import get_default_log_dirs
from xpra.util.env import envint, envbool, osexpand
from xpra.util.objects import typedict
from xpra.util.thread import is_main_thread
from xpra.util.gobject import no_arg_signal
from xpra.client.base.gobject import GObjectClientAdapter
from xpra.client.gui.ui_client_base import UIXpraClient
from xpra.client.terminal import graphics
from xpra.client.terminal.tty import (
    TerminalOutput, TerminalContext,
    get_terminal_size, cell_size_from_report, SIZE_QUERIES,
)
from xpra.client.terminal.input import (
    InputParser, KeyEvent, MouseEvent, GraphicsResponse, KeyboardFlagsResponse, TextReport,
    KEY_PRESS, KEY_REPEAT, KEY_RELEASE,
)
from xpra.client.terminal.keys import make_key_event, modifier_names
from xpra.client.terminal.backing import to_rgba
from xpra.client.terminal.window import cell_position, DEFAULT_CELL_WIDTH, DEFAULT_CELL_HEIGHT
from xpra.log import Logger, setloghandler

log = Logger("client", "terminal")
keylog = Logger("client", "keyboard")
pointerlog = Logger("client", "pointer")
cursorlog = Logger("cursor", "terminal")

GLib = gi_import("GLib")
GObject = gi_import("GObject")

# the terminal geometry to assume when the terminal does not report one
# (`get_root_size()` is called long before we can query the real terminal):
DEFAULT_COLUMNS: Final[int] = 80
DEFAULT_ROWS: Final[int] = 24
# terminals are not physical screens, assume the usual 96 DPI:
DPI: Final[int] = envint("XPRA_TERMINAL_DPI", 96)
# how long we wait for the terminal to answer our kitty graphics query, in milliseconds:
PROBE_TIMEOUT: Final[int] = envint("XPRA_TERMINAL_PROBE_TIMEOUT", 2000)
# quit when the terminal does not answer the graphics query - turn this off to
# use a terminal which supports the protocol but refuses to answer queries:
PROBE_REQUIRED: Final[bool] = envbool("XPRA_TERMINAL_PROBE_REQUIRED", True)
# bytes read from the terminal per `io_add_watch` callback:
READ_SIZE: Final[int] = envint("XPRA_TERMINAL_READ_SIZE", 8192)
# how long to wait for the rest of an escape sequence
# before treating a lone `ESC` as the Escape key (milliseconds):
INPUT_FLUSH_DELAY: Final[int] = envint("XPRA_TERMINAL_INPUT_FLUSH_DELAY", 50)
# `a=f` frame edits are how damaged regions are updated without re-sending the
# whole image, but not every terminal implementing the graphics protocol has them
# (kitty does, Ghostty does not): -1 = detect with a probe, 0 = never, 1 = always:
FRAME_EDITS: Final[int] = envint("XPRA_TERMINAL_FRAME_EDITS", -1)
# how long to wait for the terminal to answer the frame edit probe, in milliseconds:
FRAME_PROBE_TIMEOUT: Final[int] = envint("XPRA_TERMINAL_FRAME_PROBE_TIMEOUT", 1000)

# the image and placement ids we use for things which are not windows:
PROBE_IMAGE_ID: Final[int] = graphics.CURSOR_IMAGE_ID + 1
CURSOR_PLACEMENT_ID: Final[int] = 1

BELL: Final[bytes] = b"\x07"
# the format of the log file we redirect our own output to:
LOG_FORMAT: Final[str] = "%(asctime)s %(message)s"
# `CSI ? u`: ask the terminal which kitty keyboard protocol flags are in effect
KEYBOARD_QUERY: Final[bytes] = b"\x1b[?u"
# kitty keyboard flag 2: the terminal reports key releases as well as key presses
KEYBOARD_EVENT_TYPES: Final[int] = 2

# The coordinate base of the SGR pixel mouse reports (mode 1016).
# `xterm` (which introduced the mode), WezTerm and Ghostty report the same 1-based
# coordinates as the SGR cell reports the mode extends, but kitty reports them 0-based
# (`encode_mouse_event_impl` in `kitty/mouse.c` sends the window relative pixel position
# unmodified), so the base has to be picked per terminal.
# -1, the default, means: 0 when we are running in kitty, 1 everywhere else.
MOUSE_COORDINATE_BASE: Final[int] = envint("XPRA_TERMINAL_MOUSE_COORDINATE_BASE", -1)

# SGR mouse buttons 4 to 7 are the wheel, as `(deltax, deltay)`:
WHEEL_DELTAS: Final[dict[int, tuple[int, int]]] = {
    4: (0, 1),      # up
    5: (0, -1),     # down
    6: (-1, 0),     # left
    7: (1, 0),      # right
}


def is_a_tty(fileobj) -> bool:
    try:
        return bool(fileobj) and fileobj.isatty()
    except (AttributeError, OSError, ValueError):
        return False


def mouse_coordinate_base() -> int:
    """ the value to subtract from an SGR pixel mouse report, see `MOUSE_COORDINATE_BASE` """
    if MOUSE_COORDINATE_BASE >= 0:
        return MOUSE_COORDINATE_BASE
    # kitty sets both of these for the processes it starts (`TERM` is `xterm-kitty`):
    if os.environ.get("KITTY_WINDOW_ID") or "kitty" in os.environ.get("TERM", ""):
        return 0
    return 1


def find_log_file() -> str:
    """ a writable path for the log file we redirect our own output to """
    for log_dir in get_default_log_dirs():
        path = osexpand(log_dir)
        if os.path.isdir(path) and os.access(path, os.W_OK):
            return os.path.join(path, f"xpra-terminal-{os.getpid()}.log")
    return ""


class XpraTerminalClient(GObjectClientAdapter, UIXpraClient):
    """
    An xpra client which renders the forwarded windows into a terminal
    using the kitty graphics protocol, and reads the keyboard and pointer
    from the terminal using the kitty keyboard protocol and SGR pixel mouse reports.

    The terminal is left completely untouched until the handshake has completed,
    so that authentication prompts still work in cooked mode.
    """

    __gsignals__ = {}
    # add signals from super classes (all no-arg signals)
    for signal_name in UIXpraClient.__signals__:
        __gsignals__[signal_name] = no_arg_signal

    @staticmethod
    def get_subsystem_classes() -> dict[str, type]:
        classes = dict(UIXpraClient.get_subsystem_classes())
        # the substitutions are imported lazily: the modules they replace are
        # import-blocked when the matching client feature is turned off
        # (see `enforce_client_features` in `xpra.client.base.features`),
        # and in that case the subsystem is not composed at all:
        if "display" in classes:
            from xpra.client.terminal.subsystem.display import TerminalDisplayClient
            classes["display"] = TerminalDisplayClient
        if "clipboard" in classes:
            from xpra.client.terminal.subsystem.clipboard import TerminalClipboardClient
            classes["clipboard"] = TerminalClipboardClient
        return classes

    def __init__(self):
        GObjectClientAdapter.__init__(self)
        UIXpraClient.__init__(self)
        # `client_type` is reset by both `__init__` calls above, so set it last:
        self.client_type = "terminal"
        # terminal state (nothing is touched until `start_terminal_mode`):
        self.terminal_fd: int = -1
        self.terminal_output: TerminalOutput | None = None
        self.terminal_context: TerminalContext | None = None
        # (columns, rows, width in pixels, height in pixels):
        self.terminal_size: tuple[int, int, int, int] = (0, 0, 0, 0)
        self.input_parser = InputParser()
        self.input_watch: int = 0
        self.input_flush_timer: int = 0
        self.sigwinch_watch: int = 0
        self.probe_timer: int = 0
        self.graphics_ok: bool = False
        # whether the terminal supports `a=f` frame edits (see `FRAME_EDITS`):
        self.frame_edits: bool = FRAME_EDITS > 0
        self.frame_probe_sent: bool = False
        self.frame_probe_timer: int = 0
        self.log_handler = None
        self.saved_log_handlers: list | None = None
        # the terminal only reports key releases when the kitty keyboard protocol
        # is active, otherwise we have to synthesize them (see `handle_key_event`):
        self.kitty_keyboard: bool = False
        # window manager state:
        # `_stack` holds the regular (non override-redirect) window ids, bottom first,
        # `_or_stack` the override-redirect ones in the order they were created:
        self._stack: list[int] = []
        self._or_stack: list[int] = []
        self._or_parent: dict[int, int] = {}
        self._zorder: dict[int, int] = {}
        self._focused: int = 0
        # input state, reported back to the subsystems which ask for it:
        self.mouse_base: int = mouse_coordinate_base()
        self._pointer_pos: tuple[int, int] = (0, 0)
        self._buttons: list[int] = []
        self._modifiers: list[str] = []
        # cursor state:
        self._cursor_data: tuple = ()
        self._cursor_serial: int = 0
        self._cursor_placed: bool = False
        self.init_terminal_size()
        # the keyboard helper must be replaced before the `keyboard` subsystem
        # instantiates it, which happens in `init_ui`:
        if kb := self.get_subsystem("keyboard"):
            from xpra.client.terminal.keyboard import TerminalKeyboardHelper
            kb.helper_class = TerminalKeyboardHelper
        if window := self.get_subsystem("window"):
            window.connect("new-window", self._new_window)

    def __repr__(self):
        return "XpraTerminalClient"

    def client_toolkit(self) -> str:
        return "terminal"

    ######################################################################
    # lifecycle

    def init(self, opts) -> None:
        # there is nowhere to put a system tray icon in a terminal
        # (`get_system_tray_classes()` returns nothing), so the tray forwarding
        # must not be advertised to the server - it would send us tray windows
        # we have no way of creating:
        opts.system_tray = False
        UIXpraClient.init(self, opts)
        # a terminal window has no decorations to put a header bar in:
        self.headerbar = "no"

    def init_ui(self, opts) -> None:
        UIXpraClient.init_ui(self, opts)
        # the terminal stays in cooked mode until the connection is up,
        # so that the password prompt and any error message still work:
        self.after_handshake(self.start_terminal_mode)

    def run(self) -> ExitValue:
        UIXpraClient.run(self)
        return GObjectClientAdapter.run(self)

    def quit(self, exit_code: ExitValue = ExitCode.OK) -> None:
        if self.main_loop is None:
            # `GObjectClientAdapter.quit` stops the main loop, and there is none yet:
            if self.exit_code is None:
                self.exit_code = exit_code
            self.cleanup()
            return
        GObjectClientAdapter.quit(self, exit_code)

    def cleanup(self) -> None:
        # the terminal is restored first: everything below may log,
        # and the log output must not land on the alternate screen
        self.stop_terminal_mode()
        UIXpraClient.cleanup(self)

    ######################################################################
    # terminal mode

    def init_terminal_size(self) -> None:
        fd = -1
        try:
            fd = sys.stdin.fileno()
        except (AttributeError, ValueError, OSError):
            log("init_terminal_size() no usable stdin", exc_info=True)
        self.terminal_fd = fd
        self.terminal_size = get_terminal_size(fd) if fd >= 0 else (0, 0, 0, 0)
        log("init_terminal_size() fd=%i, size=%s", fd, self.terminal_size)

    def make_terminal_output(self) -> TerminalOutput:
        """ the single terminal writer - overridden by the tests to capture what we emit """
        return TerminalOutput(getattr(sys.stdout, "buffer", sys.stdout))

    def start_terminal_mode(self) -> None:
        """ switch the terminal into graphics mode - UI thread, once, after the handshake """
        if self.terminal_output is not None:
            return
        self.redirect_logging()
        output = self.make_terminal_output()
        self.terminal_output = output
        self.terminal_context = TerminalContext(self.terminal_fd, output)
        self.terminal_context.enter()
        self.watch_terminal_input()
        self.watch_terminal_size()
        # ask the terminal what it supports, and give up on it when it says nothing:
        output.write(KEYBOARD_QUERY)
        output.write(graphics.probe(PROBE_IMAGE_ID))
        output.flush()
        self.probe_timer = self.timeout_add(PROBE_TIMEOUT, self.graphics_probe_timeout)

    def stop_terminal_mode(self) -> None:
        """ restore the terminal - idempotent, and safe to call before `run()` """
        if iw := self.input_watch:
            self.input_watch = 0
            self.source_remove(iw)
        if sw := self.sigwinch_watch:
            self.sigwinch_watch = 0
            self.source_remove(sw)
        if ft := self.input_flush_timer:
            self.input_flush_timer = 0
            self.source_remove(ft)
        self.cancel_probe_timer()
        self.cancel_frame_probe_timer()
        self.frame_probe_sent = False
        output = self.terminal_output
        self.terminal_output = None
        if output is not None:
            self.delete_images(output)
        context = self.terminal_context
        self.terminal_context = None
        if context is not None:
            context.exit()
        self.restore_logging()

    def delete_images(self, output: TerminalOutput) -> None:
        """ free every kitty image we uploaded - best effort, the terminal may already be gone """
        for wid in tuple(self._zorder.keys()):
            output.write(graphics.delete_image(wid))
        if self._cursor_serial:
            self._cursor_serial = 0
            self._cursor_placed = False
            output.write(graphics.delete_image(graphics.CURSOR_IMAGE_ID))
        if self.graphics_ok:
            output.write(graphics.delete_image(PROBE_IMAGE_ID))
        output.flush()

    def redirect_logging(self) -> None:
        """ our own log output must not end up on the alternate screen """
        if self.saved_log_handlers is not None:
            return
        handler: logging.Handler | None = None
        if not is_a_tty(sys.stderr):
            # stderr has been redirected already, keep using it:
            handler = logging.StreamHandler(sys.stderr)
        elif path := find_log_file():
            try:
                handler = logging.FileHandler(path)
                log.info("terminal client log file: %r", path)
            except OSError:
                log("redirect_logging()", exc_info=True)
        if handler is None:
            # nowhere to write to: drop our own output rather than corrupt the screen
            handler = logging.NullHandler()
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        self.saved_log_handlers = list(logging.root.handlers)
        self.log_handler = handler
        setloghandler(handler)

    def restore_logging(self) -> None:
        saved = self.saved_log_handlers
        if saved is None:
            return
        self.saved_log_handlers = None
        logging.root.handlers = saved
        if handler := self.log_handler:
            self.log_handler = None
            handler.close()

    ######################################################################
    # terminal geometry

    def update_terminal_size(self) -> bool:
        size = get_terminal_size(self.terminal_fd) if self.terminal_fd >= 0 else (0, 0, 0, 0)
        if size == (0, 0, 0, 0) or size == self.terminal_size:
            return False
        log("update_terminal_size() %s -> %s", self.terminal_size, size)
        self.terminal_size = size
        return True

    def cell_size(self) -> tuple[int, int]:
        """ the size of a terminal cell, in pixels """
        cols, rows, width, height = self.terminal_size
        cell_width = width // cols if cols > 0 and width > 0 else DEFAULT_CELL_WIDTH
        cell_height = height // rows if rows > 0 and height > 0 else DEFAULT_CELL_HEIGHT
        return max(1, cell_width), max(1, cell_height)

    def terminal_pixel_size(self) -> tuple[int, int]:
        """ the size of the terminal, in pixels - this is the 'screen' size we advertise """
        cols, rows, width, height = self.terminal_size
        if width > 0 and height > 0:
            return width, height
        cell_width, cell_height = self.cell_size()
        return (cols or DEFAULT_COLUMNS) * cell_width, (rows or DEFAULT_ROWS) * cell_height

    def watch_terminal_size(self) -> None:
        # prefer `GLibUnix.signal_add` (GLib >= 2.80), fall back to the deprecated
        # `GLib.unix_signal_add` and then to a plain signal handler
        # (same ladder as `install_signal_handlers` in `xpra.util.glib`):
        try:
            glib_unix = gi_import("GLibUnix")
            self.sigwinch_watch = glib_unix.signal_add(GLib.PRIORITY_DEFAULT, signal.SIGWINCH,
                                                       self.terminal_size_changed)
            return
        except (ImportError, AttributeError, TypeError):
            log("GLibUnix.signal_add is not available", exc_info=True)
        try:
            self.sigwinch_watch = GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGWINCH,
                                                       self.terminal_size_changed)
        except (AttributeError, TypeError):
            log("watch_terminal_size()", exc_info=True)
            signal.signal(signal.SIGWINCH, self.handle_sigwinch)

    def handle_sigwinch(self, _signum, _frame) -> None:
        # signal handlers must not touch the terminal, hop onto the main loop:
        self.idle_add(self.terminal_size_changed)

    def terminal_size_changed(self, *_args) -> bool:
        if not self.update_terminal_size():
            return True
        if self.terminal_size[2] <= 0:
            # this terminal does not report a pixel size, ask it again for its geometry:
            self.query_terminal_size()
        if display := self.get_subsystem("display"):
            display.screen_size_changed()
        return True

    def query_terminal_size(self) -> None:
        """ ask the terminal for its pixel geometry - the answers arrive as `TextReport` events """
        if output := self.terminal_output:
            for query in SIZE_QUERIES:
                output.write(query)
            output.flush()

    def handle_text_report(self, report: TextReport) -> None:
        """
        The answer to one of the `SIZE_QUERIES` (`TerminalContext.enter` sends them):
        a pty allocated by an intermediary which only forwards rows and columns reports
        no pixel size at all, and this is the only other way of finding out the cell size.
        """
        cols, rows, width, height = self.terminal_size
        if width > 0 and height > 0:
            log("ignoring %s, the terminal size is already known: %s", report, self.terminal_size)
            return
        cell_width, cell_height = cell_size_from_report(report.kind, report.values, cols, rows)
        if cols <= 0 or rows <= 0 or cell_width <= 0 or cell_height <= 0:
            log("ignoring unusable %s", report)
            return
        self.terminal_size = (cols, rows, cols * cell_width, rows * cell_height)
        log("handle_text_report(%s) terminal size=%s", report, self.terminal_size)
        if display := self.get_subsystem("display"):
            display.screen_size_changed()

    ######################################################################
    # terminal input

    def watch_terminal_input(self) -> None:
        if self.terminal_fd < 0 or self.input_watch:
            return
        self.input_watch = GLib.io_add_watch(self.terminal_fd, GLib.PRIORITY_DEFAULT,
                                             GLib.IO_IN | GLib.IO_HUP, self.handle_terminal_input)

    def handle_terminal_input(self, _source, condition) -> bool:
        if condition & GLib.IO_IN:
            try:
                data = os.read(self.terminal_fd, READ_SIZE)
            except OSError:
                log("handle_terminal_input()", exc_info=True)
                data = b""
            if data:
                self.process_input_events(self.input_parser.feed(data))
                self.schedule_input_flush()
                return True
        log("the terminal input stream has been closed")
        self.input_watch = 0
        self.disconnect_and_quit(ExitCode.OK, "terminal closed")
        return False

    def schedule_input_flush(self) -> None:
        # a terminal without the kitty keyboard protocol sends a bare `ESC` for the
        # Escape key, which is indistinguishable from the start of an escape sequence:
        # drain the parser if nothing else arrives shortly after.
        # Only ever a single buffered byte: a stalled multi-byte sequence just means a
        # slow terminal or congested link and the rest of it must be waited for -
        # flushing it would drop the key and mistype its remainder as garbage:
        if self.input_flush_timer:
            self.source_remove(self.input_flush_timer)
            self.input_flush_timer = 0
        if self.input_parser.pending == 1:
            self.input_flush_timer = self.timeout_add(INPUT_FLUSH_DELAY, self.flush_terminal_input)

    def flush_terminal_input(self) -> bool:
        self.input_flush_timer = 0
        if self.input_parser.pending != 1:
            return False
        # if more input is already waiting on the fd, the rest of the sequence has
        # arrived and the io watch is about to deliver it - do not flush a real
        # escape sequence's `ESC` just because this timer was dispatched first:
        if self.terminal_fd >= 0:
            readable, _, _ = select.select([self.terminal_fd], [], [], 0)
            if readable:
                return False
        self.process_input_events(self.input_parser.flush())
        return False

    def process_input_events(self, events: Sequence[object]) -> None:
        for event in events:
            if isinstance(event, KeyEvent):
                self.handle_key_event(event)
            elif isinstance(event, MouseEvent):
                self.handle_mouse_event(event)
            elif isinstance(event, GraphicsResponse):
                self.handle_graphics_response(event)
            elif isinstance(event, KeyboardFlagsResponse):
                self.handle_keyboard_flags(event)
            elif isinstance(event, TextReport):
                self.handle_text_report(event)
            else:
                log("ignoring terminal event %s", event)

    ######################################################################
    # keyboard

    def handle_keyboard_flags(self, response: KeyboardFlagsResponse) -> None:
        self.kitty_keyboard = bool(response.flags & KEYBOARD_EVENT_TYPES)
        keylog("the terminal reports keyboard flags %i, key releases=%s",
               response.flags, self.kitty_keyboard)

    def handle_key_event(self, event: KeyEvent) -> None:
        # the modifiers reported with the event are the best (and only) source we have:
        self._modifiers = modifier_names(event.mods)
        kb = self.get_subsystem("keyboard")
        window = self.get_window(self._focused)
        keylog("handle_key_event(%s) focused=%#x, window=%s", event, self._focused, window)
        if kb is None or window is None:
            return
        kb.handle_key_action(window, make_key_event(event))
        if not self.kitty_keyboard and event.event_type in (KEY_PRESS, KEY_REPEAT):
            # a terminal which does not report key releases: synthesize one,
            # or the key would stay pressed on the server forever
            release = KeyEvent(event.code, event.shifted, event.base, event.mods,
                               KEY_RELEASE, event.text)
            kb.handle_key_action(window, make_key_event(release))

    def get_current_modifiers(self) -> Sequence[str]:
        return tuple(self._modifiers)

    ######################################################################
    # pointer

    def get_raw_mouse_position(self) -> tuple[int, int]:
        return self._pointer_pos

    def get_mouse_position(self) -> tuple[int, int]:
        position = self._pointer_pos
        if display := self.get_subsystem("display"):
            position = display.cp(*position)
        return position

    def handle_mouse_event(self, event: MouseEvent) -> None:
        # the parser reports the coordinates exactly as the terminal sent them,
        # turn them into terminal pixels (see `mouse_coordinate_base`):
        x = max(0, event.x - self.mouse_base)
        y = max(0, event.y - self.mouse_base)
        self._pointer_pos = (x, y)
        self._modifiers = modifier_names(event.mods)
        wid, window = self.hit_test(x, y)
        pointerlog("handle_mouse_event(%s) position=%s, window=%#x", event, (x, y), wid)
        if window is not None:
            wx, wy = window._pos
            pointer = (x, y, x - wx, y - wy)
        else:
            pointer = (x, y, x, y)
        if event.event in ("motion", "press", "release"):
            self.update_cursor()
        if event.event == "wheel":
            self.send_wheel(wid, window, event.button, pointer)
        elif event.event in ("press", "release"):
            self.send_click(wid, window, event.button, event.event == "press", pointer)
        else:
            pointer_sub = self.get_subsystem("pointer")
            if pointer_sub:
                pointer_sub.send_mouse_position(-1, wid, pointer, modifiers=self._modifiers,
                                                buttons=tuple(self._buttons))

    def send_click(self, wid: int, window, button: int, pressed: bool, pointer) -> None:
        if button <= 0:
            return
        if pressed:
            if window is None:
                # a press on the terminal background: there is nothing to send it to
                return
            if button not in self._buttons:
                self._buttons.append(button)
            self.focus_window(wid)
            if not window.is_OR():
                # there is no window manager in a terminal: clicking raises
                self.raise_window(wid)
                window.refresh_placement()
        elif button in self._buttons:
            # the release is sent even when the pointer has been dragged out of the window
            # it was pressed on (`wid` is then 0, ie the root window):
            # a press which is never released leaves the button held down on the server
            self._buttons.remove(button)
        if w := self.get_subsystem("window"):
            w.send_button(-1, wid, button, pressed, pointer,
                          self._modifiers, tuple(self._buttons), {})

    def send_wheel(self, wid: int, window, button: int, pointer) -> None:
        deltax, deltay = WHEEL_DELTAS.get(button, (0, 0))
        if window is None or (not deltax and not deltay):
            return
        if w := self.get_subsystem("window"):
            w.wheel_event(-1, wid, deltax, deltay, pointer)

    ######################################################################
    # window manager state: stacking order, z indexes and focus

    def get_window(self, wid: int):
        window = self.get_subsystem("window")
        return window.get_window(wid) if window else None

    def _new_window(self, _emitter, window) -> None:
        wid = window.wid
        if window.is_OR():
            metadata = getattr(window, "_metadata", typedict())
            parent = metadata.intget("parent", 0) or getattr(window, "_transient_for", 0)
            self._or_parent[wid] = parent
            if wid not in self._or_stack:
                self._or_stack.append(wid)
        elif wid not in self._stack:
            self._stack.append(wid)
            # a freshly created regular window takes the focus if nothing has it,
            # otherwise the keyboard would be dead until the user clicks:
            if not self._focused:
                self.focus_window(wid)
        log("_new_window(%s) stack=%s, override-redirect=%s", window, self._stack, self._or_stack)
        self.update_zorder()

    def forget_window(self, wid: int) -> None:
        if wid in self._stack:
            self._stack.remove(wid)
        if wid in self._or_stack:
            self._or_stack.remove(wid)
        self._or_parent.pop(wid, None)
        self._zorder.pop(wid, None)
        if self._focused == wid:
            self._focused = 0
            # focus falls back to the window now at the top of the stack:
            if self._stack:
                self.focus_window(self._stack[-1])
        self.update_zorder()

    def destroy_window(self, wid: int, window) -> None:
        self.forget_window(wid)
        if w := self.get_subsystem("window"):
            w.destroy_window(wid, window)

    def stacking_order(self) -> list[int]:
        """ every window id, bottom first: an override-redirect window sits just above its parent """
        order: list[int] = []
        for wid in self._stack:
            order.append(wid)
            order += [owid for owid in self._or_stack if self._or_parent.get(owid, 0) == wid]
        # the override-redirect windows we could not attach to a parent go on top:
        order += [owid for owid in self._or_stack if owid not in order]
        return order

    def window_zorder(self) -> dict[int, int]:
        """
        The kitty `z` index of every window: regular windows are spaced out
        (10, 12, 14, ...) so that each of them has room for its
        override-redirect children just above it.
        """
        zorder: dict[int, int] = {}
        index = 0
        for wid in self.stacking_order():
            if wid in self._or_parent:
                parent_z = zorder.get(self._or_parent[wid], graphics.WINDOW_Z_BASE + index * graphics.WINDOW_Z_STEP)
                zorder[wid] = parent_z + graphics.OVERRIDE_REDIRECT_Z_OFFSET
            else:
                zorder[wid] = graphics.WINDOW_Z_BASE + index * graphics.WINDOW_Z_STEP
                index += 1
        return zorder

    def window_z(self, wid: int) -> int:
        return self._zorder.get(wid, graphics.WINDOW_Z_BASE)

    def update_zorder(self, skip: int = 0) -> None:
        """ recalculate the z indexes and re-place every window whose index changed """
        zorder = self.window_zorder()
        changed = tuple(wid for wid, z in zorder.items() if self._zorder.get(wid) != z)
        self._zorder = zorder
        log("update_zorder(%#x) changed=%s, zorder=%s", skip, changed, zorder)
        for wid in changed:
            if wid == skip:
                # the caller re-places this one itself:
                continue
            if window := self.get_window(wid):
                window.refresh_placement()

    def raise_window(self, wid: int) -> None:
        """ move a window to the top of the stack (its caller re-places it) """
        if wid in self._stack:
            self._stack.remove(wid)
            self._stack.append(wid)
        elif wid in self._or_stack:
            self._or_stack.remove(wid)
            self._or_stack.append(wid)
        self.update_zorder(wid)

    def lower_window(self, wid: int) -> None:
        if wid in self._stack:
            self._stack.remove(wid)
            self._stack.insert(0, wid)
        elif wid in self._or_stack:
            self._or_stack.remove(wid)
            self._or_stack.insert(0, wid)
        self.update_zorder(wid)

    def restack_window(self, wid: int, other_wid: int, above: int) -> None:
        """ place a window directly above (`above=1`) or below another one """
        stack = self._stack if wid in self._stack else self._or_stack
        if wid not in stack:
            return
        if other_wid not in stack:
            # no sibling to compare against: top or bottom of the stack will do
            if above:
                self.raise_window(wid)
            else:
                self.lower_window(wid)
            return
        stack.remove(wid)
        index = stack.index(other_wid)
        stack.insert(index + 1 if above else index, wid)
        self.update_zorder(wid)

    def focus_window(self, wid: int) -> None:
        if self._focused == wid:
            return
        self._focused = wid
        if w := self.get_subsystem("window"):
            w.update_focus(wid, True)

    def hit_test(self, x: int, y: int) -> tuple[int, Any]:
        """ the topmost mapped window containing this terminal pixel """
        for wid in reversed(self.stacking_order()):
            window = self.get_window(wid)
            if window is None or not getattr(window, "_mapped", False):
                continue
            wx, wy = window._pos
            ww, wh = window._size
            if wx <= x < wx + ww and wy <= y < wy + wh:
                return wid, window
        return 0, None

    ######################################################################
    # cursor

    def set_windows_cursor(self, windows, cursor_data) -> None:
        cursorlog("set_windows_cursor(%s, %i values)", windows, len(cursor_data or ()))
        self._cursor_data = tuple(cursor_data or ())
        # the `cursor` subsystem re-applies the cursors it recorded here:
        if cursor := self.get_subsystem("cursor"):
            for window in windows:
                if self._cursor_data:
                    cursor._cursors[window] = cursor_data
                else:
                    cursor._cursors.pop(window, None)
        # a new cursor image has to be uploaded before it can be placed:
        self._cursor_serial = 0
        self.update_cursor()

    def update_cursor(self) -> None:
        """ show the pointer cursor at its current position - UI thread """
        output = self.terminal_output
        if output is None:
            return
        data = self._cursor_data
        # ("raw", _, _, width, height, xhot, yhot, serial, pixels, name) - see `CursorClient`:
        if len(data) < 9 or str(data[0]) != "raw":
            self.remove_cursor(output)
            return
        try:
            width = int(data[3])
            height = int(data[4])
            xhot = int(data[5])
            yhot = int(data[6])
            serial = int(data[7])
            pixels = data[8]
            if width <= 0 or height <= 0:
                self.remove_cursor(output)
                return
            if serial != self._cursor_serial:
                # the cursor pixels are RGBA on the wire (see `CursorClient` and the
                # `raw` cursor images the X11 and Wayland servers produce):
                output.write(graphics.transmit(graphics.CURSOR_IMAGE_ID, width, height,
                                               to_rgba("RGBA", pixels, width, height, width * 4)))
                self._cursor_serial = serial
            cell_width, cell_height = self.cell_size()
            max_width, max_height = self.terminal_pixel_size()
            px, py = self._pointer_pos
            row, col, x_off, y_off = cell_position(px - xhot, py - yhot, cell_width, cell_height,
                                                   max_width, max_height)
            output.write(graphics.place(graphics.CURSOR_IMAGE_ID, CURSOR_PLACEMENT_ID,
                                        row, col, x_off, y_off, graphics.CURSOR_Z))
            self._cursor_placed = True
            output.flush()
        except (TypeError, ValueError) as e:
            cursorlog("update_cursor()", exc_info=True)
            cursorlog.warn("Warning: cannot render the pointer cursor")
            cursorlog.warn(f" {e}")
            self._cursor_data = ()

    def remove_cursor(self, output: TerminalOutput) -> None:
        if not self._cursor_placed:
            return
        self._cursor_placed = False
        output.write(graphics.delete_placement(graphics.CURSOR_IMAGE_ID, CURSOR_PLACEMENT_ID))
        output.flush()

    ######################################################################
    # kitty graphics protocol support

    def handle_graphics_response(self, response: GraphicsResponse) -> None:
        if response.image_id != PROBE_IMAGE_ID:
            log("ignoring graphics response for image %i: %s", response.image_id, response.message)
            return
        if not self.graphics_ok:
            self.cancel_probe_timer()
            if not response.ok:
                self.graphics_unsupported(f"the terminal rejected our test image: {response.message}")
                return
            log("the terminal supports the kitty graphics protocol")
            self.graphics_ok = True
            self.probe_frame_edits()
            # everything mapped before the probe answered has not been drawn yet:
            for window in self.get_windows():
                window.refresh_placement()
            return
        if self.frame_probe_sent:
            self.frame_probe_sent = False
            self.cancel_frame_probe_timer()
            self.frame_edits = response.ok
            if response.ok:
                log("the terminal supports frame edits")
            else:
                log.info("this terminal does not support frame edits: %s", response.message or "rejected")
                log.info(" damaged regions will be updated by re-sending the whole image")
            self.free_probe_image()

    def probe_frame_edits(self) -> None:
        """ find out if the terminal implements `a=f` frame edits, unless `FRAME_EDITS` forces it """
        output = self.terminal_output
        if FRAME_EDITS >= 0 or output is None:
            self.frame_edits = FRAME_EDITS > 0
            self.free_probe_image()
            return
        self.frame_probe_sent = True
        # store a real 1x1 image under the probe id, then try to edit its frame:
        output.write(graphics.transmit(PROBE_IMAGE_ID, 1, 1, b"\x00\x00\x00\x00"))
        output.write(graphics.probe_frame_edit(PROBE_IMAGE_ID))
        output.flush()
        self.frame_probe_timer = self.timeout_add(FRAME_PROBE_TIMEOUT, self.frame_probe_timeout)

    def frame_probe_timeout(self) -> bool:
        self.frame_probe_timer = 0
        if self.frame_probe_sent:
            self.frame_probe_sent = False
            self.frame_edits = False
            log.info("the terminal did not answer the frame edit query")
            log.info(" damaged regions will be updated by re-sending the whole image")
            self.free_probe_image()
        return False

    def free_probe_image(self) -> None:
        if output := self.terminal_output:
            output.write(graphics.delete_image(PROBE_IMAGE_ID))
            output.flush()

    def cancel_frame_probe_timer(self) -> None:
        if ft := self.frame_probe_timer:
            self.frame_probe_timer = 0
            self.source_remove(ft)

    def graphics_probe_timeout(self) -> None:
        self.probe_timer = 0
        self.graphics_unsupported("no answer to the kitty graphics protocol query")

    def graphics_unsupported(self, message: str) -> None:
        if self.graphics_ok:
            return
        if not PROBE_REQUIRED:
            log.warn("Warning: %s", message)
            log.warn(" carrying on because 'XPRA_TERMINAL_PROBE_REQUIRED' is disabled")
            self.graphics_ok = True
            return
        # `warn_and_quit` restores the terminal before it says anything (see below):
        self.warn_and_quit(ExitCode.UNSUPPORTED,
                           "this terminal does not support the kitty graphics protocol:\n"
                           f" {message}")

    def cancel_probe_timer(self) -> None:
        if pt := self.probe_timer:
            self.probe_timer = 0
            self.source_remove(pt)

    ######################################################################
    # fatal errors

    def restore_terminal_for_message(self) -> bool:
        """
        Leave terminal mode before a message is shown to the user.

        Anything logged while terminal mode is active is written to our log file
        (see `redirect_logging`) and would land on the alternate screen anyway,
        which is discarded when the terminal is restored.
        Returns `False` when the caller has to try again from the UI thread,
        since the terminal must not be written to from any other thread.
        """
        if self.terminal_output is None and self.saved_log_handlers is None:
            return True
        if not is_main_thread():
            return False
        self.stop_terminal_mode()
        return True

    def warn_and_quit(self, exit_code: ExitValue, message: str) -> None:
        if not self.restore_terminal_for_message():
            self.idle_add(self.warn_and_quit, exit_code, message)
            return
        UIXpraClient.warn_and_quit(self, exit_code, message)

    def server_disconnect_warning(self, reason: str, *extra_info) -> None:
        if not self.restore_terminal_for_message():
            self.idle_add(self.server_disconnect_warning, reason, *extra_info)
            return
        UIXpraClient.server_disconnect_warning(self, reason, *extra_info)

    ######################################################################
    # terminal output for the other components

    def write_terminal(self, data: bytes) -> None:
        """ write to the terminal - UI thread """
        if output := self.terminal_output:
            output.write(data)
            output.flush()

    def write_osc52(self, data: bytes) -> None:
        # the clipboard packets are handled on the UI thread (see `ClipboardClient`):
        self.write_terminal(data)

    def window_bell(self, window, device: int, percent: int, pitch: int, duration: int, bell_class,
                    bell_id: int, bell_name: str) -> None:
        log("window_bell(%s, %s, %s, %s)", window, bell_class, bell_id, bell_name)
        self.write_terminal(BELL)

    ######################################################################
    # the rest of the frontend contract

    def get_encodings(self) -> Sequence[str]:
        encoding = self.get_subsystem("encoding")
        return encoding.get_encodings() if encoding else ()

    def get_client_window_classes(self, _geom, _metadata, _override_redirect) -> Sequence[type]:
        from xpra.client.terminal.window import ClientWindow
        # there is no OpenGL alternative to fall back from:
        return (ClientWindow, )

    def get_group_leader(self, wid: int, metadata: typedict, override_redirect: bool):
        # there is no window manager to group anything for:
        return None

    def get_xdpi(self) -> int:
        return DPI

    def get_ydpi(self) -> int:
        return DPI

    def get_gl_client_window_module(self, _enable_opengl: str) -> tuple[dict, Any]:
        # there is no OpenGL rendering into a terminal:
        return {}, None

    def get_notifier_classes(self) -> Sequence[Any]:
        return ()

    def get_tray_classes(self) -> Sequence[type]:
        return ()

    def get_system_tray_classes(self) -> Sequence[type]:
        return ()

    def get_menu_helper(self):
        # the menus need a toolkit we don't have:
        return None

    @staticmethod
    def get_menu_helper_class():
        return None

    def window_grab(self, wid: int, window) -> None:
        log("window_grab(%#x, %s) the terminal client cannot grab the pointer", wid, window)
        if w := self.get_subsystem("window"):
            w._window_with_grab = wid

    def window_ungrab(self) -> None:
        log("window_ungrab()")
        if w := self.get_subsystem("window"):
            w._window_with_grab = 0

    def get_info(self) -> dict[str, Any]:
        info = UIXpraClient.get_info(self)
        info["terminal"] = {
            "size": self.terminal_size,
            "cell-size": self.cell_size(),
            "graphics": self.graphics_ok,
            "frame-edits": self.frame_edits,
            "kitty-keyboard": self.kitty_keyboard,
            "mouse-coordinate-base": self.mouse_base,
            "stack": tuple(self._stack),
            "override-redirect": tuple(self._or_stack),
            "focused": self._focused,
        }
        return info


GObject.type_register(XpraTerminalClient)


def make_client(_opts) -> XpraTerminalClient:
    # never talk to the local X11 display, even when `$DISPLAY` is set:
    # the display subsystem's capability probes (`get_wm_name`, `get_vrefresh`, ...)
    # would try to use the X11 bindings without a display source and raise
    # (same guard as the fd_portal shadow server):
    os.environ.setdefault("XPRA_NOX11", "1")
    # `SIGINT` is deliberately left to `install_signal_handlers`
    # (`GObjectClientAdapter.install_signal_handlers`, called from `init`):
    # the default handler would kill us with the terminal still in raw mode
    return XpraTerminalClient()
