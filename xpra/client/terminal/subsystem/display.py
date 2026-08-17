# This file is part of Xpra.
# Copyright (C) 2026 Yan Shoshitaishvili <yans@pwn.college>
# Xpra is released under the terms of the GNU GPL v2, or, at your option, any
# later version. See the file COPYING for details.

from typing import Final
from collections.abc import Sequence

from xpra.util.env import envint
from xpra.util.parsing import DEFAULT_REFRESH_RATE
from xpra.client.subsystem.display import DisplayClient
from xpra.log import Logger

log = Logger("screen", "terminal")

# the terminal size we assume until the client can tell us the real one
# (`get_root_size` is called before the client enters terminal mode):
DEFAULT_COLUMNS: Final[int] = 80
DEFAULT_ROWS: Final[int] = 24
DEFAULT_CELL_WIDTH: Final[int] = 10
DEFAULT_CELL_HEIGHT: Final[int] = 20
DEFAULT_ROOT_SIZE: Final[tuple[int, int]] = (
    DEFAULT_COLUMNS * DEFAULT_CELL_WIDTH,
    DEFAULT_ROWS * DEFAULT_CELL_HEIGHT,
)
MONITOR_NAME: Final[str] = "terminal"
# terminals don't have a refresh rate, this is the rate at which we are willing to repaint,
# in milli-Hz (as in the `monitors` capability):
REFRESH_RATE: Final[int] = envint("XPRA_TERMINAL_REFRESH_RATE", DEFAULT_REFRESH_RATE)
# terminals don't have a physical size either, assume the usual 96 DPI:
DPI: Final[int] = envint("XPRA_TERMINAL_DPI", 96)
MM_PER_INCH: Final[float] = 25.4


class TerminalDisplayClient(DisplayClient):
    """
    Display subsystem for the terminal client.

    The 'screen' is the terminal's own pixel area: the client owns the terminal
    and exposes its size as `terminal_pixel_size()`.
    None of the queries here may touch a window system: the terminal client runs
    without X11 or Wayland (and often without a display at all).
    """
    __slots__ = ()

    def init(self, opts) -> None:
        # `DisplayClient.init` starts `X11DisplayPropsWatcher` when xsettings are enabled:
        # that watcher belongs to the X11 session this terminal happens to run in,
        # its workarea and DPI have nothing to do with the session we are attaching to.
        opts.xsettings = "no"
        super().init(opts)

    def get_root_size(self) -> tuple[int, int]:
        # this is called from `init` (via `parse_scaling`), long before the client
        # switches the terminal to raw mode, so it must never fail:
        size = ()
        terminal_pixel_size = getattr(self.client, "terminal_pixel_size", None)
        if callable(terminal_pixel_size):
            size = terminal_pixel_size()
        if size and len(size) >= 2:
            w = int(size[0])
            h = int(size[1])
            if w > 0 and h > 0:
                return w, h
        log("get_root_size() no terminal size available from %s, using %s", self.client, DEFAULT_ROOT_SIZE)
        return DEFAULT_ROOT_SIZE

    def get_screen_sizes(self, xscale=1, yscale=1) -> Sequence[tuple[int, int]]:
        # a terminal is always a single screen:
        w, h = self.get_root_size()
        return ((round(w / xscale), round(h / yscale)), )

    def get_monitors_info(self) -> dict:
        # the default implementation imports `xpra.gtk.info`, which this client must not do.
        # the geometry is in server coordinate space, as with every other backend:
        w, h = self.get_root_size()
        geometry = self.crect(0, 0, w, h)
        return {
            0: {
                "name": MONITOR_NAME,
                "primary": True,
                "geometry": geometry,
                "workarea": geometry,
                "width-mm": round(geometry[2] * MM_PER_INCH / DPI),
                "height-mm": round(geometry[3] * MM_PER_INCH / DPI),
                "refresh-rate": REFRESH_RATE,
            },
        }

    def has_transparency(self) -> bool:
        # the kitty graphics protocol composites RGBA images onto the terminal background:
        return True
