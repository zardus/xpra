# This file is part of Xpra.
# Copyright (C) 2026 Yan Shoshitaishvili <yans@pwn.college>
# Xpra is released under the terms of the GNU GPL v2, or, at your option, any
# later version. See the file COPYING for details.

import zlib
from typing import Final
from base64 import b64encode

from xpra.util.env import envint
from xpra.log import Logger

log = Logger("client", "terminal")

# base64 payload bytes per escape sequence, always a multiple of 4
# (the kitty protocol requires the payload of every non-final chunk to be a multiple of 4):
MAX_CHUNK: Final[int] = max(4, envint("XPRA_TERMINAL_MAX_CHUNK", 4096) // 4 * 4)

APC: Final[bytes] = b"\x1b_G"           # application program command, kitty graphics introducer
ST: Final[bytes] = b"\x1b\\"            # string terminator
DECSC: Final[bytes] = b"\x1b7"          # save cursor position
DECRC: Final[bytes] = b"\x1b8"          # restore cursor position
CSI: Final[bytes] = b"\x1b["

MAX_U32: Final[int] = 0xFFFFFFFF
MIN_I32: Final[int] = -0x80000000
MAX_I32: Final[int] = 0x7FFFFFFF

# the image id used for the pointer cursor, kept well clear of any window id:
CURSOR_IMAGE_ID: Final[int] = 0x7FFFFF00
# z-index space: regular windows get 10, 12, 14... by stack order,
# an override-redirect window sits at its parent's z + 1, the cursor sits above everything:
WINDOW_Z_BASE: Final[int] = 10
WINDOW_Z_STEP: Final[int] = 2
OVERRIDE_REDIRECT_Z_OFFSET: Final[int] = 1
CURSOR_Z: Final[int] = 2 ** 30


def _check_u32(name: str, value: int) -> None:
    if not 0 <= value <= MAX_U32:
        raise ValueError(f"invalid {name}: {value} does not fit in 32 bits")


def _check_i32(name: str, value: int) -> None:
    if not MIN_I32 <= value <= MAX_I32:
        raise ValueError(f"invalid {name}: {value} does not fit in a signed 32 bit integer")


def escape(control: str, payload: bytes = b"") -> bytes:
    """ wrap the control data and its (already encoded) payload in a kitty graphics escape sequence """
    if payload:
        return APC + control.encode("ascii") + b";" + payload + ST
    return APC + control.encode("ascii") + ST


def chunked(control: str, payload: bytes) -> bytes:
    """
    Split an encoded payload into `MAX_CHUNK` sized escape sequences.
    The first chunk carries the full control data, every following chunk carries only `m=`.
    `m=1` means "more data follows", `m=0` terminates the transfer.
    A payload small enough to fit in a single sequence is sent without any `m=` key.
    """
    size = len(payload)
    if size <= MAX_CHUNK:
        return escape(control, payload)
    parts = [escape(f"{control},m=1", payload[:MAX_CHUNK])]
    pos = MAX_CHUNK
    while pos < size:
        end = min(pos + MAX_CHUNK, size)
        parts.append(escape("m=%i" % int(end < size), payload[pos:end]))
        pos = end
    return b"".join(parts)


def encode_pixels(pixels: bytes, compress: bool) -> tuple[bytes, bool]:
    """
    base64 encode the pixel data, deflating it first when that actually makes it smaller.
    Returns the encoded payload and whether it is compressed (which requires the `o=z` key).
    """
    if compress:
        deflated = zlib.compress(pixels)
        if len(deflated) < len(pixels):
            return b64encode(deflated), True
    return b64encode(pixels), False


def transmit(image_id: int, width: int, height: int, pixels: bytes, alpha=True, compress=True) -> bytes:
    """
    Transmit a whole image: `a=t`.
    `pixels` must be `width * height` row-contiguous RGBA pixels (RGB when `alpha` is false).
    """
    _check_u32("image id", image_id)
    payload, deflated = encode_pixels(pixels, compress)
    control = f"a=t,q=2,i={image_id},f={32 if alpha else 24},s={width},v={height}"
    if deflated:
        control += ",o=z"
    log("transmit(%i, %i, %i, %i bytes, %s, %s)", image_id, width, height, len(pixels), alpha, compress)
    return chunked(control, payload)


def place(image_id: int, placement_id: int, row: int, col: int, x_off: int, y_off: int, z: int) -> bytes:
    """
    Place an image: `a=p`, at the given 1-based terminal cell with intra-cell pixel offsets.
    The cursor is saved and restored around the placement so the terminal state is left untouched.
    Rows and columns below 1 are clamped: the caller owns the clipping policy.
    """
    _check_u32("image id", image_id)
    _check_u32("placement id", placement_id)
    _check_i32("z index", z)
    cup = CSI + b"%i;%iH" % (max(1, row), max(1, col))
    control = f"a=p,q=2,i={image_id},p={placement_id},z={z},C=1,X={x_off},Y={y_off}"
    return DECSC + cup + escape(control) + DECRC


def patch(image_id: int, x: int, y: int, width: int, height: int, pixels: bytes, compress=True) -> bytes:
    """
    Update a rectangle of an image already held by the terminal: `a=f` frame edit of frame 1,
    with `X=1` so the new pixels replace the old ones instead of being alpha blended into them.
    """
    _check_u32("image id", image_id)
    payload, deflated = encode_pixels(pixels, compress)
    control = f"a=f,q=2,i={image_id},r=1,x={x},y={y},s={width},v={height}"
    if deflated:
        control += ",o=z"
    control += ",X=1"
    log("patch(%i, %i, %i, %i, %i, %i bytes, %s)", image_id, x, y, width, height, len(pixels), compress)
    return chunked(control, payload)


def delete_placement(image_id: int, placement_id: int) -> bytes:
    """ remove a single placement (`d=i`, lowercase: the image data is kept) """
    _check_u32("image id", image_id)
    _check_u32("placement id", placement_id)
    return escape(f"a=d,d=i,i={image_id},p={placement_id},q=2")


def delete_image(image_id: int) -> bytes:
    """ remove an image and free its data (`d=I`, uppercase) """
    _check_u32("image id", image_id)
    return escape(f"a=d,d=I,i={image_id},q=2")


def probe(image_id: int) -> bytes:
    """
    Query support for the graphics protocol: `a=q` with a single transparent RGBA pixel.
    Unlike every other command this one is not quieted, since we want the terminal's reply.
    """
    _check_u32("image id", image_id)
    return escape(f"a=q,i={image_id},f=32,s=1,v=1,t=d", b64encode(b"\0\0\0\0"))
