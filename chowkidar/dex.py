"""Read the string table from Dalvik executables (classes*.dex).

Every literal an app uses (URLs, bot tokens, hostnames) ends up in the DEX
string table, so this gives cleaner indicators than scanning raw bytes.
"""

from __future__ import annotations

import struct

DEX_MAGIC = b"dex\n"
MAX_STRINGS = 200_000  # guard against crafted headers


def _uleb128(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80 or shift > 28:
            return result, pos
        shift += 7


def strings(data: bytes) -> list[str]:
    """Return the DEX string table, or [] if the data is not a valid DEX file."""
    if len(data) < 0x70 or not data.startswith(DEX_MAGIC):
        return []
    size, offset = struct.unpack_from("<II", data, 0x38)
    if size > MAX_STRINGS or offset + size * 4 > len(data):
        return []
    out: list[str] = []
    for i in range(size):
        (str_off,) = struct.unpack_from("<I", data, offset + i * 4)
        if str_off >= len(data):
            continue
        try:
            _utf16_len, pos = _uleb128(data, str_off)
            end = data.index(b"\x00", pos)
        except (IndexError, ValueError):
            continue
        # DEX uses Modified UTF-8; plain UTF-8 decoding is right for almost
        # every string that matters here (URLs, tokens, hostnames).
        out.append(data[pos:end].decode("utf-8", errors="replace"))
    return out
