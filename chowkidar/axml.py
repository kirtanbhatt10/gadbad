"""Minimal parser for Android binary XML (AXML), used by AndroidManifest.xml.

Only the parts Chowkidar needs are implemented: the string pool, the resource
map and element/attribute events. No third-party dependencies.

Malware authors often tamper with the manifest to break analysis tools, so the
parser is defensive: bad offsets are skipped instead of raising, and attribute
names that were blanked out are recovered from the resource-ID map.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_RESOURCE_MAP_TYPE = 0x0180

UTF8_FLAG = 0x100
NO_INDEX = 0xFFFFFFFF

TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

# Framework attribute IDs (android.R.attr) for names that obfuscators blank out.
KNOWN_ATTR_IDS = {
    0x01010001: "label",
    0x01010002: "icon",
    0x01010003: "name",
    0x01010006: "permission",
    0x0101000E: "enabled",
    0x01010010: "exported",
    0x0101020C: "minSdkVersion",
    0x01010270: "targetSdkVersion",
    0x010104EC: "usesCleartextTraffic",
}


class AXMLError(ValueError):
    """Raised when the data is not binary XML at all."""


@dataclass
class Element:
    tag: str
    attrs: dict[str, object]
    depth: int
    children: list["Element"] = field(default_factory=list)

    def iter(self, tag: str | None = None):
        if tag is None or self.tag == tag:
            yield self
        for child in self.children:
            yield from child.iter(tag)

    def get(self, name: str, default=None):
        return self.attrs.get(name, default)


def _read_string_pool(data: bytes, offset: int) -> list[str]:
    header_size, size = struct.unpack_from("<HI", data, offset + 2)
    count, _styles, flags, strings_start, _styles_start = struct.unpack_from("<IIIII", data, offset + 8)
    is_utf8 = bool(flags & UTF8_FLAG)
    offsets_at = offset + header_size
    base = offset + strings_start
    end = offset + size
    strings: list[str] = []
    for i in range(count):
        try:
            (rel,) = struct.unpack_from("<I", data, offsets_at + i * 4)
            pos = base + rel
            if pos >= end:
                strings.append("")
                continue
            if is_utf8:
                # utf16 length (1-2 bytes), then utf8 byte length (1-2 bytes)
                n = data[pos]
                pos += 2 if n & 0x80 else 1
                n = data[pos]
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | data[pos + 1]
                    pos += 2
                else:
                    pos += 1
                strings.append(data[pos : pos + n].decode("utf-8", errors="replace"))
            else:
                (n,) = struct.unpack_from("<H", data, pos)
                pos += 2
                if n & 0x8000:
                    (low,) = struct.unpack_from("<H", data, pos)
                    n = ((n & 0x7FFF) << 16) | low
                    pos += 2
                strings.append(data[pos : pos + n * 2].decode("utf-16-le", errors="replace"))
        except (struct.error, IndexError):
            strings.append("")
    return strings


def _value(strings: list[str], raw: int, dtype: int, data: int) -> object:
    if dtype == TYPE_STRING:
        idx = raw if raw != NO_INDEX else data
        return strings[idx] if idx < len(strings) else ""
    if dtype == TYPE_INT_BOOLEAN:
        return data != 0
    if dtype == TYPE_INT_DEC:
        return struct.unpack("<i", struct.pack("<I", data))[0]
    if dtype == TYPE_INT_HEX:
        return data
    if dtype == TYPE_REFERENCE:
        return f"@0x{data:08x}"
    if raw != NO_INDEX and raw < len(strings):
        return strings[raw]
    return data


def parse(data: bytes) -> Element:
    """Parse binary XML and return the root element."""
    if len(data) < 8:
        raise AXMLError("too short to be binary XML")
    (chunk_type,) = struct.unpack_from("<H", data, 0)
    if chunk_type != RES_XML_TYPE:
        raise AXMLError("not binary XML")

    strings: list[str] = []
    res_ids: list[int] = []
    root: Element | None = None
    stack: list[Element] = []

    (header_size,) = struct.unpack_from("<H", data, 2)
    pos = header_size
    while pos + 8 <= len(data):
        ctype, chdr, csize = struct.unpack_from("<HHI", data, pos)
        if csize < 8 or pos + csize > len(data):
            break  # corrupt chunk: stop rather than read garbage
        if ctype == RES_STRING_POOL_TYPE:
            strings = _read_string_pool(data, pos)
        elif ctype == RES_XML_RESOURCE_MAP_TYPE:
            n = (csize - chdr) // 4
            res_ids = list(struct.unpack_from(f"<{n}I", data, pos + chdr))
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            ext = pos + chdr
            _ns, name_idx, attr_start, attr_size, attr_count = struct.unpack_from("<IIHHH", data, ext)
            tag = strings[name_idx] if name_idx < len(strings) else ""
            attrs: dict[str, object] = {}
            for i in range(attr_count):
                a = ext + attr_start + i * attr_size
                try:
                    _ans, aname, araw, _sz, _res0, dtype, adata = struct.unpack_from("<IIIHBBI", data, a)
                except struct.error:
                    break
                name = strings[aname] if aname < len(strings) else ""
                if not name and aname < len(res_ids):
                    name = KNOWN_ATTR_IDS.get(res_ids[aname], f"attr_0x{res_ids[aname]:08x}")
                attrs[name] = _value(strings, araw, dtype, adata)
            element = Element(tag=tag, attrs=attrs, depth=len(stack))
            if stack:
                stack[-1].children.append(element)
            elif root is None:
                root = element
            stack.append(element)
        elif ctype == RES_XML_END_ELEMENT_TYPE:
            if stack:
                stack.pop()
        pos += csize

    if root is None:
        raise AXMLError("no elements found")
    return root
