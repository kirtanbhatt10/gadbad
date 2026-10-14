"""Build synthetic APK parts (binary manifest, DEX, ZIP) for tests.

No real malware is needed: these produce the same structures Chowkidar parses.
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from chowkidar.axml import KNOWN_ATTR_IDS

NAME_TO_ATTR_ID = {v: k for k, v in KNOWN_ATTR_IDS.items()}

# An element is (tag, attrs, children)
El = tuple


def _pool(strings: list[str], utf8: bool) -> bytes:
    data = bytearray()
    offsets = []
    for s in strings:
        offsets.append(len(data))
        if utf8:
            raw = s.encode("utf-8")
            assert len(s) < 0x80 and len(raw) < 0x80, "builder only supports short UTF-8 strings"
            data += bytes([len(s), len(raw)]) + raw + b"\x00"
        else:
            data += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    strings_start = 28 + 4 * len(strings)
    size = strings_start + len(data)
    flags = 0x100 if utf8 else 0
    header = struct.pack("<HHIIIIII", 0x0001, 28, size, len(strings), 0, flags, strings_start, 0)
    return header + b"".join(struct.pack("<I", o) for o in offsets) + bytes(data)


def build_axml(root: El, *, utf8: bool = False, obfuscate_attr_names: bool = False) -> bytes:
    """Encode an element tree as Android binary XML."""
    strings: list[str] = []
    res_ids: list[int] = []

    def collect_attr_names(el: El):
        for name in el[1]:
            if obfuscate_attr_names and name in NAME_TO_ATTR_ID and name not in strings:
                strings.append(name)
                res_ids.append(NAME_TO_ATTR_ID[name])
        for child in el[2]:
            collect_attr_names(child)

    collect_attr_names(root)
    attr_slots = {name: i for i, name in enumerate(strings)}
    if obfuscate_attr_names:
        strings = [""] * len(strings)  # names blanked, only resource IDs remain

    def idx(s: str) -> int:
        if s not in strings[len(res_ids):]:
            strings.append(s)
            return len(strings) - 1
        return len(res_ids) + strings[len(res_ids):].index(s)

    def attr_name_idx(name: str) -> int:
        return attr_slots[name] if obfuscate_attr_names and name in attr_slots else idx(name)

    body = bytearray()

    def emit(el: El):
        tag, attrs, children = el
        encoded = []
        for name, value in attrs.items():
            n = attr_name_idx(name)
            if isinstance(value, bool):
                encoded.append(struct.pack("<IIIHBBI", 0xFFFFFFFF, n, 0xFFFFFFFF, 8, 0, 0x12, 0xFFFFFFFF if value else 0))
            elif isinstance(value, int):
                encoded.append(struct.pack("<IIIHBBI", 0xFFFFFFFF, n, 0xFFFFFFFF, 8, 0, 0x10, value))
            else:
                s = idx(value)
                encoded.append(struct.pack("<IIIHBBI", 0xFFFFFFFF, n, s, 8, 0, 0x03, s))
        ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, idx(tag), 20, 20, len(encoded), 0, 0, 0)
        node = struct.pack("<II", 1, 0xFFFFFFFF) + ext + b"".join(encoded)
        body.extend(struct.pack("<HHI", 0x0102, 16, 8 + len(node)) + node)
        for child in children:
            emit(child)
        end = struct.pack("<II", 1, 0xFFFFFFFF) + struct.pack("<II", 0xFFFFFFFF, idx(tag))
        body.extend(struct.pack("<HHI", 0x0103, 16, 8 + len(end)) + end)

    emit(root)
    pool = _pool(strings, utf8)
    resmap = b""
    if res_ids:
        resmap = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(res_ids)) + struct.pack(f"<{len(res_ids)}I", *res_ids)
    payload = pool + resmap + bytes(body)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload


def _uleb128(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def build_dex(strings: list[str]) -> bytes:
    """A DEX file whose string table holds `strings` (other sections empty)."""
    header_size = 0x70
    ids_off = header_size
    data_off = ids_off + 4 * len(strings)
    data = bytearray()
    ids = []
    for s in strings:
        ids.append(data_off + len(data))
        data += _uleb128(len(s)) + s.encode("utf-8") + b"\x00"
    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<II", header, 0x38, len(strings), ids_off)
    return bytes(header) + b"".join(struct.pack("<I", i) for i in ids) + bytes(data)


def manifest(package: str, permissions=(), components=(), app_attrs=None) -> El:
    perms = [("uses-permission", {"name": p}, []) for p in permissions]
    app = ("application", dict(app_attrs or {}), list(components))
    return ("manifest", {"package": package}, [("uses-sdk", {"minSdkVersion": 21, "targetSdkVersion": 30}, [])] + perms + [app])


def receiver(name: str, actions=(), permission: str | None = None) -> El:
    attrs = {"name": name}
    if permission:
        attrs["permission"] = permission
    filters = [("intent-filter", {}, [("action", {"name": a}, []) for a in actions])] if actions else []
    return ("receiver", attrs, filters)


def service(name: str, actions=(), permission: str | None = None) -> El:
    tag, attrs, children = receiver(name, actions, permission)
    return ("service", attrs, children)


def make_apk(path: Path, files: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return path
