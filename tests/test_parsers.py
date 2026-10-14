import pytest
from builders import build_axml, build_dex

from gadbad import axml, dex


def tree():
    return (
        "manifest",
        {"package": "com.example.app"},
        [
            ("uses-permission", {"name": "android.permission.INTERNET"}, []),
            (
                "application",
                {"label": "Example", "usesCleartextTraffic": True},
                [
                    (
                        "receiver",
                        {"name": ".Rx", "exported": True},
                        [
                            ("intent-filter", {}, [("action", {"name": "android.intent.action.BOOT_COMPLETED"}, [])]),
                        ],
                    ),
                ],
            ),
        ],
    )


@pytest.mark.parametrize("utf8", [False, True])
def test_axml_parses_utf16_and_utf8_pools(utf8):
    root = axml.parse(build_axml(tree(), utf8=utf8))
    assert root.tag == "manifest"
    assert root.get("package") == "com.example.app"
    assert [p.get("name") for p in root.iter("uses-permission")] == ["android.permission.INTERNET"]
    app = next(root.iter("application"))
    assert app.get("usesCleartextTraffic") is True
    actions = [a.get("name") for a in root.iter("action")]
    assert actions == ["android.intent.action.BOOT_COMPLETED"]


def test_axml_recovers_blanked_attribute_names():
    root = axml.parse(build_axml(tree(), obfuscate_attr_names=True))
    assert [p.get("name") for p in root.iter("uses-permission")] == ["android.permission.INTERNET"]
    assert next(root.iter("application")).get("label") == "Example"


def test_axml_rejects_plain_xml():
    with pytest.raises(axml.AXMLError):
        axml.parse(b'<?xml version="1.0"?><manifest/>')


def test_axml_survives_truncation():
    data = build_axml(tree())
    with pytest.raises(axml.AXMLError):
        axml.parse(data[:40])  # pool cut off: no elements, but no crash


def test_dex_string_table_roundtrip():
    wanted = ["Lcom/example/Main;", "https://example.com/api", "नमस्ते"]
    assert dex.strings(build_dex(wanted)) == wanted


def test_dex_rejects_non_dex():
    assert dex.strings(b"PK\x03\x04 not a dex") == []
    assert dex.strings(b"dex\n035\x00" + b"\xff" * 0x70) == []
