import zipfile
from pathlib import Path

from chowkidar.analyzer import analyze


def make_apk(path: Path, files: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return path


def test_not_a_zip_is_flagged(tmp_path):
    bad = tmp_path / "fake.apk"
    bad.write_bytes(b"not a zip at all")
    report = analyze(bad)
    assert report.is_zip is False
    assert report.verdict == "suspicious"


def test_clean_apk_has_no_findings(tmp_path):
    apk = make_apk(tmp_path / "clean.apk", {"classes.dex": b"dex\n035\x00", "res/a.xml": b"<x/>"})
    report = analyze(apk)
    assert report.has_dex is True
    assert report.findings == []
    assert report.verdict == "no indicators found"


def test_sms_and_telegram_token_are_high_risk(tmp_path):
    payload = (
        b"android.permission.RECEIVE_SMS android.permission.READ_SMS "
        b"123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678 https://example.com/c2"
    )
    apk = make_apk(tmp_path / "scam.apk", {"classes.dex": payload})
    report = analyze(apk)
    assert "android.permission.READ_SMS" in report.permissions
    assert report.telegram_tokens
    assert report.urls == ["https://example.com/c2"]
    assert report.verdict == "likely malicious"


def test_missing_file_raises(tmp_path):
    import pytest

    with pytest.raises(FileNotFoundError):
        analyze(tmp_path / "nope.apk")
