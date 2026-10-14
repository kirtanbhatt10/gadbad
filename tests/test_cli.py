import json

from test_analyzer import TOKEN, clean_apk, scam_apk

from gadbad.cli import main


def test_json_output_and_exit_code(tmp_path, capsys):
    code = main(["scan", str(scam_apk(tmp_path)), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 1
    assert data["verdict"] == "likely malicious"
    assert data["score"] == 100
    assert len(data["sha256"]) == 64


def test_clean_apk_exits_zero(tmp_path, capsys):
    assert main(["scan", str(clean_apk(tmp_path))]) == 0
    assert "NO INDICATORS FOUND" in capsys.readouterr().out


def test_text_output_in_hindi(tmp_path, capsys):
    main(["scan", str(scam_apk(tmp_path)), "--lang", "hi"])
    out = capsys.readouterr().out
    assert "SMS पढ़ सकता है" in out
    assert TOKEN not in out  # bot tokens are masked in human output


def test_markdown_report_for_complaints(tmp_path, capsys):
    main(["scan", str(scam_apk(tmp_path)), "--markdown"])
    out = capsys.readouterr().out
    assert out.startswith("# Suspicious APK report")
    assert "| SHA-256 |" in out
    assert "cybercrime.gov.in" in out
    assert TOKEN not in out


def test_missing_file_exits_two(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "nope.apk")]) == 2
