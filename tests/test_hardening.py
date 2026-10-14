"""Behaviour that matters in production: false positives, bad input, batch scans."""

import json
import zipfile

from builders import activity, build_axml, build_dex, make_apk, manifest, receiver, service
from test_analyzer import TOKEN, clean_apk, scam_apk

from gadbad.analyzer import analyze
from gadbad.cli import main

P = "android.permission."
T = "android.provider.Telephony."

SMS_APP_PERMS = [P + "READ_SMS", P + "RECEIVE_SMS", P + "SEND_SMS", P + "READ_CONTACTS", P + "RECEIVE_BOOT_COMPLETED"]
SMS_APP_COMPONENTS = [
    receiver(".SmsReceiver", actions=[T + "SMS_DELIVER"], permission=P + "BROADCAST_SMS"),
    receiver(".MmsReceiver", actions=[T + "WAP_PUSH_DELIVER"], permission=P + "BROADCAST_WAP_PUSH"),
    service(
        ".HeadlessSend",
        actions=["android.intent.action.RESPOND_VIA_MESSAGE"],
        permission=P + "SEND_RESPOND_VIA_MESSAGE",
    ),
    activity(".Compose", actions=["android.intent.action.SENDTO"]),
]


def test_real_sms_app_is_not_flagged(tmp_path):
    """A default-SMS-capable messaging app needs SMS access; that alone is not fraud."""
    m = manifest("org.example.messages", permissions=SMS_APP_PERMS, components=SMS_APP_COMPONENTS)
    report = analyze(make_apk(tmp_path / "sms.apk", {"AndroidManifest.xml": build_axml(m)}))
    assert report.is_sms_app
    assert {"sms_read", "sms_send"} <= {f.rule for f in report.findings}  # still reported
    assert report.verdict == "low risk"


def test_sms_app_with_exfiltration_is_still_caught(tmp_path):
    m = manifest("org.example.messages", permissions=SMS_APP_PERMS, components=SMS_APP_COMPONENTS)
    apk = make_apk(
        tmp_path / "sms.apk",
        {
            "AndroidManifest.xml": build_axml(m),
            "classes.dex": build_dex([f"https://api.telegram.org/bot{TOKEN}/sendMessage"]),
        },
    )
    report = analyze(apk)
    assert report.is_sms_app
    assert report.verdict == "likely malicious"


def test_partial_sms_app_gets_no_discount(tmp_path):
    m = manifest("com.fake.kyc", permissions=SMS_APP_PERMS, components=SMS_APP_COMPONENTS[:1])
    report = analyze(make_apk(tmp_path / "a.apk", {"AndroidManifest.xml": build_axml(m)}))
    assert not report.is_sms_app
    assert report.verdict == "suspicious"


def test_truncated_zip_is_reported_not_raised(tmp_path):
    good = clean_apk(tmp_path)
    broken = tmp_path / "broken.apk"
    broken.write_bytes(good.read_bytes()[:-30])  # cut off the central directory
    report = analyze(broken)
    assert not report.is_apk
    assert "not_apk" in {f.rule for f in report.findings}


def test_encrypted_member_is_skipped(tmp_path):
    apk = clean_apk(tmp_path)
    with zipfile.ZipFile(apk, "a") as zf:
        info = zipfile.ZipInfo("assets/secret.bin")
        info.flag_bits |= 0x1  # mark as encrypted
        zf.writestr(info, b"x" * 10)
    assert analyze(apk).verdict == "no indicators found"


def test_invalid_and_private_ips_are_ignored(tmp_path):
    m = manifest("com.example.net")
    apk = make_apk(
        tmp_path / "a.apk",
        {
            "AndroidManifest.xml": build_axml(m),
            "classes.dex": build_dex(
                ["http://999.1.1.1/x", "http://172.16.4.2/", "http://100.64.0.1/", "http://8.8.8.8/"]
            ),
        },
    )
    assert analyze(apk).ip_endpoints == ["http://8.8.8.8"]


def test_scheme_brands_need_word_boundaries(tmp_path):
    m = manifest("com.example.words", permissions=[P + "READ_SMS"])
    apk = make_apk(
        tmp_path / "a.apk",
        {
            "AndroidManifest.xml": build_axml(m),
            "classes.dex": build_dex(["upmayday", "yonoko"]),
        },
    )
    assert analyze(apk).brands == []


def test_directory_scan_finds_apks_recursively(tmp_path, capsys):
    (tmp_path / "nested").mkdir()
    scam_apk(tmp_path / "nested")
    clean_apk(tmp_path)
    (tmp_path / "notes.txt").write_text("ignore me")
    code = main(["scan", str(tmp_path), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list) and len(data) == 2
    assert {d["verdict"] for d in data} == {"likely malicious", "no indicators found"}
    assert code == 1


def test_fail_on_levels(tmp_path, capsys):
    m = manifest("com.fake.kyc", permissions=SMS_APP_PERMS)
    apk = str(make_apk(tmp_path / "s.apk", {"AndroidManifest.xml": build_axml(m)}))
    assert analyze(apk).verdict == "suspicious"
    assert main(["scan", apk]) == 1
    assert main(["scan", apk, "--fail-on", "likely-malicious"]) == 0
    assert main(["scan", str(scam_apk(tmp_path)), "--fail-on", "never"]) == 0
    capsys.readouterr()


def test_output_file(tmp_path, capsys):
    out = tmp_path / "report.md"
    main(["scan", str(scam_apk(tmp_path)), "--markdown", "-o", str(out)])
    assert capsys.readouterr().out == ""
    assert out.read_text(encoding="utf-8").startswith("# Suspicious APK report")


def test_batch_continues_after_a_missing_file(tmp_path, capsys):
    code = main(["scan", str(tmp_path / "missing.apk"), str(clean_apk(tmp_path))])
    assert "NO INDICATORS FOUND" in capsys.readouterr().out
    assert code == 2


def test_empty_folder_is_an_error(tmp_path, capsys):
    assert main(["scan", str(tmp_path)]) == 2


def test_json_has_schema_version(tmp_path, capsys):
    main(["scan", str(clean_apk(tmp_path)), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["schema_version"] == 1
    assert data["tool"]["name"] == "gadbad"
