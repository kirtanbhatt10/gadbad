from builders import build_axml, build_dex, make_apk, manifest, receiver, service

from chowkidar.analyzer import analyze

P = "android.permission."
TOKEN = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678"


def scam_apk(tmp_path):
    """Shaped like a fake bank-KYC app: SMS stealer with Telegram exfiltration."""
    m = manifest(
        "com.sbi.kyc.update",
        permissions=[P + "READ_SMS", P + "RECEIVE_SMS", P + "CALL_PHONE", P + "SYSTEM_ALERT_WINDOW", P + "INTERNET"],
        components=[
            receiver(".SmsReceiver", actions=["android.provider.Telephony.SMS_RECEIVED"]),
            service(".Helper", actions=["android.accessibilityservice.AccessibilityService"],
                    permission=P + "BIND_ACCESSIBILITY_SERVICE"),
        ],
        app_attrs={"usesCleartextTraffic": True},
    )
    strings = [
        f"https://api.telegram.org/bot{TOKEN}/sendMessage",
        "tel:*21*9876543210#",
        "http://45.67.89.10:8080/upload",
        "https://kyc-update-1.firebaseio.com",
        "YONO KYC update",
    ]
    return make_apk(tmp_path / "scam.apk", {
        "AndroidManifest.xml": build_axml(m),
        "classes.dex": build_dex(strings),
    })


def clean_apk(tmp_path):
    m = manifest("com.example.notes", permissions=[P + "INTERNET"])
    return make_apk(tmp_path / "clean.apk", {
        "AndroidManifest.xml": build_axml(m),
        "classes.dex": build_dex(["https://example.com/sync", "/sbin/sh"]),
    })


def rules(report):
    return {f.rule for f in report.findings}


def test_scam_apk_is_likely_malicious(tmp_path):
    report = analyze(scam_apk(tmp_path))
    assert report.package == "com.sbi.kyc.update"
    assert report.sms_receivers == [".SmsReceiver"]
    assert report.accessibility_services == [".Helper"]
    assert report.telegram_tokens == [TOKEN]
    assert report.ip_endpoints == ["http://45.67.89.10:8080"]
    assert report.firebase_urls == ["https://kyc-update-1.firebaseio.com"]
    assert {"sbi", "yono"} <= set(report.brands)
    assert {
        "sms_read", "sms_receiver", "accessibility", "call_forwarding", "overlay",
        "telegram_token", "telegram_api", "firebase", "ip_endpoint", "cleartext", "impersonation",
    } <= rules(report)
    assert report.score == 100
    assert report.verdict == "likely malicious"


def test_clean_apk_has_no_findings(tmp_path):
    report = analyze(clean_apk(tmp_path))
    assert report.is_apk
    assert report.findings == []
    assert report.brands == []  # "/sbin" must not count as SBI
    assert report.verdict == "no indicators found"


def test_call_forwarding_needs_call_permission(tmp_path):
    m = manifest("com.example.dialer")
    apk = make_apk(tmp_path / "a.apk", {
        "AndroidManifest.xml": build_axml(m),
        "classes.dex": build_dex(["*21*"]),
    })
    assert "call_forwarding" not in rules(analyze(apk))


def test_private_ips_are_ignored(tmp_path):
    m = manifest("com.example.lan")
    apk = make_apk(tmp_path / "a.apk", {
        "AndroidManifest.xml": build_axml(m),
        "classes.dex": build_dex(["http://192.168.1.5/", "http://127.0.0.1:8080"]),
    })
    assert analyze(apk).ip_endpoints == []


def test_bank_name_only_matches_whole_package_parts(tmp_path):
    m = manifest("com.sbinfra.tools", permissions=[P + "READ_SMS"])
    apk = make_apk(tmp_path / "a.apk", {"AndroidManifest.xml": build_axml(m)})
    report = analyze(apk)
    assert report.brands == []
    assert "impersonation" not in rules(report)


def test_obfuscated_manifest_still_parsed(tmp_path):
    m = manifest("com.pmkisan.list", permissions=[P + "RECEIVE_SMS"])
    apk = make_apk(tmp_path / "a.apk", {"AndroidManifest.xml": build_axml(m, obfuscate_attr_names=True)})
    report = analyze(apk)
    assert P + "RECEIVE_SMS" in report.permissions
    assert "impersonation" in rules(report)


def test_corrupt_manifest_falls_back_to_byte_search(tmp_path):
    raw = b"\x03\x00\x08\x00garbage" + (P + "READ_SMS").encode("utf-16-le")
    apk = make_apk(tmp_path / "a.apk", {"AndroidManifest.xml": raw})
    report = analyze(apk)
    assert {"bad_manifest", "sms_read"} <= rules(report)


def test_zip_without_manifest_is_not_an_apk(tmp_path):
    apk = make_apk(tmp_path / "a.apk", {"hello.txt": b"hi"})
    report = analyze(apk)
    assert not report.is_apk
    assert "not_apk" in rules(report)


def test_not_a_zip_is_flagged(tmp_path):
    bad = tmp_path / "fake.apk"
    bad.write_bytes(b"not a zip at all")
    report = analyze(bad)
    assert "not_apk" in rules(report)
    assert report.verdict == "suspicious"


def test_missing_file_raises(tmp_path):
    import pytest

    with pytest.raises(FileNotFoundError):
        analyze(tmp_path / "nope.apk")


def test_findings_explained_in_english_and_hindi(tmp_path):
    data = analyze(scam_apk(tmp_path)).to_dict()
    for finding in data["findings"]:
        assert finding["explanation"]["en"]
        assert any("ऀ" <= ch <= "ॿ" for ch in finding["explanation"]["hi"])
    assert "1930" in data["advice"]["en"]
