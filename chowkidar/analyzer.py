"""Static analysis for suspicious Android APKs.

Chowkidar never installs or runs the APK. It reads the archive, parses the
binary manifest and the DEX string tables, and looks for the indicators that
Indian scam APKs share: SMS/OTP theft, accessibility abuse, call forwarding,
brand impersonation and hardcoded exfiltration endpoints (Telegram, Firebase,
raw IPs).
"""

from __future__ import annotations

import hashlib
import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import axml, dex
from .rules import ADVICE, RULES, verdict_for

# Zip-bomb guards: skip huge members and stop after this much data.
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024

P = "android.permission."
SMS_RECEIVED = "android.provider.Telephony.SMS_RECEIVED"
ACCESSIBILITY_ACTION = "android.accessibilityservice.AccessibilityService"
DEVICE_ADMIN_ACTION = "android.app.action.DEVICE_ADMIN_ENABLED"

PERMISSION_RULES = {
    P + "READ_SMS": "sms_read",
    P + "RECEIVE_SMS": "sms_read",
    P + "SEND_SMS": "sms_send",
    P + "SYSTEM_ALERT_WINDOW": "overlay",
    P + "REQUEST_INSTALL_PACKAGES": "installs_apps",
    P + "READ_CONTACTS": "contacts",
    P + "RECEIVE_BOOT_COMPLETED": "autostart",
}

# No \b at the start: tokens usually sit right after "bot" in API URLs.
TELEGRAM_TOKEN = re.compile(r"(?<!\d)\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])")
URL = re.compile(r"https?://[^\s\"'<>\\]{4,200}")
IP_URL = re.compile(r"https?://((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?")
FIREBASE = re.compile(r"https?://[a-z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app)", re.I)
CALL_FORWARD = re.compile(r"(?:\*|%2a){1,2}21(?:\*|%2a)", re.I)

# Long, specific names: safe to match anywhere in the app's strings.
SCHEME_BRANDS = [
    "parivahan", "echallan", "e-challan", "rto challan", "pmkisan", "pm-kisan", "pm kisan",
    "pmawas", "pm-awas", "pm awas", "pmay", "yono", "aadhaar",
]
# Short bank and wallet names: only matched as whole parts of the package name.
BANK_BRANDS = {"sbi", "hdfc", "icici", "kotak", "axis", "pnb", "bob", "canara", "paytm", "phonepe"}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    evidence: str

    def explain(self, lang: str = "en") -> str:
        rule = RULES[self.rule]
        return rule.hi if lang == "hi" else rule.en


@dataclass
class Report:
    file: str
    sha256: str
    sha1: str
    md5: str
    size_bytes: int
    is_apk: bool = False
    package: str = ""
    min_sdk: object = None
    target_sdk: object = None
    permissions: list[str] = field(default_factory=list)
    sms_receivers: list[str] = field(default_factory=list)
    accessibility_services: list[str] = field(default_factory=list)
    device_admins: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    ip_endpoints: list[str] = field(default_factory=list)
    firebase_urls: list[str] = field(default_factory=list)
    telegram_tokens: list[str] = field(default_factory=list)
    brands: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return min(100, sum(RULES[f.rule].weight for f in self.findings))

    @property
    def verdict(self) -> str:
        return verdict_for(self.score)

    def advice(self, lang: str = "en") -> str:
        return ADVICE[self.verdict][lang]

    def add(self, rule_id: str, evidence: str) -> None:
        if any(f.rule == rule_id for f in self.findings):
            return
        rule = RULES[rule_id]
        self.findings.append(Finding(rule_id, rule.severity, rule.title, evidence))

    def to_dict(self) -> dict:
        data = {k: v for k, v in self.__dict__.items() if k != "findings"}
        data["score"] = self.score
        data["verdict"] = self.verdict
        data["advice"] = {"en": self.advice("en"), "hi": self.advice("hi")}
        data["findings"] = [
            {
                "rule": f.rule,
                "severity": f.severity,
                "title": f.title,
                "evidence": f.evidence,
                "explanation": {"en": f.explain("en"), "hi": f.explain("hi")},
            }
            for f in self.findings
        ]
        return data


def _hashes(path: Path) -> tuple[str, str, str]:
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest()


def _read(archive: zipfile.ZipFile, info: zipfile.ZipInfo, budget: list[int]) -> bytes:
    if info.file_size > MAX_MEMBER_BYTES or info.file_size > budget[0]:
        return b""
    try:
        data = archive.read(info)
    except (RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError):
        return b""
    budget[0] -= len(data)
    return data


def _actions(element: axml.Element) -> set[str]:
    return {str(a.get("name", "")) for a in element.iter("action")}


def _inspect_manifest(report: Report, manifest: axml.Element) -> None:
    report.package = str(manifest.get("package", ""))
    for sdk in manifest.iter("uses-sdk"):
        report.min_sdk = sdk.get("minSdkVersion")
        report.target_sdk = sdk.get("targetSdkVersion")
    report.permissions = sorted(
        {str(p.get("name", "")) for tag in ("uses-permission", "uses-permission-sdk-23") for p in manifest.iter(tag)}
        - {""}
    )
    for app in manifest.iter("application"):
        if app.get("usesCleartextTraffic") is True:
            report.add("cleartext", "android:usesCleartextTraffic=true")
    for receiver in manifest.iter("receiver"):
        name = str(receiver.get("name", "?"))
        actions = _actions(receiver)
        if SMS_RECEIVED in actions:
            report.sms_receivers.append(name)
        if receiver.get("permission") == P + "BIND_DEVICE_ADMIN" or DEVICE_ADMIN_ACTION in actions:
            report.device_admins.append(name)
    for service in manifest.iter("service"):
        if service.get("permission") == P + "BIND_ACCESSIBILITY_SERVICE" or ACCESSIBILITY_ACTION in _actions(service):
            report.accessibility_services.append(str(service.get("name", "?")))


def _fallback_permissions(raw_manifest: bytes) -> list[str]:
    """Find permission names in a manifest the parser could not read."""
    found = set()
    for perm in list(PERMISSION_RULES) + [P + "CALL_PHONE"]:
        if perm.encode() in raw_manifest or perm.encode("utf-16-le") in raw_manifest:
            found.add(perm)
    return sorted(found)


def analyze(path: str | Path) -> Report:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)

    sha256, sha1, md5 = _hashes(path)
    report = Report(file=str(path), sha256=sha256, sha1=sha1, md5=md5, size_bytes=path.stat().st_size)

    if not zipfile.is_zipfile(path):
        report.add("not_apk", "file is not a ZIP archive")
        return report

    texts: list[str] = []
    budget = [MAX_TOTAL_BYTES]
    with zipfile.ZipFile(path) as archive:
        infos = {i.filename: i for i in archive.infolist()}
        report.is_apk = "AndroidManifest.xml" in infos
        if not report.is_apk:
            report.add("not_apk", "AndroidManifest.xml is missing")

        raw_manifest = _read(archive, infos["AndroidManifest.xml"], budget) if report.is_apk else b""
        if raw_manifest:
            try:
                _inspect_manifest(report, axml.parse(raw_manifest))
            except (axml.AXMLError, IndexError, ValueError, struct.error):
                report.add("bad_manifest", "binary manifest could not be parsed")
                report.permissions = _fallback_permissions(raw_manifest)

        for name, info in infos.items():
            if name.endswith(".dex"):
                texts.extend(dex.strings(_read(archive, info, budget)))
            elif name.startswith(("assets/", "res/raw/")):
                texts.append(_read(archive, info, budget).decode("latin-1"))

    corpus = "\n".join(texts)
    _inspect_strings(report, corpus)
    _apply_rules(report, corpus)
    return report


def _inspect_strings(report: Report, corpus: str) -> None:
    report.urls = sorted(set(URL.findall(corpus)))[:100]
    report.ip_endpoints = sorted(
        {m.group(0) for m in IP_URL.finditer(corpus) if not m.group(1).startswith(("127.", "0.", "10.", "192.168."))}
    )
    report.firebase_urls = sorted(set(FIREBASE.findall(corpus)))
    report.telegram_tokens = sorted(set(TELEGRAM_TOKEN.findall(corpus)))

    lowered = corpus.lower()
    brands = {b for b in SCHEME_BRANDS if b in lowered or b in report.package.lower()}
    package_parts = set(re.split(r"[._\-]", report.package.lower()))
    brands |= BANK_BRANDS & package_parts
    report.brands = sorted(brands)


def _apply_rules(report: Report, corpus: str) -> None:
    perms = set(report.permissions)
    for perm, rule in PERMISSION_RULES.items():
        if perm in perms:
            report.add(rule, perm)

    if report.sms_receivers:
        report.add("sms_receiver", ", ".join(report.sms_receivers))
    if report.accessibility_services:
        report.add("accessibility", ", ".join(report.accessibility_services))
    if report.device_admins:
        report.add("device_admin", ", ".join(report.device_admins))

    if P + "CALL_PHONE" in perms and CALL_FORWARD.search(corpus):
        report.add("call_forwarding", "CALL_PHONE permission plus a *21* forwarding code")

    if report.telegram_tokens:
        report.add("telegram_token", f"{len(report.telegram_tokens)} token(s)")
    if "api.telegram.org" in corpus:
        report.add("telegram_api", "api.telegram.org")
    if report.firebase_urls:
        report.add("firebase", ", ".join(report.firebase_urls[:3]))
    if report.ip_endpoints:
        report.add("ip_endpoint", ", ".join(report.ip_endpoints[:3]))

    reads_sms = any(f.rule in ("sms_read", "sms_receiver") for f in report.findings)
    if report.brands and reads_sms:
        report.add("impersonation", ", ".join(report.brands))
