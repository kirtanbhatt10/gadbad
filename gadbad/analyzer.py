"""Static analysis for suspicious Android APKs.

Gadbad never installs or runs the APK. It reads the archive, parses the
binary manifest and the DEX string tables, and looks for the indicators that
Indian scam APKs share: SMS/OTP theft, accessibility abuse, call forwarding,
brand impersonation and hardcoded exfiltration endpoints (Telegram, Firebase,
raw IPs).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__, axml, dex
from .rules import ADVICE, RULES, verdict_for

SCHEMA_VERSION = 1

# Zip-bomb guards: skip huge members and stop after this much decompressed data.
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024

P = "android.permission."
T = "android.provider.Telephony."
SMS_RECEIVED = T + "SMS_RECEIVED"
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

# Android only lets an app become the default SMS app if it declares all four
# of these. Real messaging apps have them; OTP stealers almost never do. When
# they are present, SMS access is expected, so those rules count for less.
# Exfiltration rules (Telegram, IPs, Firebase, call forwarding) are unaffected.
SMS_APP_WEIGHTS = {"sms_read": 10, "sms_receiver": 10, "sms_send": 0, "contacts": 0}

# No \b at the start: tokens usually sit right after "bot" in API URLs.
TELEGRAM_TOKEN = re.compile(r"(?<!\d)\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])")
URL = re.compile(r"https?://[^\s\"'<>\\]{4,200}")
IP_URL = re.compile(r"https?://((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?")
FIREBASE = re.compile(r"https?://[a-z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app)", re.I)
CALL_FORWARD = re.compile(r"(?:\*|%2a){1,2}21(?:\*|%2a)", re.I)

# Long, specific names: matched as whole words anywhere in the app's strings.
SCHEME_BRANDS = [
    "parivahan",
    "echallan",
    "e-challan",
    "rto challan",
    "pmkisan",
    "pm-kisan",
    "pm kisan",
    "pmawas",
    "pm-awas",
    "pm awas",
    "pmay",
    "yono",
    "aadhaar",
]
SCHEME_BRAND_RE = re.compile(r"(?<![a-z])(" + "|".join(map(re.escape, SCHEME_BRANDS)) + r")(?![a-z])")
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
    min_sdk: Any = None
    target_sdk: Any = None
    is_sms_app: bool = False
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

    def weight(self, rule_id: str) -> int:
        if self.is_sms_app and rule_id in SMS_APP_WEIGHTS:
            return SMS_APP_WEIGHTS[rule_id]
        return RULES[rule_id].weight

    @property
    def score(self) -> int:
        return min(100, sum(self.weight(f.rule) for f in self.findings))

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

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": "gadbad", "version": __version__},
        }
        data.update({k: v for k, v in self.__dict__.items() if k != "findings"})
        data["score"] = self.score
        data["verdict"] = self.verdict
        data["advice"] = {"en": self.advice("en"), "hi": self.advice("hi")}
        data["findings"] = [
            {
                "rule": f.rule,
                "severity": f.severity,
                "weight": self.weight(f.rule),
                "title": f.title,
                "evidence": f.evidence,
                "explanation": {"en": f.explain("en"), "hi": f.explain("hi")},
            }
            for f in self.findings
        ]
        return data


def _hashes(path: Path) -> tuple[str, str, str]:
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()  # noqa: S324 - identifiers, not security
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest()


class _Budget:
    def __init__(self, total: int) -> None:
        self.left = total

    def read(self, archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
        if info.file_size > MAX_MEMBER_BYTES or info.file_size > self.left:
            return b""
        try:
            data = archive.read(info)
        except (RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError, EOFError):
            return b""  # encrypted, corrupt or unsupported member
        self.left -= len(data)
        return data


def _actions(element: axml.Element) -> set[str]:
    return {str(a.get("name", "")) for a in element.iter("action")}


def _components_with(manifest: axml.Element, tag: str, action: str, permission: str) -> bool:
    return any(action in _actions(el) and el.get("permission") == permission for el in manifest.iter(tag))


def _is_sms_app(manifest: axml.Element) -> bool:
    return (
        _components_with(manifest, "receiver", T + "SMS_DELIVER", P + "BROADCAST_SMS")
        and _components_with(manifest, "receiver", T + "WAP_PUSH_DELIVER", P + "BROADCAST_WAP_PUSH")
        and _components_with(
            manifest, "service", "android.intent.action.RESPOND_VIA_MESSAGE", P + "SEND_RESPOND_VIA_MESSAGE"
        )
        and any("android.intent.action.SENDTO" in _actions(a) for a in manifest.iter("activity"))
    )


def _inspect_manifest(report: Report, manifest: axml.Element) -> None:
    report.package = str(manifest.get("package", ""))
    for sdk in manifest.iter("uses-sdk"):
        report.min_sdk = sdk.get("minSdkVersion")
        report.target_sdk = sdk.get("targetSdkVersion")
    report.permissions = sorted(
        {str(p.get("name", "")) for tag in ("uses-permission", "uses-permission-sdk-23") for p in manifest.iter(tag)}
        - {""}
    )
    report.is_sms_app = _is_sms_app(manifest)
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
    for perm in [*PERMISSION_RULES, P + "CALL_PHONE"]:
        if perm.encode() in raw_manifest or perm.encode("utf-16-le") in raw_manifest:
            found.add(perm)
    return sorted(found)


def analyze(path: str | Path) -> Report:
    """Analyse one file. Raises FileNotFoundError or IsADirectoryError for bad paths."""
    path = Path(path)
    if path.is_dir():
        raise IsADirectoryError(path)
    if not path.is_file():
        raise FileNotFoundError(path)

    sha256, sha1, md5 = _hashes(path)
    report = Report(file=str(path), sha256=sha256, sha1=sha1, md5=md5, size_bytes=path.stat().st_size)

    texts: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            infos = {i.filename: i for i in archive.infolist()}
            budget = _Budget(MAX_TOTAL_BYTES)
            report.is_apk = "AndroidManifest.xml" in infos
            if not report.is_apk:
                report.add("not_apk", "AndroidManifest.xml is missing")

            raw_manifest = budget.read(archive, infos["AndroidManifest.xml"]) if report.is_apk else b""
            if raw_manifest:
                try:
                    _inspect_manifest(report, axml.parse(raw_manifest))
                except (axml.AXMLError, IndexError, ValueError, struct.error):
                    report.add("bad_manifest", "binary manifest could not be parsed")
                    report.permissions = _fallback_permissions(raw_manifest)

            for name, info in infos.items():
                if name.endswith(".dex"):
                    texts.extend(dex.strings(budget.read(archive, info)))
                elif name.startswith(("assets/", "res/raw/")):
                    texts.append(budget.read(archive, info).decode("latin-1"))
    except (zipfile.BadZipFile, EOFError, OSError) as exc:
        report.is_apk = False
        report.add("not_apk", f"not a readable ZIP archive ({exc.__class__.__name__})")
        return report

    corpus = "\n".join(texts)
    _inspect_strings(report, corpus)
    _apply_rules(report, corpus)
    return report


def _is_public_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return False  # e.g. 999.1.1.1 is not an IP address


def _inspect_strings(report: Report, corpus: str) -> None:
    report.urls = sorted(set(URL.findall(corpus)))[:100]
    report.ip_endpoints = sorted({m.group(0) for m in IP_URL.finditer(corpus) if _is_public_ip(m.group(1))})
    report.firebase_urls = sorted(set(FIREBASE.findall(corpus)))
    report.telegram_tokens = sorted(set(TELEGRAM_TOKEN.findall(corpus)))

    haystack = corpus.lower() + "\n" + report.package.lower()
    brands = set(SCHEME_BRAND_RE.findall(haystack))
    brands |= BANK_BRANDS & set(re.split(r"[._\-]", report.package.lower()))
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
