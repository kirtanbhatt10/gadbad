"""Static analysis for suspicious Android APKs.

Chowkidar never installs or runs the APK. It reads the archive, hashes it and
looks for indicators that scam apps share: SMS/OTP permissions, accessibility
abuse, Telegram bot tokens, and hardcoded command-and-control (C2) endpoints.
"""

from __future__ import annotations

import hashlib
import re
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Permissions that let an app read or forward SMS and OTP messages.
SMS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
}

# Accessibility is abused to read the screen and click "allow" on banking apps.
ACCESSIBILITY_MARKER = "android.permission.BIND_ACCESSIBILITY_SERVICE"

# Telegram bot tokens look like 123456789:AA... (35 characters after the colon).
TELEGRAM_TOKEN = re.compile(rb"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")

# Plain HTTP(S) URLs and bare IPv4 hosts embedded in code or resources.
URL = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,200}")

# Brands that scam APKs impersonate in India. Matching is only a hint.
IMPERSONATED_BRANDS = [
    b"parivahan",
    b"e-challan",
    b"echallan",
    b"pmaay",
    b"pm awas",
    b"pmkisan",
    b"sbi",
    b"hdfc",
    b"icici",
    b"kotak",
    b"paytm",
]


@dataclass
class Finding:
    severity: str  # "low", "medium" or "high"
    title: str
    detail: str


@dataclass
class Report:
    file: str
    sha256: str
    size_bytes: int
    is_zip: bool
    has_dex: bool
    permissions: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    telegram_tokens: list[str] = field(default_factory=list)
    brand_hints: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        levels = {f.severity for f in self.findings}
        if "high" in levels:
            return "likely malicious"
        if "medium" in levels:
            return "suspicious"
        return "no indicators found"

    def to_dict(self) -> dict:
        data = asdict(self)
        data["verdict"] = self.verdict
        return data


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_members(archive: zipfile.ZipFile) -> tuple[bytes, list[str]]:
    """Return all dex/resource bytes concatenated, plus the manifest permissions."""
    blob = bytearray()
    permissions: list[str] = []
    for name in archive.namelist():
        if name.endswith(".dex") or name.startswith("assets/") or name.endswith(".xml"):
            try:
                blob += archive.read(name)
            except (RuntimeError, zipfile.BadZipFile):
                continue
    # Binary AndroidManifest.xml stores permission names as UTF-16 or plain
    # strings. Searching the raw bytes for known names is good enough for a
    # first pass; a full AXML parser is a planned milestone.
    for perm in SMS_PERMISSIONS | {ACCESSIBILITY_MARKER}:
        if perm.encode() in blob:
            permissions.append(perm)
    return bytes(blob), sorted(set(permissions))


def analyze(path: str | Path) -> Report:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)

    report = Report(
        file=str(path),
        sha256=sha256_of(path),
        size_bytes=path.stat().st_size,
        is_zip=zipfile.is_zipfile(path),
        has_dex=False,
    )
    if not report.is_zip:
        report.findings.append(
            Finding("medium", "Not a valid APK", "File is not a ZIP archive, so it cannot be an installable APK.")
        )
        return report

    with zipfile.ZipFile(path) as archive:
        report.has_dex = any(n.endswith(".dex") for n in archive.namelist())
        blob, report.permissions = _read_members(archive)

    lowered = blob.lower()
    report.urls = sorted({m.decode(errors="ignore") for m in URL.findall(blob)})[:50]
    report.telegram_tokens = sorted({m.decode(errors="ignore") for m in TELEGRAM_TOKEN.findall(blob)})
    report.brand_hints = sorted({b.decode() for b in IMPERSONATED_BRANDS if b in lowered})

    sms = [p for p in report.permissions if p in SMS_PERMISSIONS]
    if sms:
        report.findings.append(
            Finding("high" if len(sms) > 1 else "medium", "Requests SMS access", ", ".join(sms))
        )
    if ACCESSIBILITY_MARKER in report.permissions:
        report.findings.append(
            Finding("medium", "Uses accessibility service", "Can read screen content and tap buttons for the user.")
        )
    if report.telegram_tokens:
        report.findings.append(
            Finding("high", "Hardcoded Telegram bot token", f"{len(report.telegram_tokens)} token(s) found. Often used to exfiltrate data.")
        )
    if report.brand_hints and sms:
        report.findings.append(
            Finding("high", "Impersonates a known brand and reads SMS", ", ".join(report.brand_hints))
        )
    return report
