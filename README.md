<div align="center">

# 🔍 Gadbad

### *Kuch toh gadbad hai* in this APK.

**Gadbad** finds the fake Android apps spreading over WhatsApp in India: fake RTO e-challan, PM-Kisan, PM Awas and bank-KYC apps that steal SMS and OTPs.
It reads the APK without installing or running it, and explains what the app can do in English or Hindi.

[![CI](https://github.com/kirtanbhatt10/gadbad/actions/workflows/ci.yml/badge.svg)](https://github.com/kirtanbhatt10/gadbad/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/gadbad?color=blue)](https://pypi.org/project/gadbad/)
[![Python](https://img.shields.io/pypi/pyversions/gadbad)](https://pypi.org/project/gadbad/)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![Typed](https://img.shields.io/badge/typing-strict-informational)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

</div>

---

## Why

Fake APKs are one of the fastest-growing fraud channels in India. A victim gets an official-looking app on WhatsApp, grants it SMS and accessibility access, and loses money within minutes. General-purpose Android tools aren't built for these scam families, or for the people who receive them.

Gadbad gives cautious users, bank fraud teams, police cyber cells and researchers a verdict in under a second, a plain-language explanation, and a report they can attach to a complaint.

## Install

```bash
pip install gadbad
```

Python 3.10 or newer, on Windows, macOS or Linux. No other dependencies.

## Use

```bash
gadbad scan app.apk                        # summary in English
gadbad scan app.apk --lang hi              # summary in Hindi
gadbad scan app.apk --markdown -o report.md  # report to attach to a cybercrime complaint
gadbad scan app.apk --json                 # full machine-readable report
gadbad scan Downloads/                     # every .apk in a folder, recursively
```

Example output for a fake bank-KYC app:

```text
Package:  com.sbi.kyc.update
Verdict:  LIKELY MALICIOUS  (risk score 100/100)

  [HIGH  ] Reads SMS
           Can read your SMS messages, including bank OTPs.
  [HIGH  ] Listens for incoming SMS
           Wakes up the moment an SMS arrives, so it can grab OTPs as they come in.
  [HIGH  ] Call-forwarding code
           Contains a call-forwarding code (*21*) that can divert your calls, including bank verification calls.
  [HIGH  ] Hardcoded Telegram bot token
           Contains a Telegram bot token, a common way to send stolen data to the attacker.
  ...

Telegram bots: 123456789:ABCD…78
IP endpoints: http://45.67.89.10:8080

Do not install this app. If you already did: switch on flight mode, uninstall it, call your bank to block
your cards and UPI, change banking passwords from another device, and report it at cybercrime.gov.in or by calling 1930.
```

The same in Hindi with `--lang hi`:

```text
  [HIGH  ] Reads SMS
           यह ऐप आपके SMS पढ़ सकता है, जिनमें बैंक के OTP भी शामिल हैं।
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing at or above the `--fail-on` level (default: `suspicious`) |
| `1` | At least one APK at or above the `--fail-on` level |
| `2` | At least one file could not be scanned |

Use `--fail-on likely-malicious` or `--fail-on never` to change the threshold, for example in automated pipelines.

## What it checks

| Check | Why it matters |
|---|---|
| Reads or listens for SMS (`READ_SMS`, `RECEIVE_SMS`, `SMS_RECEIVED` receiver) | Grabs bank OTPs as they arrive |
| Accessibility service | Reads the screen and taps buttons for the victim |
| Call-forwarding code (`*21*`) with `CALL_PHONE` | Diverts calls, including bank verification calls |
| Device admin, overlays, installing apps | Hard to uninstall, fake login screens, drops more malware |
| Telegram bot tokens and `api.telegram.org` | Common channel for sending stolen data |
| Firebase databases and public raw-IP servers | Common drop points for stolen SMS |
| Bank or scheme names (SBI, YONO, PM-Kisan, PM Awas, e-challan …) | Impersonation, flagged only when the app also reads SMS |

Each finding has a weight. The total is a risk score from 0 to 100, which maps to **no indicators found** (0), **low risk** (1–24), **suspicious** (25–59) or **likely malicious** (60+).

**Real messaging apps aren't punished.** Android only lets an app become the default SMS app if it declares four specific components. When an app declares all four, SMS access is expected and scored lower. Exfiltration signals such as Telegram tokens keep their full weight, so a stealer posing as an SMS app is still caught. Tested against [Fossify Messages](https://github.com/FossifyOrg/Messages), which scores *low risk*.

## How it works

1. **Archive checks.** Confirms the file is a real APK and computes SHA-256, SHA-1 and MD5.
2. **Manifest parsing.** A built-in parser for Android's binary XML reads permissions and components. It recovers attribute names that obfuscators blank out, and falls back to a byte search when the manifest is deliberately corrupted.
3. **String extraction.** Reads the DEX string tables and bundled assets, where URLs, bot tokens and forwarding codes live.
4. **Rules and scoring.** Each rule has a severity, a weight and an explanation in English and Hindi.

## Limits

Gadbad is a fast first check, not a full malware sandbox. Be aware that:

- **Packed or encrypted apps** that hide their strings or load code at runtime can lower the score. A low score is not proof that an app is safe.
- **The app's display name and icon** aren't read yet (see the roadmap), so look-alike names are caught only through the package name and strings.
- **Scores are heuristics.** Treat *suspicious* as "check further", not as proof.

If you find a missed scam app or a wrongly flagged real app, please [open an issue](https://github.com/kirtanbhatt10/gadbad/issues/new/choose). Share the hash, never the APK.

## Safety

- **Static only.** Gadbad never installs, opens or executes the app, and makes no network requests.
- **Zip-bomb limits.** Oversized, encrypted or corrupt archive members are skipped.
- **No counter-attacks.** Gadbad never uses the bot tokens it finds or contacts attacker servers. Tokens are masked in text and Markdown output.
- **No samples in this repo.** The tests build synthetic APKs. See [SECURITY.md](SECURITY.md) for how to handle real samples.

## Use as a library

```python
from gadbad.analyzer import analyze

report = analyze("app.apk")
print(report.verdict, report.score)
for finding in report.findings:
    print(finding.severity, finding.title, finding.explain("hi"))
```

`report.to_dict()` returns the same structure as `--json`. It carries a `schema_version` that only changes when a field is removed or changes meaning.

## Roadmap

- [ ] App display name and icon from `resources.arsc`, to catch look-alike names
- [ ] Signing certificate checks
- [ ] Known scam-family signatures
- [ ] Indicator export (STIX) for banks and CERT-In
- [ ] More languages: Gujarati, Marathi, Tamil, Bengali

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Reports of missed scams and false alarms are the most useful contributions.

## Disclaimer

Gadbad helps people make a safer decision. It is not a guarantee, legal evidence or a substitute for reporting fraud to the police. If you've lost money, report it at [cybercrime.gov.in](https://cybercrime.gov.in) or call **1930** straight away.

## Licence

MIT. See [LICENSE](LICENSE).
