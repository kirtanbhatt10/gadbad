<div align="center">

# 🔦 Chowkidar

### Scam APKs don't get past the watchman.

**Chowkidar** is a static analyser for the fake Android apps spreading over WhatsApp in India: fake RTO e-challan, PM Awas Yojana list and bank KYC apps that steal SMS and OTPs.
It reads an APK without installing it and explains what the app can do, in English and Hindi.

[![CI](https://github.com/kirtanbhatt10/chowkidar/actions/workflows/ci.yml/badge.svg)](https://github.com/kirtanbhatt10/chowkidar/actions/workflows/ci.yml)
![version](https://img.shields.io/badge/version-0.2.0-blue)
![python](https://img.shields.io/badge/python-%E2%89%A53.10-3776AB?logo=python&logoColor=white)
![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![license](https://img.shields.io/badge/license-MIT-green)

</div>

---

## Why

Fake APKs are one of the fastest-growing fraud channels in India. A victim gets an app that looks official, grants it SMS and accessibility access, and loses money within minutes. Most people can't tell a real app from a fake one, and general-purpose Android tools aren't built for these scam families or for the people who receive them.

Chowkidar gives cautious users, bank fraud teams and researchers a fast verdict, a plain-language explanation and a report they can attach to a complaint.

## What it checks

| Check | Why it matters |
|---|---|
| Reads or listens for SMS (`READ_SMS`, `RECEIVE_SMS`, `SMS_RECEIVED` receiver) | Grabs bank OTPs as they arrive |
| Accessibility service | Reads the screen and taps buttons for the victim |
| Call-forwarding code (`*21*`) with `CALL_PHONE` | Diverts calls, including bank verification calls |
| Device admin, overlay, app installs | Hard to uninstall, fake login screens, drops more malware |
| Telegram bot tokens and `api.telegram.org` | Common channel for sending stolen data |
| Firebase databases and raw-IP servers | Common drop points for stolen SMS |
| Bank or government names (SBI, YONO, PM-Kisan, PM Awas, e-challan …) | Impersonation, flagged only when the app also reads SMS |

Each finding has a weight. The total gives a risk score from 0 to 100 and one of four verdicts: **no indicators found**, **low risk**, **suspicious** or **likely malicious**.

## Quick start

```bash
pip install git+https://github.com/kirtanbhatt10/chowkidar.git

chowkidar scan suspicious.apk               # summary in English
chowkidar scan suspicious.apk --lang hi     # summary in Hindi
chowkidar scan suspicious.apk --markdown    # report to attach to a cybercrime complaint
chowkidar scan suspicious.apk --json        # full machine-readable report
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
```

Exit codes: `0` no indicators or low risk, `1` suspicious or likely malicious, `2` error.

## How it works

1. **Archive checks.** Confirms the file is a real APK and computes SHA-256, SHA-1 and MD5.
2. **Manifest parsing.** A built-in parser for Android's binary XML reads permissions and components. It recovers attribute names that obfuscators blank out, and falls back to a byte search when the manifest has been deliberately corrupted.
3. **String extraction.** Reads the DEX string tables and bundled assets, where URLs, bot tokens and forwarding codes live.
4. **Rules and scoring.** Each rule has a severity, a weight and an explanation in English and Hindi.

No third-party dependencies, and nothing in the APK is ever executed.

## Safety

- **Static only.** Chowkidar never installs, opens or executes the app.
- **No samples in this repo.** `*.apk` files are git-ignored. The tests build synthetic APKs instead. Handle real samples only in an isolated environment.
- **No counter-attacks.** Chowkidar never uses the bot tokens it finds or contacts attacker servers. Tokens are masked in human-readable output. Report findings at [cybercrime.gov.in](https://cybercrime.gov.in) or call **1930**.

## Roadmap

- [x] APK checks, hashes, risk score and verdicts
- [x] Binary manifest (AXML) and DEX string parsers
- [x] SMS, accessibility, call forwarding, Telegram, Firebase and IP indicators
- [x] English and Hindi explanations
- [x] Markdown report for complaints
- [ ] App label and icon from `resources.arsc`, to catch look-alike names
- [ ] Signing certificate checks
- [ ] Known scam-family signatures
- [ ] Indicator export (STIX) for banks and CERT-In
- [ ] More languages: Gujarati, Marathi, Tamil, Bengali

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Licence

MIT. See [LICENSE](LICENSE).
