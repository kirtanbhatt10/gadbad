<div align="center">

# 🛡️ Chowkidar

### Scam APKs don't get past the watchman.

**Chowkidar** is a static analyser for the fake Android apps spreading over WhatsApp in India: fake RTO e-challan, PM Awas Yojana list and bank KYC apps that steal SMS and OTPs.
It reads an APK, never installs it, and reports the signs of theft.

![status](https://img.shields.io/badge/status-early%20alpha-orange)
![python](https://img.shields.io/badge/python-%E2%89%A53.10-3776AB?logo=python&logoColor=white)
![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![license](https://img.shields.io/badge/license-MIT-green)

</div>

---

## Why

Fake APKs are one of the fastest-growing fraud channels in India. Victims are sent an app that looks official, grant it SMS and accessibility access, and lose money within minutes. Most people can't tell a real app from a fake one, and most existing tools aren't built for these scam families.

Chowkidar gives researchers, bank fraud teams and cautious users a fast verdict and a report they can act on.

## What it checks

| Signal | Why it matters |
|---|---|
| SMS permissions (`READ_SMS`, `RECEIVE_SMS`) | Lets the app read OTPs |
| Accessibility service | Lets the app read the screen and tap "allow" for the user |
| Telegram bot tokens hardcoded in the app | Common way to send stolen data to the attacker |
| Plain-HTTP / hardcoded C2 URLs | Where stolen data is sent |
| Brand names (PM-Kisan, PM Awas, e-challan, SBI, HDFC …) | Impersonation hint, only meaningful alongside other signals |

## Quick start

```bash
pip install -e .
chowkidar scan suspicious.apk
chowkidar scan suspicious.apk --json > report.json
```

Example output:

```text
File:     suspicious.apk
SHA-256:  74728930818bc6d3987cb32f51d2f5c7ebe1e32ac37cafe765cce69defc6e1d5
Verdict:  likely malicious
  [HIGH] Requests SMS access: android.permission.READ_SMS, android.permission.RECEIVE_SMS
  [HIGH] Impersonates a known brand and reads SMS: pmkisan
```

Exit code `0` means no indicators were found, `1` means something was flagged, and `2` means the file was missing.

## Safety

- **Static only.** Chowkidar reads the archive and never installs, opens or executes the app.
- **No samples in this repo.** `*.apk` files are git-ignored. Analyse samples only in an isolated environment.
- **No takedown or counter-attack.** Chowkidar never uses stolen credentials or contacts attacker servers. Report findings to the proper channels: [cybercrime.gov.in](https://cybercrime.gov.in) or the 1930 helpline.

## Roadmap

- [x] APK archive checks, SHA-256 and verdicts
- [x] SMS, accessibility, Telegram and URL indicators
- [ ] Proper binary `AndroidManifest.xml` parser (AXML)
- [ ] Hindi and English plain-language explanations for victims
- [ ] Indicator export (JSON / STIX) for banks and CERT-In
- [ ] Known scam-family signature database
- [ ] GitHub Action for scanning shared APKs in CI

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Licence

MIT. See [LICENSE](LICENSE).
