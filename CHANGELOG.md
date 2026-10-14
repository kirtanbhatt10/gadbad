# Changelog

All notable changes to Gadbad are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

The JSON report has its own `schema_version`. It only changes when a field is removed or changes meaning.

## [Unreleased]

## [1.0.0] - 2026-10-15

First public release. The project was renamed from Chowkidar to Gadbad, because the `chowkidar` name on PyPI belongs to an unrelated tool.

### Added

- Parser for Android binary XML (AXML) that reads permissions and components, recovers attribute names that obfuscators blank out, and falls back to a byte search on deliberately corrupted manifests.
- DEX string-table reader for URLs, bot tokens and forwarding codes.
- Detection of SMS and OTP theft, accessibility abuse, device admin, overlays, app installs, `*21*` call forwarding, Telegram bot tokens and API calls, Firebase databases, public raw-IP servers, cleartext traffic, and bank or government-scheme impersonation.
- Risk score from 0 to 100 and four verdicts: no indicators found, low risk, suspicious, likely malicious.
- Plain-language explanations and advice in English and Hindi (`--lang hi`).
- Markdown report for cybercrime complaints (`--markdown`), with SHA-256, SHA-1 and MD5 hashes and masked bot tokens.
- Folder and multi-file scans, `--fail-on` threshold, `--output` file, versioned JSON report.
- Context for real messaging apps: apps that declare every component a default SMS app needs get lower weight for SMS access. Exfiltration signals keep full weight.

### Security

- Static analysis only: APKs are never installed or executed.
- Zip-bomb limits on member size and total decompressed data. Encrypted and corrupt members are skipped.
- Only public IP addresses are reported. Private, loopback and invalid addresses are ignored.

## [0.2.0] - 2026-10-15

- Manifest and DEX parsers, scoring and Hindi explanations (released as Chowkidar).

## [0.1.0] - 2026-10-15

- Initial prototype (released as Chowkidar).

[Unreleased]: https://github.com/kirtanbhatt10/gadbad/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/kirtanbhatt10/gadbad/releases/tag/v1.0.0
