# Security policy

## Reporting a vulnerability in Gadbad

If you find a way to make Gadbad crash, hang, run code or read files it shouldn't when given a crafted APK, please report it privately through [GitHub's private vulnerability reporting](https://github.com/kirtanbhatt10/gadbad/security/advisories/new). Please don't open a public issue.

Include the Gadbad version (`gadbad --version`), your OS and Python version, and how to reproduce it. If the trigger is a crafted file, describe how to build it, or share its SHA-256 instead of the file itself.

You can expect a first reply within 7 days. Fixes for confirmed issues are released as soon as they're ready and credited in the changelog unless you'd rather stay anonymous.

## Supported versions

Only the latest release gets security fixes.

## Reporting a scam app (not a Gadbad bug)

Gadbad is not a reporting channel for fraud. If you or someone you know received a scam APK:

- In India, report it at [cybercrime.gov.in](https://cybercrime.gov.in) or call the national helpline **1930**.
- `gadbad scan app.apk --markdown -o report.md` produces a report you can attach to the complaint.

## Handling malware samples

- Never commit, attach or upload real malware samples to this repository, its issues or its pull requests. Share hashes instead.
- Analyse real samples only on a machine or VM you can wipe.
- Gadbad never installs or runs an APK, but other tools you use on the same sample might.
