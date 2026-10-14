"""Command-line entry point: `chowkidar scan <file.apk> [--json]`."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .analyzer import analyze


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="chowkidar", description="Static analysis for scam APKs.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyse an APK without running it")
    scan.add_argument("apk", help="path to the .apk file")
    scan.add_argument("--json", action="store_true", help="print the report as JSON")

    args = parser.parse_args(argv)

    try:
        report = analyze(args.apk)
    except FileNotFoundError:
        print(f"error: file not found: {args.apk}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"File:     {report.file}")
        print(f"SHA-256:  {report.sha256}")
        print(f"Verdict:  {report.verdict}")
        for finding in report.findings:
            print(f"  [{finding.severity.upper()}] {finding.title}: {finding.detail}")
    return 0 if report.verdict == "no indicators found" else 1


if __name__ == "__main__":
    raise SystemExit(main())
