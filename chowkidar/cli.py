"""Command-line entry point.

    chowkidar scan suspicious.apk                 # English summary
    chowkidar scan suspicious.apk --lang hi       # Hindi summary
    chowkidar scan suspicious.apk --json          # full machine-readable report
    chowkidar scan suspicious.apk --markdown      # report to attach to a complaint

Exit codes: 0 no indicators or low risk, 1 suspicious or likely malicious, 2 error.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .analyzer import analyze
from .report import to_markdown, to_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="chowkidar", description="Static analysis for scam APKs.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyse an APK without installing or running it")
    scan.add_argument("apk", help="path to the .apk file")
    fmt = scan.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="print the full report as JSON")
    fmt.add_argument("--markdown", action="store_true", help="print a Markdown report for a complaint")
    scan.add_argument("--lang", choices=["en", "hi"], default="en", help="language for explanations")

    args = parser.parse_args(argv)

    try:
        report = analyze(args.apk)
    except FileNotFoundError:
        print(f"error: file not found: {args.apk}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    elif args.markdown:
        print(to_markdown(report))
    else:
        print(to_text(report, args.lang))
    return 1 if report.verdict in ("suspicious", "likely malicious") else 0


if __name__ == "__main__":
    raise SystemExit(main())
