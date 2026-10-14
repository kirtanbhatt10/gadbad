"""Command-line entry point.

    gadbad scan app.apk                       # English summary
    gadbad scan app.apk --lang hi             # Hindi summary
    gadbad scan app.apk --json                # full machine-readable report
    gadbad scan app.apk --markdown -o r.md    # complaint report, written to a file
    gadbad scan downloads/                    # every .apk in a folder, recursively

Exit codes: 0 nothing at or above the --fail-on level, 1 at least one APK at or
above it, 2 at least one file could not be scanned.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from collections.abc import Iterator
from pathlib import Path

from . import __version__
from .analyzer import Report, analyze
from .report import to_markdown, to_text

FAIL_LEVELS = {
    "suspicious": {"suspicious", "likely malicious"},
    "likely-malicious": {"likely malicious"},
    "never": set(),
}


def _expand(paths: list[str]) -> Iterator[Path]:
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            yield from sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() == ".apk")
        else:
            yield path


def _render(reports: list[Report], args: argparse.Namespace) -> str:
    if args.json:
        payload = [r.to_dict() for r in reports]
        return json.dumps(payload[0] if len(payload) == 1 else payload, indent=2, ensure_ascii=False)
    if args.markdown:
        return "\n---\n\n".join(to_markdown(r) for r in reports)
    return ("\n\n" + "=" * 72 + "\n\n").join(to_text(r, args.lang) for r in reports)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gadbad",
        description="Kuch toh gadbad hai: static analysis for scam APKs. Never installs or runs the app.",
    )
    parser.add_argument("--version", action="version", version=f"gadbad {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyse APK files or folders of APKs")
    scan.add_argument("paths", nargs="+", metavar="PATH", help="APK file(s) or folder(s) to scan")
    fmt = scan.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="print the full report as JSON")
    fmt.add_argument("--markdown", action="store_true", help="print a Markdown report for a complaint")
    scan.add_argument("--lang", choices=["en", "hi"], default="en", help="language for explanations (default: en)")
    scan.add_argument(
        "--fail-on",
        choices=list(FAIL_LEVELS),
        default="suspicious",
        help="lowest verdict that makes the exit code 1 (default: suspicious)",
    )
    scan.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    return parser


def _utf8_console() -> None:
    """Hindi output must not crash on consoles that default to a legacy code page (Windows)."""
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
        reconfigure = getattr(stream, "reconfigure", None)
        if encoding != "utf8" and reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    _utf8_console()
    args = build_parser().parse_args(argv)

    reports: list[Report] = []
    errors = 0
    files = list(_expand(args.paths))
    if not files:
        print("error: no .apk files found", file=sys.stderr)
        return 2
    for path in files:
        try:
            reports.append(analyze(path))
        except FileNotFoundError:
            print(f"error: file not found: {path}", file=sys.stderr)
            errors += 1
        except (IsADirectoryError, PermissionError) as exc:
            print(f"error: cannot read {path}: {exc.__class__.__name__}", file=sys.stderr)
            errors += 1
        except Exception as exc:  # one bad file must never stop a batch scan
            print(f"error: unexpected failure on {path}: {exc!r}", file=sys.stderr)
            errors += 1

    if reports:
        text = _render(reports, args)
        if args.output:
            Path(args.output).write_text(text + "\n", encoding="utf-8")
        else:
            print(text)

    if errors:
        return 2
    flagged = FAIL_LEVELS[args.fail_on]
    return 1 if any(r.verdict in flagged for r in reports) else 0


if __name__ == "__main__":
    raise SystemExit(main())
