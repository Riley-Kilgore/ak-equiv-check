from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import DEFAULT_WORK_ROOT
from .pipeline import scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="equiv-checker")
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan_parser = subcommands.add_parser("scan", help="run all evidence stages for one package")
    scan_parser.add_argument("package", type=Path)
    scan_parser.add_argument("--work", type=Path, default=DEFAULT_WORK_ROOT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "scan":
            summary = scan(args.package, args.work)
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    raise AssertionError(args.command)
