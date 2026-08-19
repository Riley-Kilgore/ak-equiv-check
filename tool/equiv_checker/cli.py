from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import DEFAULT_WORK_ROOT
from .generate_builtins import generate as generate_builtins
from .generate_features import generate_features
from .gate import gate
from .pipeline import scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="equiv-checker")
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan_parser = subcommands.add_parser("scan", help="run all evidence stages for one package")
    scan_parser.add_argument("package", type=Path)
    scan_parser.add_argument("--work", type=Path, default=DEFAULT_WORK_ROOT)
    subcommands.add_parser(
        "generate-builtins",
        help="regenerate the twelve builtin sentinel families",
    )
    subcommands.add_parser(
        "generate-features",
        help="regenerate language feature sentinel fixtures",
    )
    gate_parser = subcommands.add_parser(
        "gate",
        help="run the scanner and enforce the sentinel evidence gate",
    )
    gate_parser.add_argument("package", nargs="?", type=Path, default=Path("sentinel"))
    gate_parser.add_argument("--work", type=Path, default=DEFAULT_WORK_ROOT)
    gate_parser.add_argument(
        "--pre-blaster",
        action="store_true",
        help="allow complete paired artifacts to await Lean-blaster",
    )
    gate_parser.add_argument(
        "--no-scan",
        action="store_true",
        help="validate existing work artifacts without rescanning",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "scan":
            summary = scan(args.package, args.work)
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if args.command == "generate-builtins":
            summary = generate_builtins()
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if args.command == "generate-features":
            summary = generate_features()
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if args.command == "gate":
            report = gate(
                args.package,
                args.work,
                allow_blaster_pending=args.pre_blaster,
                run_scan=not args.no_scan,
            )
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    raise AssertionError(args.command)
