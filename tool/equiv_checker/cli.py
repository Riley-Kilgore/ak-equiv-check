from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import (
    BLASTER_CONFIG_PATH,
    DEFAULT_WORK_ROOT,
    REPOSITORY_ROOT,
    compiler_pair,
    load_blaster_config,
)
from .corpus import run_corpus
from .generate_builtins import generate as generate_builtins
from .generate_features import generate_features
from .runner import compare_package, compare_sentinel


def _compiler_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--old-aiken", type=Path)
    parser.add_argument("--new-aiken", type=Path)
    parser.add_argument("--old-revision")
    parser.add_argument("--new-revision")
    parser.add_argument("--work", type=Path, default=DEFAULT_WORK_ROOT)
    parser.add_argument("--blaster-config", type=Path, default=BLASTER_CONFIG_PATH)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="return a failing exit status for every non-passing or reproducibility result",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="equiv-checker")
    subcommands = parser.add_subparsers(dest="command", required=True)

    compare_parser = subcommands.add_parser(
        "compare", help="compare every validator in a normal Aiken package"
    )
    compare_parser.add_argument("package", type=Path)
    _compiler_options(compare_parser)

    sentinel_parser = subcommands.add_parser(
        "sentinel", help="run the versioned language-feature sentinel gate"
    )
    sentinel_parser.add_argument(
        "package", nargs="?", type=Path, default=REPOSITORY_ROOT / "sentinel"
    )
    _compiler_options(sentinel_parser)

    corpus_parser = subcommands.add_parser(
        "corpus", help="operate on a locked Aiken corpus"
    )
    corpus_commands = corpus_parser.add_subparsers(dest="corpus_command", required=True)
    corpus_run = corpus_commands.add_parser("run", help="run a locked corpus manifest")
    corpus_run.add_argument("manifest", type=Path)
    corpus_run.add_argument(
        "--only",
        action="append",
        default=None,
        help="run only the named corpus entry; repeat for multiple entries",
    )
    _compiler_options(corpus_run)

    subcommands.add_parser(
        "generate-builtins",
        help="regenerate the builtin sentinel families",
    )
    subcommands.add_parser(
        "generate-features",
        help="regenerate language feature sentinel fixtures",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "generate-builtins":
            summary = generate_builtins()
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if args.command == "generate-features":
            summary = generate_features()
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0

        compilers = compiler_pair(
            old_aiken=args.old_aiken,
            new_aiken=args.new_aiken,
            old_revision=args.old_revision,
            new_revision=args.new_revision,
        )
        blaster_config = load_blaster_config(args.blaster_config)
        if args.command == "compare":
            summary = compare_package(
                args.package,
                compilers,
                work_root=args.work,
                strict=args.strict,
                blaster_config=blaster_config,
            )
        elif args.command == "sentinel":
            summary = compare_sentinel(
                args.package,
                compilers,
                work_root=args.work,
                strict=args.strict,
                blaster_config=blaster_config,
            )
        elif args.command == "corpus" and args.corpus_command == "run":
            summary = run_corpus(
                args.manifest,
                compilers,
                work_root=args.work,
                strict=args.strict,
                only=set(args.only) if args.only else None,
                blaster_config=blaster_config,
            )
        else:
            raise AssertionError(args.command)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 2 if args.strict and not summary["strict_pass"] else 0
    except (FileNotFoundError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1
