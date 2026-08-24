from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from .baseline import verify_baseline

from .config import (
    BLASTER_CONFIG_PATH,
    DEFAULT_WORK_ROOT,
    REPOSITORY_ROOT,
    compiler_pair,
    load_blaster_config,
)
from .candidate import (
    DEFAULT_RELEASE_LOCK,
    DEFAULT_SENTINEL,
    run_candidate_gate,
)
from .corpus import plan_corpus, run_corpus
from .compiler_artifacts import (
    DEFAULT_AIKEN_REPOSITORY,
    build_local,
    build_release,
    verify_compiler_manifest,
)
from .generate_builtins import generate as generate_builtins
from .generate_features import generate_features
from .profiles import PROFILE_LOCK, lock_profile, run_profile
from .runner import compare_package, compare_sentinel


def _compiler_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--old-aiken", type=Path)
    parser.add_argument("--new-aiken", type=Path)
    parser.add_argument("--old-compiler-manifest", type=Path)
    parser.add_argument("--new-compiler-manifest", type=Path)
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
    compiler_parser = subcommands.add_parser(
        "compiler", help="build and verify provenance-carrying Aiken compiler artifacts"
    )
    compiler_commands = compiler_parser.add_subparsers(
        dest="compiler_command", required=True
    )
    release_parser = compiler_commands.add_parser(
        "build-release", help="build an isolated released Aiken compiler"
    )
    release_parser.add_argument("--aiken-repository", default=DEFAULT_AIKEN_REPOSITORY)
    release_parser.add_argument("--aiken-source", type=Path)
    release_parser.add_argument("--ref", required=True)
    release_parser.add_argument("--label")
    release_parser.add_argument("--output", type=Path)
    local_parser = compiler_commands.add_parser(
        "build-local", help="build a provenance-carrying local Aiken compiler"
    )
    local_parser.add_argument("--aiken-source", type=Path, required=True)
    local_parser.add_argument("--label", required=True)
    local_parser.add_argument("--output", type=Path)
    local_parser.add_argument("--allow-dirty", action="store_true")
    verify_parser = compiler_commands.add_parser(
        "verify", help="verify a compiler artifact manifest and binary"
    )
    verify_parser.add_argument("manifest", type=Path)
    baseline_parser = subcommands.add_parser(
        "baseline", help="verify compact historical evidence baselines"
    )
    baseline_commands = baseline_parser.add_subparsers(
        dest="baseline_command", required=True
    )
    baseline_verify = baseline_commands.add_parser(
        "verify", help="verify checksums, identities, lineage, and CI attestation"
    )
    baseline_verify.add_argument("baseline", type=Path)

    profile_parser = subcommands.add_parser(
        "profile", help="lock and run versioned compiler comparison profiles"
    )
    profile_commands = profile_parser.add_subparsers(
        dest="profile_command", required=True
    )
    profile_lock = profile_commands.add_parser(
        "lock", help="resolve profile release tags to immutable revisions"
    )
    profile_lock.add_argument("profile")
    profile_lock.add_argument("--aiken-repository", default=DEFAULT_AIKEN_REPOSITORY)
    profile_lock.add_argument("--aiken-source", type=Path)
    profile_lock.add_argument("--output", type=Path, default=PROFILE_LOCK)
    profile_run = profile_commands.add_parser(
        "run", help="run a locked historical or local compiler profile"
    )
    profile_run.add_argument("profile")
    profile_run.add_argument("--aiken-repository", default=DEFAULT_AIKEN_REPOSITORY)
    profile_run.add_argument("--aiken-source", type=Path)
    profile_run.add_argument("--lock", type=Path, default=PROFILE_LOCK)
    profile_run.add_argument("--old-compiler-manifest", type=Path)
    profile_run.add_argument("--new-compiler-manifest", type=Path)
    profile_run.add_argument("--work", type=Path, default=DEFAULT_WORK_ROOT)
    profile_run.add_argument("--blaster-config", type=Path, default=BLASTER_CONFIG_PATH)
    profile_run.add_argument("--resume", action="store_true")
    profile_run.add_argument("--force", action="store_true")
    profile_run.add_argument("--strict", action="store_true")

    compare_parser = subcommands.add_parser(
        "compare", help="compare every validator in a normal Aiken package"
    )
    compare_parser.add_argument("package", type=Path)
    _compiler_options(compare_parser)
    compare_parser.add_argument("--resume", action="store_true")
    compare_parser.add_argument("--force", action="store_true")

    sentinel_parser = subcommands.add_parser(
        "sentinel", help="run the versioned language-feature sentinel gate"
    )
    sentinel_parser.add_argument(
        "package", nargs="?", type=Path, default=REPOSITORY_ROOT / "sentinel"
    )
    _compiler_options(sentinel_parser)
    sentinel_parser.add_argument(
        "--feature-contract",
        type=Path,
        default=REPOSITORY_ROOT / "corpus" / "aiken_language_features_v1_1_23.json",
    )
    sentinel_parser.add_argument("--resume", action="store_true")
    sentinel_parser.add_argument("--force", action="store_true")

    corpus_parser = subcommands.add_parser(
        "corpus", help="operate on a locked Aiken corpus"
    )
    corpus_commands = corpus_parser.add_subparsers(dest="corpus_command", required=True)
    corpus_plan = corpus_commands.add_parser(
        "plan", help="resolve and validate a locked corpus without compiling"
    )
    corpus_plan.add_argument("manifest", type=Path)
    corpus_plan.add_argument("--work", type=Path, default=DEFAULT_WORK_ROOT)
    corpus_run = corpus_commands.add_parser("run", help="run a locked corpus manifest")
    corpus_run.add_argument("manifest", type=Path)
    corpus_run.add_argument(
        "--only",
        action="append",
        default=None,
        help="run only the named source or target; repeat for multiple entries",
    )
    corpus_run.add_argument("--only-pair", action="append", default=None)
    corpus_run.add_argument("--shard-index", type=int)
    corpus_run.add_argument("--shard-count", type=int)
    corpus_run.add_argument("--jobs", type=int, default=1)
    corpus_run.add_argument("--resume", action="store_true")
    corpus_run.add_argument("--force", action="store_true")
    _compiler_options(corpus_run)

    candidate_parser = subcommands.add_parser(
        "candidate", help="gate a local Aiken compiler candidate"
    )
    candidate_commands = candidate_parser.add_subparsers(
        dest="candidate_command", required=True
    )
    candidate_gate = candidate_commands.add_parser(
        "gate", help="run the complete local candidate release gate"
    )
    candidate_gate.add_argument(
        "--base-compiler-manifest", type=Path, required=True
    )
    candidate_gate.add_argument(
        "--candidate-compiler-manifest", type=Path, required=True
    )
    candidate_gate.add_argument(
        "--feature-contract", type=Path, required=True
    )
    candidate_gate.add_argument("--corpus-lock", type=Path, required=True)
    candidate_gate.add_argument(
        "--scope", default="sentinel,mandatory"
    )
    candidate_gate.add_argument("--resume", action="store_true")
    candidate_gate.add_argument(
        "--policy", choices=("strict", "screening"), default="strict"
    )
    candidate_gate.add_argument(
        "--release-lock", type=Path, default=DEFAULT_RELEASE_LOCK
    )
    candidate_gate.add_argument(
        "--sentinel-package", type=Path, default=DEFAULT_SENTINEL
    )
    candidate_gate.add_argument(
        "--work", type=Path, default=DEFAULT_WORK_ROOT
    )
    candidate_gate.add_argument(
        "--blaster-config", type=Path, default=BLASTER_CONFIG_PATH
    )
    candidate_gate.add_argument("--jobs", type=int, default=1)
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
    if args.command == "compiler":
        try:
            if args.compiler_command == "build-release":
                output = args.output or (
                    REPOSITORY_ROOT / ".ak-equiv" / "compilers" / (args.label or args.ref)
                )
                result = build_release(
                    ref=args.ref,
                    output=output,
                    aiken_source=args.aiken_source,
                    aiken_repository=args.aiken_repository,
                    label=args.label,
                )
            elif args.compiler_command == "build-local":
                output = args.output or (
                    REPOSITORY_ROOT / ".ak-equiv" / "compilers" / args.label
                )
                result = build_local(
                    aiken_source=args.aiken_source,
                    output=output,
                    label=args.label,
                    allow_dirty=args.allow_dirty,
                )
            elif args.compiler_command == "verify":
                result = verify_compiler_manifest(args.manifest)
            else:
                raise AssertionError(args.compiler_command)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        except (FileNotFoundError, RuntimeError, ValueError, json.JSONDecodeError) as error:
            print(str(error), file=sys.stderr)
            return 1
    if args.command == "baseline":
        try:
            if args.baseline_command != "verify":
                raise AssertionError(args.baseline_command)
            result = verify_baseline(args.baseline)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        except (FileNotFoundError, RuntimeError, ValueError, json.JSONDecodeError) as error:
            print(str(error), file=sys.stderr)
            return 1
    if args.command == "profile":
        try:
            if args.profile_command == "lock":
                result = lock_profile(
                    args.profile,
                    output=args.output,
                    aiken_source=args.aiken_source,
                    aiken_repository=args.aiken_repository,
                )
                exit_code = 0
            elif args.profile_command == "run":
                result = run_profile(
                    args.profile,
                    work_root=args.work,
                    lock_path=args.lock,
                    aiken_source=args.aiken_source,
                    aiken_repository=args.aiken_repository,
                    old_manifest=args.old_compiler_manifest,
                    new_manifest=args.new_compiler_manifest,
                    resume=args.resume,
                    force=args.force,
                    strict=args.strict,
                    blaster_config=args.blaster_config,
                )
                exit_code = 0 if result["profile_pass"] else 2
            else:
                raise AssertionError(args.profile_command)
            print(json.dumps(result, indent=2, sort_keys=True))
            return exit_code
        except (FileNotFoundError, RuntimeError, ValueError, json.JSONDecodeError) as error:
            print(str(error), file=sys.stderr)
            return 1
    if args.command == "corpus" and args.corpus_command == "plan":
        try:
            plan = plan_corpus(args.manifest, work_root=args.work)
            print(json.dumps(plan, indent=2, sort_keys=True))
            return 0 if plan["valid"] else 1
        except (FileNotFoundError, ValueError, json.JSONDecodeError) as error:
            print(str(error), file=sys.stderr)
            return 1
    try:
        if args.command == "generate-builtins":
            summary = generate_builtins()
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if args.command == "generate-features":
            summary = generate_features()
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if args.command == "candidate":
            scope = {
                value.strip()
                for value in args.scope.split(",")
                if value.strip()
            }
            summary = run_candidate_gate(
                base_compiler_manifest=args.base_compiler_manifest,
                candidate_compiler_manifest=args.candidate_compiler_manifest,
                feature_contract=args.feature_contract,
                corpus_lock=args.corpus_lock,
                scope=scope,
                resume=args.resume,
                policy=args.policy,
                work_root=args.work,
                blaster_config_path=args.blaster_config,
                release_lock=args.release_lock,
                sentinel_package=args.sentinel_package,
                jobs=args.jobs,
            )
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0 if summary["decision"] == "pass" else 2

        compilers = compiler_pair(
            old_aiken=args.old_aiken,
            new_aiken=args.new_aiken,
            old_revision=args.old_revision,
            new_revision=args.new_revision,
            old_manifest=args.old_compiler_manifest,
            new_manifest=args.new_compiler_manifest,
        )
        blaster_config = load_blaster_config(args.blaster_config)
        if args.command == "compare":
            summary = compare_package(
                args.package,
                compilers,
                work_root=args.work,
                strict=args.strict,
                blaster_config=blaster_config,
                resume=args.resume,
                force=args.force,
            )
        elif args.command == "sentinel":
            summary = compare_sentinel(
                args.package,
                compilers,
                work_root=args.work,
                strict=args.strict,
                blaster_config=blaster_config,
                feature_contract=args.feature_contract,
                resume=args.resume,
                force=args.force,
            )
        elif args.command == "corpus" and args.corpus_command == "run":
            summary = run_corpus(
                args.manifest,
                compilers,
                work_root=args.work,
                strict=args.strict,
                only=set(args.only) if args.only else None,
                only_pair=set(args.only_pair) if args.only_pair else None,
                shard_index=args.shard_index,
                shard_count=args.shard_count,
                jobs=args.jobs,
                resume=args.resume,
                force=args.force,
                blaster_config=blaster_config,
            )
        else:
            raise AssertionError(args.command)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 2 if args.strict and not summary["strict_pass"] else 0
    except (FileNotFoundError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1
