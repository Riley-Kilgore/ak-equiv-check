from __future__ import annotations

import hashlib
import json
import shutil
import tomllib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .blaster import RealBlasterBackend
from .census import census
from .config import (
    CONTRACT_PATH,
    DEFAULT_WORK_ROOT,
    SCANNER_CONFIG_PATH,
    TOOL_ROOT,
    Compiler,
    load_blaster_config,
    load_json,
    package_name,
    sha256_file,
)
from .models import (
    BlasterBackend,
    BlasterConfig,
    FINAL_STATUSES,
    STRICT_PASSING_STATUSES,
    BlasterResult,
    InputModel,
    ScriptPair,
)
from .pairing import PairingResult, canonical_json, pair_validators, stable_hash
from .pipeline import _capture_negative_cases, prove_reachability, run_lanes
from .process import ProcessResult, run_process, write_process_logs
from .semantics import (
    EQUIVALENCE_FORMULA,
    EXCLUDED_FROM_SEMANTIC_VERDICT,
    validator_input_model,
)


CHECKER_SCHEMA_VERSION = 2
_GENERATED_NAMES = {".git", "artifacts", "build", "__pycache__"}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _ignored(relative: Path) -> bool:
    if any(part in _GENERATED_NAMES for part in relative.parts):
        return True
    name = relative.name
    return name == "plutus.json" or (
        name.startswith("plutus-") and name.endswith(".json")
    )


def hash_package_tree(package: Path, *, include_lock: bool) -> str:
    digest = hashlib.sha256()
    for path in sorted(
        candidate for candidate in package.rglob("*") if candidate.is_file()
    ):
        relative = path.relative_to(package)
        if _ignored(relative) or (
            not include_lock and relative.as_posix() == "aiken.lock"
        ):
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _copy_package(source: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns(
            ".git",
            "artifacts",
            "build",
            "plutus.json",
            "plutus-*.json",
            "__pycache__",
        ),
    )


def _git(package: Path, *arguments: str) -> ProcessResult:
    return run_process(["git", "-C", package, *arguments], package, 30.0)


def source_repository_metadata(package: Path) -> dict[str, Any]:
    root_result = _git(package, "rev-parse", "--show-toplevel")
    if root_result.exit_code != 0:
        return {
            "kind": "local_directory",
            "repository_root": None,
            "commit": None,
            "dirty": None,
            "remote": None,
            "package_path": str(package.resolve()),
            "identity": f"local:{package.resolve()}",
        }
    repository_root = Path(root_result.stdout.strip()).resolve()
    commit_result = _git(package, "rev-parse", "HEAD")
    status_result = _git(package, "status", "--porcelain", "--untracked-files=normal")
    remote_result = _git(package, "config", "--get", "remote.origin.url")
    relative = package.resolve().relative_to(repository_root).as_posix()
    commit = commit_result.stdout.strip() if commit_result.exit_code == 0 else None
    remote = remote_result.stdout.strip() if remote_result.exit_code == 0 else None
    identity = f"{remote or repository_root}@{commit or 'unknown'}:{relative or '.'}"
    return {
        "kind": "git",
        "repository_root": str(repository_root),
        "commit": commit,
        "dirty": bool(status_result.stdout.strip())
        if status_result.exit_code == 0
        else None,
        "remote": remote,
        "package_path": relative or ".",
        "identity": identity,
    }


def _plutus_version(package: Path) -> str:
    with (package / "aiken.toml").open("rb") as stream:
        manifest = tomllib.load(stream)
    value = str(manifest.get("plutus", "v3")).lower()
    return value if value.startswith("v") else f"v{value}"


def _artifact(path: Path, root: Path, kind: str) -> dict[str, Any]:
    return {
        "path": path.relative_to(root).as_posix(),
        "kind": kind,
        "trace_level": "silent",
        "trace_filter": "all",
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def _process_record(
    result: ProcessResult,
    bundle_root: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    write_process_logs(result, stdout_path, stderr_path)
    return result.to_dict() | {
        "stdout_path": stdout_path.relative_to(bundle_root).as_posix(),
        "stderr_path": stderr_path.relative_to(bundle_root).as_posix(),
        "timeout_seconds": timeout_seconds,
    }


def _build_one(
    compiler: Compiler,
    original_package: Path,
    bundle_root: Path,
    config: BlasterConfig,
) -> dict[str, Any]:
    compiler_root = bundle_root / compiler.label
    source = compiler_root / "package"
    _copy_package(original_package, source)
    source_before = hash_package_tree(source, include_lock=False)
    lock_before = (
        sha256_file(source / "aiken.lock")
        if (source / "aiken.lock").is_file()
        else None
    )
    logs = bundle_root / "logs"
    build_command = [str(compiler.executable), "build", "--out", "plutus.json"]
    build = run_process(build_command, source, config.timeouts.aiken_build)
    build_record = _process_record(
        build,
        bundle_root,
        logs / f"build-{compiler.label}.stdout.log",
        logs / f"build-{compiler.label}.stderr.log",
        config.timeouts.aiken_build,
    )
    extraction: ProcessResult | None = None
    extraction_record: dict[str, Any] | None = None
    if not build.timed_out and build.exit_code == 0:
        extraction_command = [
            str(compiler.executable),
            "build",
            "--out",
            "plutus.json",
            "--uplc",
        ]
        extraction = run_process(
            extraction_command, source, config.timeouts.uplc_extraction
        )
        extraction_record = _process_record(
            extraction,
            bundle_root,
            logs / f"uplc-extraction-{compiler.label}.stdout.log",
            logs / f"uplc-extraction-{compiler.label}.stderr.log",
            config.timeouts.uplc_extraction,
        )

    artifacts: list[dict[str, Any]] = []
    raw_root = compiler_root / "raw" / "silent"
    blueprint_source = source / "plutus.json"
    if blueprint_source.is_file():
        blueprint = raw_root / "plutus.json"
        blueprint.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(blueprint_source, blueprint)
        artifacts.append(_artifact(blueprint, compiler_root, "plutus_blueprint"))
    artifact_root = source / "artifacts"
    if artifact_root.is_dir():
        for uplc in sorted(artifact_root.rglob("*.uplc")):
            destination = raw_root / "uplc" / uplc.relative_to(artifact_root)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(uplc, destination)
            artifacts.append(_artifact(destination, compiler_root, "textual_uplc"))
    lock_after = (
        sha256_file(source / "aiken.lock")
        if (source / "aiken.lock").is_file()
        else None
    )
    if (source / "aiken.lock").is_file():
        lock_artifact = raw_root / "aiken.lock"
        lock_artifact.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / "aiken.lock", lock_artifact)
        artifacts.append(_artifact(lock_artifact, compiler_root, "dependency_lock"))
    source_after = hash_package_tree(source, include_lock=False)
    record = {
        "schema_version": CHECKER_SCHEMA_VERSION,
        "label": compiler.label,
        "package": package_name(source),
        "compiler": compiler.identity(),
        "source_copy": source.relative_to(bundle_root).as_posix(),
        "source_hash_before": source_before,
        "source_hash_after": source_after,
        "source_unchanged": source_before == source_after,
        "dependency_lock_hash_before": lock_before,
        "dependency_lock_hash_after": lock_after,
        "dependency_lock_unchanged": lock_before == lock_after,
        "primary_exit_code": build.exit_code,
        "build_timed_out": build.timed_out,
        "uplc_extraction_exit_code": extraction.exit_code if extraction else None,
        "uplc_extraction_timed_out": extraction.timed_out if extraction else False,
        "runs": [build_record] + ([extraction_record] if extraction_record else []),
        "negative_runs": [],
        "artifacts": sorted(artifacts, key=lambda row: row["path"]),
    }
    write_json(bundle_root / f"build-{compiler.label}.json", record)
    return record


def _covered_features_by_title(manifest: dict[str, Any] | None) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    if manifest is None:
        return result
    for key in ("features", "builtins"):
        for row in manifest.get(key, []):
            title = row.get("validator_title") or row.get("uplc_path")
            feature_id = row.get("feature_id")
            if isinstance(title, str) and isinstance(feature_id, str):
                result.setdefault(title, set()).add(feature_id)
    return result


def _build_failure_results(
    builds: dict[str, dict[str, Any]],
    source: dict[str, Any],
    compilers: dict[str, dict[str, Any]],
    config: BlasterConfig,
) -> list[dict[str, Any]]:
    results = []
    for label, status in (("old", "old_build_failed"), ("new", "new_build_failed")):
        if (
            builds[label]["primary_exit_code"] == 0
            and not builds[label]["build_timed_out"]
        ):
            continue
        results.append(
            {
                "pair_id": f"package-{label}-build",
                "source_identity": source,
                "validator_identity": None,
                "compiler_pair": compilers,
                "old_script": None,
                "new_script": None,
                "purpose": "package",
                "parameters": [],
                "covered_feature_ids": [],
                "input_model": None,
                "domain_assumptions": [],
                "semantic_contract": None,
                "excluded_observations": list(EXCLUDED_FROM_SEMANTIC_VERDICT),
                "blaster_dependencies": dict(config.revisions),
                "lean_version": config.lean_version,
                "z3_version": config.z3_version,
                "solver": config.solver,
                "fuel": config.fuel,
                "timeouts": asdict(config.timeouts),
                "status": status,
                "command": builds[label]["runs"][0]["command"],
                "exit_code": builds[label]["primary_exit_code"],
                "duration_seconds": builds[label]["runs"][0]["duration_seconds"],
                "generated_lean_path": None,
                "generated_lean_sha256": None,
                "stdout_path": builds[label]["runs"][0]["stdout_path"],
                "stderr_path": builds[label]["runs"][0]["stderr_path"],
                "solver_input_path": None,
                "solver_input_sha256": None,
                "witness": None,
                "phase_results": [],
                "counterexample_replay": None,
                "error": "Aiken build timed out"
                if builds[label]["build_timed_out"]
                else "Aiken build failed",
                "cost_and_trace": {
                    "included_in_semantic_verdict": False,
                    "cpu": None,
                    "memory": None,
                    "trace": None,
                },
                "semantic_result": False,
                "compatibility_result": False,
                "build_label": label,
            }
        )
    return results


def _pair_result(
    pair: ScriptPair,
    input_model: InputModel,
    status: str,
    backend_result: BlasterResult | None,
    *,
    source: dict[str, Any],
    compilers: dict[str, dict[str, Any]],
    config: BlasterConfig,
) -> dict[str, Any]:
    if status not in FINAL_STATUSES:
        raise ValueError(f"unknown pair result status: {status}")
    backend = backend_result.to_dict() if backend_result else {}
    return {
        "pair_id": pair.pair_id,
        "source_identity": source,
        "validator_identity": pair.validator_identity,
        "compiler_pair": compilers,
        "old_script": pair.old_script.to_dict(),
        "new_script": pair.new_script.to_dict(),
        "purpose": pair.purpose,
        "parameters": list(pair.parameters),
        "covered_feature_ids": list(pair.covered_feature_ids),
        "input_model": input_model.to_dict(),
        "domain_assumptions": list(input_model.domain_assumptions),
        "semantic_contract": EQUIVALENCE_FORMULA,
        "excluded_observations": list(EXCLUDED_FROM_SEMANTIC_VERDICT),
        "blaster_dependencies": dict(config.revisions),
        "lean_version": config.lean_version,
        "z3_version": config.z3_version,
        "solver": config.solver,
        "fuel": config.fuel,
        "timeouts": asdict(config.timeouts),
        "status": status,
        "command": backend.get("command"),
        "exit_code": backend.get("exit_code"),
        "duration_seconds": backend.get("duration_seconds", 0.0),
        "generated_lean_path": backend.get("generated_lean_path"),
        "generated_lean_sha256": backend.get("generated_lean_sha256"),
        "stdout_path": backend.get("stdout_path"),
        "stderr_path": backend.get("stderr_path"),
        "solver_input_path": backend.get("solver_input_path"),
        "solver_input_sha256": backend.get("solver_input_sha256"),
        "witness": backend.get("witness"),
        "phase_results": backend.get("phase_results", []),
        "counterexample_replay": None,
        "error": backend.get("error"),
        "cost_and_trace": {
            "included_in_semantic_verdict": False,
            "cpu": None,
            "memory": None,
            "trace": None,
        },
    }


def _compatibility_result(
    row: dict[str, Any],
    source: dict[str, Any],
    compilers: dict[str, dict[str, Any]],
    config: BlasterConfig,
) -> dict[str, Any]:
    return {
        "pair_id": row["pair_id"],
        "source_identity": source,
        "validator_identity": row["validator_identity"],
        "compiler_pair": compilers,
        "old_script": None,
        "new_script": None,
        "purpose": row["validator_identity"]["purpose"],
        "parameters": row["validator_identity"]["parameter_schemas"],
        "covered_feature_ids": [],
        "input_model": None,
        "domain_assumptions": [],
        "semantic_contract": None,
        "excluded_observations": list(EXCLUDED_FROM_SEMANTIC_VERDICT),
        "blaster_dependencies": dict(config.revisions),
        "lean_version": config.lean_version,
        "z3_version": config.z3_version,
        "solver": config.solver,
        "fuel": config.fuel,
        "timeouts": asdict(config.timeouts),
        "status": row["status"],
        "command": None,
        "exit_code": None,
        "duration_seconds": 0.0,
        "generated_lean_path": None,
        "generated_lean_sha256": None,
        "stdout_path": None,
        "stderr_path": None,
        "solver_input_path": None,
        "solver_input_sha256": None,
        "witness": None,
        "phase_results": [],
        "counterexample_replay": None,
        "error": None,
        "old_signature": row.get("old_signature"),
        "new_signature": row.get("new_signature"),
        "cost_and_trace": {
            "included_in_semantic_verdict": False,
            "cpu": None,
            "memory": None,
            "trace": None,
        },
    }


def _run_sentinel_evidence(
    bundle_root: Path,
    compilers: tuple[Compiler, Compiler],
    builds: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    contract = load_json(CONTRACT_PATH)
    scanner_config = load_json(SCANNER_CONFIG_PATH)
    new_source = bundle_root / "new" / "package"
    census_records, census_metadata = census(new_source)
    for compiler in compilers:
        write_json(bundle_root / compiler.label / "census.json", census_records)
        negative_runs, negative_artifacts = _capture_negative_cases(
            compiler,
            bundle_root / compiler.label / "package",
            bundle_root / compiler.label,
        )
        builds[compiler.label]["negative_runs"] = negative_runs
        builds[compiler.label]["artifacts"].extend(negative_artifacts)
        builds[compiler.label]["artifacts"] = sorted(
            builds[compiler.label]["artifacts"], key=lambda row: row["path"]
        )
        write_json(bundle_root / f"build-{compiler.label}.json", builds[compiler.label])
    reachability = {
        compiler.label: prove_reachability(
            compiler,
            bundle_root / compiler.label / "package",
            bundle_root / compiler.label,
            builds[compiler.label],
        )
        for compiler in compilers
    }
    lanes = {
        compiler.label: run_lanes(
            compiler,
            bundle_root / compiler.label / "package",
            bundle_root / compiler.label,
            census_records,
            contract,
            scanner_config,
        )
        for compiler in compilers
    }
    for label, value in lanes.items():
        write_json(bundle_root / label / "lanes.json", value)
    return {
        "census": census_records,
        "census_metadata": census_metadata,
        "reachability": reachability,
        "lanes": lanes,
        "contract": contract,
    }


def _feature_coverage(
    manifest: dict[str, Any] | None,
    sentinel_evidence: dict[str, Any] | None,
    pair_results: list[dict[str, Any]],
    builds: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if manifest is None:
        return {
            "schema_version": CHECKER_SCHEMA_VERSION,
            "mode": "package",
            "record_count": 0,
            "records": [],
        }
    assert sentinel_evidence is not None
    contract = sentinel_evidence["contract"]
    contract_rows = {
        row["id"]: {"row_kind": kind, **row}
        for kind, values in (
            ("feature", contract["features"]),
            ("builtin", contract["active_uplc_builtins"]),
        )
        for row in values
        if kind == "builtin"
        or row.get("sentinel_required", False)
        or row.get("negative_compile_case", False)
    }
    manifest_rows = {
        row["feature_id"]: {"row_kind": kind, **row}
        for kind, values in (
            ("feature", manifest.get("features", [])),
            ("builtin", manifest.get("builtins", [])),
        )
        for row in values
    }
    source_ids = {row["feature_id"] for row in sentinel_evidence["census"]}
    reachability = {
        label: {row["feature_id"]: row for row in rows}
        for label, rows in sentinel_evidence["reachability"].items()
    }
    pair_by_feature = {
        feature_id: result
        for result in pair_results
        for feature_id in result.get("covered_feature_ids", [])
    }
    negative = {
        label: {row["feature_id"]: row for row in builds[label]["negative_runs"]}
        for label in ("old", "new")
    }
    lane_runs = sentinel_evidence["lanes"]

    def lane_results(label: str, lanes: list[str]) -> dict[str, bool]:
        results: dict[str, bool] = {}
        for lane in lanes:
            if lane in {"compile", "blaster"}:
                continue
            record = lane_runs[label].get(lane)
            results[lane] = bool(
                record and record.get("required") and record.get("exit_code") == 0
            )
        return results

    records: list[dict[str, Any]] = []
    for feature_id, contract_row in sorted(contract_rows.items()):
        kind = contract_row["row_kind"]
        manifest_row = manifest_rows.get(feature_id)
        manifest_present = manifest_row is not None
        lanes = contract_row.get("lanes", [])
        source_present = feature_id in source_ids
        old_build = builds["old"]["primary_exit_code"] == 0
        new_build = builds["new"]["primary_exit_code"] == 0
        reachability_required = bool(
            manifest_row.get("reachability_required", "blaster" in lanes)
            if manifest_row
            else "blaster" in lanes
        )
        old_reach = reachability["old"].get(feature_id)
        new_reach = reachability["new"].get(feature_id)
        reachability_pass = not reachability_required or bool(
            old_reach and old_reach["pass"] and new_reach and new_reach["pass"]
        )
        old_lane_results = lane_results("old", lanes)
        new_lane_results = lane_results("new", lanes)
        non_blaster_lanes_pass = all(
            [*old_lane_results.values(), *new_lane_results.values()]
        )
        pair_result = pair_by_feature.get(feature_id)
        if not old_build:
            status = "old_build_failed"
        elif not new_build:
            status = "new_build_failed"
        elif not manifest_present:
            status = "feature_not_shared"
        elif contract_row.get("negative_compile_case"):
            old_negative = negative["old"].get(feature_id)
            new_negative = negative["new"].get(feature_id)
            status = (
                "expected_negative_diagnostic"
                if old_negative
                and old_negative["pass"]
                and new_negative
                and new_negative["pass"]
                else "feature_not_shared"
            )
        elif "blaster" in lanes:
            if not source_present or not reachability_pass or pair_result is None:
                status = "feature_not_shared"
            else:
                status = pair_result["status"]
        else:
            status = (
                "not_applicable"
                if source_present and non_blaster_lanes_pass
                else "feature_not_shared"
            )
        records.append(
            {
                "feature_id": feature_id,
                "row_kind": kind,
                "lanes": lanes,
                "manifest_present": manifest_present,
                "source_present": source_present,
                "old_build_accepted": old_build,
                "new_build_accepted": new_build,
                "lane_results_old": old_lane_results,
                "lane_results_new": new_lane_results,
                "uplc_generated_old": bool(old_reach)
                if reachability_required
                else None,
                "uplc_generated_new": bool(new_reach)
                if reachability_required
                else None,
                "reachability_required": reachability_required,
                "reachability_pass": reachability_pass,
                "pair_id": pair_result["pair_id"] if pair_result else None,
                "pair_status": pair_result["status"] if pair_result else None,
                "status": status,
            }
        )
    for feature_id, manifest_row in sorted(manifest_rows.items()):
        if feature_id in contract_rows:
            continue
        source_present = feature_id in source_ids
        records.append(
            {
                "feature_id": feature_id,
                "row_kind": manifest_row["row_kind"],
                "lanes": [],
                "manifest_present": True,
                "source_present": source_present,
                "old_build_accepted": builds["old"]["primary_exit_code"] == 0,
                "new_build_accepted": builds["new"]["primary_exit_code"] == 0,
                "lane_results_old": {},
                "lane_results_new": {},
                "uplc_generated_old": None,
                "uplc_generated_new": None,
                "reachability_required": False,
                "reachability_pass": False,
                "pair_id": None,
                "pair_status": None,
                "status": "feature_not_shared",
            }
        )
    records.sort(key=lambda row: (row["row_kind"], row["feature_id"]))
    return {
        "schema_version": CHECKER_SCHEMA_VERSION,
        "mode": "sentinel",
        "record_count": len(records),
        "records": records,
    }


def _validate_bundle(bundle_root: Path) -> list[str]:
    schemas = {
        "run.json": "run.schema.json",
        "build-old.json": "build-v2.schema.json",
        "build-new.json": "build-v2.schema.json",
        "script-pairs.json": "script-pairs.schema.json",
        "pair-results.json": "pair-results.schema.json",
        "feature-coverage.json": "feature-coverage.schema.json",
        "summary.json": "summary-v2.schema.json",
    }
    errors: list[str] = []
    for filename, schema_name in schemas.items():
        instance_path = bundle_root / filename
        schema_path = TOOL_ROOT / "schemas" / schema_name
        if not schema_path.is_file():
            errors.append(f"schema missing: {schema_path}")
            continue
        validator = Draft202012Validator(load_json(schema_path))
        try:
            instance = load_json(instance_path)
        except (FileNotFoundError, json.JSONDecodeError) as error:
            errors.append(f"{instance_path}: {error}")
            continue
        for error in sorted(
            validator.iter_errors(instance), key=lambda item: list(item.path)
        ):
            location = "/".join(str(part) for part in error.path)
            errors.append(f"{filename}:{location}: {error.message}")
    return errors


def _summary_markdown(summary: dict[str, Any]) -> str:
    counts = summary["counts"]
    labels = (
        ("Validators discovered", counts["validators_discovered"]),
        ("Validators paired", counts["validators_paired"]),
        ("Identical pairs", counts["identical_pairs"]),
        ("Blaster-valid pairs", counts["blaster_valid_pairs"]),
        ("Confirmed differences", counts["confirmed_differences"]),
        ("Unreplayed falsifications", counts["unreplayed_falsifications"]),
        ("Inconclusive pairs", counts["inconclusive_pairs"]),
        ("Unsupported pairs", counts["unsupported_pairs"]),
        ("Build failures", counts["build_failures"]),
        ("Compatibility differences", counts["compatibility_differences"]),
        ("Shared features covered", counts["shared_features_covered"]),
        ("Shared features missing", counts["shared_features_missing"]),
    )
    lines = [
        "# Equivalence checker result",
        "",
        f"Strict verdict: **{'PASS' if summary['strict_pass'] else 'FAIL'}**",
        "",
        "| Count | Value |",
        "|---|---:|",
        *(f"| {label} | {value} |" for label, value in labels),
        "",
    ]
    if summary["gaps"]:
        lines.extend(["## Gaps", "", *(f"- {gap}" for gap in summary["gaps"]), ""])
    return "\n".join(lines)


def compare_package(
    package: Path,
    compilers: tuple[Compiler, Compiler],
    *,
    work_root: Path = DEFAULT_WORK_ROOT,
    strict: bool = False,
    blaster_config: BlasterConfig | None = None,
    backend: BlasterBackend | None = None,
    sentinel: bool = False,
) -> dict[str, Any]:
    package = package.expanduser().resolve()
    if not (package / "aiken.toml").is_file():
        raise FileNotFoundError(
            f"Aiken package manifest is missing: {package / 'aiken.toml'}"
        )
    config = blaster_config or load_blaster_config()
    source_metadata = source_repository_metadata(package)
    source_hash = hash_package_tree(package, include_lock=False)
    source_state_before = hash_package_tree(package, include_lock=True)
    lock_path = package / "aiken.lock"
    lock_hash = sha256_file(lock_path) if lock_path.is_file() else None
    manifest_path = package / "coverage" / "feature-manifest.json"
    manifest = (
        load_json(manifest_path) if sentinel and manifest_path.is_file() else None
    )
    if sentinel and manifest is None:
        raise FileNotFoundError(
            f"sentinel feature manifest is missing: {manifest_path}"
        )
    checker_identity = {
        "schema_version": CHECKER_SCHEMA_VERSION,
        "mode": "sentinel" if sentinel else "package",
        "strict": strict,
        "semantic_contract": EQUIVALENCE_FORMULA,
    }
    run_payload = {
        "source_identity": source_metadata["identity"],
        "package_path": str(package),
        "source_hash": source_hash,
        "dependency_lock_hash": lock_hash,
        "old_compiler_hash": compilers[0].binary_sha256,
        "new_compiler_hash": compilers[1].binary_sha256,
        "checker_configuration": checker_identity,
        "blaster_configuration": config.identity(),
    }
    run_id = stable_hash(run_payload)
    bundle_root = work_root.expanduser().resolve() / "runs" / run_id
    if bundle_root.exists():
        shutil.rmtree(bundle_root)
    for directory in ("logs", "generated-lean", "counterexamples"):
        (bundle_root / directory).mkdir(parents=True, exist_ok=True)
    run_record = {
        "schema_version": CHECKER_SCHEMA_VERSION,
        "run_id": run_id,
        "mode": "sentinel" if sentinel else "package",
        "package": package_name(package),
        "package_path": str(package),
        "source": source_metadata,
        "source_hash": source_hash,
        "dependency_lock_hash": lock_hash,
        "compiler_pair": {
            compiler.label: compiler.identity() for compiler in compilers
        },
        "checker_configuration": checker_identity,
        "blaster_configuration": config.identity(),
        "reproducibility_gaps": [],
        "source_immutable": None,
        "strict_requested": strict,
        "strict_pass": None,
    }
    write_json(bundle_root / "run.json", run_record)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            compiler.label: executor.submit(
                _build_one, compiler, package, bundle_root, config
            )
            for compiler in compilers
        }
        builds = {label: future.result() for label, future in futures.items()}

    gaps: list[str] = []
    if lock_hash is None:
        gaps.append("missing_dependency_lock")
    if not all(build["source_unchanged"] for build in builds.values()):
        gaps.append("isolated_source_copy_changed")
    if not all(build["dependency_lock_unchanged"] for build in builds.values()):
        gaps.append("compiler_changed_dependency_lock")
    resolved_locks = {
        builds[label]["dependency_lock_hash_after"] for label in ("old", "new")
    }
    if len(resolved_locks) != 1:
        gaps.append("compiler_dependency_locks_differ")

    sentinel_evidence: dict[str, Any] | None = None
    if sentinel and all(
        builds[label]["primary_exit_code"] == 0 for label in ("old", "new")
    ):
        try:
            sentinel_evidence = _run_sentinel_evidence(bundle_root, compilers, builds)
        except (OSError, RuntimeError, ValueError) as error:
            gaps.append(f"sentinel_evidence_error:{error}")

    pairing: PairingResult | None = None
    pair_results: list[dict[str, Any]] = []
    compiler_identities = {
        compiler.label: compiler.identity() for compiler in compilers
    }
    pair_results.extend(
        _build_failure_results(builds, source_metadata, compiler_identities, config)
    )
    if not pair_results:
        coverage_map = _covered_features_by_title(manifest)
        pairing = pair_validators(
            bundle_root / "old" / "raw" / "silent" / "plutus.json",
            bundle_root / "new" / "raw" / "silent" / "plutus.json",
            bundle_root,
            package_identity=source_metadata["identity"],
            package_path=str(package),
            plutus_version=_plutus_version(package),
            covered_features_by_title=coverage_map,
        )
        actual_backend = backend or RealBlasterBackend(config)
        for pair in pairing.pairs:
            input_model = validator_input_model(pair)
            if pair.old_script.sha256 == pair.new_script.sha256:
                pair_results.append(
                    _pair_result(
                        pair,
                        input_model,
                        "identical",
                        None,
                        source=source_metadata,
                        compilers=compiler_identities,
                        config=config,
                    )
                )
                continue
            blaster_result = actual_backend.compare(pair, input_model, bundle_root)
            result = _pair_result(
                pair,
                input_model,
                blaster_result.status,
                blaster_result,
                source=source_metadata,
                compilers=compiler_identities,
                config=config,
            )
            if (
                blaster_result.status == "blaster_falsified_unreplayed"
                and blaster_result.witness
            ):
                replay = actual_backend.replay(
                    pair, input_model, blaster_result.witness, bundle_root
                )
                result["counterexample_replay"] = replay
                if replay.get("confirmed"):
                    result["status"] = "confirmed_non_equivalent"
            pair_results.append(result)
        pair_results.extend(
            _compatibility_result(
                row,
                source_metadata,
                compiler_identities,
                config,
            )
            for row in pairing.compatibility_results
        )
    script_pairs = {
        "schema_version": CHECKER_SCHEMA_VERSION,
        "record_count": len(pairing.pairs) if pairing else 0,
        "records": [pair.to_dict() for pair in pairing.pairs] if pairing else [],
    }
    write_json(bundle_root / "script-pairs.json", script_pairs)
    pair_results.sort(key=lambda row: row["pair_id"])
    write_json(
        bundle_root / "pair-results.json",
        {
            "schema_version": CHECKER_SCHEMA_VERSION,
            "record_count": len(pair_results),
            "records": pair_results,
        },
    )
    feature_coverage = (
        _feature_coverage(
            manifest,
            sentinel_evidence,
            pair_results,
            builds,
        )
        if not sentinel or sentinel_evidence is not None
        else {
            "schema_version": CHECKER_SCHEMA_VERSION,
            "mode": "sentinel",
            "record_count": 0,
            "records": [],
        }
    )
    write_json(bundle_root / "feature-coverage.json", feature_coverage)

    source_state_after = hash_package_tree(package, include_lock=True)
    source_immutable = source_state_before == source_state_after
    if not source_immutable:
        gaps.append("original_source_or_lock_changed")
    if pairing and pairing.old_count == 0 and pairing.new_count == 0:
        gaps.append("no_validators_discovered")
    applicable_statuses = [row["status"] for row in pair_results]
    feature_statuses = [row["status"] for row in feature_coverage["records"]]
    statuses = applicable_statuses + feature_statuses
    strict_pass = (
        not gaps
        and bool(statuses)
        and all(status in STRICT_PASSING_STATUSES for status in statuses)
    )
    counts = {
        "validators_discovered": (
            (pairing.old_count + pairing.new_count) if pairing else 0
        ),
        "validators_discovered_old": pairing.old_count if pairing else 0,
        "validators_discovered_new": pairing.new_count if pairing else 0,
        "validators_paired": len(pairing.pairs) if pairing else 0,
        "identical_pairs": sum(row["status"] == "identical" for row in pair_results),
        "blaster_valid_pairs": sum(
            row["status"] == "blaster_valid" for row in pair_results
        ),
        "confirmed_differences": sum(
            row["status"] == "confirmed_non_equivalent" for row in pair_results
        ),
        "unreplayed_falsifications": sum(
            row["status"] == "blaster_falsified_unreplayed" for row in pair_results
        ),
        "inconclusive_pairs": sum(
            row["status"] == "blaster_inconclusive" for row in pair_results
        ),
        "unsupported_pairs": sum(
            row["status"] == "blaster_unsupported" for row in pair_results
        ),
        "build_failures": sum(
            row["status"] in {"old_build_failed", "new_build_failed"}
            for row in pair_results
        ),
        "compatibility_differences": sum(
            row["status"]
            in {
                "validator_missing_old",
                "validator_missing_new",
                "validator_signature_changed",
                "feature_not_shared",
            }
            for row in pair_results
        ),
        "shared_features_covered": sum(
            row["status"] in STRICT_PASSING_STATUSES
            for row in feature_coverage["records"]
        ),
        "shared_features_missing": sum(
            row["status"] not in STRICT_PASSING_STATUSES
            for row in feature_coverage["records"]
        ),
    }
    summary = {
        "schema_version": CHECKER_SCHEMA_VERSION,
        "run_id": run_id,
        "package": package_name(package),
        "mode": "sentinel" if sentinel else "package",
        "strict_requested": strict,
        "strict_pass": strict_pass,
        "best_effort_completed": True,
        "counts": counts,
        "status_counts": {
            status: applicable_statuses.count(status)
            for status in sorted(set(applicable_statuses))
        },
        "gaps": sorted(set(gaps)),
        "output": str(bundle_root),
        "source_immutable": source_immutable,
        "dependency_lock_shared": len(resolved_locks) == 1
        and None not in resolved_locks,
        "schema_errors": [],
    }
    write_json(bundle_root / "summary.json", summary)
    (bundle_root / "summary.md").write_text(
        _summary_markdown(summary), encoding="utf-8"
    )
    run_record["reproducibility_gaps"] = summary["gaps"]
    run_record["source_immutable"] = source_immutable
    run_record["strict_pass"] = strict_pass
    write_json(bundle_root / "run.json", run_record)

    schema_errors = _validate_bundle(bundle_root)
    if schema_errors:
        summary["schema_errors"] = schema_errors
        summary["strict_pass"] = False
        if "schema_validation_failed" not in summary["gaps"]:
            summary["gaps"].append("schema_validation_failed")
        run_record["strict_pass"] = False
        run_record["reproducibility_gaps"] = summary["gaps"]
        write_json(bundle_root / "summary.json", summary)
        write_json(bundle_root / "run.json", run_record)
        (bundle_root / "summary.md").write_text(
            _summary_markdown(summary), encoding="utf-8"
        )
    return summary


def compare_sentinel(
    package: Path,
    compilers: tuple[Compiler, Compiler],
    *,
    work_root: Path = DEFAULT_WORK_ROOT,
    strict: bool = False,
    blaster_config: BlasterConfig | None = None,
    backend: BlasterBackend | None = None,
) -> dict[str, Any]:
    return compare_package(
        package,
        compilers,
        work_root=work_root,
        strict=strict,
        blaster_config=blaster_config,
        backend=backend,
        sentinel=True,
    )
