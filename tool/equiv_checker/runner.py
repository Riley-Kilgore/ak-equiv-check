from __future__ import annotations

import hashlib
import json
import re
import shutil
import tomllib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .blaster import RealBlasterBackend
from .blueprints import inspect_blueprint
from .census import census, ensure_shim, inspect_uplc
from .config import (
    CONTRACT_PATH,
    DEFAULT_WORK_ROOT,
    SCANNER_CONFIG_PATH,
    TOOL_ROOT,
    Compiler,
    load_blaster_config,
    load_json,
    package_name,
    platform_key,
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
from .semantics import (
    EQUIVALENCE_FORMULA,
    EXCLUDED_FROM_SEMANTIC_VERDICT,
    validator_input_models,
)
from .process import ProcessResult, run_process, write_process_logs


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
    return (
        name in {"codegen-triggers.json", "regression.json"}
        or name == "plutus.json"
        or (name.startswith("plutus-") and name.endswith(".json"))
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


def _compiler_evidence_identity(compiler: Compiler) -> dict[str, Any]:
    provenance = compiler.provenance
    return {
        "release": compiler.release,
        "reported_version": compiler.reported_version,
        "git_revision": compiler.git_revision,
        "binary_sha256": compiler.binary_sha256,
        "artifact_id": provenance.get("artifact_id"),
        "artifact_kind": provenance.get("artifact_kind"),
        "source_tree_sha256": provenance.get("source_tree_sha256"),
        "cargo_lock_sha256": provenance.get("cargo_lock_sha256"),
        "dirty": provenance.get("dirty"),
        "reproducible_from_commit": provenance.get("reproducible_from_commit"),
    }


def checker_implementation_sha256() -> str:
    digest = hashlib.sha256()
    package_root = Path(__file__).resolve().parent
    filenames = (
        "blaster.py",
        "census.py",
        "config.py",
        "corpus.py",
        "models.py",
        "pairing.py",
        "pipeline.py",
        "process.py",
        "runner.py",
        "semantics.py",
    )
    for filename in filenames:
        path = package_root / filename
        digest.update(filename.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    schema_root = package_root.parent / "schemas"
    for path in sorted(schema_root.glob("*.json")):
        relative = f"schemas/{path.name}"
        digest.update(relative.encode("utf-8"))
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


def source_repository_metadata(
    package: Path,
    *,
    source_hash: str | None = None,
    dependency_lock_hash: str | None = None,
    adapter_hash: str | None = None,
) -> dict[str, Any]:
    source_hash = source_hash or hash_package_tree(package, include_lock=False)
    lock_path = package / "aiken.lock"
    dependency_lock_hash = (
        dependency_lock_hash
        if dependency_lock_hash is not None
        else sha256_file(lock_path)
        if lock_path.is_file()
        else None
    )
    root_result = _git(package, "rev-parse", "--show-toplevel")
    if root_result.exit_code != 0:
        logical_identity_fields = {
            "canonical_repository_url": "local-content",
            "package_subpath": ".",
            "source_hash": source_hash,
            "dependency_lock_hash": dependency_lock_hash,
            "adapter_hash": adapter_hash,
        }
        identity_fields = {"revision": None, **logical_identity_fields}
        return {
            "kind": "local_directory",
            "repository_root": None,
            "commit": None,
            "dirty": None,
            "remote": None,
            "package_path": ".",
            "identity_fields": identity_fields,
            "identity": stable_hash(identity_fields),
            "logical_identity_fields": logical_identity_fields,
            "logical_identity": stable_hash(logical_identity_fields),
        }
    repository_root = Path(root_result.stdout.strip()).resolve()
    commit_result = _git(package, "rev-parse", "HEAD")
    status_result = _git(package, "status", "--porcelain", "--untracked-files=normal")
    remote_result = _git(package, "config", "--get", "remote.origin.url")
    relative = package.resolve().relative_to(repository_root).as_posix() or "."
    commit = commit_result.stdout.strip() if commit_result.exit_code == 0 else None
    remote = remote_result.stdout.strip() if remote_result.exit_code == 0 else None
    canonical_remote = remote or "local-git"
    match = re.fullmatch(r"git@github\.com:(.+?)(?:\.git)?", canonical_remote)
    if match:
        canonical_remote = f"https://github.com/{match.group(1)}"
    canonical_remote = canonical_remote.removesuffix(".git").rstrip("/")
    logical_identity_fields = {
        "canonical_repository_url": canonical_remote,
        "package_subpath": relative,
        "source_hash": source_hash,
        "dependency_lock_hash": dependency_lock_hash,
        "adapter_hash": adapter_hash,
    }
    identity_fields = {"revision": commit, **logical_identity_fields}
    return {
        "kind": "git",
        "repository_root": str(repository_root),
        "commit": commit,
        "dirty": bool(status_result.stdout.strip())
        if status_result.exit_code == 0
        else None,
        "remote": remote,
        "package_path": relative,
        "identity_fields": identity_fields,
        "identity": stable_hash(identity_fields),
        "logical_identity_fields": logical_identity_fields,
        "logical_identity": stable_hash(logical_identity_fields),
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
        "environment_inherited": False,
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
    build = run_process(
        build_command,
        source,
        config.timeouts.aiken_build,
        inherit_environment=False,
    )
    build_record = _process_record(
        build,
        bundle_root,
        logs / f"build-{compiler.label}.stdout.log",
        logs / f"build-{compiler.label}.stderr.log",
        config.timeouts.aiken_build,
    )
    extraction: ProcessResult | None = None
    extraction_record: dict[str, Any] | None = None
    extraction_records: list[dict[str, Any]] = []
    if not build.timed_out and build.exit_code == 0:
        extraction_command = [
            str(compiler.executable),
            "build",
            "--out",
            "plutus.json",
            "--uplc",
        ]
        extraction = run_process(
            extraction_command,
            source,
            config.timeouts.uplc_extraction,
            inherit_environment=False,
        )
        extraction_record = _process_record(
            extraction,
            bundle_root,
            logs / f"uplc-extraction-{compiler.label}.stdout.log",
            logs / f"uplc-extraction-{compiler.label}.stderr.log",
            config.timeouts.uplc_extraction,
        )
        extraction_records.append(extraction_record)

    artifacts: list[dict[str, Any]] = []
    raw_root = compiler_root / "raw" / "silent"
    blueprint_source = source / "plutus.json"
    if blueprint_source.is_file():
        blueprint = raw_root / "plutus.json"
        blueprint.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(blueprint_source, blueprint)
        artifacts.append(_artifact(blueprint, compiler_root, "plutus_blueprint"))
    blueprint_present = blueprint_source.is_file()
    blueprint_compatibility = (
        inspect_blueprint(blueprint_source)
        if blueprint_present
        else {
            "status": "blueprint_missing_required_field",
            "detail": "blueprint file is missing",
            "schema_family": None,
            "parser_version": "aiken-blueprint-parser/v1",
        }
    )
    blueprint_malformed = (
        blueprint_compatibility["status"] != "blueprint_schema_supported"
    )
    blueprint_value: dict[str, Any] | None = None
    if blueprint_present and not blueprint_malformed:
        blueprint_value = json.loads(blueprint_source.read_text(encoding="utf-8"))
    abi_inspection: dict[str, Any] | None = None
    abi_inspection_error: str | None = None
    if blueprint_value is not None:
        try:
            abi_inspection = inspect_uplc(blueprint_source)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
            abi_inspection_error = str(error)
    extraction_exit_code = extraction.exit_code if extraction else None
    extraction_timed_out = extraction.timed_out if extraction else False
    if (
        extraction is not None
        and extraction.exit_code != 0
        and not extraction.timed_out
        and not blueprint_malformed
        and blueprint_value is not None
    ):
        validators = blueprint_value["validators"]
        precise_success = bool(validators)
        extraction_inputs = compiler_root / "extraction-inputs"
        extraction_inputs.mkdir(parents=True, exist_ok=True)
        for index, validator in enumerate(validators):
            title = validator.get("title")
            compiled_code = validator.get("compiledCode")
            if not isinstance(title, str) or not isinstance(compiled_code, str):
                precise_success = False
                continue
            title_hash = hashlib.sha256(title.encode("utf-8")).hexdigest()[:16]
            encoded = extraction_inputs / f"{index:03d}-{title_hash}.cborhex"
            encoded.write_text(compiled_code + "\n", encoding="ascii")
            precise = run_process(
                [
                    str(compiler.executable),
                    "uplc",
                    "decode",
                    "-c",
                    "--hex",
                    str(encoded),
                ],
                source,
                config.timeouts.uplc_extraction,
            )
            precise_record = _process_record(
                precise,
                bundle_root,
                logs / f"uplc-extraction-{compiler.label}-{index:03d}.stdout.log",
                logs / f"uplc-extraction-{compiler.label}-{index:03d}.stderr.log",
                config.timeouts.uplc_extraction,
            )
            extraction_records.append(precise_record)
            if precise.timed_out or precise.exit_code != 0:
                precise_success = False
                extraction_timed_out = extraction_timed_out or precise.timed_out
                continue
            destination = raw_root / "uplc" / f"{index:03d}-{title_hash}.uplc"
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(precise.stdout, encoding="utf-8")
            artifacts.append(_artifact(destination, compiler_root, "textual_uplc"))
        extraction_exit_code = 0 if precise_success else 1
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
        "uplc_extraction_exit_code": extraction_exit_code,
        "uplc_extraction_timed_out": extraction_timed_out,
        "blueprint_present": blueprint_present,
        "blueprint_malformed": blueprint_malformed,
        "blueprint_compatibility": blueprint_compatibility,
        "abi_inspection": abi_inspection,
        "abi_inspection_error": abi_inspection_error,
        "runs": [build_record, *extraction_records],
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
    for label in ("old", "new"):
        build = builds[label]
        stage = "build"
        if build["build_timed_out"] or build["primary_exit_code"] != 0:
            status = f"{label}_build_failed"
            detail = "Aiken build timed out" if build["build_timed_out"] else "Aiken build failed"
            run = build["runs"][0]
        elif (
            build["uplc_extraction_timed_out"]
            or build["uplc_extraction_exit_code"] != 0
        ):
            status = f"{label}_uplc_extraction_failed"
            detail = (
                "UPLC extraction timed out"
                if build["uplc_extraction_timed_out"]
                else "UPLC extraction failed"
            )
            stage = "uplc-extraction"
            run = build["runs"][-1]
        elif not build["blueprint_present"]:
            status = f"{label}_blueprint_missing"
            detail = "successful build and UPLC extraction produced no plutus.json"
            stage = "blueprint"
            run = build["runs"][-1]
        elif build["blueprint_malformed"]:
            status = build["blueprint_compatibility"]["status"]
            detail = build["blueprint_compatibility"].get(
                "detail", "plutus.json uses an unsupported blueprint schema"
            )
            stage = "blueprint"
            run = build["runs"][-1]
        elif build["abi_inspection"] is None:
            status = "compiled_abi_unverified"
            detail = build["abi_inspection_error"] or "compiled UPLC ABI inspection is missing"
            stage = "abi"
            run = build["runs"][-1]
        else:
            continue
        results.append(
            {
                "pair_id": f"package-{label}-{stage}",
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
                "runtime_step_bound": config.runtime_step_bound,
                "fuel_semantics": "maximum CEK transitions per modeled input",
                "timeouts": asdict(config.timeouts),
                "status": status,
                "command": run["command"],
                "exit_code": run["exit_code"],
                "duration_seconds": run["duration_seconds"],
                "generated_lean_path": None,
                "generated_lean_sha256": None,
                "stdout_path": run["stdout_path"],
                "stderr_path": run["stderr_path"],
                "solver_input_path": None,
                "solver_input_sha256": None,
                "witness": None,
                "phase_results": [],
                "counterexample_replay": None,
                "error": detail,
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
    attempt_sequence: int = 1,
) -> dict[str, Any]:
    if status not in FINAL_STATUSES:
        raise ValueError(f"unknown pair result status: {status}")
    backend = backend_result.to_dict() if backend_result else {}
    evidence_fields = {
        "script_pair_identity": pair.pair_id,
        "old_script_hash": pair.old_script.sha256,
        "new_script_hash": pair.new_script.sha256,
        "input_model_version": input_model.profile,
        "domain_hash": stable_hash(input_model.domain_expression),
        "observation_hash": stable_hash(input_model.observation),
        "blaster_revisions": dict(sorted(config.revisions.items())),
        "lean_version": config.lean_version,
        "z3_version": config.z3_version,
        "runtime_step_bound": config.runtime_step_bound,
    }
    evidence_id = stable_hash(evidence_fields)
    attempt_fields = {
        "evidence_id": evidence_id,
        "timeouts": asdict(config.timeouts),
        "runner_schema_version": CHECKER_SCHEMA_VERSION,
        "execution_environment": platform_key(),
        "attempt_sequence": attempt_sequence,
    }
    return {
        "pair_id": pair.pair_id,
        "evidence_id": evidence_id,
        "evidence_identity": evidence_fields,
        "attempt_id": stable_hash(attempt_fields),
        "attempt_sequence": attempt_sequence,
        "execution_environment": platform_key(),
        "source_identity": source,
        "validator_identity": pair.validator_identity,
        "compiler_pair": compilers,
        "old_script": pair.old_script.to_dict(),
        "new_script": pair.new_script.to_dict(),
        "purpose": pair.purpose,
        "parameters": list(pair.parameters),
        "covered_feature_ids": list(pair.covered_feature_ids),
        "abi": pair.abi,
        "input_model": input_model.to_dict(),
        "domain_assumptions": list(input_model.domain_assumptions),
        "semantic_contract": EQUIVALENCE_FORMULA,
        "excluded_observations": list(EXCLUDED_FROM_SEMANTIC_VERDICT),
        "blaster_dependencies": dict(config.revisions),
        "lean_version": config.lean_version,
        "z3_version": config.z3_version,
        "solver": config.solver,
        "runtime_step_bound": config.runtime_step_bound,
        "fuel_semantics": "maximum CEK transitions per modeled input; preparation timeouts are separate and inconclusive",
        "timeouts": asdict(config.timeouts),
        "evaluator": config.evaluator.identity() if config.evaluator else None,
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
        "proof_obligations": backend.get("proof_obligations", {}),
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
        "runtime_step_bound": config.runtime_step_bound,
        "fuel_semantics": "maximum CEK transitions per modeled input",
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
        "abi": {
            "verified": False,
            "equal": False,
            "old": row.get("old_abi"),
            "new": row.get("new_abi"),
        },
        "old_abi": row.get("old_abi"),
        "new_abi": row.get("new_abi"),
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
    feature_contract: Path,
) -> dict[str, Any]:
    contract = load_json(feature_contract)
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


def _load_valid_pair_results(bundle_root: Path) -> dict[str, dict[str, Any]]:
    schema = load_json(TOOL_ROOT / "schemas" / "pair-results.schema.json")
    validator = Draft202012Validator(schema)
    results: dict[str, dict[str, Any]] = {}
    pairs_root = bundle_root / "pairs"
    if not pairs_root.is_dir():
        return results
    for result_path in sorted(pairs_root.glob("*/result.json")):
        try:
            row = load_json(result_path)
        except (OSError, json.JSONDecodeError):
            continue
        wrapper = {
            "schema_version": CHECKER_SCHEMA_VERSION,
            "record_count": 1,
            "records": [row],
        }
        if any(validator.iter_errors(wrapper)):
            continue
        pair_id = row.get("pair_id")
        if isinstance(pair_id, str) and result_path.parent.name == pair_id:
            results[pair_id] = row
    return results


def _restore_reused_artifacts(
    row: dict[str, Any],
    previous_root: Path,
    bundle_root: Path,
) -> None:
    relative_paths: set[str] = set()

    def collect(value: Any, key: str | None = None) -> None:
        if isinstance(value, dict):
            for nested_key, nested in value.items():
                collect(nested, nested_key)
        elif isinstance(value, list):
            for nested in value:
                collect(nested, key)
        elif (
            isinstance(value, str)
            and key is not None
            and (key == "path" or key.endswith("_path"))
            and not Path(value).is_absolute()
        ):
            relative_paths.add(value)

    collect(row)
    for relative in sorted(relative_paths):
        source = previous_root / relative
        destination = bundle_root / relative
        if source.is_file() and not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)


def _replay_counterexample(
    backend: BlasterBackend,
    config: BlasterConfig,
    compilers: dict[str, dict[str, Any]],
    pair: ScriptPair,
    input_model: InputModel,
    witness: dict[str, Any],
    bundle_root: Path,
) -> dict[str, Any]:
    evaluator = config.evaluator
    if evaluator is not None and evaluator.binary_sha256 in {
        compiler.get("binary_sha256") for compiler in compilers.values()
    }:
        return {
            "confirmed": False,
            "reason": "independent replay evaluator must not be either compared compiler binary",
            "evaluator": evaluator.identity(),
        }
    return backend.replay(pair, input_model, witness, bundle_root)


def _cached_pair_matches(
    row: dict[str, Any] | None,
    pair: ScriptPair,
    input_model: InputModel,
    source: dict[str, Any],
    compilers: dict[str, dict[str, Any]],
    config: BlasterConfig,
) -> bool:
    if row is None:
        return False
    expected = _pair_result(
        pair,
        input_model,
        "identical",
        None,
        source=source,
        compilers=compilers,
        config=config,
    )
    return (
        row.get("pair_id") == pair.pair_id
        and row.get("evidence_id") == expected["evidence_id"]
        and row.get("evidence_identity") == expected["evidence_identity"]
        and row.get("status") in FINAL_STATUSES
    )


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
    pair_results_path = bundle_root / "pair-results.json"
    if pair_results_path.is_file():
        try:
            aggregate = load_json(pair_results_path)
            for row in aggregate.get("records", []):
                pair_id = row.get("pair_id")
                if not isinstance(pair_id, str):
                    continue
                individual_path = bundle_root / "pairs" / pair_id / "result.json"
                if not individual_path.is_file():
                    errors.append(f"missing individual pair result: {pair_id}")
                elif load_json(individual_path) != row:
                    errors.append(f"individual pair result mismatch: {pair_id}")
        except (json.JSONDecodeError, OSError, AttributeError) as error:
            errors.append(f"individual pair result validation failed: {error}")
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
    feature_contract: Path = CONTRACT_PATH,
    resume: bool = False,
    force: bool = False,
    only_pairs: set[str] | None = None,
    source_identity_override: dict[str, Any] | None = None,
    require_script_difference: bool = False,
) -> dict[str, Any]:
    package = package.expanduser().resolve()
    if not (package / "aiken.toml").is_file():
        raise FileNotFoundError(
            f"Aiken package manifest is missing: {package / 'aiken.toml'}"
        )
    config = blaster_config or load_blaster_config()
    feature_contract = feature_contract.expanduser().resolve()
    if sentinel and not feature_contract.is_file():
        raise FileNotFoundError(f"feature contract is missing: {feature_contract}")
    source_hash = hash_package_tree(package, include_lock=False)
    source_state_before = hash_package_tree(package, include_lock=True)
    lock_path = package / "aiken.lock"
    lock_hash = sha256_file(lock_path) if lock_path.is_file() else None
    source_metadata = source_identity_override or source_repository_metadata(
        package,
        source_hash=source_hash,
        dependency_lock_hash=lock_hash,
    )
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
        "require_script_difference": require_script_difference,
        "semantic_contract": EQUIVALENCE_FORMULA,
        "feature_contract_sha256": (
            sha256_file(feature_contract) if sentinel else None
        ),
        "runner_sha256": checker_implementation_sha256(),
    }
    run_payload = {
        "source_identity": source_metadata["identity"],
        "source_hash": source_hash,
        "dependency_lock_hash": lock_hash,
        "old_compiler": _compiler_evidence_identity(compilers[0]),
        "new_compiler": _compiler_evidence_identity(compilers[1]),
        "checker_configuration": checker_identity,
        "blaster_configuration": config.identity(),
    }
    run_id = stable_hash(run_payload)
    bundle_root = work_root.expanduser().resolve() / "runs" / run_id
    requested_pairs = frozenset(only_pairs or ())
    cached_pair_results: dict[str, dict[str, Any]] = {}
    previous_bundle_root: Path | None = None
    current_attempt_sequence = 1
    if bundle_root.exists():
        if resume or (force and requested_pairs):
            cached_pair_results = _load_valid_pair_results(bundle_root)
        if (
            resume
            and not force
            and not requested_pairs
            and (bundle_root / "summary.json").is_file()
        ):
            validation_errors = _validate_bundle(bundle_root)
            if not validation_errors:
                reused_summary = load_json(bundle_root / "summary.json")
                reused_summary["reused"] = True
                return reused_summary
        if not (resume or force):
            raise ValueError(
                f"comparison run already exists: {bundle_root}; use --resume or --force"
            )
        attempts_root = work_root.expanduser().resolve() / "attempts" / run_id
        attempts_root.mkdir(parents=True, exist_ok=True)
        attempt_sequence = 1
        while (attempts_root / f"{attempt_sequence:06d}").exists():
            attempt_sequence += 1
        previous_bundle_root = attempts_root / f"{attempt_sequence:06d}"
        shutil.move(bundle_root, previous_bundle_root)
        current_attempt_sequence = attempt_sequence + 1
    for directory in ("logs", "generated-lean", "counterexamples", "pairs"):
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
    ensure_shim()

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
            sentinel_evidence = _run_sentinel_evidence(
                bundle_root, compilers, builds, feature_contract
            )
        except (OSError, RuntimeError, ValueError) as error:
            gaps.append(f"sentinel_evidence_error:{error}")

    pairing: PairingResult | None = None
    pair_results: list[dict[str, Any]] = []
    compiler_identities = {
        compiler.label: compiler.identity() for compiler in compilers
    }
    reused_pair_ids: set[str] = set()
    pair_results.extend(
        _build_failure_results(builds, source_metadata, compiler_identities, config)
    )
    if not pair_results:
        coverage_map = _covered_features_by_title(manifest)
        pairing = pair_validators(
            bundle_root / "old" / "raw" / "silent" / "plutus.json",
            bundle_root / "new" / "raw" / "silent" / "plutus.json",
            bundle_root,
            package_identity=source_metadata.get(
                "logical_identity", source_metadata["identity"]
            ),
            package_path=str(package),
            plutus_version=_plutus_version(package),
            covered_features_by_title=coverage_map,
            old_abi_inspection=builds["old"]["abi_inspection"],
            new_abi_inspection=builds["new"]["abi_inspection"],
        )
        discovered_pair_ids = {pair.pair_id for pair in pairing.pairs}
        missing_requested_pairs = sorted(requested_pairs - discovered_pair_ids)
        if missing_requested_pairs:
            raise ValueError(
                "requested pair(s) are not present in the rebuilt package: "
                + ", ".join(missing_requested_pairs)
            )
        script_difference_observed = any(
            pair.old_script.sha256 != pair.new_script.sha256 for pair in pairing.pairs
        )
        actual_backend = backend or RealBlasterBackend(config)
        for pair in pairing.pairs:
            raw_model, ledger_model = validator_input_models(pair)
            cached = cached_pair_results.get(pair.pair_id)
            cached_matches = _cached_pair_matches(
                cached,
                pair,
                raw_model,
                source_metadata,
                compiler_identities,
                config,
            )
            unselected = bool(requested_pairs) and pair.pair_id not in requested_pairs
            if cached_matches and ((resume and not force) or unselected):
                if previous_bundle_root is not None:
                    _restore_reused_artifacts(
                        cached,
                        previous_bundle_root,
                        bundle_root,
                    )
                if (
                    resume
                    and cached.get("status") == "blaster_falsified_unreplayed"
                    and isinstance(cached.get("witness"), dict)
                ):
                    replay = _replay_counterexample(
                        actual_backend,
                        config,
                        compiler_identities,
                        pair,
                        raw_model,
                        cached["witness"],
                        bundle_root,
                    )
                    cached["counterexample_replay"] = replay
                    raw_record = cached.get("model_results", {}).get(raw_model.profile)
                    if isinstance(raw_record, dict):
                        raw_record["counterexample_replay"] = replay
                    if replay.get("confirmed"):
                        cached["status"] = "confirmed_non_equivalent"
                pair_results.append(cached)
                reused_pair_ids.add(pair.pair_id)
                continue
            if unselected:
                raise ValueError(
                    "no matching cached evidence exists for unselected pair "
                    f"{pair.pair_id}"
                )
            if pair.old_script.sha256 == pair.new_script.sha256:
                identical_status = (
                    "expected_codegen_delta_not_observed"
                    if require_script_difference and not script_difference_observed
                    else "identical"
                )
                result = _pair_result(
                    pair,
                    raw_model,
                    identical_status,
                    None,
                    source=source_metadata,
                    compilers=compiler_identities,
                    config=config,
                    attempt_sequence=current_attempt_sequence,
                )
                result["model_results"] = {
                    raw_model.profile: {
                        "status": identical_status,
                        "input_model": raw_model.to_dict(),
                    },
                    ledger_model.profile: {
                        "status": (
                            identical_status
                            if ledger_model.supported
                            else "ledger_model_unsupported"
                        ),
                        "input_model": ledger_model.to_dict(),
                    },
                }
                pair_results.append(result)
                continue

            raw_backend_result = actual_backend.compare(pair, raw_model, bundle_root)
            raw_status = (
                "equivalent_under_raw_model"
                if raw_backend_result.status == "blaster_valid"
                else raw_backend_result.status
            )
            result = _pair_result(
                pair,
                raw_model,
                raw_status,
                raw_backend_result,
                source=source_metadata,
                compilers=compiler_identities,
                config=config,
                attempt_sequence=current_attempt_sequence,
            )
            raw_replay = None
            if (
                raw_backend_result.status == "blaster_falsified_unreplayed"
                and raw_backend_result.witness
            ):
                raw_replay = _replay_counterexample(
                    actual_backend,
                    config,
                    compiler_identities,
                    pair,
                    raw_model,
                    raw_backend_result.witness,
                    bundle_root,
                )
                result["counterexample_replay"] = raw_replay
                if raw_replay.get("confirmed"):
                    result["status"] = "confirmed_non_equivalent"

            if ledger_model.supported:
                ledger_backend_result = actual_backend.compare(
                    pair, ledger_model, bundle_root
                )
                ledger_status = (
                    "equivalent_under_ledger_model"
                    if ledger_backend_result.status == "blaster_valid"
                    else ledger_backend_result.status
                )
                ledger_replay = None
                if (
                    ledger_backend_result.status == "blaster_falsified_unreplayed"
                    and ledger_backend_result.witness
                ):
                    ledger_replay = _replay_counterexample(
                        actual_backend,
                        config,
                        compiler_identities,
                        pair,
                        ledger_model,
                        ledger_backend_result.witness,
                        bundle_root,
                    )
                ledger_record = {
                    "status": ledger_status,
                    "input_model": ledger_model.to_dict(),
                    "backend": ledger_backend_result.to_dict(),
                    "counterexample_replay": ledger_replay,
                }
                if (
                    result["status"] == "confirmed_non_equivalent"
                    and ledger_status == "equivalent_under_ledger_model"
                ):
                    result["status"] = "off_ledger_difference"
            else:
                ledger_record = {
                    "status": "ledger_model_unsupported",
                    "input_model": ledger_model.to_dict(),
                    "backend": None,
                    "counterexample_replay": None,
                }
            result["model_results"] = {
                raw_model.profile: {
                    "status": raw_status,
                    "input_model": raw_model.to_dict(),
                    "backend": raw_backend_result.to_dict(),
                    "counterexample_replay": raw_replay,
                },
                ledger_model.profile: ledger_record,
            }
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
    for row in pair_results:
        write_json(bundle_root / "pairs" / row["pair_id"] / "result.json", row)
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
                "compiled_abi_unverified",
                "compiled_abi_mismatch",
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
        "selected_pair_ids": sorted(requested_pairs),
        "reused_pair_count": len(reused_pair_ids),
        "require_script_difference": require_script_difference,
        "script_difference_observed": (
            any(
                row.get("old_script", {}).get("sha256")
                != row.get("new_script", {}).get("sha256")
                for row in pair_results
                if isinstance(row.get("old_script"), dict)
                and isinstance(row.get("new_script"), dict)
            )
        ),
        "reused_pair_ids": sorted(reused_pair_ids),
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
    feature_contract: Path = CONTRACT_PATH,
    resume: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    return compare_package(
        package,
        compilers,
        work_root=work_root,
        strict=strict,
        blaster_config=blaster_config,
        backend=backend,
        sentinel=True,
        feature_contract=feature_contract,
        resume=resume,
        force=force,
    )
