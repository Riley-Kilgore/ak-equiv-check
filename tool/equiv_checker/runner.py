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

from .evidence import (
    GENERATED_LEAN_SCHEMA_VERSION,
    candidate_witness_id,
    checker_implementation_id,
    obligation_result_id,
    platform_identity,
    replay_id,
)
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
    FeatureEvidenceLink,
    HandlerPairRecord,
    InputModel,
    ProgramPairRecord,
    SemanticObligationRecord,
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


def hash_package_tree(
    package: Path,
    *,
    include_lock: bool,
    exclude_top_level: frozenset[str] = frozenset(),
) -> str:
    digest = hashlib.sha256()
    for path in sorted(
        candidate for candidate in package.rglob("*") if candidate.is_file()
    ):
        relative = path.relative_to(package)
        if (
            _ignored(relative)
            or relative.parts[0] in exclude_top_level
            or (not include_lock and relative.as_posix() == "aiken.lock")
        ):
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()

def _normalized_dependency_lock(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _normalized_dependency_lock(child)
            for key, child in value.items()
            if key not in {"secs_since_epoch", "nanos_since_epoch"}
        }
    if isinstance(value, list):
        return [_normalized_dependency_lock(child) for child in value]
    return value


def dependency_graph_sha256(lock_path: Path) -> str | None:
    if not lock_path.is_file():
        return None
    raw = lock_path.read_bytes()
    try:
        lock = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        payload = {
            "schema_version": "aiken-dependency-graph/v1",
            "unparsed_lock_sha256": hashlib.sha256(raw).hexdigest(),
        }
    else:
        payload = {
            "schema_version": "aiken-dependency-graph/v1",
            "lock": _normalized_dependency_lock(lock),
        }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


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
    """Compatibility alias for the complete checker implementation tree ID."""
    return checker_implementation_id()




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
    remote_result = _git(package, "config", "--get", "remote.origin.url")
    relative = package.resolve().relative_to(repository_root).as_posix() or "."
    status_result = _git(
        repository_root,
        "status",
        "--porcelain",
        "--untracked-files=normal",
        "--",
        relative,
    )
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
    dependency_graph_before = dependency_graph_sha256(source / "aiken.lock")
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
    dependency_graph_after = dependency_graph_sha256(source / "aiken.lock")
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
        "dependency_graph_before": dependency_graph_before,
        "dependency_graph_after": dependency_graph_after,
        "dependency_lock_unchanged": (
            dependency_graph_before == dependency_graph_after
        ),
        "dependency_lock_bytes_unchanged": lock_before == lock_after,
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


def _row_checksum(row: dict[str, Any]) -> str:
    return stable_hash(
        {key: value for key, value in row.items() if key != "artifact_checksum"}
    )


def _seal_evidence_row(row: dict[str, Any]) -> dict[str, Any]:
    row["artifact_checksum"] = _row_checksum(row)
    return row


def _pair_result(
    pair: ProgramPairRecord,
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
    model_id = input_model.semantic_model_id(config.runtime_step_bound)
    obligation_kind = (
        "ledger_observational_equivalence"
        if input_model.profile.startswith("ledger-valid")
        else "observational_equivalence"
    )
    equivalence_obligation = SemanticObligationRecord.create(
        pair,
        input_model,
        obligation_kind,
        config.runtime_step_bound,
    )
    checker = config.checker_configuration()
    cache_binding = {
        "logical_obligation_id": equivalence_obligation.logical_obligation_id,
        "checker_configuration_id": checker["checker_configuration_id"],
        "old_script_sha256": pair.old_script.sha256,
        "new_script_sha256": pair.new_script.sha256,
        "old_program_artifact_id": pair.old_script.program_artifact_id,
        "new_program_artifact_id": pair.new_script.program_artifact_id,
        "verified_abi_id": pair.verified_abi_id,
        "semantic_model_id": model_id,
        "generated_source_schema_version": GENERATED_LEAN_SCHEMA_VERSION,
    }
    evidence_id = stable_hash(
        cache_binding
        | {
            "solver_status": status,
            "generated_lean_sha256": backend.get("generated_lean_sha256"),
        }
    )
    return {
        "program_pair_id": pair.program_pair_id,
        "evidence_id": evidence_id,
        "cache_binding": cache_binding,
        "attempt_id": equivalence_obligation.attempt_id(
            config, attempt_sequence
        ),
        "attempt_sequence": attempt_sequence,
        "execution_environment": platform_key(),
        "source_identity": source,
        "handler_pair_ids": list(pair.handler_pair_ids),
        "handler_references": list(pair.handler_references),
        "compiler_pair": compilers,
        "old_program_artifact": pair.old_script.to_dict(),
        "new_program_artifact": pair.new_script.to_dict(),
        "verified_abi_id": pair.verified_abi_id,
        "verified_abi": pair.verified_abi,
        "covered_feature_ids": list(pair.covered_feature_ids),
        "semantic_model_id": model_id,
        "input_model": input_model.to_dict(),
        "domain_assumptions": list(input_model.domain_assumptions),
        "semantic_contract": EQUIVALENCE_FORMULA,
        "excluded_observations": list(EXCLUDED_FROM_SEMANTIC_VERDICT),
        "checker_configuration": checker,
        "runtime_step_bound": config.runtime_step_bound,
        "fuel_semantics": "maximum CEK transitions per modeled input; process timeouts are execution evidence",
        "timeouts": asdict(config.timeouts),
        "evaluator": config.evaluator.identity() if config.evaluator else None,
        "secondary_evaluator": (
            config.secondary_evaluator.identity()
            if config.secondary_evaluator
            else None
        ),
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
        "evidence_reuse": None,
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
    obligation_results: list[dict[str, Any]] | None = None,
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
    source_ids = {
        row["feature_id"] for row in sentinel_evidence["census"]
    }
    reachability = {
        label: {row["feature_id"]: row for row in rows}
        for label, rows in sentinel_evidence["reachability"].items()
    }
    pair_by_feature: dict[str, list[dict[str, Any]]] = {}
    for result in pair_results:
        if not isinstance(result.get("program_pair_id"), str):
            continue
        for feature_id in result.get("covered_feature_ids", []):
            pair_by_feature.setdefault(feature_id, []).append(result)
    negative = {
        label: {
            row["feature_id"]: row
            for row in builds[label]["negative_runs"]
        }
        for label in ("old", "new")
    }
    lane_runs = sentinel_evidence["lanes"]
    obligation_result_ids = {
        row["logical_obligation_id"]: row["evidence_result_id"]
        for row in (obligation_results or [])
    }

    def lane_results(label: str, lanes: list[str]) -> dict[str, bool]:
        results: dict[str, bool] = {}
        for lane in lanes:
            if lane in {"compile", "blaster"}:
                continue
            record = lane_runs[label].get(lane)
            results[lane] = bool(
                record
                and record.get("required")
                and record.get("exit_code") == 0
            )
        return results

    def pair_state(status: str) -> str:
        if status == "identical":
            return "pair_identical"
        if status in {
            "equivalent_under_raw_model",
            "equivalent_under_ledger_model",
        }:
            return "pair_complete_equivalent"
        if status == "bounded_equivalent":
            return "pair_bounded_equivalent"
        if status in {
            "confirmed_non_equivalent",
            "off_ledger_difference",
            "blaster_falsified_unreplayed",
        }:
            return "pair_confirmed_non_equivalent"
        if status in {
            "blaster_unsupported",
            "raw_model_unsupported",
            "ledger_model_unsupported",
            "fallback_purpose_unsupported",
            "raw_model_not_bound_to_abi",
        }:
            return "pair_unsupported"
        return "pair_inconclusive"

    def aggregate_pair_state(rows: list[dict[str, Any]]) -> str:
        if not rows:
            return "pair_missing"
        states = {pair_state(row["status"]) for row in rows}
        for state in (
            "pair_confirmed_non_equivalent",
            "pair_bounded_equivalent",
            "pair_unsupported",
            "pair_inconclusive",
            "pair_missing",
        ):
            if state in states:
                return state
        if "pair_complete_equivalent" in states:
            return "pair_complete_equivalent"
        return "pair_identical"

    records: list[dict[str, Any]] = []
    all_feature_ids = sorted(set(contract_rows) | set(manifest_rows))
    for feature_id in all_feature_ids:
        contract_row = contract_rows.get(feature_id)
        manifest_row = manifest_rows.get(feature_id)
        kind = (
            contract_row or manifest_row or {"row_kind": "feature"}
        )["row_kind"]
        lanes = list((contract_row or {}).get("lanes", []))
        linked_pairs = pair_by_feature.get(feature_id, [])
        old_build = builds["old"]["primary_exit_code"] == 0
        new_build = builds["new"]["primary_exit_code"] == 0
        old_reach = reachability["old"].get(feature_id)
        new_reach = reachability["new"].get(feature_id)
        reachability_required = bool(
            (manifest_row or {}).get(
                "reachability_required", "blaster" in lanes
            )
        )
        old_lane_results = lane_results("old", lanes)
        new_lane_results = lane_results("new", lanes)
        pair_aggregate = aggregate_pair_state(linked_pairs)
        if not old_build:
            status = "old_build_failed"
        elif not new_build:
            status = "new_build_failed"
        elif contract_row is None:
            status = "feature_new_only"
        elif manifest_row is None:
            status = "pair_missing"
        elif old_reach is None and new_reach is not None:
            status = "feature_new_only"
        elif new_reach is None and old_reach is not None:
            status = "feature_old_only"
        elif reachability_required and not (
            old_reach and old_reach.get("pass")
        ):
            status = "old_reachability_failed"
        elif reachability_required and not (
            new_reach and new_reach.get("pass")
        ):
            status = "new_reachability_failed"
        elif (contract_row or {}).get("negative_compile_case"):
            old_negative = negative["old"].get(feature_id)
            new_negative = negative["new"].get(feature_id)
            status = (
                "expected_negative_diagnostic"
                if old_negative
                and old_negative.get("pass")
                and new_negative
                and new_negative.get("pass")
                else "pair_inconclusive"
            )
        elif "blaster" in lanes:
            status = pair_aggregate
        else:
            status = (
                "not_applicable"
                if feature_id in source_ids
                and all(
                    [
                        *old_lane_results.values(),
                        *new_lane_results.values(),
                    ]
                )
                else "pair_inconclusive"
            )
        logical_ids = sorted(
            {
                obligation["logical_obligation_id"]
                for pair_row in linked_pairs
                for model in pair_row.get("model_results", {}).values()
                for obligation in model.get(
                    "semantic_obligations", []
                )
            }
        )
        authoritative = sorted(
            {
                obligation_result_ids[logical_id]
                for logical_id in logical_ids
                if logical_id in obligation_result_ids
            }
        )
        records.append(
            {
                "feature_id": feature_id,
                "row_kind": kind,
                "lanes": lanes,
                "manifest_present": manifest_row is not None,
                "source_present": feature_id in source_ids,
                "old_build_accepted": old_build,
                "new_build_accepted": new_build,
                "lane_results_old": old_lane_results,
                "lane_results_new": new_lane_results,
                "reachability_required": reachability_required,
                "old_reachability": old_reach,
                "new_reachability": new_reach,
                "handler_pair_ids": sorted(
                    {
                        handler_id
                        for row in linked_pairs
                        for handler_id in row.get(
                            "handler_pair_ids", []
                        )
                    }
                ),
                "program_pair_ids": sorted(
                    {
                        row["program_pair_id"]
                        for row in linked_pairs
                    }
                ),
                "semantic_obligation_ids": logical_ids,
                "all_linked_evidence": authoritative,
                "required_evidence": authoritative
                if "blaster" in lanes
                else [],
                "authoritative_evidence": authoritative,
                "pair_results": [
                    {
                        "program_pair_id": row[
                            "program_pair_id"
                        ],
                        "evidence_id": row["evidence_id"],
                        "state": pair_state(row["status"]),
                    }
                    for row in linked_pairs
                ],
                "aggregate_feature_result": status,
                "status": status,
            }
        )
    return {
        "schema_version": CHECKER_SCHEMA_VERSION,
        "mode": "sentinel",
        "record_count": len(records),
        "records": records,
    }


def _compact_feature_links(
    feature_coverage: dict[str, Any],
) -> dict[str, Any]:
    records = [
        {
            "feature_id": row["feature_id"],
            "row_kind": row["row_kind"],
            "status": row["status"],
            "handler_pair_ids": row["handler_pair_ids"],
            "program_pair_ids": row["program_pair_ids"],
            "semantic_obligation_ids": row[
                "semantic_obligation_ids"
            ],
            "all_linked_evidence": row["all_linked_evidence"],
            "required_evidence": row["required_evidence"],
            "authoritative_evidence": row[
                "authoritative_evidence"
            ],
        }
        for row in feature_coverage["records"]
    ]
    return {
        "schema_version": CHECKER_SCHEMA_VERSION,
        "record_count": len(records),
        "records": records,
    }


def _load_valid_pair_results(bundle_root: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    pairs_root = bundle_root / "pairs"
    if not pairs_root.is_dir():
        return results
    for result_path in sorted(pairs_root.glob("*/result.json")):
        try:
            row = load_json(result_path)
        except (OSError, json.JSONDecodeError):
            continue
        if (
            not isinstance(row, dict)
            or row.get("artifact_checksum") != _row_checksum(row)
        ):
            continue
        pair_id = row.get("program_pair_id")
        if not isinstance(pair_id, str) or result_path.parent.name != pair_id:
            continue
        generated_valid = True

        def validate_generated(value: Any) -> None:
            nonlocal generated_valid
            if not generated_valid:
                return
            if isinstance(value, dict):
                path = value.get("generated_lean_path")
                checksum = value.get("generated_lean_sha256")
                if path is not None or checksum is not None:
                    if not isinstance(path, str) or not isinstance(checksum, str):
                        generated_valid = False
                        return
                    source = bundle_root / path
                    if not source.is_file() or sha256_file(source) != checksum:
                        generated_valid = False
                        return
                for nested in value.values():
                    validate_generated(nested)
            elif isinstance(value, list):
                for nested in value:
                    validate_generated(nested)

        validate_generated(row)
        if generated_valid:
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
    pair: ProgramPairRecord,
    input_model: InputModel,
    witness: dict[str, Any],
    bundle_root: Path,
) -> dict[str, Any]:
    evaluators = tuple(
        evaluator
        for evaluator in (
            config.evaluator,
            config.secondary_evaluator,
        )
        if evaluator is not None
    )
    compiler_hashes = {
        compiler.get("binary_sha256") for compiler in compilers.values()
    }
    collision = next(
        (
            evaluator
            for evaluator in evaluators
            if evaluator.binary_sha256 in compiler_hashes
        ),
        None,
    )
    if collision is not None:
        return {
            "confirmed": False,
            "reason": "replay evaluator must be a separate binary from both compared compilers",
            "evaluator": collision.identity(),
        }
    replay = backend.replay(pair, input_model, witness, bundle_root)
    trust = replay.get("replay_trust")
    if isinstance(trust, dict):
        trust["separate_binary"] = bool(evaluators)
    replay["source_relationships"] = {
        "old_compiler_source": compilers.get("old", {}).get(
            "provenance", {}
        ).get("source", compilers.get("old", {}).get("git_revision")),
        "new_compiler_source": compilers.get("new", {}).get(
            "provenance", {}
        ).get("source", compilers.get("new", {}).get("git_revision")),
        "replay_evaluator_sources": [
            {
                "name": evaluator.name,
                "revision": evaluator.revision,
                "binary_sha256": evaluator.binary_sha256,
                "distinct_uplc_implementation": (
                    evaluator.distinct_uplc_implementation
                ),
            }
            for evaluator in evaluators
        ],
        "symbolic_checker_source": config.checker_configuration(),
    }
    return replay


def _planned_logical_obligation_ids(
    pair: ProgramPairRecord,
    config: BlasterConfig,
) -> list[str]:
    raw_model, ledger_models = validator_input_models(pair)
    identifiers: set[str] = set()
    for model in (raw_model, *ledger_models):
        kinds = (
            (
                "ledger_domain_non_vacuity",
                "old_program_completion",
                "new_program_completion",
                "ledger_observational_equivalence",
            )
            if model.profile.startswith("ledger-valid")
            else (
                "domain_non_vacuity",
                "old_program_completion",
                "new_program_completion",
                "observational_equivalence",
            )
        )
        identifiers.update(
            SemanticObligationRecord.create(
                pair,
                model,
                kind,
                config.runtime_step_bound,
            ).logical_obligation_id
            for kind in kinds
        )
    return sorted(identifiers)


def _planned_semantic_model_ids(
    pair: ProgramPairRecord,
    config: BlasterConfig,
) -> list[str]:
    raw_model, ledger_models = validator_input_models(pair)
    return sorted(
        model.semantic_model_id(config.runtime_step_bound)
        for model in (raw_model, *ledger_models)
    )


def _cached_pair_matches(
    row: dict[str, Any] | None,
    pair: ProgramPairRecord,
    input_model: InputModel,
    source: dict[str, Any],
    compilers: dict[str, dict[str, Any]],
    config: BlasterConfig,
) -> bool:
    del source, compilers
    if (
        row is None
        or row.get("artifact_checksum") != _row_checksum(row)
        or row.get("program_pair_id") != pair.program_pair_id
    ):
        return False
    expected = _pair_result(
        pair,
        input_model,
        "identical",
        None,
        source={},
        compilers={},
        config=config,
    )
    cached_binding = dict(row.get("cache_binding", {}))
    cached_obligations = cached_binding.pop(
        "logical_obligation_ids", None
    )
    cached_models = cached_binding.pop("semantic_model_ids", None)
    expected_obligations = (
        []
        if row.get("status")
        in {"identical", "expected_codegen_delta_not_observed"}
        else _planned_logical_obligation_ids(pair, config)
    )
    return (
        cached_binding == expected["cache_binding"]
        and cached_models == _planned_semantic_model_ids(pair, config)
        and cached_obligations == expected_obligations
        and row.get("status") in FINAL_STATUSES
    )


def _validate_bundle(bundle_root: Path) -> list[str]:
    schemas = {
        "run.json": "run.schema.json",
        "build-old.json": "build-v2.schema.json",
        "build-new.json": "build-v2.schema.json",
        "validator-records.json": "validator-records.schema.json",
        "handler-pairs.json": "handler-pairs.schema.json",
        "program-pairs.json": "program-pairs.schema.json",
        "pair-results.json": "pair-results.schema.json",
        "semantic-obligations.json": "semantic-obligations.schema.json",
        "obligation-results.json": "obligation-results.schema.json",
        "validator-links.json": "validator-links.schema.json",
        "feature-coverage.json": "feature-coverage.schema.json",
        "feature-links.json": "feature-links.schema.json",
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
                pair_id = row.get("program_pair_id")
                if not isinstance(pair_id, str):
                    errors.append("program result missing program_pair_id")
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
        ("Source validator records, old", counts["validator_records_old"]),
        ("Source validator records, new", counts["validator_records_new"]),
        ("Blueprint handler pairs", counts["handler_pairs"]),
        ("Unique compiled program pairs", counts["unique_program_pairs"]),
        (
            "Unique changed program pairs",
            counts["unique_changed_program_pairs"],
        ),
        ("Unique raw obligations", counts["unique_raw_obligations"]),
        (
            "Unique ledger obligations",
            counts["unique_ledger_obligations"],
        ),
        (
            "Deduplicated obligations",
            counts["deduplicated_obligations"],
        ),
        (
            "Deduplicated solver invocations",
            counts["deduplicated_invocations"],
        ),
        ("Identical program pairs", counts["identical_program_pairs"]),
        (
            "Confirmed non-equivalent obligations",
            counts["confirmed_non_equivalent_obligations"],
        ),
        (
            "Inconclusive obligations",
            counts["inconclusive_obligations"],
        ),
        (
            "Unsupported obligations",
            counts["unsupported_obligations"],
        ),
        ("ABI failures", counts["abi_failures"]),
        ("Reused obligations", counts["reused_obligations"]),
        ("Build failures", counts["build_failures"]),
        (
            "Compatibility differences",
            counts["compatibility_differences"],
        ),
        ("Feature rows", counts["feature_rows"]),
        ("Shared features covered", counts["shared_features_covered"]),
        ("Shared features missing", counts["shared_features_missing"]),
    )
    lines = [
        "# Equivalence checker result",
        "",
        f"Strict verdict: **{'PASS' if summary['strict_pass'] else 'FAIL'}**",
        "",
        "| Entity or state | Count |",
        "|---|---:|",
        *(f"| {label} | {value} |" for label, value in labels),
        "",
        "Program-pair and semantic-obligation counts are unique; handler and feature links do not multiply proof counts.",
        "",
    ]
    if summary["gaps"]:
        lines.extend(
            ["## Gaps", "", *(f"- {gap}" for gap in summary["gaps"]), ""]
        )
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
        builds[label]["dependency_graph_after"] for label in ("old", "new")
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
            package_path=str(source_metadata["package_path"]),
            plutus_version=_plutus_version(package),
            covered_features_by_title=coverage_map,
            old_abi_inspection=builds["old"]["abi_inspection"],
            new_abi_inspection=builds["new"]["abi_inspection"],
            old_abi_parser_error=builds["old"]["abi_inspection_error"],
            new_abi_parser_error=builds["new"]["abi_inspection_error"],
            repository=source_metadata.get(
                "canonical_repository_url",
                source_metadata.get("identity", "unknown"),
            ),
            package=package_name(package),
            old_compiler_artifact_id=compilers[0].provenance.get(
                "artifact_id", compilers[0].binary_sha256
            ),
            new_compiler_artifact_id=compilers[1].provenance.get(
                "artifact_id", compilers[1].binary_sha256
            ),
            require_verified_abi=strict,
        )
        discovered_pair_ids = {
            pair.program_pair_id for pair in pairing.program_pairs
        }
        missing_requested_pairs = sorted(requested_pairs - discovered_pair_ids)
        if missing_requested_pairs:
            raise ValueError(
                "requested pair(s) are not present in the rebuilt package: "
                + ", ".join(missing_requested_pairs)
            )
        script_difference_observed = any(
            pair.old_script.sha256 != pair.new_script.sha256
            for pair in pairing.program_pairs
        )
        actual_backend = backend or RealBlasterBackend(config)

        def planned_obligations(
            pair: ProgramPairRecord, model: InputModel
        ) -> list[dict[str, Any]]:
            if not model.supported:
                return []
            kinds = (
                (
                    "ledger_domain_non_vacuity",
                    "old_program_completion",
                    "new_program_completion",
                    "ledger_observational_equivalence",
                )
                if model.profile.startswith("ledger-valid")
                else (
                    "domain_non_vacuity",
                    "old_program_completion",
                    "new_program_completion",
                    "observational_equivalence",
                )
            )
            return [
                SemanticObligationRecord.create(
                    pair, model, kind, config.runtime_step_bound
                ).to_dict()
                for kind in kinds
            ]

        for pair in sorted(
            pairing.program_pairs,
            key=lambda record: (
                record.old_script.sha256 == record.new_script.sha256,
                record.program_pair_id,
            ),
        ):
            raw_model, ledger_models = validator_input_models(pair)
            cached = cached_pair_results.get(pair.program_pair_id)
            cached_matches = _cached_pair_matches(
                cached,
                pair,
                raw_model,
                source_metadata,
                compiler_identities,
                config,
            )
            unselected = (
                bool(requested_pairs)
                and pair.program_pair_id not in requested_pairs
            )
            if cached_matches and ((resume and not force) or unselected):
                if previous_bundle_root is not None:
                    _restore_reused_artifacts(
                        cached,
                        previous_bundle_root,
                        bundle_root,
                    )
                reused = json.loads(json.dumps(cached))
                original_checksum = reused["artifact_checksum"]
                original_attempt = reused["attempt_id"]
                original_run = reused.get("run_id", run_id)
                reused["attempt_id"] = SemanticObligationRecord.create(
                    pair,
                    raw_model,
                    "observational_equivalence",
                    config.runtime_step_bound,
                ).attempt_id(config, current_attempt_sequence)
                reused["attempt_sequence"] = current_attempt_sequence
                reused["handler_pair_ids"] = list(pair.handler_pair_ids)
                reused["handler_references"] = list(pair.handler_references)
                reused["covered_feature_ids"] = list(pair.covered_feature_ids)
                reused["evidence_reuse"] = {
                    "original_attempt_id": original_attempt,
                    "original_run_id": original_run,
                    "original_artifact_checksum": original_checksum,
                    "reuse_validation_result": "exact_identity_and_artifact_match",
                    "new_attempt_id": reused["attempt_id"],
                }
                if (
                    resume
                    and reused.get("status")
                    == "blaster_falsified_unreplayed"
                    and isinstance(reused.get("witness"), dict)
                ):
                    replay = _replay_counterexample(
                        actual_backend,
                        config,
                        compiler_identities,
                        pair,
                        raw_model,
                        reused["witness"],
                        bundle_root,
                    )
                    reused["counterexample_replay"] = replay
                    raw_record = reused.get("model_results", {}).get(
                        raw_model.semantic_model_id(config.runtime_step_bound)
                    )
                    if isinstance(raw_record, dict):
                        raw_record["counterexample_replay"] = replay
                    if replay.get("confirmed"):
                        reused["status"] = "confirmed_non_equivalent"
                pair_results.append(_seal_evidence_row(reused))
                reused_pair_ids.add(pair.program_pair_id)
                continue
            if unselected:
                raise ValueError(
                    "no matching cached evidence exists for unselected pair "
                    f"{pair.program_pair_id}"
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
                result["run_id"] = run_id
                result["model_results"] = {
                    model.semantic_model_id(config.runtime_step_bound): {
                        "status": (
                            identical_status
                            if model.supported
                            else "ledger_model_unsupported"
                        ),
                        "semantic_model_id": model.semantic_model_id(
                            config.runtime_step_bound
                        ),
                        "input_model": model.to_dict(),
                        "semantic_obligations": [],
                        "backend": None,
                        "counterexample_replay": None,
                    }
                    for model in (raw_model, *ledger_models)
                }
                result["cache_binding"]["semantic_model_ids"] = sorted(
                    result["model_results"]
                )
                result["cache_binding"]["logical_obligation_ids"] = []
                pair_results.append(_seal_evidence_row(result))
                continue

            raw_backend_result = actual_backend.compare(
                pair, raw_model, bundle_root
            )
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
            result["run_id"] = run_id
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
            model_results: dict[str, dict[str, Any]] = {
                raw_model.semantic_model_id(config.runtime_step_bound): {
                    "status": raw_status,
                    "semantic_model_id": raw_model.semantic_model_id(
                        config.runtime_step_bound
                    ),
                    "input_model": raw_model.to_dict(),
                    "semantic_obligations": planned_obligations(
                        pair, raw_model
                    ),
                    "backend": raw_backend_result.to_dict(),
                    "counterexample_replay": raw_replay,
                }
            }
            ledger_statuses: list[str] = []
            for ledger_model in ledger_models:
                model_id = ledger_model.semantic_model_id(
                    config.runtime_step_bound
                )
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
                        ledger_backend_result.status
                        == "blaster_falsified_unreplayed"
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
                        if ledger_replay.get("confirmed"):
                            ledger_status = "confirmed_non_equivalent"
                    ledger_backend = ledger_backend_result.to_dict()
                else:
                    ledger_status = "ledger_model_unsupported"
                    ledger_replay = None
                    ledger_backend = None
                ledger_statuses.append(ledger_status)
                model_results[model_id] = {
                    "status": ledger_status,
                    "semantic_model_id": model_id,
                    "input_model": ledger_model.to_dict(),
                    "semantic_obligations": planned_obligations(
                        pair, ledger_model
                    ),
                    "backend": ledger_backend,
                    "counterexample_replay": ledger_replay,
                }
            if result["status"] == "confirmed_non_equivalent":
                if "confirmed_non_equivalent" in ledger_statuses:
                    result["status"] = "confirmed_non_equivalent"
                elif ledger_statuses and all(
                    status
                    in {
                        "equivalent_under_ledger_model",
                        "ledger_model_unsupported",
                    }
                    for status in ledger_statuses
                ) and any(
                    status == "equivalent_under_ledger_model"
                    for status in ledger_statuses
                ):
                    result["status"] = "off_ledger_difference"
            result["model_results"] = model_results
            logical_ids = sorted(
                {
                    obligation["logical_obligation_id"]
                    for model_record in model_results.values()
                    for obligation in model_record["semantic_obligations"]
                }
            )
            result["cache_binding"]["semantic_model_ids"] = sorted(
                model_results
            )
            result["cache_binding"][
                "logical_obligation_ids"
            ] = logical_ids
            pair_results.append(_seal_evidence_row(result))
        pair_results.extend(
            _compatibility_result(
                row,
                source_metadata,
                compiler_identities,
                config,
            )
            for row in pairing.compatibility_results
        )

    validator_records = {
        "schema_version": CHECKER_SCHEMA_VERSION,
        "old": [
            row.to_dict() for row in pairing.validator_records_old
        ]
        if pairing
        else [],
        "new": [
            row.to_dict() for row in pairing.validator_records_new
        ]
        if pairing
        else [],
    }
    write_json(bundle_root / "validator-records.json", validator_records)
    handler_pairs = {
        "schema_version": CHECKER_SCHEMA_VERSION,
        "record_count": len(pairing.handler_pairs) if pairing else 0,
        "records": [
            row.to_dict() for row in pairing.handler_pairs
        ]
        if pairing
        else [],
    }
    write_json(bundle_root / "handler-pairs.json", handler_pairs)
    program_pairs = {
        "schema_version": CHECKER_SCHEMA_VERSION,
        "record_count": len(pairing.program_pairs) if pairing else 0,
        "records": [
            pair.to_dict() for pair in pairing.program_pairs
        ]
        if pairing
        else [],
    }
    write_json(bundle_root / "program-pairs.json", program_pairs)
    pair_results.sort(
        key=lambda row: str(
            row.get("program_pair_id", row.get("pair_id", ""))
        )
    )
    serialized_program_results = [
        row
        for row in pair_results
        if isinstance(row.get("program_pair_id"), str)
    ]
    task_results = [
        row
        for row in pair_results
        if not isinstance(row.get("program_pair_id"), str)
    ]
    write_json(
        bundle_root / "pair-results.json",
        {
            "schema_version": CHECKER_SCHEMA_VERSION,
            "record_count": len(serialized_program_results),
            "records": serialized_program_results,
        },
    )
    write_json(
        bundle_root / "task-results.json",
        {
            "schema_version": CHECKER_SCHEMA_VERSION,
            "record_count": len(task_results),
            "records": task_results,
        },
    )
    for row in pair_results:
        pair_id = row.get("program_pair_id")
        if isinstance(pair_id, str):
            write_json(
                bundle_root / "pairs" / pair_id / "result.json",
                row,
            )

    semantic_obligations_by_id: dict[str, dict[str, Any]] = {}
    obligation_results: list[dict[str, Any]] = []
    execution_attempts_by_id: dict[str, dict[str, Any]] = {}
    witnesses_by_id: dict[str, dict[str, Any]] = {}
    replays_by_id: dict[str, dict[str, Any]] = {}
    model_omissions: list[dict[str, Any]] = []
    checker = config.checker_configuration()
    execution_platform = platform_identity()

    def terminal_obligation_status(
        proof_status: str | None, model_status: str
    ) -> str:
        if proof_status in {"proven", "valid", "falsified"}:
            return proof_status
        if proof_status == "inconclusive":
            return "inconclusive"
        if model_status == "blaster_timeout":
            return "timeout"
        if "unsupported" in model_status:
            return "unsupported"
        if model_status in {"blaster_error", "domain_non_vacuous_failed"}:
            return "tool_error" if model_status == "blaster_error" else "invalid"
        if model_status == "bounded_equivalent":
            return "bounded"
        if model_status == "blaster_inconclusive":
            return "inconclusive"
        return "invalid"

    for row in pair_results:
        program_pair_id_value = row.get("program_pair_id")
        if not isinstance(program_pair_id_value, str):
            continue
        for model_record in row.get("model_results", {}).values():
            input_model_record = model_record.get("input_model", {})
            planned_kinds = (
                [
                    "ledger_domain_non_vacuity",
                    "old_program_completion",
                    "new_program_completion",
                    "ledger_observational_equivalence",
                ]
                if str(input_model_record.get("profile", "")).startswith(
                    "ledger-valid"
                )
                else [
                    "domain_non_vacuity",
                    "old_program_completion",
                    "new_program_completion",
                    "observational_equivalence",
                ]
            )
            if (
                input_model_record.get("supported") is False
                and not model_record.get("semantic_obligations")
            ):
                model_omissions.append(
                    {
                        "semantic_model_id": model_record["semantic_model_id"],
                        "program_pair_id": program_pair_id_value,
                        "status": "ledger_model_unsupported",
                        "reason": input_model_record.get("unsupported_reason"),
                        "planned_obligation_kinds": planned_kinds,
                    }
                )
                continue
            backend_record = model_record.get("backend")
            proof_results = (
                backend_record.get("proof_obligations", {})
                if isinstance(backend_record, dict)
                else {}
            )
            phases = (
                backend_record.get("phase_results", [])
                if isinstance(backend_record, dict)
                else []
            )
            phase_rows = [phase for phase in phases if isinstance(phase, dict)]
            planned_ids = sorted(
                obligation["logical_obligation_id"]
                for obligation in model_record.get("semantic_obligations", [])
            )
            for obligation in model_record.get("semantic_obligations", []):
                obligation_id = obligation["logical_obligation_id"]
                previous = semantic_obligations_by_id.setdefault(
                    obligation_id, obligation
                )
                if previous != obligation:
                    raise RuntimeError(
                        f"conflicting semantic obligation {obligation_id}"
                    )
                proof = proof_results.get(obligation["obligation_kind"], {})
                generated_source_sha256 = proof.get("generated_lean_sha256")
                matching_phases = [
                    (index, phase)
                    for index, phase in enumerate(phase_rows, start=1)
                    if generated_source_sha256 is not None
                    and phase.get("generated_lean_sha256")
                    == generated_source_sha256
                ]
                if matching_phases:
                    phase_index, phase = matching_phases[-1]
                elif phase_rows:
                    phase_index, phase = len(phase_rows), phase_rows[-1]
                    generated_source_sha256 = phase.get(
                        "generated_lean_sha256"
                    )
                else:
                    phase_index, phase = 1, {}
                execution_sequence = (
                    (int(row.get("attempt_sequence", 1)) - 1) * 1000
                    + phase_index
                )
                execution_plan = {
                    "kind": (
                        "generated_lean_process"
                        if phase
                        else "terminal_without_process"
                    ),
                    "program_pair_id": program_pair_id_value,
                    "semantic_model_id": obligation["semantic_model_id"],
                    "planned_logical_obligation_ids": planned_ids,
                    "phase": phase.get("phase", "scheduler_terminalization"),
                    "command": [
                        (
                            f"<absolute-diagnostic:{Path(str(value)).name}>"
                            if Path(str(value)).is_absolute()
                            else str(value)
                        )
                        for value in phase.get("command", [])
                    ],
                    "effective_options": phase.get("effective_options", {}),
                }
                obligation_record = SemanticObligationRecord(
                    **obligation
                )
                execution_attempt_id_value = (
                    obligation_record.execution_attempt_id(
                        config,
                        execution_plan=execution_plan,
                        generated_source_sha256=generated_source_sha256,
                        execution_sequence=execution_sequence,
                        platform=execution_platform,
                    )
                )
                execution_record = {
                    "execution_attempt_id": execution_attempt_id_value,
                    "checker_configuration_id": checker[
                        "checker_configuration_id"
                    ],
                    "checker_implementation_id": checker[
                        "checker_implementation_id"
                    ],
                    "execution_plan": execution_plan,
                    "generated_source_sha256": generated_source_sha256,
                    "process_timeouts": asdict(config.timeouts),
                    "random_seed": config.random_seed,
                    "platform_identity": execution_platform,
                    "execution_sequence": execution_sequence,
                    "command": phase.get("command"),
                    "exit_code": phase.get("exit_code"),
                    "timed_out": bool(phase.get("timed_out", False)),
                    "duration_seconds": float(
                        phase.get("duration_seconds", 0.0)
                    ),
                    "stdout_path": phase.get("stdout_path"),
                    "stderr_path": phase.get("stderr_path"),
                }
                existing_execution = execution_attempts_by_id.setdefault(
                    execution_attempt_id_value, execution_record
                )
                if existing_execution != execution_record:
                    raise RuntimeError(
                        "conflicting execution attempt "
                        f"{execution_attempt_id_value}"
                    )
                relevant_solver_options = {
                    **phase.get("effective_options", {}),
                    "solver": config.solver,
                    "solver_timeout": config.timeouts.z3,
                }
                attempt_sequence = int(row.get("attempt_sequence", 1))
                obligation_attempt_id_value = (
                    obligation_record.obligation_attempt_id(
                        config,
                        execution_attempt_id_value=execution_attempt_id_value,
                        relevant_solver_options=relevant_solver_options,
                        attempt_sequence=attempt_sequence,
                    )
                )
                witness_reference = None
                raw_witness = (
                    backend_record.get("witness")
                    if isinstance(backend_record, dict)
                    else None
                )
                if (
                    obligation["obligation_kind"]
                    in {
                        "observational_equivalence",
                        "ledger_observational_equivalence",
                    }
                    and isinstance(raw_witness, dict)
                    and raw_witness.get("logical_obligation_id")
                    == obligation_id
                ):
                    witness_record = {
                        **raw_witness,
                        "producing_logical_obligation_id": obligation_id,
                        "producing_obligation_attempt_id": (
                            obligation_attempt_id_value
                        ),
                        "producing_execution_attempt_id": (
                            execution_attempt_id_value
                        ),
                    }
                    witness_identity = candidate_witness_id(witness_record)
                    witness_record["witness_id"] = witness_identity
                    witnesses_by_id[witness_identity] = witness_record
                    witness_reference = witness_identity
                replay_reference = None
                model_replay = model_record.get("counterexample_replay")
                if (
                    witness_reference is not None
                    and isinstance(model_replay, dict)
                    and obligation["obligation_kind"]
                    in {
                        "observational_equivalence",
                        "ledger_observational_equivalence",
                    }
                ):
                    replay_record = {
                        **model_replay,
                        "logical_obligation_id": obligation_id,
                        "obligation_attempt_id": obligation_attempt_id_value,
                        "execution_attempt_id": execution_attempt_id_value,
                        "witness_id": witness_reference,
                        "old_program_artifact_id": row[
                            "old_program_artifact"
                        ]["program_artifact_id"],
                        "new_program_artifact_id": row[
                            "new_program_artifact"
                        ]["program_artifact_id"],
                        "old_script_sha256": row["old_program_artifact"][
                            "script_sha256"
                        ],
                        "new_script_sha256": row["new_program_artifact"][
                            "script_sha256"
                        ],
                    }
                    replay_identity = replay_id(replay_record)
                    replay_record["replay_id"] = replay_identity
                    replays_by_id[replay_identity] = replay_record
                    replay_reference = replay_identity
                result_identity = {
                    "logical_obligation_id": obligation_id,
                    "obligation_attempt_id": obligation_attempt_id_value,
                    "execution_attempt_id": execution_attempt_id_value,
                    "checker_configuration_id": checker[
                        "checker_configuration_id"
                    ],
                    "checker_implementation_id": checker[
                        "checker_implementation_id"
                    ],
                    "program_pair_id": program_pair_id_value,
                    "semantic_model_id": obligation[
                        "semantic_model_id"
                    ],
                    "obligation_kind": obligation["obligation_kind"],
                    "status": terminal_obligation_status(
                        proof.get("status"), model_record["status"]
                    ),
                    "generated_source_sha256": generated_source_sha256,
                    "solver_status": proof.get("solver_status"),
                    "witness_reference": witness_reference,
                    "replay_reference": replay_reference,
                    "relevant_solver_options": relevant_solver_options,
                    "attempt_sequence": attempt_sequence,
                }
                obligation_results.append(
                    {
                        "evidence_result_id": obligation_result_id(
                            result_identity
                        ),
                        **result_identity,
                        "generated_source_schema_version": (
                            GENERATED_LEAN_SCHEMA_VERSION
                        ),
                        "generated_source_path": proof.get(
                            "generated_lean_path"
                        ),
                        "reused": row.get("evidence_reuse")
                        is not None,
                    }
                )
    semantic_obligations = {
        "schema_version": CHECKER_SCHEMA_VERSION,
        "record_count": len(semantic_obligations_by_id),
        "records": sorted(
            semantic_obligations_by_id.values(),
            key=lambda row: row["logical_obligation_id"],
        ),
    }
    write_json(
        bundle_root / "semantic-obligations.json",
        semantic_obligations,
    )
    obligation_results.sort(
        key=lambda row: (
            row["logical_obligation_id"],
            row["obligation_attempt_id"],
        )
    )
    write_json(
        bundle_root / "obligation-results.json",
        {
            "schema_version": CHECKER_SCHEMA_VERSION,
            "record_count": len(obligation_results),
            "records": obligation_results,
        },
    )
    for filename, records in (
        (
            "execution-attempts.json",
            sorted(
                execution_attempts_by_id.values(),
                key=lambda item: item["execution_attempt_id"],
            ),
        ),
        (
            "witnesses.json",
            sorted(
                witnesses_by_id.values(),
                key=lambda item: item["witness_id"],
            ),
        ),
        (
            "replays.json",
            sorted(
                replays_by_id.values(),
                key=lambda item: item["replay_id"],
            ),
        ),
        (
            "semantic-model-omissions.json",
            sorted(
                model_omissions,
                key=lambda item: (
                    item["program_pair_id"],
                    item["semantic_model_id"],
                ),
            ),
        ),
    ):
        write_json(
            bundle_root / filename,
            {
                "schema_version": CHECKER_SCHEMA_VERSION,
                "record_count": len(records),
                "records": records,
            },
        )
    write_json(
        bundle_root / "validator-links.json",
        {
            "schema_version": CHECKER_SCHEMA_VERSION,
            "record_count": len(pairing.handler_pairs)
            if pairing
            else 0,
            "records": [
                {
                    **handler.to_dict(),
                    "logical_obligation_ids": sorted(
                        {
                            obligation[
                                "logical_obligation_id"
                            ]
                            for obligation in semantic_obligations_by_id.values()
                            if obligation["program_pair_id"]
                            == handler.program_pair_id
                        }
                    ),
                    "evidence_result_ids": sorted(
                        {
                            result["evidence_result_id"]
                            for result in obligation_results
                            if result["program_pair_id"]
                            == handler.program_pair_id
                        }
                    ),
                }
                for handler in (pairing.handler_pairs if pairing else ())
            ],
        },
    )
    feature_coverage = (
        _feature_coverage(
            manifest,
            sentinel_evidence,
            pair_results,
            builds,
            obligation_results,
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
    write_json(
        bundle_root / "feature-links.json",
        _compact_feature_links(feature_coverage),
    )

    source_state_after = hash_package_tree(package, include_lock=True)
    source_immutable = source_state_before == source_state_after
    if not source_immutable:
        gaps.append("original_source_or_lock_changed")
    if pairing and pairing.old_count == 0 and pairing.new_count == 0:
        gaps.append("no_validators_discovered")
    applicable_statuses = [row["status"] for row in pair_results]
    feature_statuses = [
        row["status"] for row in feature_coverage["records"]
    ]
    statuses = applicable_statuses + feature_statuses
    program_result_rows = [
        row
        for row in pair_results
        if isinstance(row.get("program_pair_id"), str)
    ]
    program_status_counts = {
        status: sum(row["status"] == status for row in program_result_rows)
        for status in sorted(
            {row["status"] for row in program_result_rows}
        )
    }
    obligation_status_counts = {
        status: sum(
            row["status"] == status for row in obligation_results
        )
        for status in sorted(
            {str(row["status"]) for row in obligation_results}
        )
    }
    program_state_invariant = (
        sum(program_status_counts.values())
        == len(pairing.program_pairs)
        if pairing
        else not program_result_rows
    )
    obligation_state_invariant = (
        sum(obligation_status_counts.values())
        == len(semantic_obligations_by_id)
        == len(obligation_results)
    )
    if not program_state_invariant or not obligation_state_invariant:
        gaps.append("report_count_invariant_failed")
    strict_pass = (
        not gaps
        and bool(statuses)
        and all(
            status in STRICT_PASSING_STATUSES for status in statuses
        )
    )
    raw_obligation_ids = {
        row["logical_obligation_id"]
        for row in semantic_obligations_by_id.values()
        if str(row["input_model"]["profile"]).startswith("raw-uplc")
    }
    ledger_obligation_ids = set(semantic_obligations_by_id) - raw_obligation_ids
    changed_pairs = [
        row
        for row in program_result_rows
        if row["old_program_artifact"]["script_sha256"]
        != row["new_program_artifact"]["script_sha256"]
    ]
    unsupported_statuses = {
        "blaster_unsupported",
        "raw_model_unsupported",
        "ledger_model_unsupported",
        "fallback_purpose_unsupported",
    }
    inconclusive_statuses = {
        "blaster_inconclusive",
        "blaster_timeout",
        "blaster_error",
        "domain_non_vacuous_failed",
    }
    abi_failure_statuses = {
        "old_raw_abi_unresolved",
        "new_raw_abi_unresolved",
        "raw_abi_mismatch",
        "raw_abi_parser_error",
        "raw_model_not_bound_to_abi",
        "compiled_abi_unverified",
        "compiled_abi_mismatch",
    }
    counts = {
        "validator_records_old": pairing.old_count if pairing else 0,
        "validator_records_new": pairing.new_count if pairing else 0,
        "handler_pairs": len(pairing.handler_pairs) if pairing else 0,
        "unique_program_pairs": len(pairing.program_pairs)
        if pairing
        else 0,
        "unique_changed_program_pairs": len(changed_pairs),
        "unique_raw_obligations": len(raw_obligation_ids),
        "unique_ledger_obligations": len(ledger_obligation_ids),
        "deduplicated_obligations": max(
            0,
            (
                len(pairing.handler_pairs) * 4
                if pairing
                else 0
            )
            - len(raw_obligation_ids),
        ),
        "deduplicated_invocations": max(
            0,
            (
                sum(
                    pair.old_script.sha256
                    != pair.new_script.sha256
                    for pair in pairing.program_pairs
                    for _handler in pair.handler_pair_ids
                )
                if pairing
                else 0
            )
            - len(changed_pairs),
        ),
        "identical_program_pairs": sum(
            row["status"] == "identical" for row in program_result_rows
        ),
        "bounded_equivalent_obligations": sum(
            row["status"] == "bounded_equivalent"
            for row in obligation_results
        ),
        "equivalent_under_raw_model_obligations": sum(
            row["status"] in {"proven", "valid"}
            and row["logical_obligation_id"] in raw_obligation_ids
            for row in obligation_results
        ),
        "equivalent_under_ledger_model_obligations": sum(
            row["status"] in {"proven", "valid"}
            and row["logical_obligation_id"] in ledger_obligation_ids
            for row in obligation_results
        ),
        "off_ledger_differences": sum(
            row["status"] == "off_ledger_difference"
            for row in program_result_rows
        ),
        "confirmed_non_equivalent_obligations": sum(
            row["status"] in {"falsified", "confirmed_non_equivalent"}
            for row in obligation_results
        ),
        "unreplayed_falsifications": sum(
            row["status"] == "blaster_falsified_unreplayed"
            for row in obligation_results
        ),
        "inconclusive_obligations": sum(
            row["status"] in inconclusive_statuses
            or row["status"] == "inconclusive"
            for row in obligation_results
        ),
        "unsupported_obligations": sum(
            row["status"] in unsupported_statuses
            for row in obligation_results
        ),
        "abi_failures": sum(
            row["status"] in abi_failure_statuses
            for row in pair_results
        ),
        "reused_obligations": sum(
            row["reused"] for row in obligation_results
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
                *abi_failure_statuses,
            }
            for row in pair_results
        ),
        "feature_rows": len(feature_coverage["records"]),
        "shared_features_covered": sum(
            row["status"] in STRICT_PASSING_STATUSES
            for row in feature_coverage["records"]
        ),
        "shared_features_missing": sum(
            row["status"] not in STRICT_PASSING_STATUSES
            for row in feature_coverage["records"]
        ),
        "program_state_total": sum(program_status_counts.values()),
        "obligation_state_total": sum(obligation_status_counts.values()),
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
        "program_status_counts": program_status_counts,
        "obligation_status_counts": obligation_status_counts,
        "count_invariants": {
            "program_final_states_equal_unique_program_pairs": (
                program_state_invariant
            ),
            "obligation_final_states_equal_unique_obligations": (
                obligation_state_invariant
            ),
        },
        "status_counts": {
            status: applicable_statuses.count(status)
            for status in sorted(set(applicable_statuses))
        },
        "selected_pair_ids": sorted(requested_pairs),
        "reused_pair_count": len(reused_pair_ids),
        "require_script_difference": require_script_difference,
        "script_difference_observed": bool(changed_pairs),
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
