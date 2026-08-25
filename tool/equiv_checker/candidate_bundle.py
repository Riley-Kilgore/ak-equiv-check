from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile
from typing import Any, Mapping

from .candidate_policy import classify_changed_pairs, derive_candidate_decisions
from .evidence import (
    WITNESS_FIELDS,
    candidate_witness_id,
    canonical_json,
    checker_configuration_id,
    evidence_run_id,
    execution_attempt_id_from_record,
    identity_hash,
    logical_obligation_id,
    obligation_attempt_id_from_record,
    obligation_result_id,
    program_artifact_id,
    program_pair_id,
    replay_id,
    semantic_model_id,
    validate_witness_record,
    verified_abi_id,
)

CANDIDATE_BUNDLE_SCHEMA_VERSION = "equiv-candidate-bundle/v1"
REQUIRED_BUNDLE_FILES = frozenset(
    {
        "candidate-manifest.json",
        "global-plan.json",
        "global-program-pairs.json",
        "global-semantic-obligations.json",
        "program-artifacts.json",
        "program-pairs.json",
        "feature-contract.json",
        "corpus-lock.json",
        "compiler-release-lock.json",
        "semantic-models.json",
        "semantic-model-omissions.json",
        "semantic-obligations.json",
        "obligation-results.json",
        "execution-attempts.json",
        "witnesses.json",
        "replays.json",
        "validator-links.json",
        "feature-links.json",
        "task-results.json",
        "source-results.json",
        "evidence-lineage.json",
        "pair-classifications.json",
        "strict-decision.json",
        "screening-decision.json",
        "selected-decision.json",
        "environment.json",
        "checksums.json",
        "ci-attestation.json",
    }
)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid candidate bundle JSON: {path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"candidate bundle JSON is not an object: {path}")
    return value


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _record_set(value: Mapping[str, Any], name: str) -> list[dict[str, Any]]:
    records = value.get("records")
    if not isinstance(records, list) or not all(
        isinstance(row, dict) for row in records
    ):
        raise ValueError(f"{name} does not contain an object record set")
    if value.get("record_count") != len(records):
        raise ValueError(f"{name} record count mismatch")
    return records

def _bundle_regular_files(
    root: Path, *, excluded: frozenset[str] = frozenset()
) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError(f"candidate bundle contains a symlink: {relative}")
        if path.is_file() and relative not in excluded:
            files.append(path)
    return files



def _candidate_bundle_content_inputs(
    root: Path, manifest: Mapping[str, Any]
) -> dict[str, Any]:
    normalized_manifest = dict(manifest)
    normalized_manifest.pop("candidate_bundle_content_id", None)
    excluded = {
        "candidate-manifest.json",
        "checksums.json",
        "ci-attestation.json",
    }
    files = {
        path.relative_to(root).as_posix(): {
            "sha256": _sha256(path),
            "size": path.stat().st_size,
        }
        for path in _bundle_regular_files(
            root, excluded=frozenset(excluded)
        )
    }
    return {
        "schema_version": CANDIDATE_BUNDLE_SCHEMA_VERSION,
        "manifest": normalized_manifest,
        "files": files,
    }


def candidate_bundle_content_id(content_inputs: Mapping[str, Any]) -> str:
    return identity_hash(
        "candidate_bundle_content", dict(content_inputs)
    )


def finalize_candidate_bundle(
    root: Path,
    *,
    manifest: Mapping[str, Any],
    ci_attestation: Mapping[str, Any],
) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    candidate_manifest = dict(manifest)
    candidate_manifest["schema_version"] = CANDIDATE_BUNDLE_SCHEMA_VERSION
    content_id = candidate_bundle_content_id(
        _candidate_bundle_content_inputs(root, candidate_manifest)
    )
    candidate_manifest["candidate_bundle_content_id"] = content_id
    _write_json(root / "candidate-manifest.json", candidate_manifest)
    attestation = dict(ci_attestation)
    if attestation.get("artifact_sha256") == "$candidate_bundle_content_id":
        attestation["artifact_sha256"] = content_id
    attestation["candidate_bundle_content_id"] = content_id
    _write_json(root / "ci-attestation.json", attestation)
    files = {
        path.relative_to(root).as_posix(): {
            "sha256": _sha256(path),
            "size": path.stat().st_size,
        }
        for path in _bundle_regular_files(
            root, excluded=frozenset({"checksums.json"})
        )
    }
    _write_json(
        root / "checksums.json",
        {
            "schema_version": CANDIDATE_BUNDLE_SCHEMA_VERSION,
            "algorithm": "sha256",
            "files": files,
        },
    )
    return candidate_manifest


def candidate_ci_provenance_valid(
    attestation: Mapping[str, Any],
    *,
    cryptographically_verified: bool = False,
) -> bool:
    if not cryptographically_verified:
        return False
    if (
        attestation.get("provenance_kind") != "github_actions"
        or attestation.get("trusted_event") is not True
        or attestation.get("signed_attestation_expected") is not True
        or not isinstance(attestation.get("github_run_id"), int)
        or int(attestation["github_run_id"]) <= 0
    ):
        return False
    return all(
        isinstance(value, str)
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
        for value in (
            attestation.get("repository_commit"),
            attestation.get("workflow_revision"),
        )
    )


def _assert_relative_logical_paths(value: Any, location: str = "$identity") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            _assert_relative_logical_paths(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _assert_relative_logical_paths(child, f"{location}[{index}]")
    elif isinstance(value, str):
        if value.startswith("/") or PurePosixPath(value).is_absolute():
            raise ValueError(
                f"absolute path in logical identity input: {location}"
            )

def _task_inputs_verified(task: Mapping[str, Any]) -> bool:
    task_source = task.get("source_hash_before")
    task_dependency = task.get("dependency_graph_before")
    if (
        not isinstance(task_source, str)
        or task_source != task.get("source_hash_after")
        or task_dependency != task.get("dependency_graph_after")
        or task_dependency is None
    ):
        return False
    for field in ("old_result", "new_result"):
        result = task.get(field)
        if result is None:
            continue
        if not isinstance(result, Mapping):
            return False
        source_before = result.get("source_hash_before")
        dependency_before = result.get(
            "dependency_graph_before",
            result.get("dependency_lock_hash_before"),
        )
        dependency_after = result.get(
            "dependency_graph_after",
            result.get("dependency_lock_hash_after"),
        )
        dependency_matches = dependency_before == task_dependency or (
            dependency_before is None
            and task.get("dependency_graph_kind") == "verified_empty"
        )
        if (
            source_before != task_source
            or source_before != result.get("source_hash_after")
            or not dependency_matches
            or dependency_before != dependency_after
            or result.get("source_unchanged", True) is False
            or result.get("dependency_lock_unchanged", True) is False
        ):
            return False
    return True


def expected_task_classification(
    task: Mapping[str, Any],
    pair_classification_by_id: Mapping[str, str],
) -> str | None:
    if not _task_inputs_verified(task):
        return "source_mutated"
    lane = task.get("lane")
    if lane == "equivalence":
        classifications = [
            pair_classification_by_id[str(pair_id)]
            for pair_id in task.get("program_pair_ids", [])
        ]
        for side in ("old", "new"):
            result = task.get(f"{side}_result")
            if not isinstance(result, dict) or "primary_exit_code" not in result:
                continue
            if (
                result.get("build_timed_out")
                or result.get("primary_exit_code") != 0
            ):
                return f"{side}_build_failed"
            if not task.get("equivalence_required") and not classifications:
                continue
            if result.get("uplc_extraction_timed_out") or result.get(
                "uplc_extraction_exit_code"
            ) not in {None, 0}:
                return f"{side}_uplc_extraction_failed"
            if result.get("blueprint_present") is False:
                return f"{side}_blueprint_missing"
            if result.get("blueprint_malformed") is True:
                compatibility = result.get("blueprint_compatibility")
                status = (
                    compatibility.get("status")
                    if isinstance(compatibility, dict)
                    else "blueprint_malformed"
                )
                return f"{side}_{status}"
            if result.get("abi_inspection_status") == "unverified":
                return "compiled_abi_unverified"
        if not classifications:
            return (
                "missing_evidence"
                if task.get("equivalence_required")
                else "not_applicable"
            )
        if all(
            classification
            in {
                "identical",
                "equivalent_under_raw_model",
                "bounded_equivalent",
            }
            for classification in classifications
        ):
            return "equivalence_passed"
        return classifications[0]
    old = task.get("old_result")
    new = task.get("new_result")
    if not isinstance(old, dict) or not isinstance(new, dict):
        return None
    if lane == "negative-diagnostic":
        expected_diagnostic = task.get("expected_diagnostic")
        if not isinstance(expected_diagnostic, str):
            return None
        expression = re.compile(expected_diagnostic)
        old_match = old.get("exit_code") not in {None, 0} and bool(
            expression.search(str(old.get("diagnostic_text", "")))
        )
        new_match = new.get("exit_code") not in {None, 0} and bool(
            expression.search(str(new.get("diagnostic_text", "")))
        )
        if old_match and new_match:
            return "expected_negative_diagnostic"
        return "old_lane_failed" if not old_match else "new_lane_failed"
    if old.get("timed_out") or old.get("exit_code") != 0:
        return (
            "old_build_failed"
            if lane in {"compile", "config"}
            else "old_lane_failed"
        )
    if new.get("timed_out") or new.get("exit_code") != 0:
        return (
            "new_build_failed"
            if lane in {"compile", "config"}
            else "new_lane_failed"
        )
    return {
        "compile": "compile_passed",
        "check": "check_passed",
        "bench": "benchmark_passed",
        "config": "configuration_passed",
        "docs": "documentation_passed",
    }.get(str(lane))




def verify_candidate_bundle(path: Path) -> dict[str, Any]:
    root = path.expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"candidate bundle is not a directory: {root}")
    missing = sorted(name for name in REQUIRED_BUNDLE_FILES if not (root / name).is_file())
    if missing:
        raise ValueError("candidate bundle is incomplete; missing=" + ", ".join(missing))
    checksums = _read_json(root / "checksums.json")
    if checksums.get("schema_version") != CANDIDATE_BUNDLE_SCHEMA_VERSION:
        raise ValueError("unsupported candidate checksum schema")
    checksum_files = checksums.get("files")
    if not isinstance(checksum_files, dict):
        raise ValueError("candidate checksum table is invalid")
    actual_files = {
        child.relative_to(root).as_posix()
        for child in _bundle_regular_files(
            root, excluded=frozenset({"checksums.json"})
        )
    }
    if set(checksum_files) != actual_files:
        raise ValueError("candidate checksum file inventory mismatch")
    for name, record in checksum_files.items():
        if not isinstance(record, dict):
            raise ValueError(f"candidate checksum record is invalid: {name}")
        file_path = root / name
        if _sha256(file_path) != record.get("sha256"):
            raise ValueError(f"candidate checksum mismatch: {name}")
        if file_path.stat().st_size != record.get("size"):
            raise ValueError(f"candidate size mismatch: {name}")

    manifest = _read_json(root / "candidate-manifest.json")
    if manifest.get("schema_version") != CANDIDATE_BUNDLE_SCHEMA_VERSION:
        raise ValueError("unsupported candidate bundle schema")
    expected_content_id = candidate_bundle_content_id(
        _candidate_bundle_content_inputs(root, manifest)
    )
    if manifest.get("candidate_bundle_content_id") != expected_content_id:
        raise ValueError("candidate bundle content identity mismatch")
    identity_inputs = manifest.get("evidence_identity_inputs")
    if not isinstance(identity_inputs, dict):
        raise ValueError("candidate evidence identity inputs are missing")
    for identity_field, filename in (
        ("feature_contract_sha256", "feature-contract.json"),
        ("corpus_lock_sha256", "corpus-lock.json"),
        ("release_lock_sha256", "compiler-release-lock.json"),
    ):
        if identity_inputs.get(identity_field) != _sha256(root / filename):
            raise ValueError(
                f"candidate input checksum mismatch: {filename}"
            )
    _assert_relative_logical_paths(identity_inputs)
    expected_run_id = evidence_run_id(identity_inputs)
    if manifest.get("evidence_run_id") != expected_run_id:
        raise ValueError("candidate evidence run identity mismatch")
    checker_configuration = manifest.get("checker_configuration")
    if not isinstance(checker_configuration, dict):
        raise ValueError("candidate checker configuration is missing")
    checker_configuration_payload = dict(checker_configuration)
    configured_id = checker_configuration_payload.pop(
        "checker_configuration_id", None
    )
    if checker_configuration_id(checker_configuration_payload) != configured_id:
        raise ValueError("candidate checker configuration identity mismatch")
    if identity_inputs.get("checker_configuration_id") != configured_id:
        raise ValueError("evidence run has wrong checker configuration")
    if identity_inputs.get("checker_implementation_id") != checker_configuration.get(
        "checker_implementation_id"
    ):
        raise ValueError("evidence run has wrong checker implementation")
    compiler_records: dict[str, Mapping[str, Any]] = {}
    for role, identity_field in (
        ("base_compiler", "base_compiler_artifact_id"),
        ("candidate_compiler", "candidate_compiler_artifact_id"),
    ):
        compiler = manifest.get(role)
        if not isinstance(compiler, dict):
            raise ValueError(f"candidate bundle is missing {role} provenance")
        compiler_records[role] = compiler
        artifact_identity = {
            "artifact_kind": compiler.get("artifact_kind"),
            "source_tree_sha256": compiler.get("source_tree_sha256"),
            "commit_sha": compiler.get("source_commit"),
            "binary_sha256": compiler.get("binary_sha256"),
            "target": compiler.get("target"),
            "build_command": compiler.get("build_command"),
        }
        expected_compiler_id = hashlib.sha256(
            canonical_json(artifact_identity).encode("utf-8")
        ).hexdigest()
        if (
            compiler.get("artifact_id") != expected_compiler_id
            or identity_inputs.get(identity_field) != expected_compiler_id
        ):
            raise ValueError(f"{role} identity mismatch")
    candidate_compiler = compiler_records["candidate_compiler"]
    source_commit = candidate_compiler.get("source_commit")
    candidate_clean = bool(
        candidate_compiler.get("artifact_kind") == "local"
        and candidate_compiler.get("dirty") is False
        and candidate_compiler.get("untracked_source_manifest") == []
    )
    candidate_committed = bool(
        candidate_compiler.get("reproducible_from_commit") is True
        and isinstance(source_commit, str)
        and len(source_commit) == 40
        and all(character in "0123456789abcdef" for character in source_commit)
    )
    if (
        manifest.get("candidate_source_clean") is not candidate_clean
        or manifest.get("candidate_source_committed")
        is not candidate_committed
        or manifest.get("development_only")
        is not (not candidate_clean or not candidate_committed)
    ):
        raise ValueError("candidate source provenance flags are inconsistent")

    program_artifacts = _record_set(
        _read_json(root / "program-artifacts.json"), "program-artifacts.json"
    )
    artifact_by_id: dict[str, dict[str, Any]] = {}
    for artifact in program_artifacts:
        try:
            serialized = bytes.fromhex(str(artifact["serialized_script_bytes_hex"]))
        except ValueError as error:
            raise ValueError("program artifact has invalid serialized bytes") from error
        expected_artifact_id = program_artifact_id(
            serialized,
            str(artifact["plutus_version"]),
            str(artifact["serialization_format"]),
        )
        if artifact.get("program_artifact_id") != expected_artifact_id:
            raise ValueError("program artifact identity mismatch")
        if expected_artifact_id in artifact_by_id:
            raise ValueError("duplicate program artifact identity")
        if hashlib.sha256(serialized).hexdigest() != artifact.get("script_sha256"):
            raise ValueError("program artifact script checksum mismatch")
        if len(serialized) != artifact.get("script_size"):
            raise ValueError("program artifact size mismatch")
        artifact_by_id[expected_artifact_id] = artifact

    program_pairs = _record_set(
        _read_json(root / "program-pairs.json"), "program-pairs.json"
    )
    pair_by_id: dict[str, dict[str, Any]] = {}
    for pair in program_pairs:
        old_id = pair["old_program_artifact"]["program_artifact_id"]
        new_id = pair["new_program_artifact"]["program_artifact_id"]
        if old_id not in artifact_by_id or new_id not in artifact_by_id:
            raise ValueError("program pair references an unknown artifact")
        for side, artifact_id_value in (
            ("old_program_artifact", old_id),
            ("new_program_artifact", new_id),
        ):
            embedded = pair[side]
            canonical = artifact_by_id[artifact_id_value]
            for field in (
                "program_artifact_id",
                "script_sha256",
                "script_size",
                "plutus_version",
                "serialization_format",
            ):
                if embedded.get(field) != canonical.get(field):
                    raise ValueError(
                        f"program pair has inconsistent {side} metadata"
                    )
        if (
            pair["old_program_artifact"].get("compiler_artifact_id")
            != compiler_records["base_compiler"]["artifact_id"]
            or pair["new_program_artifact"].get("compiler_artifact_id")
            != compiler_records["candidate_compiler"]["artifact_id"]
        ):
            raise ValueError("program pair has wrong compiler provenance")
        abi_id = verified_abi_id(pair["verified_abi"])
        if abi_id != pair.get("verified_abi_id"):
            raise ValueError("verified ABI identity mismatch")
        expected_pair_id = program_pair_id(old_id, new_id, abi_id)
        if pair.get("program_pair_id") != expected_pair_id:
            raise ValueError("program pair identity mismatch")
        if expected_pair_id in pair_by_id:
            raise ValueError("duplicate program pair identity")
        pair_by_id[expected_pair_id] = pair
    global_pairs = _record_set(
        _read_json(root / "global-program-pairs.json"),
        "global-program-pairs.json",
    )
    if global_pairs != program_pairs:
        raise ValueError("global program pair plan changed after planning")

    semantic_models = _record_set(
        _read_json(root / "semantic-models.json"), "semantic-models.json"
    )
    model_by_id: dict[str, dict[str, Any]] = {}
    for model in semantic_models:
        expected_model_id = semantic_model_id(
            model["input_model"], int(model["semantic_runtime_bound"])
        )
        if model.get("semantic_model_id") != expected_model_id:
            raise ValueError("semantic model identity mismatch")
        if expected_model_id in model_by_id:
            raise ValueError("duplicate semantic model identity")
        model_by_id[expected_model_id] = model

    obligations = _record_set(
        _read_json(root / "semantic-obligations.json"),
        "semantic-obligations.json",
    )
    global_obligations = _record_set(
        _read_json(root / "global-semantic-obligations.json"),
        "global-semantic-obligations.json",
    )
    if global_obligations != obligations:
        raise ValueError("global semantic obligation plan changed after planning")
    obligation_by_id: dict[str, dict[str, Any]] = {}
    for obligation in obligations:
        pair_id = str(obligation["program_pair_id"])
        model_id = str(obligation["semantic_model_id"])
        if pair_id not in pair_by_id or model_id not in model_by_id:
            raise ValueError("semantic obligation has an unknown parent")
        expected_obligation_id = logical_obligation_id(
            pair_id, model_id, str(obligation["obligation_kind"])
        )
        if obligation.get("logical_obligation_id") != expected_obligation_id:
            raise ValueError("logical obligation identity mismatch")
        if expected_obligation_id in obligation_by_id:
            raise ValueError("duplicate logical obligation identity")
        obligation_by_id[expected_obligation_id] = obligation

    executions = _record_set(
        _read_json(root / "execution-attempts.json"),
        "execution-attempts.json",
    )
    execution_by_id: dict[str, dict[str, Any]] = {}
    for execution in executions:
        _assert_relative_logical_paths(execution["execution_plan"])
        expected_execution_id = execution_attempt_id_from_record(execution)
        if execution.get("execution_attempt_id") != expected_execution_id:
            raise ValueError("execution attempt identity mismatch")
        if execution.get("checker_configuration_id") != configured_id:
            raise ValueError("execution attempt has wrong checker configuration")
        if expected_execution_id in execution_by_id:
            raise ValueError("duplicate execution attempt identity")
        if execution.get("checker_implementation_id") != checker_configuration.get(
            "checker_implementation_id"
        ):
            raise ValueError("execution attempt has wrong checker implementation")
        execution_by_id[expected_execution_id] = execution

    witnesses = _record_set(_read_json(root / "witnesses.json"), "witnesses.json")
    witness_by_id: dict[str, dict[str, Any]] = {}
    for witness in witnesses:
        witness_id_value = str(witness.get("witness_id"))
        if candidate_witness_id(witness) != witness_id_value:
            raise ValueError("witness identity mismatch")
        if witness_id_value in witness_by_id:
            raise ValueError("duplicate witness identity")
        protocol_witness = {
            key: witness[key] for key in WITNESS_FIELDS if key in witness
        }
        validate_witness_record(protocol_witness, {})
        witness_by_id[witness_id_value] = witness

    replays = _record_set(_read_json(root / "replays.json"), "replays.json")
    replay_by_id: dict[str, dict[str, Any]] = {}
    for replay in replays:
        replay_id_value = str(replay.get("replay_id"))
        if replay_id(replay) != replay_id_value:
            raise ValueError("replay identity mismatch")
        if replay_id_value in replay_by_id:
            raise ValueError("duplicate replay identity")
        replay_by_id[replay_id_value] = replay

    results = _record_set(
        _read_json(root / "obligation-results.json"),
        "obligation-results.json",
    )
    result_by_obligation: dict[str, dict[str, Any]] = {}
    attempt_parent: dict[str, str] = {}
    for result in results:
        obligation_id = str(result["logical_obligation_id"])
        if obligation_id not in obligation_by_id:
            raise ValueError("obligation result has an unknown logical parent")
        if result.get("status") == "pending":
            raise ValueError("final candidate bundle contains a pending obligation")
        execution_id = str(result["execution_attempt_id"])
        if execution_id not in execution_by_id:
            raise ValueError("obligation result has a wrong execution parent")
        obligation = obligation_by_id[obligation_id]
        execution = execution_by_id[execution_id]
        for field in (
            "program_pair_id",
            "semantic_model_id",
            "obligation_kind",
        ):
            if result.get(field) != obligation.get(field):
                raise ValueError(f"obligation result has wrong {field} parent")
        if (
            result.get("checker_configuration_id") != configured_id
            or result.get("checker_implementation_id")
            != checker_configuration.get("checker_implementation_id")
            or result.get("checker_configuration_id")
            != execution.get("checker_configuration_id")
            or result.get("checker_implementation_id")
            != execution.get("checker_implementation_id")
            or result.get("generated_source_sha256")
            != execution.get("generated_source_sha256")
        ):
            raise ValueError(
                "obligation result has inconsistent execution configuration"
            )
        generated_source_hash = result.get("generated_source_sha256")
        generated_source_path = result.get("generated_source_path")
        if generated_source_hash is None:
            if generated_source_path is not None:
                raise ValueError("source-free result has a generated source path")
        else:
            if not isinstance(generated_source_path, str):
                raise ValueError("result is missing its generated source path")
            logical_path = PurePosixPath(generated_source_path)
            if logical_path.is_absolute() or ".." in logical_path.parts:
                raise ValueError("result generated source path is not relative")
            bundled_source = root / logical_path
            if (
                not bundled_source.is_file()
                or _sha256(bundled_source) != generated_source_hash
            ):
                raise ValueError("result generated source checksum mismatch")
        execution_plan = execution["execution_plan"]
        planned_ids = execution_plan.get("planned_logical_obligation_ids")
        if (
            not isinstance(planned_ids, list)
            or obligation_id not in planned_ids
            or any(item not in obligation_by_id for item in planned_ids)
            or execution_plan.get("program_pair_id")
            != result.get("program_pair_id")
            or execution_plan.get("semantic_model_id")
            != result.get("semantic_model_id")
        ):
            raise ValueError("obligation result has inconsistent execution plan")
        if obligation_attempt_id_from_record(result) != result.get(
            "obligation_attempt_id"
        ):
            raise ValueError("obligation attempt identity mismatch")
        attempt_id_value = str(result["obligation_attempt_id"])
        previous_parent = attempt_parent.setdefault(attempt_id_value, obligation_id)
        if previous_parent != obligation_id:
            raise ValueError(
                "one obligation attempt ID is used by different logical obligations"
            )
        if obligation_result_id(result) != result.get("evidence_result_id"):
            raise ValueError("obligation result identity mismatch")
        if obligation_id in result_by_obligation:
            raise ValueError("logical obligation has more than one final result")
        witness_reference = result.get("witness_reference")
        replay_reference = result.get("replay_reference")
        if witness_reference is not None:
            witness = witness_by_id.get(str(witness_reference))
            if witness is None:
                raise ValueError("obligation result references an unknown witness")
            if witness.get("producing_logical_obligation_id") != obligation_id:
                raise ValueError("witness has wrong logical obligation parent")
            if witness.get("producing_obligation_attempt_id") != attempt_id_value:
                raise ValueError("witness has wrong obligation attempt parent")
            if witness.get("producing_execution_attempt_id") != execution_id:
                raise ValueError("witness has wrong execution attempt parent")
            validate_witness_record(
                {
                    key: witness[key]
                    for key in WITNESS_FIELDS
                    if key in witness
                },
                {
                    "program_pair_id": result["program_pair_id"],
                    "logical_obligation_id": obligation_id,
                    "semantic_model_id": result["semantic_model_id"],
                    "checker_implementation_id": result[
                        "checker_implementation_id"
                    ],
                },
            )
        if replay_reference is not None:
            replay = replay_by_id.get(str(replay_reference))
            if replay is None:
                raise ValueError("obligation result references an unknown replay")
            if replay.get("logical_obligation_id") != obligation_id:
                raise ValueError("replay has wrong logical obligation parent")
            if replay.get("obligation_attempt_id") != attempt_id_value:
                raise ValueError("replay has wrong obligation attempt parent")
            if replay.get("execution_attempt_id") != execution_id:
                raise ValueError("replay has wrong execution attempt parent")
            if replay.get("witness_id") != witness_reference:
                raise ValueError("replay has wrong witness parent")
            if replay.get("confirmed") is not True:
                raise ValueError("replay did not confirm the semantic difference")
            if result.get("obligation_kind") not in {
                "observational_equivalence",
                "ledger_observational_equivalence",
            }:
                raise ValueError("replay is not bound to equivalence")
            pair = pair_by_id[str(result["program_pair_id"])]
            if (
                replay.get("old_program_artifact_id")
                != pair["old_program_artifact"]["program_artifact_id"]
                or replay.get("new_program_artifact_id")
                != pair["new_program_artifact"]["program_artifact_id"]
                or replay.get("old_script_sha256")
                != pair["old_program_artifact"]["script_sha256"]
                or replay.get("new_script_sha256")
                != pair["new_program_artifact"]["script_sha256"]
            ):
                raise ValueError("replay has wrong program artifacts")
        result_by_obligation[obligation_id] = result
    if set(result_by_obligation) != set(obligation_by_id):
        raise ValueError("not every planned logical obligation has one final result")
    referenced_witnesses = {
        str(result["witness_reference"])
        for result in results
        if result.get("witness_reference") is not None
    }
    referenced_replays = {
        str(result["replay_reference"])
        for result in results
        if result.get("replay_reference") is not None
    }
    if referenced_witnesses != set(witness_by_id):
        raise ValueError("candidate bundle contains unreferenced witnesses")
    if referenced_replays != set(replay_by_id):
        raise ValueError("candidate bundle contains unreferenced replays")

    omissions = _record_set(
        _read_json(root / "semantic-model-omissions.json"),
        "semantic-model-omissions.json",
    )
    omitted_models: set[tuple[str, str]] = set()
    for omission in omissions:
        if omission.get("status") != "ledger_model_unsupported":
            raise ValueError("unsupported model omission has an invalid status")
        if omission.get("semantic_model_id") not in model_by_id:
            raise ValueError("model omission references an unknown semantic model")
        omission_key = (
            str(omission.get("program_pair_id")),
            str(omission.get("semantic_model_id")),
        )
        if (
            omission_key in omitted_models
            or omission_key[0] not in pair_by_id
            or model_by_id[omission_key[1]]
            .get("input_model", {})
            .get("supported")
            is not False
        ):
            raise ValueError("model omission identity or support state is invalid")
        omitted_models.add(omission_key)
        if omission.get("planned_obligation_kinds") != [
            "ledger_domain_non_vacuity",
            "old_program_completion",
            "new_program_completion",
            "ledger_observational_equivalence",
        ]:
            raise ValueError("model omission has invalid planned obligations")
        if any(
            obligation["semantic_model_id"] == omission["semantic_model_id"]
            for obligation in obligations
        ):
            raise ValueError("omitted unsupported model instantiated obligations")

    validator_links = _record_set(
        _read_json(root / "validator-links.json"), "validator-links.json"
    )
    feature_links = _record_set(
        _read_json(root / "feature-links.json"), "feature-links.json"
    )
    task_results = _record_set(
        _read_json(root / "task-results.json"), "task-results.json"
    )
    source_results = _record_set(
        _read_json(root / "source-results.json"), "source-results.json"
    )
    evidence_ids = {str(row["evidence_result_id"]) for row in results}
    result_id_by_obligation = {
        str(row["logical_obligation_id"]): str(row["evidence_result_id"])
        for row in results
    }
    link_identity_fields = {
        "validator": "handler_pair_id",
        "feature": "feature_id",
        "task": "task_id",
        "source": "source_id",
    }
    seen_link_ids: dict[str, set[str]] = {
        name: set() for name in link_identity_fields
    }
    for name, links in (
        ("validator", validator_links),
        ("feature", feature_links),
        ("task", task_results),
        ("source", source_results),
    ):
        for link in links:
            link_id = link.get(link_identity_fields[name])
            if (
                not isinstance(link_id, str)
                or link_id in seen_link_ids[name]
            ):
                raise ValueError(f"duplicate or missing {name} link identity")
            seen_link_ids[name].add(link_id)
            for field in (
                "program_pair_ids",
                "logical_obligation_ids",
                "evidence_result_ids",
            ):
                values = link.get(field)
                if (
                    not isinstance(values, list)
                    or len(values) != len(set(values))
                ):
                    raise ValueError(f"{name} link has invalid {field}")
            for pair_id in link.get("program_pair_ids", []):
                if pair_id not in pair_by_id:
                    raise ValueError(f"{name} link references an unknown program pair")
            for obligation_id in link.get("logical_obligation_ids", []):
                if obligation_id not in obligation_by_id:
                    raise ValueError(f"{name} link references an unknown obligation")
            for evidence_id in link.get("evidence_result_ids", []):
                if evidence_id not in evidence_ids:
                    raise ValueError(f"{name} link references unknown evidence")
            linked_pairs = set(link["program_pair_ids"])
            linked_obligations = set(link["logical_obligation_ids"])
            expected_evidence = {
                result_id_by_obligation[obligation_id]
                for obligation_id in linked_obligations
            }
            if (
                set(link["evidence_result_ids"]) != expected_evidence
                or any(
                    obligation_by_id[obligation_id]["program_pair_id"]
                    not in linked_pairs
                    for obligation_id in linked_obligations
                )
            ):
                raise ValueError(f"{name} link has inconsistent evidence parents")
    task_by_id = {
        str(row["task_id"]): row for row in task_results
    }
    source_by_id = {
        str(row["source_id"]): row for row in source_results
    }
    for task_id, task in task_by_id.items():
        source_id = str(task.get("source_id"))
        if (
            source_id not in source_by_id
            or task_id not in source_by_id[source_id].get("task_ids", [])
        ):
            raise ValueError("task link has an inconsistent source parent")
    for source_id, source in source_by_id.items():
        expected_tasks = {
            task_id
            for task_id, task in task_by_id.items()
            if task.get("source_id") == source_id
        }
        if set(source.get("task_ids", [])) != expected_tasks:
            raise ValueError("source link has incomplete task consumers")

    lineage = _record_set(
        _read_json(root / "evidence-lineage.json"),
        "evidence-lineage.json",
    )
    lineage_by_result = {
        str(row["evidence_result_id"]): row for row in lineage
    }
    if len(lineage_by_result) != len(lineage):
        raise ValueError("duplicate evidence lineage identity")
    if set(lineage_by_result) != evidence_ids:
        raise ValueError("evidence lineage is incomplete")
    for result in results:
        row = lineage_by_result[str(result["evidence_result_id"])]
        if row.get("logical_obligation_id") != result.get("logical_obligation_id"):
            raise ValueError("evidence lineage has wrong logical parent")
        if row.get("obligation_attempt_id") != result.get("obligation_attempt_id"):
            raise ValueError("evidence lineage has wrong obligation attempt parent")
        if row.get("execution_attempt_id") != result.get("execution_attempt_id"):
            raise ValueError("evidence lineage has wrong execution attempt parent")
    cache_reused_obligations = sum(
        row.get("cache_reused") is True for row in lineage
    )
    executed_unique_obligations = len(results) - cache_reused_obligations
    executed_batches = {
        (result["program_pair_id"], result["semantic_model_id"])
        for result in results
        if lineage_by_result[result["evidence_result_id"]].get(
            "cache_reused"
        )
        is not True
    }

    pair_classifications, changed_counts = classify_changed_pairs(
        program_pairs, semantic_models, obligations, results
    )
    serialized_classifications = _record_set(
        _read_json(root / "pair-classifications.json"),
        "pair-classifications.json",
    )
    if pair_classifications != serialized_classifications:
        raise ValueError("changed-pair classification mismatch")
    if changed_counts.get("raw_partition_exhaustive") != 1:
        raise ValueError("changed-pair raw classification is not exhaustive")
    pair_classification_by_id = {
        str(row["program_pair_id"]): str(row["classification"])
        for row in pair_classifications
    }
    passing_task_classifications = {
        "equivalence_passed",
        "compile_passed",
        "check_passed",
        "benchmark_passed",
        "configuration_passed",
        "documentation_passed",
        "expected_negative_diagnostic",
        "not_applicable",
    }
    for task in task_results:
        expected_classification = expected_task_classification(
            task, pair_classification_by_id
        )
        if expected_classification is None:
            if task.get("classification") in passing_task_classifications:
                raise ValueError(
                    "candidate task has unverified passing classification"
                )
        elif task.get("classification") != expected_classification:
            raise ValueError("candidate task classification mismatch")
        if task.get("lane") != "equivalence" and task.get(
            "original_classification"
        ) != task.get("classification"):
            raise ValueError("candidate task original classification mismatch")
        expected_inputs_verified = _task_inputs_verified(task)
        if (
            task.get("source_immutable") is not expected_inputs_verified
            or task.get("inputs_verified") is not expected_inputs_verified
        ):
            raise ValueError("candidate task source invariant mismatch")
    for source_id, source in source_by_id.items():
        source_tasks = [
            task
            for task in task_results
            if task.get("source_id") == source_id
        ]
        expected_inputs_verified = all(
            _task_inputs_verified(task) for task in source_tasks
        )
        expected_source_inputs = sorted(
            {
                canonical_json(
                    {
                        "source_hash": task.get("source_hash_before"),
                        "dependency_graph": task.get(
                            "dependency_graph_before"
                        ),
                        "adapter_hash": task.get("adapter_hash"),
                    }
                )
                for task in source_tasks
            }
        )
        if (
            source.get("inputs_verified") is not expected_inputs_verified
            or source.get("source_inputs") != expected_source_inputs
        ):
            raise ValueError("candidate source input verification mismatch")
    global_plan = _read_json(root / "global-plan.json")
    expected_plan_counts = {
        "program_artifacts": len(program_artifacts),
        "unique_program_pairs": len(program_pairs),
        "semantic_models": len(semantic_models),
        "unique_semantic_obligations": len(obligations),
        "model_omissions": len(omissions),
        "validator_links": len(validator_links),
        "feature_links": len(feature_links),
        "task_links": len(task_results),
        "source_links": len(source_results),
        "pending_obligations": 0,
    }
    if (
        global_plan.get("schema_version")
        != CANDIDATE_BUNDLE_SCHEMA_VERSION
        or global_plan.get("evidence_run_id") != expected_run_id
        or global_plan.get("identity_conflicts") != []
        or global_plan.get("semantic_execution_started_after_plan_write")
        is not True
        or global_plan.get("phase_order")
        != [
            "build_and_discovery",
            "global_obligation_plan",
            "global_evidence_lookup",
            "semantic_execution",
            "linking_and_decisions",
        ]
        or global_plan.get("counts") != expected_plan_counts
    ):
        raise ValueError("candidate global plan invariants do not hold")
    counts = manifest.get("counts")
    if not isinstance(counts, dict):
        raise ValueError("candidate manifest counts are missing")
    if (
        counts.get("obligation_results") != len(results)
        or counts.get("pending_obligations") != 0
        or counts.get("cache_reused_obligations")
        != cache_reused_obligations
        or counts.get("executed_unique_obligations")
        != executed_unique_obligations
        or counts.get("semantic_execution_batches") != len(executed_batches)
    ):
        raise ValueError("candidate obligation count invariants do not hold")
    obligations_by_pair: dict[str, int] = {}
    for obligation in obligations:
        pair_id = str(obligation["program_pair_id"])
        obligations_by_pair[pair_id] = obligations_by_pair.get(pair_id, 0) + 1
    consumer_reuses = sum(
        obligations_by_pair.get(pair_id, 0)
        * max(
            0,
            sum(
                pair_id in task.get("program_pair_ids", [])
                for task in task_results
            )
            - 1,
        )
        for pair_id in pair_by_id
    )
    if counts.get("duplicate_solver_invocations_prevented") != (
        consumer_reuses + cache_reused_obligations
    ):
        raise ValueError("candidate deduplication count invariant does not hold")
    for name, value in global_plan.get("counts", {}).items():
        if counts.get(name) != value:
            raise ValueError(f"candidate global plan count mismatch: {name}")
    for name, value in changed_counts.items():
        if counts.get(name) != value:
            raise ValueError(f"candidate changed-pair count mismatch: {name}")
    attestation = _read_json(root / "ci-attestation.json")
    ci_provenance_valid = candidate_ci_provenance_valid(attestation)
    if (
        ci_provenance_valid
        and attestation.get("artifact_sha256") != expected_content_id
    ):
        raise ValueError("CI attestation artifact digest mismatch")
    expected_decisions = derive_candidate_decisions(
        evidence_run_id=expected_run_id,
        selected_policy=str(manifest["selected_policy"]),
        pair_classifications=pair_classifications,
        task_results=task_results,
        source_results=source_results,
        counts=counts,
        candidate_clean=candidate_clean,
        candidate_committed=candidate_committed,
        evidence_verified=True,
        ci_provenance_valid=ci_provenance_valid,
    )
    for policy, filename in (
        ("strict", "strict-decision.json"),
        ("screening", "screening-decision.json"),
        ("selected", "selected-decision.json"),
    ):
        if _read_json(root / filename) != expected_decisions[policy]:
            raise ValueError(f"candidate {policy} decision mismatch")
    if attestation.get("candidate_bundle_content_id") != expected_content_id:
        raise ValueError("CI attestation has wrong candidate bundle parent")
    return {
        "valid": True,
        "schema_version": CANDIDATE_BUNDLE_SCHEMA_VERSION,
        "candidate_bundle_content_id": expected_content_id,
        "evidence_run_id": expected_run_id,
        "checker_implementation_id": checker_configuration[
            "checker_implementation_id"
        ],
        "counts": counts,
        "strict_decision": expected_decisions["strict"]["decision"],
        "screening_decision": expected_decisions["screening"]["decision"],
        "selected_policy": manifest["selected_policy"],
        "strict_decision_id": expected_decisions["strict"]["decision_id"],
        "screening_decision_id": expected_decisions["screening"][
            "decision_id"
        ],
        "selected_decision_id": expected_decisions["selected"][
            "selected_decision_id"
        ],
        "selected_decision": expected_decisions["selected"][
            "selected_decision"
        ],
        "publishable": expected_decisions["selected"]["publishable"],
    }


def verify_attested_candidate_archive(
    archive: Path,
    *,
    repository: str,
    attestation_bundle: Path | None = None,
) -> dict[str, Any]:
    archive_path = archive.expanduser().resolve()
    if not archive_path.is_file():
        raise ValueError(
            f"candidate evidence archive is not a file: {archive_path}"
        )
    if not repository or "/" not in repository:
        raise ValueError("GitHub repository must use owner/name form")
    command = [
        "gh",
        "attestation",
        "verify",
        str(archive_path),
        "--repo",
        repository,
        "--signer-workflow",
        f"{repository}/.github/workflows/ci.yml",
        "--source-ref",
        "refs/heads/main",
        "--format",
        "json",
    ]
    if attestation_bundle is not None:
        command.extend(
            [
                "--bundle",
                str(attestation_bundle.expanduser().resolve()),
            ]
        )
    try:
        verified = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=120.0,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(
            "GitHub artifact attestation verification could not run"
        ) from error
    if verified.returncode != 0:
        detail = verified.stderr.strip() or verified.stdout.strip()
        raise ValueError(
            "GitHub artifact attestation verification failed"
            + (f": {detail}" if detail else "")
        )

    with tempfile.TemporaryDirectory(
        prefix="equiv-candidate-verify-"
    ) as temporary:
        extracted_root = Path(temporary)
        seen: set[str] = set()
        try:
            tar = tarfile.open(archive_path, mode="r:gz")
        except (OSError, tarfile.TarError) as error:
            raise ValueError("candidate evidence archive is invalid") from error
        with tar:
            for member in tar.getmembers():
                logical = PurePosixPath(member.name)
                if logical.is_absolute() or ".." in logical.parts:
                    raise ValueError(
                        "candidate archive contains an unsafe path"
                    )
                normalized = logical.as_posix().removeprefix("./")
                if normalized in {"", "."}:
                    continue
                if normalized in seen:
                    raise ValueError(
                        "candidate archive contains a duplicate path"
                    )
                seen.add(normalized)
                destination = extracted_root.joinpath(*logical.parts)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise ValueError(
                        "candidate archive contains a non-regular entry"
                    )
                source = tar.extractfile(member)
                if source is None:
                    raise ValueError(
                        "candidate archive member cannot be read"
                    )
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(source.read())

        internal = verify_candidate_bundle(extracted_root)
        manifest = _read_json(extracted_root / "candidate-manifest.json")
        attestation = _read_json(extracted_root / "ci-attestation.json")
        if not candidate_ci_provenance_valid(
            attestation, cryptographically_verified=True
        ):
            raise ValueError(
                "candidate archive has inconsistent CI provenance metadata"
            )
        decisions = derive_candidate_decisions(
            evidence_run_id=str(manifest["evidence_run_id"]),
            selected_policy=str(manifest["selected_policy"]),
            pair_classifications=_record_set(
                _read_json(extracted_root / "pair-classifications.json"),
                "pair-classifications.json",
            ),
            task_results=_record_set(
                _read_json(extracted_root / "task-results.json"),
                "task-results.json",
            ),
            source_results=_record_set(
                _read_json(extracted_root / "source-results.json"),
                "source-results.json",
            ),
            counts=dict(manifest["counts"]),
            candidate_clean=manifest.get("candidate_source_clean") is True,
            candidate_committed=(
                manifest.get("candidate_source_committed") is True
            ),
            evidence_verified=True,
            ci_provenance_valid=True,
        )
        selected = decisions["selected"]
        return internal | {
            "archive_sha256": _sha256(archive_path),
            "ci_provenance": "github_sigstore_verified",
            "strict_decision_id": decisions["strict"]["decision_id"],
            "screening_decision_id": decisions["screening"][
                "decision_id"
            ],
            "selected_decision_id": selected["selected_decision_id"],
            "selected_decision": selected["selected_decision"],
            "publishable": selected["publishable"],
        }
