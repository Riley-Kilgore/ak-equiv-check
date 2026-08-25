from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from .candidate_bundle import (
    CANDIDATE_BUNDLE_SCHEMA_VERSION,
    candidate_ci_provenance_valid,
    expected_task_classification,
    finalize_candidate_bundle,
    verify_candidate_bundle,
)
from .candidate_execution import execute_model, planned_model_obligations
from .candidate_policy import classify_changed_pairs, derive_candidate_decisions
from .compiler_artifacts import (
    compiler_from_manifest,
    verify_compiler_manifest,
    verify_release_lock,
)
from .config import (
    BLASTER_CONFIG_PATH,
    DEFAULT_WORK_ROOT,
    REPOSITORY_ROOT,
    load_blaster_config,
)
from .corpus import run_corpus
from .evidence import (
    GENERATED_LEAN_SCHEMA_VERSION,
    canonical_json,
    evidence_run_id,
    identity_hash,
    platform_identity,
)
from .evidence_store import EvidenceStore
from .models import (
    BlasterConfig,
    BlasterResult,
    InputModel,
    ProgramPairRecord,
    ScriptArtifact,
)
from .runner import compare_sentinel, write_json
from .semantics import validator_input_models
from .blaster import RealBlasterBackend

DEFAULT_RELEASE_LOCK = REPOSITORY_ROOT / "corpus" / "compiler_release.lock.json"
DEFAULT_SENTINEL = REPOSITORY_ROOT / "sentinel"


class _DiscoveryBackend:
    """Builds global plans without invoking Lean, Blaster, or a solver."""

    def __init__(self, config: BlasterConfig):
        self.config = config

    def compare(
        self,
        pair: ProgramPairRecord,
        input_model: InputModel,
        output_root: Path,
    ) -> BlasterResult:
        del pair, input_model, output_root
        return BlasterResult(
            status="blaster_unsupported",
            command=None,
            exit_code=None,
            duration_seconds=0.0,
            error="candidate phase A discovery only",
        )

    def replay(
        self,
        pair: ProgramPairRecord,
        input_model: InputModel,
        witness: dict[str, Any],
        output_root: Path,
    ) -> dict[str, Any]:
        del pair, input_model, witness, output_root
        raise RuntimeError("discovery backend cannot replay counterexamples")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid candidate input JSON: {path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"candidate input must contain an object: {path}")
    return value


def _records(path: Path, filename: str) -> list[dict[str, Any]]:
    wrapper = _load(path / filename)
    records = wrapper.get("records")
    if not isinstance(records, list) or not all(
        isinstance(row, dict) for row in records
    ):
        raise ValueError(f"invalid compact evidence record set: {path / filename}")
    if wrapper.get("record_count") != len(records):
        raise ValueError(f"record count mismatch: {path / filename}")
    return records


def _record_set(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": CANDIDATE_BUNDLE_SCHEMA_VERSION,
        "record_count": len(records),
        "records": records,
    }


def _merge_program_pair(
    previous: dict[str, Any], current: Mapping[str, Any]
) -> dict[str, Any]:
    union_fields = (
        "handler_pair_ids",
        "handler_references",
        "covered_feature_ids",
    )
    previous_core = json.loads(json.dumps(previous))
    current_core = json.loads(json.dumps(current))
    for field in union_fields:
        previous_core.pop(field, None)
        current_core.pop(field, None)
    for side in ("old_program_artifact", "new_program_artifact"):
        previous_core[side].pop("source_validator_references", None)
        current_core[side].pop("source_validator_references", None)
    if previous_core != current_core:
        raise ValueError(
            "program pair identity conflict: "
            f"{previous['program_pair_id']}"
        )
    for field in union_fields:
        values = {
            canonical_json(value): value
            for value in [*previous.get(field, []), *current.get(field, [])]
        }
        previous[field] = [values[key] for key in sorted(values)]
    for side in ("old_program_artifact", "new_program_artifact"):
        values = sorted(
            set(
                previous[side].get("source_validator_references", [])
                + list(
                    current[side].get("source_validator_references", [])
                )
            )
        )
        previous[side]["source_validator_references"] = values
    return previous


def _input_model(value: Mapping[str, Any]) -> InputModel:
    return InputModel(
        kind=str(value["kind"]),
        profile=str(value["profile"]),
        version=str(value["version"]),
        plutus_version=str(value["plutus_version"]),
        purpose=str(value["purpose"]),
        variables=tuple(dict(row) for row in value["variables"]),
        quantified_components=tuple(value["quantified_components"]),
        argument_order=tuple(value["argument_order"]),
        arity=int(value["arity"]),
        domain_expression=str(value["domain_expression"]),
        domain_assumptions=tuple(value["domain_assumptions"]),
        domain_witness=value.get("domain_witness"),
        observation=str(value["observation"]),
        non_vacuity=dict(value["non_vacuity"]),
        supported=bool(value.get("supported", True)),
        unsupported_reason=value.get("unsupported_reason"),
    )


def _program_pair(
    row: Mapping[str, Any], child_root: Path
) -> ProgramPairRecord:
    def artifact(side: str) -> ScriptArtifact:
        value = row[f"{side}_program_artifact"]
        relative = str(value["path"])
        return ScriptArtifact(
            path=child_root / relative,
            relative_path=relative,
            sha256=str(value["script_sha256"]),
            size=int(value["script_size"]),
            plutus_version=str(value["plutus_version"]),
            serialization_format=str(value["serialization_format"]),
            compiler_artifact_id=str(value["compiler_artifact_id"]),
            source_validator_references=tuple(
                value.get("source_validator_references", [])
            ),
            program_artifact_id=str(value["program_artifact_id"]),
        )

    return ProgramPairRecord(
        program_pair_id=str(row["program_pair_id"]),
        old_script=artifact("old"),
        new_script=artifact("new"),
        verified_abi_id=str(row["verified_abi_id"]),
        verified_abi=dict(row["verified_abi"]),
        plutus_version=str(row["plutus_version"]),
        handler_pair_ids=tuple(row.get("handler_pair_ids", [])),
        handler_references=tuple(
            dict(value) for value in row.get("handler_references", [])
        ),
        covered_feature_ids=tuple(row.get("covered_feature_ids", [])),
    )


def _result_summary(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    fields = (
        "command",
        "exit_code",
        "timed_out",
        "duration_seconds",
        "timeout_seconds",
        "stdout_sha256",
        "stderr_sha256",
        "source_hash_before",
        "source_hash_after",
        "dependency_graph_before",
        "diagnostic_text",
        "dependency_graph_after",
        "primary_exit_code",
        "source_unchanged",
        "dependency_lock_unchanged",
        "dependency_lock_hash_before",
        "dependency_lock_hash_after",
        "dependency_graph_before",
        "dependency_graph_after",
        "dependency_lock_bytes_unchanged",
        "dependency_lock_sha256_before",
        "dependency_lock_sha256_after",
        "build_timed_out",
        "uplc_extraction_exit_code",
        "uplc_extraction_timed_out",
        "blueprint_present",
        "blueprint_malformed",
        "blueprint_compatibility",
    )
    summary = {field: value.get(field) for field in fields if field in value}
    if "abi_inspection" in value:
        summary["abi_inspection_status"] = (
            "verified" if value["abi_inspection"] is not None else "unverified"
        )
    return summary

def _result_inputs_unchanged(
    value: Any,
    *,
    expected_source_hash: str,
    expected_dependency_graph: str | None,
) -> bool:
    if not isinstance(value, Mapping):
        return True
    source_before = value.get("source_hash_before")
    source_after = value.get("source_hash_after")
    dependency_before = value.get(
        "dependency_graph_before", value.get("dependency_lock_hash_before")
    )
    dependency_after = value.get(
        "dependency_graph_after", value.get("dependency_lock_hash_after")
    )
    return bool(
        source_before == expected_source_hash
        and source_before == source_after
        and dependency_before == expected_dependency_graph
        and dependency_before == dependency_after
        and value.get("source_unchanged", True) is not False
        and value.get("dependency_lock_unchanged", True) is not False
    )


def _task_record(
    row: Mapping[str, Any],
    *,
    program_pair_ids: list[str],
    logical_obligation_ids: list[str],
) -> dict[str, Any]:
    classification = str(
        row.get("final_classification", row.get("classification", "invalid"))
    )
    source_before = row.get("source_hash_before", row.get("source_hash"))
    source_after = row.get("source_hash_after", row.get("source_hash"))
    raw_dependency_before = row.get(
        "dependency_graph_before", row.get("dependency_lock_hash")
    )
    raw_dependency_after = row.get(
        "dependency_graph_after", row.get("dependency_lock_hash")
    )
    inputs_verified = bool(
        isinstance(source_before, str)
        and source_before == source_after
        and raw_dependency_before == raw_dependency_after
        and row.get("source_immutable") is True
        and all(
            _result_inputs_unchanged(
                row.get(field),
                expected_source_hash=source_before,
                expected_dependency_graph=raw_dependency_before,
            )
            for field in ("old_result", "new_result")
        )
    )
    dependency_before = raw_dependency_before
    dependency_after = raw_dependency_after
    dependency_graph_kind = "lockfile"
    if dependency_before is None and dependency_after is None:
        dependency_graph_kind = "verified_empty"
        dependency_before = identity_hash(
            "dependency_graph",
            {"state": "no_lockfile", "source_hash": source_before},
        )
        dependency_after = identity_hash(
            "dependency_graph",
            {"state": "no_lockfile", "source_hash": source_after},
        )
    return {
        "task_id": str(row["task_id"]),
        "source_id": str(row.get("source_id", "feature-sentinel")),
        "target_id": row.get("target_id"),
        "lane": str(row.get("lane", "equivalence")),
        "classification": classification,
        "original_classification": classification,
        "strict_relevance": bool(row.get("strict_relevance", True)),
        "equivalence_required": bool(row.get("equivalence_required", False)),
        "expected_outcome": row.get("expected_outcome"),
        "expected_diagnostic": row.get("expected_diagnostic"),
        "source_hash_before": source_before,
        "source_hash_after": source_after,
        "dependency_graph_before": dependency_before,
        "dependency_graph_after": dependency_after,
        "dependency_graph_kind": dependency_graph_kind,
        "adapter_hash": row.get("adapter_hash"),
        "timeout_seconds": row.get("timeout_seconds"),
        "old_result": _result_summary(row.get("old_result")),
        "new_result": _result_summary(row.get("new_result")),
        "source_immutable": inputs_verified,
        "inputs_verified": inputs_verified,
        "program_pair_ids": sorted(program_pair_ids),
        "logical_obligation_ids": sorted(logical_obligation_ids),
        "evidence_result_ids": [],
    }


def _local_attestation() -> dict[str, Any]:
    github_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    trusted_event = os.environ.get("GITHUB_EVENT_NAME") not in {
        "pull_request",
        "pull_request_target",
    }
    commit = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if (
        github_actions
        and trusted_event
        and len(commit) == 40
        and run_id.isdigit()
    ):
        return {
            "schema_version": "equiv-ci-attestation/v1",
            "provenance_kind": "github_actions",
            "repository_commit": commit,
            "workflow_revision": commit,
            "github_run_id": int(run_id),
            "github_run_attempt": int(
                os.environ.get("GITHUB_RUN_ATTEMPT", "1")
            ),
            "job_name": os.environ.get("GITHUB_JOB"),
            "trusted_event": True,
            "signed_attestation_expected": True,
            "artifact_sha256": None,
            "verification_result": "external_attestation_required",
        }
    return {
        "schema_version": "equiv-ci-attestation/v1",
        "provenance_kind": "local_development",
        "repository_commit": None,
        "workflow_revision": None,
        "github_run_id": None,
        "trusted_event": False,
        "signed_attestation_expected": False,
        "artifact_sha256": None,
        "verification_result": "not_ci_attested",
    }


def run_candidate_gate(
    *,
    base_compiler_manifest: Path,
    candidate_compiler_manifest: Path,
    feature_contract: Path,
    corpus_lock: Path,
    scope: set[str],
    resume: bool,
    policy: str,
    work_root: Path = DEFAULT_WORK_ROOT,
    blaster_config_path: Path = BLASTER_CONFIG_PATH,
    release_lock: Path = DEFAULT_RELEASE_LOCK,
    sentinel_package: Path = DEFAULT_SENTINEL,
    jobs: int = 1,
) -> dict[str, Any]:
    unknown_scope = scope - {"sentinel", "mandatory"}
    if unknown_scope or not scope:
        raise ValueError(
            "candidate gate scope must contain sentinel and/or mandatory"
        )
    if policy not in {"strict", "screening"}:
        raise ValueError("candidate gate policy must be strict or screening")
    work = work_root.expanduser().resolve()
    base_path = base_compiler_manifest.expanduser().resolve()
    candidate_path = candidate_compiler_manifest.expanduser().resolve()
    feature_path = feature_contract.expanduser().resolve()
    corpus_path = corpus_lock.expanduser().resolve()
    release_path = release_lock.expanduser().resolve()
    base_manifest = verify_compiler_manifest(base_path)
    candidate_manifest = verify_compiler_manifest(candidate_path)
    if candidate_manifest.get("artifact_kind") != "local":
        raise ValueError("candidate compiler manifest is not a local build artifact")
    release_validation = verify_release_lock(base_path, release_path)
    compilers = (
        compiler_from_manifest("old", base_path),
        compiler_from_manifest("new", candidate_path),
    )
    config = load_blaster_config(blaster_config_path)
    discovery_backend = _DiscoveryBackend(config)

    stages: dict[str, dict[str, Any]] = {}
    child_consumers: dict[Path, list[dict[str, str]]] = {}
    if "sentinel" in scope:
        sentinel = compare_sentinel(
            sentinel_package,
            compilers,
            work_root=work,
            strict=False,
            blaster_config=config,
            backend=discovery_backend,
            feature_contract=feature_path,
            resume=resume,
        )
        stages["sentinel"] = sentinel
        sentinel_output = Path(sentinel["output"])
        child_consumers.setdefault(sentinel_output, []).append(
            {
                "consumer_kind": "sentinel",
                "consumer_id": "feature-sentinel",
                "source_id": "feature-sentinel",
                "task_id": "feature-sentinel",
            }
        )
    if "mandatory" in scope:
        corpus = run_corpus(
            corpus_path,
            compilers,
            work_root=work,
            strict=False,
            jobs=jobs,
            resume=resume,
            blaster_config=config,
            backend=discovery_backend,
        )
        stages["mandatory"] = corpus
        for task in corpus.get("results", []):
            semantic = task.get("semantic_summary")
            if isinstance(semantic, dict) and isinstance(
                semantic.get("output"), str
            ):
                child_consumers.setdefault(
                    Path(semantic["output"]), []
                ).append(
                    {
                        "consumer_kind": "mandatory_task",
                        "consumer_id": str(task["task_id"]),
                        "source_id": str(task["source_id"]),
                        "task_id": str(task["task_id"]),
                    }
                )

    pair_rows_by_id: dict[str, dict[str, Any]] = {}
    pair_roots: dict[str, Path] = {}
    pair_consumers: dict[str, list[dict[str, str]]] = {}
    child_pair_ids: dict[Path, list[str]] = {}
    raw_validator_links: list[dict[str, Any]] = []
    raw_feature_links: list[dict[str, Any]] = []
    for child, consumers in sorted(
        child_consumers.items(), key=lambda item: str(item[0])
    ):
        rows = _records(child, "program-pairs.json")
        child_pair_ids[child] = sorted(
            str(row["program_pair_id"]) for row in rows
        )
        for row in rows:
            pair_id = str(row["program_pair_id"])
            if pair_id in pair_rows_by_id:
                _merge_program_pair(pair_rows_by_id[pair_id], row)
            else:
                pair_rows_by_id[pair_id] = json.loads(json.dumps(row))
                pair_roots[pair_id] = child
            existing_consumers = {
                canonical_json(value): value
                for value in pair_consumers.get(pair_id, [])
            }
            for consumer in consumers:
                existing_consumers[canonical_json(consumer)] = consumer
            pair_consumers[pair_id] = [
                existing_consumers[key]
                for key in sorted(existing_consumers)
            ]
        raw_validator_links.extend(_records(child, "validator-links.json"))
        feature_file = child / "feature-links.json"
        if feature_file.is_file():
            raw_feature_links.extend(_records(child, "feature-links.json"))

    program_pairs = [
        pair_rows_by_id[pair_id] for pair_id in sorted(pair_rows_by_id)
    ]
    pair_objects = {
        pair_id: _program_pair(pair_rows_by_id[pair_id], pair_roots[pair_id])
        for pair_id in sorted(pair_rows_by_id)
    }
    program_artifact_records: dict[str, dict[str, Any]] = {}
    for pair_id, pair in pair_objects.items():
        del pair_id
        for artifact in (pair.old_script, pair.new_script):
            serialized_hex = artifact.path.read_text(encoding="ascii").strip().lower()
            record = {
                "program_artifact_id": artifact.program_artifact_id,
                "serialized_script_bytes_hex": serialized_hex,
                "script_sha256": artifact.sha256,
                "script_size": artifact.size,
                "plutus_version": artifact.plutus_version,
                "serialization_format": artifact.serialization_format,
            }
            previous = program_artifact_records.setdefault(
                artifact.program_artifact_id, record
            )
            if previous != record:
                raise ValueError(
                    "program artifact identity conflict: "
                    f"{artifact.program_artifact_id}"
                )

    semantic_model_rows: dict[str, dict[str, Any]] = {}
    obligation_rows: dict[str, dict[str, Any]] = {}
    omission_rows: dict[str, dict[str, Any]] = {}
    model_objects: dict[str, InputModel] = {}
    model_pairs: dict[str, str] = {}
    for pair_id, pair in pair_objects.items():
        if pair.old_script.sha256 == pair.new_script.sha256:
            continue
        raw_model, ledger_models = validator_input_models(pair)
        for model in (raw_model, *ledger_models):
            model_id = model.semantic_model_id(config.runtime_step_bound)
            model_record = {
                "semantic_model_id": model_id,
                "program_pair_id": pair_id,
                "semantic_runtime_bound": config.runtime_step_bound,
                "required": not model.profile.startswith("ledger-valid"),
                "input_model": model.to_dict(),
            }
            previous = semantic_model_rows.setdefault(model_id, model_record)
            if previous["input_model"] != model_record["input_model"]:
                raise ValueError(f"semantic model identity conflict: {model_id}")
            model_objects[model_id] = model
            model_pairs[model_id] = pair_id
            planned = planned_model_obligations(
                pair, model, config.runtime_step_bound
            )
            if not planned:
                omission_rows[f"{pair_id}:{model_id}"] = {
                    "semantic_model_id": model_id,
                    "program_pair_id": pair_id,
                    "status": "ledger_model_unsupported",
                    "reason": model.unsupported_reason,
                    "planned_obligation_kinds": [
                        "ledger_domain_non_vacuity",
                        "old_program_completion",
                        "new_program_completion",
                        "ledger_observational_equivalence",
                    ],
                }
            for obligation in planned:
                row = obligation.to_dict()
                previous_obligation = obligation_rows.setdefault(
                    obligation.logical_obligation_id, row
                )
                if previous_obligation != row:
                    raise ValueError(
                        "logical obligation identity conflict: "
                        f"{obligation.logical_obligation_id}"
                    )

    source_identity_rows: list[dict[str, Any]] = []
    task_rows: list[dict[str, Any]] = []
    task_child: dict[str, Path] = {}
    if "sentinel" in stages:
        summary = stages["sentinel"]
        child = Path(summary["output"])
        run = _load(child / "run.json")
        builds = {
            label: _load(child / f"build-{label}.json")
            for label in ("old", "new")
        }
        sentinel_task = _task_record(
            {
                "task_id": "feature-sentinel",
                "lane": "equivalence",
                "classification": "discovery_completed",
                "equivalence_required": True,
                "source_hash_before": run["source_hash"],
                "source_hash_after": run["source_hash"],
                "dependency_graph_before": builds["old"]["dependency_graph_before"],
                "dependency_graph_after": builds["new"]["dependency_graph_after"],
                "timeout_seconds": config.timeouts.aiken_build,
                "old_result": builds["old"],
                "new_result": builds["new"],
                "source_immutable": summary.get("source_immutable"),
            },
            program_pair_ids=child_pair_ids.get(child, []),
            logical_obligation_ids=[
                obligation_id
                for obligation_id, obligation in obligation_rows.items()
                if obligation["program_pair_id"]
                in child_pair_ids.get(child, [])
            ],
        )
        task_rows.append(sentinel_task)
        task_child["feature-sentinel"] = child
    if "mandatory" in stages:
        for task in stages["mandatory"].get("results", []):
            semantic = task.get("semantic_summary")
            child = (
                Path(semantic["output"])
                if isinstance(semantic, dict)
                and isinstance(semantic.get("output"), str)
                else None
            )
            pair_ids = child_pair_ids.get(child, []) if child else []
            logical_ids = [
                obligation_id
                for obligation_id, obligation in obligation_rows.items()
                if obligation["program_pair_id"] in pair_ids
            ]
            normalized = _task_record(
                task,
                program_pair_ids=pair_ids,
                logical_obligation_ids=logical_ids,
            )
            task_rows.append(normalized)
            if child is not None:
                task_child[str(task["task_id"])] = child
    task_rows.sort(key=lambda row: row["task_id"])

    source_groups: dict[str, list[dict[str, Any]]] = {}
    for task in task_rows:
        source_groups.setdefault(str(task["source_id"]), []).append(task)
    for source_id, tasks in sorted(source_groups.items()):
        inputs_verified = all(
            task.get("inputs_verified") is True for task in tasks
        )
        source_identity_rows.append(
            {
                "source_id": source_id,
                "task_ids": sorted(str(task["task_id"]) for task in tasks),
                "source_inputs": sorted(
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
                        for task in tasks
                    }
                ),
                "inputs_verified": inputs_verified,
                "program_pair_ids": sorted(
                    {
                        pair_id
                        for task in tasks
                        for pair_id in task["program_pair_ids"]
                    }
                ),
                "logical_obligation_ids": sorted(
                    {
                        obligation_id
                        for task in tasks
                        for obligation_id in task[
                            "logical_obligation_ids"
                        ]
                    }
                ),
                "evidence_result_ids": [],
            }
        )

    checker_configuration = config.checker_configuration()
    source_identity_inputs = [
        {
            "source_id": row["source_id"],
            "source_inputs": row["source_inputs"],
            "task_ids": row["task_ids"],
        }
        for row in source_identity_rows
    ]
    evidence_identity_inputs = {
        "base_compiler_artifact_id": base_manifest["artifact_id"],
        "candidate_compiler_artifact_id": candidate_manifest["artifact_id"],
        "source_and_dependency_inputs": source_identity_inputs,
        "feature_contract_sha256": _sha256(feature_path),
        "corpus_lock_sha256": _sha256(corpus_path),
        "release_lock_sha256": release_validation["release_lock_sha256"],
        "scope": sorted(scope),
        "checker_implementation_id": checker_configuration[
            "checker_implementation_id"
        ],
        "checker_configuration_id": checker_configuration[
            "checker_configuration_id"
        ],
        "semantic_model_ids": sorted(semantic_model_rows),
        "runtime_bounds": {
            "semantic_runtime_step_bound": config.runtime_step_bound,
            "process_timeouts": asdict(config.timeouts),
            "random_seed": config.random_seed,
        },
    }
    run_id = evidence_run_id(evidence_identity_inputs)
    output = work / "candidate-gates" / run_id
    if output.exists() and not resume:
        raise ValueError(
            f"candidate evidence run already exists: {output}; use --resume"
        )
    output.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(feature_path, output / "feature-contract.json")
    shutil.copyfile(corpus_path, output / "corpus-lock.json")
    shutil.copyfile(release_path, output / "compiler-release-lock.json")

    static_counts = {
        "program_artifacts": len(program_artifact_records),
        "unique_program_pairs": len(program_pairs),
        "semantic_models": len(semantic_model_rows),
        "model_omissions": len(omission_rows),
        "unique_semantic_obligations": len(obligation_rows),
        "validator_links": len(raw_validator_links),
        "feature_links": len(raw_feature_links),
        "task_links": len(task_rows),
        "source_links": len(source_identity_rows),
        "pending_obligations": 0,
    }
    global_plan = {
        "schema_version": CANDIDATE_BUNDLE_SCHEMA_VERSION,
        "evidence_run_id": run_id,
        "phase_order": [
            "build_and_discovery",
            "global_obligation_plan",
            "global_evidence_lookup",
            "semantic_execution",
            "linking_and_decisions",
        ],
        "semantic_execution_started_after_plan_write": True,
        "identity_conflicts": [],
        "counts": static_counts,
    }
    semantic_models = [
        semantic_model_rows[key] for key in sorted(semantic_model_rows)
    ]
    obligations = [obligation_rows[key] for key in sorted(obligation_rows)]
    omissions = [omission_rows[key] for key in sorted(omission_rows)]
    write_json(output / "global-plan.json", global_plan)
    write_json(
        output / "global-program-pairs.json", _record_set(program_pairs)
    )
    write_json(
        output / "global-semantic-obligations.json",
        _record_set(obligations),
    )
    write_json(output / "program-pairs.json", _record_set(program_pairs))
    write_json(
        output / "semantic-obligations.json", _record_set(obligations)
    )
    write_json(
        output / "semantic-models.json", _record_set(semantic_models)
    )
    write_json(
        output / "semantic-model-omissions.json", _record_set(omissions)
    )
    write_json(
        output / "program-artifacts.json",
        _record_set(
            [
                program_artifact_records[key]
                for key in sorted(program_artifact_records)
            ]
        ),
    )

    store = EvidenceStore(work / "evidence-store")
    expected_by_id = {
        obligation_id: {
            "logical_obligation_id": obligation_id,
            "checker_configuration_id": checker_configuration[
                "checker_configuration_id"
            ],
            "checker_implementation_id": checker_configuration[
                "checker_implementation_id"
            ],
            "generated_source_schema_version": GENERATED_LEAN_SCHEMA_VERSION,
            "program_pair_id": obligation["program_pair_id"],
            "semantic_model_id": obligation["semantic_model_id"],
            "obligation_kind": obligation["obligation_kind"],
        }
        for obligation_id, obligation in obligation_rows.items()
    }
    grouped_obligations: dict[tuple[str, str], list[str]] = {}
    for obligation_id, obligation in obligation_rows.items():
        grouped_obligations.setdefault(
            (
                str(obligation["program_pair_id"]),
                str(obligation["semantic_model_id"]),
            ),
            [],
        ).append(obligation_id)
    obligation_results: dict[str, dict[str, Any]] = {}
    execution_attempts: dict[str, dict[str, Any]] = {}
    witnesses: dict[str, dict[str, Any]] = {}
    replays: dict[str, dict[str, Any]] = {}
    evidence_materials: dict[str, dict[str, Any]] = {}
    lineage: dict[str, dict[str, Any]] = {}
    cache_reuse_count = 0
    executed_obligation_count = 0
    executed_batch_count = 0
    backend = RealBlasterBackend(config)
    compiler_identities = {
        compiler.label: compiler.identity() for compiler in compilers
    }
    priority = sorted(
        grouped_obligations,
        key=lambda key: (
            not model_objects[key[1]].profile.startswith("raw-uplc"),
            key[0],
            key[1],
        ),
    )
    for pair_id, model_id in priority:
        obligation_ids = sorted(grouped_obligations[(pair_id, model_id)])
        with store.execution_claim(
            checker_configuration["checker_configuration_id"],
            obligation_ids,
        ):
            cached = {
                obligation_id: store.load(expected_by_id[obligation_id])
                for obligation_id in obligation_ids
            }
            present = {
                obligation_id: value
                for obligation_id, value in cached.items()
                if value is not None
            }
            if present and len(present) != len(obligation_ids):
                for obligation_id in present:
                    store.quarantine(expected_by_id[obligation_id])
                present = {}
            if len(present) == len(obligation_ids):
                cache_reuse_count += len(obligation_ids)
                for obligation_id, cached_value in present.items():
                    assert cached_value is not None
                    result = dict(cached_value["result"])
                    result["reused"] = True
                    obligation_results[obligation_id] = result
                    execution = cached_value["execution_attempt"]
                    evidence_materials[result["evidence_result_id"]] = {
                        "generated_source": cached_value[
                            "generated_source"
                        ],
                        "logs": dict(cached_value["logs"]),
                    }
                    execution_attempts[execution["execution_attempt_id"]] = execution
                    if cached_value["witness"] is not None:
                        witness = cached_value["witness"]
                        witnesses[witness["witness_id"]] = witness
                    if cached_value["replay"] is not None:
                        replay = cached_value["replay"]
                        replays[replay["replay_id"]] = replay
                    lineage[result["evidence_result_id"]] = {
                        "evidence_result_id": result["evidence_result_id"],
                        "logical_obligation_id": obligation_id,
                        "obligation_attempt_id": result[
                            "obligation_attempt_id"
                        ],
                        "execution_attempt_id": result[
                            "execution_attempt_id"
                        ],
                        "cache_reused": True,
                        "cache_entry": cached_value["entry_path"],
                    }
                continue
            executed_batch_count += 1
            execution_root = output / "semantic-work" / pair_id / model_id
            execution_root.mkdir(parents=True, exist_ok=True)
            executed = execute_model(
                pair=pair_objects[pair_id],
                model=model_objects[model_id],
                config=config,
                backend=backend,
                output_root=execution_root,
                compiler_identities=compiler_identities,
            )
            executed_obligation_count += len(executed["results"])
            execution_by_id = {
                row["execution_attempt_id"]: row
                for row in executed["execution_attempts"]
            }
            witness_by_id = {
                row["witness_id"]: row for row in executed["witnesses"]
            }
            replay_by_id = {
                row["replay_id"]: row for row in executed["replays"]
            }
            for result in executed["results"]:
                obligation_id = str(result["logical_obligation_id"])
                stored = store.put(
                    result=result,
                    execution_attempt=execution_by_id[
                        result["execution_attempt_id"]
                    ],
                    witness=witness_by_id.get(result["witness_reference"]),
                    replay=replay_by_id.get(result["replay_reference"]),
                    generated_source=executed["generated_sources"].get(
                        obligation_id
                    ),
                    logs=executed["logs"].get(obligation_id),
                )
                stored_result = dict(stored["result"])
                stored_result["reused"] = bool(stored["cache_reused"])
                obligation_results[obligation_id] = stored_result
                execution = stored["execution_attempt"]
                execution_attempts[execution["execution_attempt_id"]] = execution
                if stored["witness"] is not None:
                    witness = stored["witness"]
                    witnesses[witness["witness_id"]] = witness
                if stored["replay"] is not None:
                    replay = stored["replay"]
                    replays[replay["replay_id"]] = replay
                lineage[stored_result["evidence_result_id"]] = {
                    "evidence_result_id": stored_result["evidence_result_id"],
                    "logical_obligation_id": obligation_id,
                    "obligation_attempt_id": stored_result[
                        "obligation_attempt_id"
                    ],
                    "execution_attempt_id": stored_result[
                        "execution_attempt_id"
                    ],
                    "cache_reused": bool(stored["cache_reused"]),
                    "cache_entry": stored["entry_path"],
                }
                evidence_materials[stored_result["evidence_result_id"]] = {
                    "generated_source": stored["generated_source"],
                    "logs": dict(stored["logs"]),
                }

    final_results = [
        obligation_results[key] for key in sorted(obligation_results)
    ]
    generated_source_root = output / "generated-sources"
    semantic_log_root = output / "semantic-logs"
    for result in final_results:
        evidence_id = str(result["evidence_result_id"])
        material = evidence_materials[evidence_id]
        expected_source_hash = result.get("generated_source_sha256")
        generated_source = material["generated_source"]
        if expected_source_hash is not None:
            if (
                not isinstance(generated_source, bytes)
                or hashlib.sha256(generated_source).hexdigest()
                != expected_source_hash
            ):
                raise ValueError(
                    "evidence store is missing the generated source for "
                    + str(result["logical_obligation_id"])
                )
            bundled_source = (
                generated_source_root
                / f"{result['logical_obligation_id']}.lean"
            )
            bundled_source.parent.mkdir(parents=True, exist_ok=True)
            bundled_source.write_bytes(generated_source)
            result["generated_source_path"] = bundled_source.relative_to(
                output
            ).as_posix()
        for name, value in material["logs"].items():
            if Path(name).name != name:
                raise ValueError("evidence store returned an invalid log name")
            bundled_log = (
                semantic_log_root
                / str(result["logical_obligation_id"])
                / name
            )
            bundled_log.parent.mkdir(parents=True, exist_ok=True)
            bundled_log.write_bytes(value)
    evidence_result_by_obligation = {
        row["logical_obligation_id"]: row["evidence_result_id"]
        for row in final_results
    }
    pair_classifications, changed_counts = classify_changed_pairs(
        program_pairs, semantic_models, obligations, final_results
    )
    pair_classification_by_id = {
        row["program_pair_id"]: row["classification"]
        for row in pair_classifications
    }
    for task in task_rows:
        task["evidence_result_ids"] = sorted(
            evidence_result_by_obligation[obligation_id]
            for obligation_id in task["logical_obligation_ids"]
        )
        classification = expected_task_classification(
            task, pair_classification_by_id
        )
        if classification is not None:
            task["classification"] = classification
    for source in source_identity_rows:
        source["evidence_result_ids"] = sorted(
            evidence_result_by_obligation[obligation_id]
            for obligation_id in source["logical_obligation_ids"]
        )

    validator_by_id: dict[str, dict[str, Any]] = {}
    for row in raw_validator_links:
        handler_id = str(row["handler_pair_id"])
        pair_id = row.get("program_pair_id")
        pair_ids = [str(pair_id)] if isinstance(pair_id, str) else []
        link = {
            "handler_pair_id": handler_id,
            "program_pair_ids": pair_ids,
            "logical_obligation_ids": sorted(
                obligation_id
                for obligation_id, obligation in obligation_rows.items()
                if obligation["program_pair_id"] in pair_ids
            ),
            "evidence_result_ids": [],
            "feature_ids": sorted(row.get("feature_ids", [])),
            "source_ids": sorted(
                {
                    consumer["source_id"]
                    for current_pair in pair_ids
                    for consumer in pair_consumers.get(current_pair, [])
                }
            ),
            "task_ids": sorted(
                {
                    consumer["task_id"]
                    for current_pair in pair_ids
                    for consumer in pair_consumers.get(current_pair, [])
                }
            ),
            "validator_purpose": row.get("purpose"),
        }
        link["evidence_result_ids"] = sorted(
            evidence_result_by_obligation[obligation_id]
            for obligation_id in link["logical_obligation_ids"]
        )
        previous = validator_by_id.setdefault(handler_id, link)
        if previous != link:
            for field in (
                "program_pair_ids",
                "logical_obligation_ids",
                "evidence_result_ids",
                "feature_ids",
                "source_ids",
                "task_ids",
            ):
                previous[field] = sorted(
                    set(previous[field]) | set(link[field])
                )

    feature_by_id: dict[str, dict[str, Any]] = {}
    for row in raw_feature_links:
        feature_id = str(row["feature_id"])
        pair_ids = sorted(
            pair_id
            for pair_id in row.get("program_pair_ids", [])
            if pair_id in pair_rows_by_id
        )
        link = feature_by_id.setdefault(
            feature_id,
            {
                "feature_id": feature_id,
                "handler_pair_ids": [],
                "program_pair_ids": [],
                "logical_obligation_ids": [],
                "evidence_result_ids": [],
                "task_ids": [],
                "source_ids": [],
            },
        )
        link["handler_pair_ids"] = sorted(
            set(link["handler_pair_ids"])
            | set(row.get("handler_pair_ids", []))
        )
        link["program_pair_ids"] = sorted(
            set(link["program_pair_ids"]) | set(pair_ids)
        )
    for feature_id, link in feature_by_id.items():
        del feature_id
        link["logical_obligation_ids"] = sorted(
            obligation_id
            for obligation_id, obligation in obligation_rows.items()
            if obligation["program_pair_id"]
            in link["program_pair_ids"]
        )
        link["evidence_result_ids"] = sorted(
            evidence_result_by_obligation[obligation_id]
            for obligation_id in link["logical_obligation_ids"]
        )
        link["task_ids"] = sorted(
            {
                consumer["task_id"]
                for pair_id in link["program_pair_ids"]
                for consumer in pair_consumers.get(pair_id, [])
            }
        )
        link["source_ids"] = sorted(
            {
                consumer["source_id"]
                for pair_id in link["program_pair_ids"]
                for consumer in pair_consumers.get(pair_id, [])
            }
        )

    consumer_reuses = sum(
        max(0, len(consumers) - 1)
        for consumers in pair_consumers.values()
    )
    runtime_counts = {
        "cache_reused_obligations": cache_reuse_count,
        "executed_unique_obligations": executed_obligation_count,
        "semantic_execution_batches": executed_batch_count,
        "duplicate_solver_invocations_prevented": consumer_reuses
        + cache_reuse_count,
        "obligation_results": len(final_results),
        "pending_obligations": 0,
    }
    decision_counts = static_counts | runtime_counts | changed_counts
    candidate_clean = candidate_manifest["source"].get("dirty") is False
    candidate_committed = bool(
        candidate_manifest.get("reproducibility", {}).get(
            "reproducible_from_commit"
        )
    )
    ci_attestation = _local_attestation()
    ci_valid = candidate_ci_provenance_valid(ci_attestation)
    decisions = derive_candidate_decisions(
        evidence_run_id=run_id,
        selected_policy=policy,
        pair_classifications=pair_classifications,
        task_results=task_rows,
        source_results=source_identity_rows,
        counts=decision_counts,
        candidate_clean=candidate_clean,
        candidate_committed=candidate_committed,
        evidence_verified=True,
        ci_provenance_valid=ci_valid,
    )

    for filename, rows in (
        (
            "obligation-results.json",
            final_results,
        ),
        (
            "execution-attempts.json",
            [execution_attempts[key] for key in sorted(execution_attempts)],
        ),
        ("witnesses.json", [witnesses[key] for key in sorted(witnesses)]),
        ("replays.json", [replays[key] for key in sorted(replays)]),
        (
            "evidence-lineage.json",
            [lineage[key] for key in sorted(lineage)],
        ),
        (
            "validator-links.json",
            [validator_by_id[key] for key in sorted(validator_by_id)],
        ),
        (
            "feature-links.json",
            [feature_by_id[key] for key in sorted(feature_by_id)],
        ),
        ("task-results.json", task_rows),
        ("source-results.json", source_identity_rows),
        ("pair-classifications.json", pair_classifications),
    ):
        write_json(output / filename, _record_set(rows))
    write_json(output / "strict-decision.json", decisions["strict"])
    write_json(output / "screening-decision.json", decisions["screening"])
    write_json(output / "selected-decision.json", decisions["selected"])
    write_json(
        output / "environment.json",
        {
            "schema_version": CANDIDATE_BUNDLE_SCHEMA_VERSION,
            "captured_at_utc": datetime.now(UTC).isoformat(),
            "platform_identity": platform_identity(),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "python_executable": sys.executable,
            "checker_configuration": config.identity(),
        },
    )

    compiler_identity = lambda manifest: {
        "artifact_id": manifest["artifact_id"],
        "artifact_kind": manifest["artifact_kind"],
        "target": manifest["target"],
        "build_command": manifest["build"]["command"],
        "binary_sha256": manifest["binary"]["sha256"],
        "reported_version": manifest["binary"]["reported_version"],
        "source_tree_sha256": manifest["source"]["source_tree_sha256"],
        "source_commit": manifest["source"]["commit_sha"],
        "cargo_lock_sha256": manifest["source"]["cargo_lock_sha256"],
        "dirty": manifest["source"].get("dirty", False),
        "tracked_diff_sha256": manifest["source"].get(
            "tracked_diff_sha256"
        ),
        "untracked_source_manifest": manifest["source"].get(
            "untracked_source_manifest", []
        ),
        "reproducible_from_commit": manifest.get(
            "reproducibility", {}
        ).get("reproducible_from_commit") is True,
    }
    bundle_manifest = {
        "evidence_run_id": run_id,
        "selected_policy": policy,
        "base_compiler": compiler_identity(base_manifest),
        "candidate_compiler": compiler_identity(candidate_manifest),
        "candidate_source_clean": candidate_clean,
        "candidate_source_committed": candidate_committed,
        "development_only": not candidate_clean or not candidate_committed,
        "checker_configuration": checker_configuration,
        "evidence_identity_inputs": evidence_identity_inputs,
        "release_lock_validation": release_validation,
        "counts": decision_counts,
        "strict_decision_id": decisions["strict"]["decision_id"],
        "screening_decision_id": decisions["screening"]["decision_id"],
        "selected_decision_id": decisions["selected"][
            "selected_decision_id"
        ],
    }
    reproducibility = candidate_manifest.get("reproducibility", {}).get(
        "bundle"
    )
    if not candidate_clean and isinstance(reproducibility, dict):
        bundle_path = reproducibility.get("path")
        if isinstance(bundle_path, str):
            source_patch = candidate_path.parent / bundle_path
            if source_patch.is_dir():
                shutil.copytree(
                    source_patch,
                    output / "candidate-source-patch",
                    dirs_exist_ok=True,
                )
    finalized_manifest = finalize_candidate_bundle(
        output,
        manifest=bundle_manifest,
        ci_attestation=ci_attestation,
    )
    if ci_attestation.get("artifact_sha256") == "$candidate_bundle_content_id":
        ci_attestation["artifact_sha256"] = finalized_manifest[
            "candidate_bundle_content_id"
        ]
        finalize_candidate_bundle(
            output,
            manifest=bundle_manifest,
            ci_attestation=ci_attestation,
        )
    verification = verify_candidate_bundle(output)
    selected = decisions["selected"]
    return {
        **selected,
        "evidence_run_id": run_id,
        "candidate_bundle_content_id": verification[
            "candidate_bundle_content_id"
        ],
        "strict_decision_id": decisions["strict"]["decision_id"],
        "screening_decision_id": decisions["screening"]["decision_id"],
        "output": str(output),
        "counts": decision_counts,
        "bundle_verification": verification,
    }
