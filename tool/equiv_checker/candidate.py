from __future__ import annotations

import hashlib
import json
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
from .evidence import canonical_json, platform_identity
from .runner import compare_sentinel, write_json

DEFAULT_RELEASE_LOCK = REPOSITORY_ROOT / "corpus" / "compiler_release.lock.json"
DEFAULT_SENTINEL = REPOSITORY_ROOT / "sentinel"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stable_id(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def _records(output: Path, filename: str) -> list[dict[str, Any]]:
    path = output / filename
    if not path.is_file():
        return []
    wrapper = _load(path)
    records = wrapper.get("records")
    if not isinstance(records, list) or not all(
        isinstance(row, dict) for row in records
    ):
        raise ValueError(f"invalid compact evidence record set: {path}")
    if wrapper.get("record_count") != len(records):
        raise ValueError(f"record count mismatch: {path}")
    return records


def _nested_value(record: dict[str, Any], path: str) -> tuple[dict[str, Any], str]:
    parts = path.split(".")
    parent = record
    for part in parts[:-1]:
        child = parent.get(part)
        if not isinstance(child, dict):
            raise ValueError(f"evidence row is missing object field {part} in {path}")
        parent = child
    return parent, parts[-1]


def _merge_unique(
    rows: list[dict[str, Any]],
    key: str,
    *,
    merge_fields: tuple[str, ...] = (),
) -> tuple[list[dict[str, Any]], list[str]]:
    merged: dict[str, dict[str, Any]] = {}
    conflicts: list[str] = []
    for row in rows:
        identity = row.get(key)
        if not isinstance(identity, str):
            raise ValueError(f"evidence row is missing {key}")
        previous = merged.get(identity)
        if previous is None:
            merged[identity] = json.loads(json.dumps(row))
            continue
        previous_comparable = json.loads(json.dumps(previous))
        current_comparable = json.loads(json.dumps(row))
        for field in merge_fields:
            previous_parent, previous_leaf = _nested_value(
                previous_comparable, field
            )
            current_parent, current_leaf = _nested_value(current_comparable, field)
            previous_parent.pop(previous_leaf, None)
            current_parent.pop(current_leaf, None)
        if previous_comparable != current_comparable:
            conflicts.append(identity)
            continue
        for field in merge_fields:
            previous_parent, previous_leaf = _nested_value(previous, field)
            current_parent, current_leaf = _nested_value(row, field)
            previous_values = previous_parent.get(previous_leaf, [])
            current_values = current_parent.get(current_leaf, [])
            if not isinstance(previous_values, list) or not isinstance(
                current_values, list
            ):
                raise ValueError(f"merge field {field} must contain an array")
            values = {
                canonical_json(value): value
                for value in [*previous_values, *current_values]
            }
            previous_parent[previous_leaf] = [
                values[item] for item in sorted(values)
            ]
    return [merged[item] for item in sorted(merged)], sorted(set(conflicts))


def _write_record_set(
    root: Path, filename: str, records: list[dict[str, Any]]
) -> None:
    write_json(
        root / filename,
        {"schema_version": 2, "record_count": len(records), "records": records},
    )


def _changed_pair_counts(
    changed_pairs: list[dict[str, Any]],
    child_results: list[dict[str, Any]],
) -> dict[str, int]:
    changed_ids = {row["program_pair_id"] for row in changed_pairs}
    statuses: dict[str, set[str]] = {identity: set() for identity in changed_ids}
    for row in child_results:
        identity = row.get("program_pair_id")
        status = row.get("status")
        if identity in statuses and isinstance(status, str):
            statuses[identity].add(status)

    counts = {
        "complete_equivalent_changed_pairs": 0,
        "bounded_changed_pairs": 0,
        "confirmed_difference_changed_pairs": 0,
        "unsupported_changed_pairs": 0,
        "inconclusive_changed_pairs": 0,
    }
    for pair_statuses in statuses.values():
        if pair_statuses and pair_statuses <= {
            "equivalent_under_raw_model",
            "equivalent_under_ledger_model",
        }:
            counts["complete_equivalent_changed_pairs"] += 1
        elif "bounded_equivalent" in pair_statuses:
            counts["bounded_changed_pairs"] += 1
        elif pair_statuses & {
            "confirmed_non_equivalent",
            "off_ledger_difference",
            "blaster_falsified_unreplayed",
        }:
            counts["confirmed_difference_changed_pairs"] += 1
        elif any("unsupported" in status for status in pair_statuses):
            counts["unsupported_changed_pairs"] += 1
        else:
            counts["inconclusive_changed_pairs"] += 1
    return counts


def _mandatory_repository_outcomes(
    task_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in task_results:
        if row.get("stage") != "mandatory":
            continue
        source_id = row.get("source_id")
        if isinstance(source_id, str):
            grouped.setdefault(source_id, []).append(row)
    outcomes: list[dict[str, Any]] = []
    for source_id, rows in sorted(grouped.items()):
        classifications: dict[str, int] = {}
        for row in rows:
            classification = str(row.get("classification", "unclassified"))
            classifications[classification] = (
                classifications.get(classification, 0) + 1
            )
        outcomes.append(
            {
                "source_id": source_id,
                "task_count": len(rows),
                "strict_pass": all(row.get("strict_pass") is True for row in rows),
                "classifications": dict(sorted(classifications.items())),
            }
        )
    return outcomes


def _markdown(decision: dict[str, Any]) -> str:
    counts = decision["counts"]
    lines = [
        "# Local candidate release decision",
        "",
        f"Decision: **{decision['decision'].upper()}**",
        f"Evidence suitability: **{decision['evidence_suitability']}**",
        "",
        "| Evidence | Count |",
        "|---|---:|",
        f"| Validator handlers | {counts['validator_handlers']} |",
        f"| Unique program pairs | {counts['unique_program_pairs']} |",
        f"| Changed program pairs | {counts['changed_program_pairs']} |",
        f"| Complete-equivalent changed pairs | {counts['complete_equivalent_changed_pairs']} |",
        f"| Bounded changed pairs | {counts['bounded_changed_pairs']} |",
        f"| Confirmed differences | {counts['confirmed_difference_changed_pairs']} |",
        f"| Unsupported changed pairs | {counts['unsupported_changed_pairs']} |",
        f"| Inconclusive changed pairs | {counts['inconclusive_changed_pairs']} |",
        f"| Unique semantic obligations | {counts['unique_semantic_obligations']} |",
        f"| Solver invocations | {counts['solver_invocations']} |",
        f"| Deduplicated invocations | {counts['deduplicated_invocations']} |",
        f"| Shared language features | {counts['shared_language_features']} |",
        f"| New-only language features | {counts['new_only_language_features']} |",
        f"| Old-only language features | {counts['old_only_language_features']} |",
        f"| Mandatory tasks | {counts['mandatory_tasks']} |",
        "",
    ]
    if decision["mandatory_repository_outcomes"]:
        lines.extend(
            [
                "## Mandatory repository outcomes",
                "",
                "| Source | Tasks | Strict pass |",
                "|---|---:|---|",
                *(
                    f"| `{row['source_id']}` | {row['task_count']} | "
                    f"{str(row['strict_pass']).lower()} |"
                    for row in decision["mandatory_repository_outcomes"]
                ),
                "",
            ]
        )
    if decision["blocking_evidence_ids"]:
        lines.extend(
            [
                "## Blocking evidence",
                "",
                *(
                    f"- `{identifier}`"
                    for identifier in decision["blocking_evidence_ids"]
                ),
                "",
            ]
        )
    if decision["development_notice"]:
        lines.extend(
            ["## Development notice", "", decision["development_notice"], ""]
        )
    return "\n".join(lines)


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
    strict = policy == "strict"
    base_path = base_compiler_manifest.expanduser().resolve()
    candidate_path = candidate_compiler_manifest.expanduser().resolve()
    feature_path = feature_contract.expanduser().resolve()
    corpus_path = corpus_lock.expanduser().resolve()
    work = work_root.expanduser().resolve()
    base_manifest = verify_compiler_manifest(base_path)
    candidate_manifest = verify_compiler_manifest(candidate_path)
    base_lock_validation = verify_release_lock(base_path, release_lock)
    compilers = (
        compiler_from_manifest("old", base_path),
        compiler_from_manifest("new", candidate_path),
    )
    config = load_blaster_config(blaster_config_path)
    identity = {
        "base_artifact_id": base_manifest["artifact_id"],
        "candidate_artifact_id": candidate_manifest["artifact_id"],
        "feature_contract_sha256": _sha256(feature_path),
        "corpus_lock_sha256": _sha256(corpus_path),
        "release_lock_sha256": base_lock_validation["release_lock_sha256"],
        "scope": sorted(scope),
        "policy": policy,
        "checker_configuration_id": config.checker_configuration()[
            "checker_configuration_id"
        ],
    }
    gate_id = _stable_id(identity)
    output = work / "candidate-gates" / gate_id
    output.mkdir(parents=True, exist_ok=True)

    stages: dict[str, dict[str, Any]] = {}
    child_outputs: list[Path] = []
    if "sentinel" in scope:
        sentinel = compare_sentinel(
            sentinel_package,
            compilers,
            work_root=work,
            strict=strict,
            blaster_config=config,
            feature_contract=feature_path,
            resume=resume,
        )
        stages["sentinel"] = sentinel
        child_outputs.append(Path(sentinel["output"]))
    if "mandatory" in scope:
        corpus = run_corpus(
            corpus_path,
            compilers,
            work_root=work,
            strict=strict,
            jobs=jobs,
            resume=resume,
            blaster_config=config,
        )
        stages["mandatory"] = corpus
        for task in corpus.get("results", []):
            semantic = task.get("semantic_summary")
            if isinstance(semantic, dict) and isinstance(
                semantic.get("output"), str
            ):
                child_outputs.append(Path(semantic["output"]))

    input_failures: list[str] = []
    for child in child_outputs:
        summary = _load(child / "summary.json")
        if not summary.get("source_immutable"):
            input_failures.append(
                _stable_id({"kind": "source_not_immutable", "run": summary["run_id"]})
            )
        if not summary.get("dependency_lock_shared"):
            input_failures.append(
                _stable_id({"kind": "dependency_inputs_differ", "run": summary["run_id"]})
            )

    all_program_pairs = [
        row for child in child_outputs for row in _records(child, "program-pairs.json")
    ]
    program_pairs, program_conflicts = _merge_unique(
        all_program_pairs,
        "program_pair_id",
        merge_fields=(
            "handler_pair_ids",
            "handler_references",
            "covered_feature_ids",
            "old_program_artifact.source_validator_references",
            "new_program_artifact.source_validator_references",
        ),
    )
    all_obligations = [
        row
        for child in child_outputs
        for row in _records(child, "semantic-obligations.json")
    ]
    obligations, obligation_conflicts = _merge_unique(
        all_obligations, "logical_obligation_id"
    )
    all_results = [
        row
        for child in child_outputs
        for row in _records(child, "obligation-results.json")
    ]
    obligation_results, result_conflicts = _merge_unique(
        all_results, "logical_obligation_id"
    )
    execution_counts: dict[str, int] = {}
    for row in all_results:
        if not row.get("reused"):
            logical_id = row["logical_obligation_id"]
            execution_counts[logical_id] = execution_counts.get(logical_id, 0) + 1
    duplicate_invocations = sorted(
        logical_id
        for logical_id, count in execution_counts.items()
        if count > 1
    )
    all_validator_links = [
        row
        for child in child_outputs
        for row in _records(child, "validator-links.json")
    ]
    validator_links, validator_conflicts = _merge_unique(
        all_validator_links,
        "handler_pair_id",
        merge_fields=(
            "feature_ids",
            "logical_obligation_ids",
            "evidence_result_ids",
        ),
    )
    all_feature_links = [
        row
        for child in child_outputs
        for row in _records(child, "feature-links.json")
    ]
    feature_links, feature_conflicts = _merge_unique(
        all_feature_links,
        "feature_id",
        merge_fields=(
            "handler_pair_ids",
            "program_pair_ids",
            "semantic_obligation_ids",
            "all_linked_evidence",
            "required_evidence",
            "authoritative_evidence",
            "pair_results",
        ),
    )

    task_results: list[dict[str, Any]] = []
    if "sentinel" in stages:
        task_results.append(
            {
                "task_id": _stable_id({"gate_id": gate_id, "stage": "sentinel"}),
                "stage": "sentinel",
                "strict_pass": stages["sentinel"]["strict_pass"],
                "classification": "completed",
                "run_id": stages["sentinel"]["run_id"],
                "output": stages["sentinel"]["output"],
            }
        )
    if "mandatory" in stages:
        for row in stages["mandatory"].get("results", []):
            task_results.append({"stage": "mandatory", **row})

    dirty = bool(candidate_manifest["source"].get("dirty"))
    blocker_ids = [*input_failures]
    for kind, identities in (
        ("program_identity_conflict", program_conflicts),
        ("obligation_identity_conflict", obligation_conflicts),
        ("obligation_result_conflict", result_conflicts),
        ("duplicate_semantic_invocation", duplicate_invocations),
        ("validator_link_conflict", validator_conflicts),
        ("feature_link_conflict", feature_conflicts),
    ):
        blocker_ids.extend(
            _stable_id({"kind": kind, "identity": item}) for item in identities
        )
    for name, stage in stages.items():
        if not stage.get("strict_pass"):
            blocker_ids.append(
                _stable_id(
                    {
                        "kind": "stage_failed",
                        "stage": name,
                        "run_id": stage.get("run_id", stage.get("plan_id")),
                    }
                )
            )
    if dirty:
        blocker_ids.append(
            _stable_id(
                {
                    "kind": "dirty_candidate_development_only",
                    "artifact_id": candidate_manifest["artifact_id"],
                }
            )
        )
    for row in task_results:
        if row.get("strict_pass") is False:
            identifier = row.get("blocking_evidence_id")
            blocker_ids.append(
                identifier
                if isinstance(identifier, str)
                else _stable_id(
                    {
                        "kind": "mandatory_task_failed",
                        "task_id": row.get("task_id"),
                        "classification": row.get("classification"),
                    }
                )
            )
    blocker_ids = sorted(set(blocker_ids))
    changed_pairs = [
        row
        for row in program_pairs
        if row["old_program_artifact"]["script_sha256"]
        != row["new_program_artifact"]["script_sha256"]
    ]
    child_program_results = [
        result
        for child in child_outputs
        for result in _records(child, "pair-results.json")
    ]
    invocation_count = sum(
        1
        for result in child_program_results
        if not result.get("evidence_reuse")
        for model in result.get("model_results", {}).values()
        if isinstance(model.get("backend"), dict)
        and model["backend"].get("command")
    )
    deduplicated_count = sum(
        counts.get(
            "deduplicated_invocations",
            counts.get("deduplicated_invocation_count", 0),
        )
        for child in child_outputs
        if (counts := _load(child / "summary.json").get("counts", {}))
    )
    changed_counts = _changed_pair_counts(changed_pairs, child_program_results)
    new_only_features = sum(
        row.get("status") == "feature_new_only" for row in feature_links
    )
    old_only_features = sum(
        row.get("status") == "feature_old_only" for row in feature_links
    )
    counts = {
        "validator_handlers": len(validator_links),
        "unique_program_pairs": len(program_pairs),
        "changed_program_pairs": len(changed_pairs),
        **changed_counts,
        "unique_semantic_obligations": len(obligations),
        "obligation_results": len(obligation_results),
        "solver_invocations": invocation_count,
        "deduplicated_invocations": deduplicated_count,
        "feature_rows": len(feature_links),
        "shared_language_features": (
            len(feature_links) - new_only_features - old_only_features
        ),
        "new_only_language_features": new_only_features,
        "old_only_language_features": old_only_features,
        "build_and_compatibility_failures": sum(
            row.get("stage") == "mandatory"
            and row.get("strict_pass") is False
            and row.get("classification")
            not in {
                "confirmed_non_equivalent",
                "bounded_equivalent",
                "unsupported",
                "inconclusive",
            }
            for row in task_results
        ),
        "mandatory_tasks": sum(
            row.get("stage") == "mandatory" for row in task_results
        ),
    }
    development_notice = (
        "The candidate compiler was built from dirty local source. Its semantic "
        "results are development evidence only and are not a reproducible release baseline."
        if dirty
        else None
    )
    decision = {
        "schema_version": 1,
        "gate_id": gate_id,
        "decision": "pass" if not blocker_ids else "fail",
        "policy": policy,
        "scope": sorted(scope),
        "base_compiler_artifact_id": base_manifest["artifact_id"],
        "candidate_compiler_artifact_id": candidate_manifest["artifact_id"],
        "candidate_source_state": "dirty" if dirty else "clean",
        "evidence_suitability": "development_only" if dirty else "release",
        "publishable": not blocker_ids and not dirty,
        "development_notice": development_notice,
        "strict_decision": "pass" if not blocker_ids else "fail",
        "mandatory_repository_outcomes": _mandatory_repository_outcomes(task_results),
        "counts": counts,
        "blocking_evidence_ids": blocker_ids,
        "stage_results": {
            name: {
                "strict_pass": bool(stage.get("strict_pass")),
                "run_id": stage.get("run_id"),
                "plan_id": stage.get("plan_id"),
                "output": stage.get("output"),
            }
            for name, stage in stages.items()
        },
        "release_lock_validation": base_lock_validation,
        "comparison_input_validation": {
            "valid": not input_failures,
            "checked_run_count": len(child_outputs),
            "blocking_evidence_ids": input_failures,
        },
    }

    _write_record_set(output, "program-pairs.json", program_pairs)
    _write_record_set(output, "semantic-obligations.json", obligations)
    _write_record_set(output, "obligation-results.json", obligation_results)
    _write_record_set(output, "validator-links.json", validator_links)
    _write_record_set(output, "feature-links.json", feature_links)
    _write_record_set(output, "task-results.json", task_results)
    write_json(output / "release-decision.json", decision)
    (output / "release-decision.md").write_text(
        _markdown(decision), encoding="utf-8"
    )
    lineage = {
        "schema_version": 1,
        "gate_id": gate_id,
        "base_compiler_manifest": {
            "path": str(base_path),
            "sha256": _sha256(base_path),
            "artifact_id": base_manifest["artifact_id"],
        },
        "candidate_compiler_manifest": {
            "path": str(candidate_path),
            "sha256": _sha256(candidate_path),
            "artifact_id": candidate_manifest["artifact_id"],
        },
        "feature_contract": {"path": str(feature_path), "sha256": _sha256(feature_path)},
        "corpus_lock": {"path": str(corpus_path), "sha256": _sha256(corpus_path)},
        "child_runs": [
            {
                "run_id": _load(child / "summary.json")["run_id"],
                "path": str(child),
                "summary_sha256": _sha256(child / "summary.json"),
            }
            for child in child_outputs
        ],
        "obligation_lineage": [
            {
                "logical_obligation_id": row["logical_obligation_id"],
                "evidence_result_id": row["evidence_result_id"],
                "attempt_id": row["attempt_id"],
            }
            for row in obligation_results
        ],
    }
    write_json(output / "evidence-lineage.json", lineage)
    write_json(
        output / "environment.json",
        {
            "schema_version": 1,
            "captured_at_utc": datetime.now(UTC).isoformat(),
            "platform_identity": platform_identity(),
            "python_version": platform.python_version(),
            "python_executable": sys.executable,
            "checker_configuration": config.checker_configuration(),
            "replay_evaluators": [
                evaluator.identity()
                for evaluator in (config.evaluator, config.secondary_evaluator)
                if evaluator is not None
            ],
        },
    )
    checksummed = sorted(
        path
        for path in output.iterdir()
        if path.is_file() and path.name != "checksums.json"
    )
    write_json(
        output / "checksums.json",
        {
            "schema_version": 1,
            "files": [
                {
                    "path": path.name,
                    "sha256": _sha256(path),
                    "size": path.stat().st_size,
                }
                for path in checksummed
            ],
        },
    )
    return decision | {"output": str(output)}
