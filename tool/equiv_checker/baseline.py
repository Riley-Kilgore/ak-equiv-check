from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .evidence import canonical_json, identity_hash


REQUIRED_BASELINE_FILES = frozenset(
    {
        "handler-pairs.ndjson",
        "program-pairs.ndjson",
        "semantic-obligations.ndjson",
        "obligation-results.ndjson",
        "evidence-lineage.ndjson",
        "validator-links.ndjson",
        "feature-links.ndjson",
        "task-results.ndjson",
        "compiler-lock.json",
        "source-lock.json",
        "environment.json",
        "summary.json",
        "summary.md",
        "checksums.json",
        "ci-attestation.json",
    }
)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid baseline JSON: {path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"baseline JSON must contain an object: {path}")
    return value


def _read_ndjson(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        for line_number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(
                    f"baseline NDJSON row is not an object: {path}:{line_number}"
                )
            records.append(value)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid baseline NDJSON: {path}") from error
    return records


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def baseline_content_id(checksums: dict[str, str]) -> str:
    return identity_hash(
        "baseline-content",
        {
            "schema_version": 2,
            "algorithm": "sha256",
            "files": checksums,
        },
    )


def _linked_id_set(
    row: dict[str, Any],
    field: str,
    allowed: set[str],
    record_kind: str,
) -> set[str]:
    values = row.get(field)
    if (
        not isinstance(values, list)
        or any(not isinstance(value, str) for value in values)
        or len(values) != len(set(values))
        or not set(values).issubset(allowed)
    ):
        raise ValueError(f"{record_kind} has invalid {field}")
    return set(values)


def verify_baseline(path: Path) -> dict[str, Any]:
    root = path.expanduser().resolve()
    missing = sorted(name for name in REQUIRED_BASELINE_FILES if not (root / name).is_file())
    if missing:
        raise ValueError("baseline files missing: " + ", ".join(missing))
    checksums_record = _read_json(root / "checksums.json")
    if checksums_record.get("schema_version") != 2:
        raise ValueError("baseline checksums must use schema_version 2")
    if checksums_record.get("algorithm") != "sha256":
        raise ValueError("unsupported baseline checksum algorithm")
    checksums = checksums_record.get("files")
    if not isinstance(checksums, dict) or not checksums:
        raise ValueError("baseline checksums are empty")
    unbound = sorted(
        child.name
        for child in root.iterdir()
        if child.is_file()
        and child.name not in {"checksums.json", "ci-attestation.json"}
        and child.name not in checksums
    )
    if unbound:
        raise ValueError("baseline files are not checksummed: " + ", ".join(unbound))
    for name, expected in checksums.items():
        if not isinstance(name, str) or not isinstance(expected, str):
            raise ValueError("invalid baseline checksum entry")
        artifact = root / name
        if not artifact.is_file() or _sha256(artifact) != expected:
            raise ValueError(f"baseline checksum mismatch: {name}")
    content_id = baseline_content_id(checksums)
    if checksums_record.get("baseline_content_id") != content_id:
        raise ValueError("baseline content identity mismatch")

    summary = _read_json(root / "summary.json")
    if summary.get("schema_version") != 2:
        raise ValueError("baseline summary must use schema_version 2")
    if summary.get("source_provenance", {}).get("dirty") is not False:
        raise ValueError("canonical baseline source provenance is dirty")

    handler_pairs = _read_ndjson(root / "handler-pairs.ndjson")
    program_pairs = _read_ndjson(root / "program-pairs.ndjson")
    obligations = _read_ndjson(root / "semantic-obligations.ndjson")
    results = _read_ndjson(root / "obligation-results.ndjson")
    lineage = _read_ndjson(root / "evidence-lineage.ndjson")
    validator_links = _read_ndjson(root / "validator-links.ndjson")
    feature_links = _read_ndjson(root / "feature-links.ndjson")
    task_results = _read_ndjson(root / "task-results.ndjson")
    pair_ids = {
        row.get("program_pair_id")
        for row in program_pairs
        if isinstance(row.get("program_pair_id"), str)
    }
    if len(pair_ids) != len(program_pairs):
        raise ValueError("duplicate or missing program-pair identity")
    handler_ids = {
        row.get("handler_pair_id")
        for row in handler_pairs
        if isinstance(row.get("handler_pair_id"), str)
    }
    if len(handler_ids) != len(handler_pairs):
        raise ValueError("duplicate or missing handler-pair identity")
    for row in handler_pairs:
        if row.get("program_pair_id") not in pair_ids:
            raise ValueError("handler pair has no program-pair parent")
    obligation_ids = {
        row.get("logical_obligation_id")
        for row in obligations
        if isinstance(row.get("logical_obligation_id"), str)
    }
    if len(obligation_ids) != len(obligations):
        raise ValueError("duplicate or missing logical-obligation identity")
    for row in obligations:
        if row.get("program_pair_id") not in pair_ids:
            raise ValueError("semantic obligation has no program-pair parent")
    evidence_ids: set[str] = set()
    result_obligation_ids: set[str] = set()
    evidence_by_obligation: dict[str, str] = {}
    for row in results:
        obligation_id = row.get("logical_obligation_id")
        if (
            obligation_id not in obligation_ids
            or obligation_id in result_obligation_ids
        ):
            raise ValueError(
                "duplicate or orphaned obligation result"
            )
        result_obligation_ids.add(obligation_id)
        evidence_id = row.get("evidence_result_id")
        if not isinstance(evidence_id, str) or evidence_id in evidence_ids:
            raise ValueError("duplicate or missing evidence-result identity")
        evidence_ids.add(evidence_id)
        evidence_by_obligation[obligation_id] = evidence_id
    if result_obligation_ids != obligation_ids:
        raise ValueError("obligation results are incomplete")
    lineage_evidence_ids: set[str] = set()
    for row in lineage:
        evidence_id = row.get("evidence_result_id")
        if evidence_id not in evidence_ids or evidence_id in lineage_evidence_ids:
            raise ValueError("duplicate or orphaned evidence lineage")
        lineage_evidence_ids.add(evidence_id)
    if lineage_evidence_ids != evidence_ids:
        raise ValueError("evidence lineage is incomplete")
    handlers_by_id = {
        row["handler_pair_id"]: row for row in handler_pairs
    }
    programs_by_id = {
        row["program_pair_id"]: row for row in program_pairs
    }
    for row in program_pairs:
        linked_handlers = _linked_id_set(
            row, "handler_pair_ids", handler_ids, "program pair"
        )
        actual_handlers = {
            handler_id
            for handler_id, handler in handlers_by_id.items()
            if handler.get("program_pair_id") == row["program_pair_id"]
        }
        if linked_handlers != actual_handlers:
            raise ValueError("program-pair handler links are incomplete")

    validator_handler_ids: set[str] = set()
    validator_links_by_handler: dict[str, dict[str, Any]] = {}
    obligation_parent = {
        row["logical_obligation_id"]: row["program_pair_id"]
        for row in obligations
    }
    for row in validator_links:
        handler_id = row.get("handler_pair_id")
        if (
            handler_id not in handler_ids
            or handler_id in validator_handler_ids
        ):
            raise ValueError("duplicate or missing validator handler link")
        validator_handler_ids.add(handler_id)
        validator_links_by_handler[handler_id] = row
        handler = handlers_by_id[handler_id]
        program_pair_id = row.get("program_pair_id")
        if program_pair_id != handler.get("program_pair_id"):
            raise ValueError("validator link has the wrong program pair")
        linked_obligations = _linked_id_set(
            row,
            "logical_obligation_ids",
            obligation_ids,
            "validator link",
        )
        linked_evidence = _linked_id_set(
            row, "evidence_result_ids", evidence_ids, "validator link"
        )
        if (
            any(
                obligation_parent[obligation_id] != program_pair_id
                for obligation_id in linked_obligations
            )
            or linked_evidence
            != {
                evidence_by_obligation[obligation_id]
                for obligation_id in linked_obligations
            }
        ):
            raise ValueError("validator link evidence has the wrong parent")
    if validator_handler_ids != handler_ids:
        raise ValueError("validator handler links are incomplete")

    feature_ids: set[str] = set()
    expected_handler_features = {
        handler_id: set() for handler_id in handler_ids
    }
    expected_program_features = {
        program_id: set() for program_id in pair_ids
    }
    for row in feature_links:
        feature_id = row.get("feature_id")
        if not isinstance(feature_id, str) or feature_id in feature_ids:
            raise ValueError("duplicate or missing feature identity")
        feature_ids.add(feature_id)
        linked_handlers = _linked_id_set(
            row, "handler_pair_ids", handler_ids, "feature link"
        )
        linked_programs = _linked_id_set(
            row, "program_pair_ids", pair_ids, "feature link"
        )
        linked_obligations = _linked_id_set(
            row,
            "semantic_obligation_ids",
            obligation_ids,
            "feature link",
        )
        required_evidence = _linked_id_set(
            row, "required_evidence", evidence_ids, "feature link"
        )
        authoritative_evidence = _linked_id_set(
            row, "authoritative_evidence", evidence_ids, "feature link"
        )
        all_evidence = _linked_id_set(
            row, "all_linked_evidence", evidence_ids, "feature link"
        )
        linked_evidence_for_obligations = {
            evidence_by_obligation[obligation_id]
            for obligation_id in linked_obligations
        }
        if (
            not linked_handlers
            or not linked_programs
            or not linked_obligations
            or not required_evidence
            or not required_evidence.issubset(authoritative_evidence)
            or not authoritative_evidence.issubset(all_evidence)
            or all_evidence != linked_evidence_for_obligations
        ):
            raise ValueError("feature link is missing authoritative evidence")
        if any(
            handlers_by_id[handler_id].get("program_pair_id")
            not in linked_programs
            for handler_id in linked_handlers
        ):
            raise ValueError("feature handler does not use a linked program")
        if any(
            obligation_parent[obligation_id] not in linked_programs
            for obligation_id in linked_obligations
        ):
            raise ValueError("feature obligation has the wrong program parent")
        for handler_id in linked_handlers:
            expected_handler_features[handler_id].add(feature_id)
        for program_id in linked_programs:
            expected_program_features[program_id].add(feature_id)

    for handler_id, expected_features in expected_handler_features.items():
        if (
            set(handlers_by_id[handler_id].get("feature_ids", []))
            != expected_features
            or set(
                validator_links_by_handler[handler_id].get("feature_ids", [])
            )
            != expected_features
        ):
            raise ValueError("validator feature links are incomplete")
    for program_id, expected_features in expected_program_features.items():
        if (
            set(programs_by_id[program_id].get("covered_feature_ids", []))
            != expected_features
        ):
            raise ValueError("program feature links are incomplete")
    if not task_results:
        raise ValueError("baseline task results are empty")

    counts = summary.get("counts")
    if not isinstance(counts, dict):
        raise ValueError("baseline summary counts are missing")
    expected_counts = {
        "handler_pairs": len(handler_pairs),
        "handler_pair_records": len(handler_pairs),
        "unique_program_pairs": len(program_pairs),
        "program_pair_records": len(program_pairs),
        "program_state_total": len(program_pairs),
        "semantic_obligation_records": len(obligations),
        "obligation_result_records": len(results),
        "obligation_state_total": len(obligations),
        "validator_handlers": len(validator_links),
        "validator_link_records": len(validator_links),
        "feature_rows": len(feature_links),
        "feature_link_records": len(feature_links),
    }
    for name, expected in expected_counts.items():
        if counts.get(name) != expected:
            raise ValueError(
                f"baseline summary count mismatch for {name}: "
                f"expected {expected}, got {counts.get(name)!r}"
            )
    invariants = summary.get("count_invariants")
    required_invariants = {
        "obligation_final_states_equal_unique_obligations",
        "program_final_states_equal_unique_program_pairs",
    }
    if not isinstance(invariants, dict) or any(
        invariants.get(name) is not True for name in required_invariants
    ):
        raise ValueError("baseline summary count invariants do not hold")

    attestation = _read_json(root / "ci-attestation.json")
    required_attestation = {
        "baseline_content_id",
        "repository_commit",
        "workflow_revision",
        "github_run_id",
        "job_id",
        "artifact_id",
        "artifact_sha256",
        "platform",
        "capture_command",
        "verification_result",
    }
    if set(attestation) - {
        "schema_version",
        "attestation_kind",
        "profile_id",
        *required_attestation,
    }:
        raise ValueError("CI attestation has unknown fields")
    if not required_attestation.issubset(attestation):
        raise ValueError("CI attestation is incomplete")
    if attestation.get("schema_version") != 2:
        raise ValueError("CI attestation must use schema_version 2")
    if attestation.get("attestation_kind") != "public_ci_reproduction":
        raise ValueError("baseline is not attested by public CI")
    if attestation.get("verification_result") != "verified":
        raise ValueError("CI baseline verification did not succeed")
    if attestation.get("baseline_content_id") != content_id:
        raise ValueError("CI attestation content identity mismatch")
    if attestation.get("profile_id") != summary.get("profile", {}).get(
        "profile_id"
    ):
        raise ValueError("CI attestation profile identity mismatch")
    for field in ("repository_commit", "workflow_revision"):
        value = attestation.get(field)
        if (
            not isinstance(value, str)
            or len(value) != 40
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError(f"CI attestation {field} is invalid")
    for field in ("github_run_id", "job_id", "artifact_id"):
        value = attestation.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"CI attestation {field} is invalid")
    artifact_sha = attestation.get("artifact_sha256")
    if (
        not isinstance(artifact_sha, str)
        or len(artifact_sha) != 64
        or any(character not in "0123456789abcdef" for character in artifact_sha)
    ):
        raise ValueError("CI artifact SHA-256 is invalid")
    for field in ("platform", "capture_command"):
        if not isinstance(attestation.get(field), str) or not attestation[field]:
            raise ValueError(f"CI attestation {field} is invalid")

    return {
        "schema_version": 2,
        "valid": True,
        "baseline_content_id": content_id,
        "profile_id": summary.get("profile", {}).get("profile_id"),
        "counts": {
            "handler_pairs": len(handler_pairs),
            "program_pairs": len(program_pairs),
            "semantic_obligations": len(obligations),
            "obligation_results": len(results),
            "lineage_records": len(lineage),
        },
        "ci_attestation": attestation,
    }
