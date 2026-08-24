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
    for row in results:
        if row.get("logical_obligation_id") not in obligation_ids:
            raise ValueError("obligation result has no logical-obligation parent")
        evidence_id = row.get("evidence_result_id")
        if not isinstance(evidence_id, str) or evidence_id in evidence_ids:
            raise ValueError("duplicate or missing evidence-result identity")
        evidence_ids.add(evidence_id)
    for row in lineage:
        if row.get("evidence_result_id") not in evidence_ids:
            raise ValueError("evidence lineage has no result parent")

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
    artifact_sha = attestation.get("artifact_sha256")
    if not isinstance(artifact_sha, str) or len(artifact_sha) != 64:
        raise ValueError("CI artifact SHA-256 is invalid")

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
