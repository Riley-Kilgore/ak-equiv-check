from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROFILE_REGISTRY = ROOT / "corpus" / "compiler_profiles.json"
PROFILE_LOCK = ROOT / "corpus" / "compiler_profiles.lock.json"


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected an object in {path}")
    return value


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _identity(kind: str, payload: Any) -> str:
    return hashlib.sha256(
        _canonical(
            {
                "identity_schema_version": "equiv-evidence-identity/v3",
                "identity_kind": kind,
                "value": payload,
            }
        ).encode("utf-8")
    ).hexdigest()


def _profile(identifier: str) -> dict[str, Any]:
    registry = _read(PROFILE_REGISTRY)
    matches = [
        row
        for row in registry["profiles"]
        if row["id"] == identifier or row["name"] == identifier
    ]
    if len(matches) != 1:
        raise ValueError(f"unknown or ambiguous profile: {identifier}")
    return matches[0]


def _records(run: Path, filename: str) -> list[dict[str, Any]]:
    value = _read(run / filename)
    records = value.get("records")
    if not isinstance(records, list) or not all(
        isinstance(row, dict) for row in records
    ):
        raise ValueError(f"invalid record set: {run / filename}")
    return records


def _portable(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace(str(ROOT), "$ROOT")
    if isinstance(value, list):
        return [_portable(item) for item in value]
    if not isinstance(value, dict):
        return value
    result: dict[str, Any] = {}
    for key, item in value.items():
        if isinstance(item, str) and (
            key == "executable"
            or key == "repository_root"
            or key == "manifest_path"
            or (key.endswith("_path") and Path(item).is_absolute())
        ):
            continue
        result[key] = _portable(item)
    return result


def _obligation_result_identity(record: dict[str, Any]) -> str:
    return _identity(
        "obligation_result",
        {
            "logical_obligation_id": record["logical_obligation_id"],
            "obligation_attempt_id": record["obligation_attempt_id"],
            "execution_attempt_id": record["execution_attempt_id"],
            "checker_configuration_id": record["checker_configuration_id"],
            "checker_implementation_id": record["checker_implementation_id"],
            "program_pair_id": record["program_pair_id"],
            "semantic_model_id": record["semantic_model_id"],
            "obligation_kind": record["obligation_kind"],
            "status": record["status"],
            "generated_source_sha256": record.get("generated_source_sha256"),
            "solver_status": record.get("solver_status"),
            "witness_reference": record.get("witness_reference"),
            "replay_reference": record.get("replay_reference"),
            "relevant_solver_options": record["relevant_solver_options"],
            "attempt_sequence": int(record["attempt_sequence"]),
        },
    )


def _make_identity_bound_records_portable(
    record_files: dict[str, list[dict[str, Any]]],
) -> None:
    replay_id_changes: dict[str, str] = {}
    portable_replays: list[dict[str, Any]] = []
    for replay in record_files["replays.ndjson"]:
        portable = _portable(replay)
        previous_id = str(portable.pop("replay_id"))
        current_id = _identity("counterexample_replay", portable)
        portable["replay_id"] = current_id
        replay_id_changes[previous_id] = current_id
        portable_replays.append(portable)
    record_files["replays.ndjson"] = portable_replays

    evidence_id_changes: dict[str, str] = {}
    for result in record_files["obligation-results.ndjson"]:
        previous_id = str(result["evidence_result_id"])
        replay_reference = result.get("replay_reference")
        if replay_reference in replay_id_changes:
            result["replay_reference"] = replay_id_changes[replay_reference]
        current_id = _obligation_result_identity(result)
        result["evidence_result_id"] = current_id
        evidence_id_changes[previous_id] = current_id

    for link in record_files["validator-links.ndjson"]:
        link["evidence_result_ids"] = sorted(
            evidence_id_changes[evidence_id]
            for evidence_id in link["evidence_result_ids"]
        )


def _manifest_record(path: Path) -> dict[str, Any]:
    manifest = _read(path)
    return {
        key: manifest[key]
        for key in (
            "artifact_id",
            "artifact_kind",
            "binary",
            "build",
            "cache_key",
            "label",
            "reproducibility",
            "source",
            "target",
            "toolchain",
        )
    }


def _write_ndjson(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(
            json.dumps(_portable(row), sort_keys=True) + "\n"
            for row in records
        ),
        encoding="utf-8",
    )


def _bind_historical_feature_links(
    profile: dict[str, Any],
    record_files: dict[str, list[dict[str, Any]]],
    pair_results: list[dict[str, Any]],
) -> None:
    trigger_path = ROOT / profile["fixture"] / "codegen-triggers.json"
    if not trigger_path.is_file():
        return
    trigger_document = _read(trigger_path)
    triggers = trigger_document.get("records")
    if not isinstance(triggers, list) or not all(
        isinstance(row, dict) for row in triggers
    ):
        raise ValueError(f"invalid historical feature records: {trigger_path}")

    program_pairs = record_files["program-pairs.ndjson"]
    programs_by_hashes: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for pair in program_pairs:
        key = (
            pair["old_program_artifact"]["script_sha256"],
            pair["new_program_artifact"]["script_sha256"],
        )
        programs_by_hashes.setdefault(key, []).append(pair)
    obligations = record_files["semantic-obligations.ndjson"]
    evidence_by_obligation = {
        row["logical_obligation_id"]: row["evidence_result_id"]
        for row in record_files["obligation-results.ndjson"]
    }
    status_by_pair = {
        row["program_pair_id"]: row["status"] for row in pair_results
    }
    feature_status = {
        "equivalent_under_raw_model": "pair_complete_equivalent",
        "equivalent_under_ledger_model": "pair_complete_equivalent",
        "confirmed_non_equivalent": "pair_confirmed_non_equivalent",
        "bounded_equivalent": "pair_bounded_equivalent",
        "blaster_inconclusive": "pair_inconclusive",
        "blaster_unsupported": "pair_unsupported",
    }
    handlers = record_files["handler-pairs.ndjson"]
    validator_links = record_files["validator-links.ndjson"]
    feature_links: list[dict[str, Any]] = []
    seen_features: set[str] = set()
    for trigger in triggers:
        feature_id = trigger.get("feature_id")
        if not isinstance(feature_id, str) or feature_id in seen_features:
            raise ValueError("historical feature IDs must be unique strings")
        seen_features.add(feature_id)
        key = (
            trigger.get("old_compiled_code_sha256"),
            trigger.get("new_compiled_code_sha256"),
        )
        matches = programs_by_hashes.get(key, [])
        if len(matches) != 1:
            raise ValueError(
                f"historical feature {feature_id} does not identify one program pair"
            )
        program_pair = matches[0]
        program_pair_id = program_pair["program_pair_id"]
        handler_pair_ids = sorted(program_pair["handler_pair_ids"])
        obligation_rows = [
            obligation
            for obligation in obligations
            if obligation["program_pair_id"] == program_pair_id
        ]
        obligation_ids = sorted(
            obligation["logical_obligation_id"]
            for obligation in obligation_rows
        )
        authoritative_obligation_ids = sorted(
            obligation["logical_obligation_id"]
            for obligation in obligation_rows
            if obligation.get("input_model", {}).get("profile")
            == "raw-uplc/v1"
        )
        evidence_ids = sorted(
            evidence_by_obligation[obligation_id]
            for obligation_id in obligation_ids
        )
        authoritative_evidence_ids = sorted(
            evidence_by_obligation[obligation_id]
            for obligation_id in authoritative_obligation_ids
        )
        pair_status = status_by_pair.get(program_pair_id)
        if pair_status not in feature_status:
            raise ValueError(
                f"historical feature {feature_id} has unsupported pair status "
                f"{pair_status!r}"
            )
        feature_links.append(
            {
                "feature_id": feature_id,
                "row_kind": "historical_codegen_trigger",
                "status": feature_status[pair_status],
                "source_location": trigger.get("source_location"),
                "language_construct": trigger.get("language_construct"),
                "expected_compiler_change": trigger.get(
                    "expected_compiler_change"
                ),
                "old_script_sha256": key[0],
                "new_script_sha256": key[1],
                "handler_pair_ids": handler_pair_ids,
                "program_pair_ids": [program_pair_id],
                "semantic_obligation_ids": obligation_ids,
                "required_evidence": authoritative_evidence_ids,
                "authoritative_evidence": authoritative_evidence_ids,
                "all_linked_evidence": evidence_ids,
            }
        )
        program_pair["covered_feature_ids"] = sorted(
            set(program_pair.get("covered_feature_ids", [])) | {feature_id}
        )
        for row in handlers:
            if row["handler_pair_id"] in handler_pair_ids:
                row["feature_ids"] = sorted(
                    set(row.get("feature_ids", [])) | {feature_id}
                )
        for row in validator_links:
            if row["handler_pair_id"] in handler_pair_ids:
                row["feature_ids"] = sorted(
                    set(row.get("feature_ids", [])) | {feature_id}
                )
    record_files["feature-links.ndjson"] = feature_links


def _bind_replay_evidence(
    obligation_results: list[dict[str, Any]],
    pair_results: list[dict[str, Any]],
) -> None:
    results_by_obligation = {
        row["logical_obligation_id"]: row for row in obligation_results
    }
    for pair in pair_results:
        replay = pair.get("counterexample_replay")
        witness = pair.get("witness")
        if not isinstance(replay, dict) or not replay.get("confirmed"):
            continue
        obligation_id = replay.get("logical_obligation_id")
        result = results_by_obligation.get(obligation_id)
        if result is None:
            raise ValueError(
                "confirmed replay has no matching obligation result"
            )
        if not isinstance(witness, dict):
            raise ValueError("confirmed replay has no machine witness record")
        result["witness"] = witness
        result["replay"] = replay


def _summary_markdown(summary: dict[str, Any]) -> str:
    profile = summary["profile"]
    counts = summary["counts"]
    lines = [
        f"# {profile['profile_name']}",
        "",
        f"- Profile ID: `{profile['profile_id']}`",
        f"- Semantic status: `{profile['semantic_status']}`",
        f"- Semantic strict result: `{profile['semantic_strict_result']}`",
        f"- Expectation matched: `{str(profile['expectation_matched']).lower()}`",
        f"- Source dirty: `{str(summary['source_provenance']['dirty']).lower()}`",
        "",
        "## Evidence counts",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
    ]
    lines.extend(
        f"| `{name}` | {count} |"
        for name, count in sorted(counts.items())
    )
    lines.extend(["", "## Remaining gaps", ""])
    if summary["gaps"]:
        lines.extend(f"- `{gap}`" for gap in summary["gaps"])
    else:
        lines.append("None.")
    return "\n".join(lines) + "\n"


def _ci_attestation(
    value: dict[str, Any],
    *,
    profile_id: str,
    baseline_run_id: str,
    content_id: str,
    capture_command: str,
) -> dict[str, Any]:
    workflow = value.get("workflow_run")
    job = value.get("job")
    artifact = value.get("artifact")
    if not all(isinstance(item, dict) for item in (workflow, job, artifact)):
        raise ValueError("CI provenance is missing workflow, job, or artifact")
    if value.get("profile_id") != profile_id:
        raise ValueError("CI provenance profile does not match the baseline")
    if value.get("baseline_run_id") != baseline_run_id:
        raise ValueError("CI provenance run does not match the captured run")
    if workflow.get("conclusion") != "success" or job.get("conclusion") != "success":
        raise ValueError("CI reproduction did not succeed")
    digest = artifact.get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ValueError("CI artifact digest must be SHA-256")
    head_sha = workflow.get("head_sha")
    if not isinstance(head_sha, str) or len(head_sha) != 40:
        raise ValueError("CI repository commit is invalid")
    return {
        "schema_version": 3,
        "attestation_kind": "public_ci_reproduction",
        "profile_id": profile_id,
        "baseline_content_id": content_id,
        "repository_commit": head_sha,
        "workflow_revision": value.get("workflow_revision", head_sha),
        "github_run_id": workflow.get("id"),
        "job_id": job.get("id"),
        "artifact_id": artifact.get("id"),
        "artifact_sha256": digest.removeprefix("sha256:"),
        "platform": value.get("platform", "ubuntu-24.04"),
        "capture_command": capture_command,
        "verification_result": "verified",
    }


def capture(
    run: Path,
    output: Path,
    identifier: str,
    ci_provenance_path: Path | None = None,
) -> None:
    run = run.expanduser().resolve()
    output = output.expanduser().resolve()
    profile = _profile(identifier)
    profile_result = _read(run / "profile-result.json")
    summary = _read(run / "summary.json")
    run_record = _read(run / "run.json")
    if profile_result.get("profile_id") != profile["id"]:
        raise ValueError("profile result does not match the requested profile")
    if not profile_result.get("profile_pass"):
        raise ValueError("cannot capture a failing historical profile")
    if not summary.get("source_immutable"):
        raise ValueError("cannot capture a mutable source run")
    source = run_record.get("source", {})
    if source.get("dirty") is not False:
        raise ValueError("canonical historical baseline source must be clean")

    if output.exists():
        if not output.is_dir():
            raise ValueError(f"baseline output is not a directory: {output}")
        for child in output.iterdir():
            if not child.is_file():
                raise ValueError(
                    f"baseline output contains an unexpected directory: {child}"
                )
            child.unlink()
    output.mkdir(parents=True, exist_ok=True)
    pair_results = _records(run, "pair-results.json")
    program_pairs = _records(run, "program-pairs.json")
    program_artifacts: dict[str, dict[str, Any]] = {}
    for pair in program_pairs:
        for side in ("old_program_artifact", "new_program_artifact"):
            artifact = pair[side]
            serialized_hex = (
                (run / artifact["path"])
                .read_text(encoding="ascii")
                .strip()
                .lower()
            )
            record = {
                "program_artifact_id": artifact["program_artifact_id"],
                "serialized_script_bytes_hex": serialized_hex,
                "script_sha256": artifact["script_sha256"],
                "script_size": artifact["script_size"],
                "plutus_version": artifact["plutus_version"],
                "serialization_format": artifact["serialization_format"],
            }
            previous = program_artifacts.setdefault(
                artifact["program_artifact_id"], record
            )
            if previous != record:
                raise ValueError("conflicting historical program artifact")
    record_files = {
        "handler-pairs.ndjson": _records(run, "handler-pairs.json"),
        "program-artifacts.ndjson": [
            program_artifacts[key] for key in sorted(program_artifacts)
        ],
        "program-pairs.ndjson": program_pairs,
        "semantic-obligations.ndjson": _records(
            run, "semantic-obligations.json"
        ),
        "obligation-results.ndjson": _records(run, "obligation-results.json"),
        "execution-attempts.ndjson": _records(
            run, "execution-attempts.json"
        ),
        "witnesses.ndjson": _records(run, "witnesses.json"),
        "replays.ndjson": _records(run, "replays.json"),
        "validator-links.ndjson": _records(run, "validator-links.json"),
        "feature-links.ndjson": _records(run, "feature-links.json"),
    }
    _make_identity_bound_records_portable(record_files)
    _bind_historical_feature_links(profile, record_files, pair_results)
    obligation_results = record_files["obligation-results.ndjson"]
    record_files["evidence-lineage.ndjson"] = [
        {
            "evidence_result_id": row["evidence_result_id"],
            "logical_obligation_id": row["logical_obligation_id"],
            "program_pair_id": row["program_pair_id"],
            "obligation_attempt_id": row["obligation_attempt_id"],
            "execution_attempt_id": row["execution_attempt_id"],
            "checker_configuration_id": row["checker_configuration_id"],
            "checker_implementation_id": row["checker_implementation_id"],
            "witness_reference": row.get("witness_reference"),
            "replay_reference": row.get("replay_reference"),
            "reused": row.get("reused", False),
        }
        for row in obligation_results
    ]
    for filename, records in record_files.items():
        _write_ndjson(output / filename, records)

    manifests: dict[str, dict[str, Any]] = {}
    for label in ("old", "new"):
        manifest_path = Path(
            run_record["compiler_pair"][label]["provenance"]["manifest_path"]
        )
        manifests[label] = _manifest_record(manifest_path)
    compiler_lock = {
        "schema_version": 3,
        "profile_lock": _read(PROFILE_LOCK)["profiles"][profile["id"]],
        "compilers": manifests,
    }
    builds = {
        label: _read(run / f"build-{label}.json")
        for label in ("old", "new")
    }
    source_lock = {
        "schema_version": 3,
        "fixture": profile["fixture"],
        "package": run_record["package"],
        "source_hash": run_record["source_hash"],
        "dependency_lock_hash": run_record["dependency_lock_hash"],
        "source_immutable": run_record["source_immutable"],
        "source_provenance": _portable(source),
        "old_new_source_hash_equal": builds["old"]["source_hash_before"]
        == builds["new"]["source_hash_before"],
        "old_new_dependency_lock_equal": builds["old"][
            "dependency_lock_hash_before"
        ]
        == builds["new"]["dependency_lock_hash_before"],
    }
    environment = {
        "schema_version": 3,
        "blaster_configuration": run_record["blaster_configuration"],
        "checker_configuration": run_record["checker_configuration"],
        "checker_implementation_id": run_record["blaster_configuration"][
            "checker_implementation_id"
        ],
        "replay_trust": [
            row.get("counterexample_replay", {}).get("replay_trust")
            for row in pair_results
            if isinstance(row.get("counterexample_replay"), dict)
        ],
    }
    counts = dict(summary["counts"])
    counts.update(
        {
            "handler_pair_records": len(record_files["handler-pairs.ndjson"]),
            "program_pair_records": len(record_files["program-pairs.ndjson"]),
            "program_artifact_records": len(
                record_files["program-artifacts.ndjson"]
            ),
            "semantic_obligation_records": len(
                record_files["semantic-obligations.ndjson"]
            ),
            "obligation_result_records": len(obligation_results),
            "execution_attempt_records": len(
                record_files["execution-attempts.ndjson"]
            ),
            "witness_records": len(record_files["witnesses.ndjson"]),
            "replay_records": len(record_files["replays.ndjson"]),
            "validator_link_records": len(record_files["validator-links.ndjson"]),
            "feature_link_records": len(record_files["feature-links.ndjson"]),
            "validator_handlers": len(record_files["validator-links.ndjson"]),
            "feature_rows": len(record_files["feature-links.ndjson"]),
        }
    )
    compact_summary = {
        "schema_version": 3,
        "profile": {
            key: profile_result[key]
            for key in (
                "profile_id",
                "profile_name",
                "semantic_status",
                "semantic_statuses",
                "profile_expectation",
                "expectation_matched",
                "semantic_strict_result",
                "expected_strict_result",
                "profile_pass",
            )
        },
        "run_id": run_record["run_id"],
        "checker_implementation_id": run_record["blaster_configuration"][
            "checker_implementation_id"
        ],
        "counts": counts,
        "count_invariants": summary["count_invariants"],
        "status_counts": summary["status_counts"],
        "obligation_status_counts": summary["obligation_status_counts"],
        "strict_pass": summary["strict_pass"],
        "script_difference_observed": summary["script_difference_observed"],
        "source_provenance": _portable(source),
        "gaps": summary["gaps"],
    }
    json_files = {
        "compiler-lock.json": compiler_lock,
        "source-lock.json": source_lock,
        "environment.json": environment,
        "summary.json": compact_summary,
    }
    for filename, value in json_files.items():
        _write(output / filename, value)
    (output / "summary.md").write_text(
        _summary_markdown(compact_summary), encoding="utf-8"
    )
    task_rows = [
        {
            "task": f"build-{label}",
            "compiler": _portable(build["compiler"]),
            "source_hash_before": build["source_hash_before"],
            "source_hash_after": build["source_hash_after"],
            "source_unchanged": build["source_unchanged"],
            "dependency_lock_hash_before": build["dependency_lock_hash_before"],
            "dependency_lock_hash_after": build["dependency_lock_hash_after"],
            "dependency_lock_unchanged": build["dependency_lock_unchanged"],
            "primary_exit_code": build["primary_exit_code"],
        }
        for label, build in builds.items()
    ]
    _write_ndjson(output / "task-results.ndjson", task_rows)

    checksummed_files = sorted(
        child.name
        for child in output.iterdir()
        if child.is_file()
        and child.name not in {"checksums.json", "ci-attestation.json"}
    )
    checksums = {name: _sha256(output / name) for name in checksummed_files}
    content_id = _identity(
        "baseline-content",
        {
            "schema_version": 3,
            "algorithm": "sha256",
            "files": checksums,
        },
    )
    _write(
        output / "checksums.json",
        {
            "schema_version": 3,
            "algorithm": "sha256",
            "baseline_content_id": content_id,
            "files": checksums,
        },
    )
    capture_command = (
        "python scripts/capture_historical_baseline.py "
        f"--profile {profile['id']} --run {run_record['run_id']} "
        f"--output results/baselines/{profile['id']} "
        "--ci-provenance ci-provenance.json"
    )
    if ci_provenance_path is not None:
        attestation = _ci_attestation(
            _read(ci_provenance_path.expanduser().resolve()),
            profile_id=profile["id"],
            baseline_run_id=run_record["run_id"],
            content_id=content_id,
            capture_command=capture_command,
        )
        _write(output / "ci-attestation.json", attestation)


def attach_attestation(
    baseline: Path,
    identifier: str,
    ci_provenance_path: Path,
) -> None:
    baseline = baseline.expanduser().resolve()
    profile = _profile(identifier)
    checksums = _read(baseline / "checksums.json")
    summary = _read(baseline / "summary.json")
    if checksums.get("schema_version") != 3:
        raise ValueError("baseline checksums must use schema_version 3")
    content_id = checksums.get("baseline_content_id")
    run_id = summary.get("run_id")
    if not isinstance(content_id, str) or not isinstance(run_id, str):
        raise ValueError("baseline is missing its content ID or run ID")
    capture_command = (
        "python scripts/capture_historical_baseline.py "
        f"--profile {profile['id']} --run {run_id} "
        f"--output results/baselines/{profile['id']}"
    )
    attestation = _ci_attestation(
        _read(ci_provenance_path.expanduser().resolve()),
        profile_id=profile["id"],
        baseline_run_id=run_id,
        content_id=content_id,
        capture_command=capture_command,
    )
    _write(baseline / "ci-attestation.json", attestation)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="capture or attest a compact schema-version-3 historical baseline"
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--run", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--ci-provenance", type=Path)
    args = parser.parse_args()
    if args.baseline is not None:
        if args.run is not None or args.output is not None:
            parser.error("--baseline cannot be combined with --run or --output")
        if args.ci_provenance is None:
            parser.error("--baseline requires --ci-provenance")
        attach_attestation(
            args.baseline,
            args.profile,
            args.ci_provenance,
        )
        return 0
    if args.run is None or args.output is None:
        parser.error("capture requires --run and --output")
    capture(
        args.run,
        args.output,
        args.profile,
        args.ci_provenance,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            detail = f"{type(error).__name__}: {error}".replace("%", "%25")
            print(f"::error title=Historical baseline capture failed::{detail}")
        raise
