from __future__ import annotations

import argparse
import hashlib
import json
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
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _manifest_record(path: Path) -> dict[str, Any]:
    manifest = _read(path)
    source = manifest["source"]
    return {
        "artifact_id": manifest["artifact_id"],
        "artifact_kind": manifest["artifact_kind"],
        "binary": manifest["binary"],
        "build": manifest["build"],
        "cache_key": manifest["cache_key"],
        "label": manifest["label"],
        "reproducibility": manifest["reproducibility"],
        "source": source,
        "target": manifest["target"],
        "toolchain": manifest["toolchain"],
    }


def _portable_compiler(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    compiler = {
        key: item
        for key, item in value.items()
        if key != "executable"
    }
    provenance = compiler.get("provenance")
    if isinstance(provenance, dict):
        compiler["provenance"] = {
            key: item
            for key, item in provenance.items()
            if key != "manifest_path"
        }
    return compiler


def _compact_replay(value: Any, run: Path) -> Any:
    if not isinstance(value, dict):
        return value
    replay = dict(value)
    for label in ("old", "new"):
        evaluation = replay.get(label)
        if isinstance(evaluation, dict):
            replay[label] = {
                key: item
                for key, item in evaluation.items()
                if key != "command"
            }
    arguments_path = replay.get("arguments_path")
    if isinstance(arguments_path, str):
        path = run / arguments_path
        if _sha256(path) != replay.get("arguments_sha256"):
            raise ValueError(f"replay argument hash mismatch: {path}")
        replay["arguments"] = _read(path)
    return replay


def _compact_pair(row: dict[str, Any], run: Path) -> dict[str, Any]:
    witness = row.get("witness")
    compiler_pair = row.get("compiler_pair")
    if isinstance(compiler_pair, dict):
        compiler_pair = {
            label: _portable_compiler(compiler)
            for label, compiler in compiler_pair.items()
        }
    source_identity = row.get("source_identity")
    if isinstance(source_identity, dict):
        source_identity = {
            key: item
            for key, item in source_identity.items()
            if key != "repository_root"
        }
    return {
        "pair_id": row["pair_id"],
        "status": row["status"],
        "old_script_sha256": row.get("old_script", {}).get("sha256"),
        "new_script_sha256": row.get("new_script", {}).get("sha256"),
        "validator_identity": row.get("validator_identity"),
        "compiler_pair": compiler_pair,
        "abi": row.get("abi"),
        "input_model": row.get("input_model"),
        "domain_assumptions": row.get("domain_assumptions"),
        "proof_obligations": row.get("proof_obligations"),
        "theorem_hash": (
            witness.get("theorem_hash")
            if isinstance(witness, dict)
            else row.get("proof_obligations", {})
            .get("observational_equivalence", {})
            .get("theorem_hash")
        ),
        "generated_lean_sha256": row.get("generated_lean_sha256"),
        "solver_input_sha256": row.get("solver_input_sha256"),
        "witness": witness,
        "counterexample_replay": _compact_replay(
            row.get("counterexample_replay"), run
        ),
        "evaluator": row.get("evaluator"),
        "source_identity": source_identity,
    }


def capture(run: Path, output: Path, identifier: str) -> None:
    run = run.expanduser().resolve()
    output = output.expanduser().resolve()
    profile = _profile(identifier)
    profile_result = _read(run / "profile-result.json")
    if profile_result["profile_id"] != profile["id"]:
        raise ValueError("profile result does not match the requested profile")
    summary = _read(run / "summary.json")
    run_record = _read(run / "run.json")
    pair_records = _read(run / "pair-results.json")["records"]
    builds = {label: _read(run / f"build-{label}.json") for label in ("old", "new")}

    manifests: dict[str, dict[str, Any]] = {}
    for label in ("old", "new"):
        manifest_path = Path(run_record["compiler_pair"][label]["provenance"]["manifest_path"])
        manifests[label] = _manifest_record(manifest_path)
    lock = _read(PROFILE_LOCK)["profiles"][profile["id"]]
    compiler_lock = {
        "schema_version": 1,
        "profile_lock": lock,
        "compilers": manifests,
    }
    source_lock = {
        "schema_version": 1,
        "fixture": profile["fixture"],
        "package": run_record["package"],
        "source_hash": run_record["source_hash"],
        "dependency_lock_hash": run_record["dependency_lock_hash"],
        "source_immutable": run_record["source_immutable"],
        "old_new_source_hash_equal": builds["old"]["source_hash_before"]
        == builds["new"]["source_hash_before"],
        "old_new_dependency_lock_equal": builds["old"]["dependency_lock_hash_before"]
        == builds["new"]["dependency_lock_hash_before"],
    }
    first_pair = pair_records[0] if pair_records else {}
    environment = {
        "schema_version": 1,
        "blaster_configuration": run_record["blaster_configuration"],
        "checker_configuration": run_record["checker_configuration"],
        "blaster_dependencies": first_pair.get("blaster_dependencies"),
        "execution_environment": first_pair.get("execution_environment"),
    }
    source = run_record["source"]
    source_provenance = {
        "schema_version": 1,
        "kind": source.get("kind"),
        "repository_url": source.get("remote"),
        "commit": source.get("commit"),
        "dirty": source.get("dirty"),
        "package_path": source.get("package_path"),
        "source_identity": source.get("identity"),
        "source_identity_fields": source.get("identity_fields"),
        "source_hash": run_record["source_hash"],
    }
    compact_pairs = [_compact_pair(row, run) for row in pair_records]
    status_counts: dict[str, int] = {}
    for row in compact_pairs:
        status_counts[row["status"]] = status_counts.get(row["status"], 0) + 1
    counts = {
        "total_generated_validator_pairs": len(compact_pairs),
        "byte_identical_pairs": sum(
            row["old_script_sha256"] == row["new_script_sha256"] for row in compact_pairs
        ),
        "non_identical_pairs": sum(
            row["old_script_sha256"] != row["new_script_sha256"] for row in compact_pairs
        ),
        "strict_complete_equivalence_results": status_counts.get(
            "equivalent_under_raw_model", 0
        ),
        "bounded_results": status_counts.get("bounded_equivalent", 0),
        "inconclusive_results": sum(
            count for status, count in status_counts.items() if "inconclusive" in status
        ),
        "confirmed_non_equivalent_results": status_counts.get(
            "confirmed_non_equivalent", 0
        ),
    }
    compact_summary = {
        "schema_version": 1,
        "profile": {key: profile_result[key] for key in (
            "profile_id",
            "profile_name",
            "semantic_status",
            "semantic_statuses",
            "profile_expectation",
            "expectation_matched",
            "semantic_strict_result",
            "expected_strict_result",
            "profile_pass",
        )},
        "run_id": run_record["run_id"],
        "counts": counts,
        "status_counts": status_counts,
        "strict_pass": summary["strict_pass"],
        "script_difference_observed": summary["script_difference_observed"],
        "gaps": summary["gaps"],
    }
    feature_coverage = _read(run / "feature-coverage.json")
    trigger_path = ROOT / profile["fixture"] / "codegen-triggers.json"
    if trigger_path.is_file():
        triggers = _read(trigger_path)
        feature_coverage["historical_codegen_triggers"] = triggers["records"]
        feature_coverage["historical_shared_feature_contract"] = triggers.get(
            "shared_feature_contract"
        )
        feature_coverage["historical_coverage_claims"] = triggers.get(
            "coverage_claims"
        )

    task_rows = []
    for label, build in builds.items():
        task_rows.append(
            {
                "task": f"build-{label}",
                "compiler": _portable_compiler(build["compiler"]),
                "source_hash_before": build["source_hash_before"],
                "source_hash_after": build["source_hash_after"],
                "source_unchanged": build["source_unchanged"],
                "dependency_lock_hash_before": build["dependency_lock_hash_before"],
                "dependency_lock_hash_after": build["dependency_lock_hash_after"],
                "dependency_lock_unchanged": build["dependency_lock_unchanged"],
                "blueprint_compatibility": build["blueprint_compatibility"],
                "abi_inspection": build["abi_inspection"],
                "primary_exit_code": build["primary_exit_code"],
            }
        )

    files = {
        "compiler-lock.json": compiler_lock,
        "source-lock.json": source_lock,
        "environment.json": environment,
        "feature-coverage.json": feature_coverage,
        "source-provenance.json": source_provenance,
        "summary.json": compact_summary,
    }
    for name, value in files.items():
        _write(output / name, value)
    (output / "task-results.ndjson").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in task_rows),
        encoding="utf-8",
    )
    (output / "pair-results.ndjson").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in compact_pairs),
        encoding="utf-8",
    )
    artifact_names = sorted([*files, "task-results.ndjson", "pair-results.ndjson"])
    checksums = {
        "schema_version": 1,
        "algorithm": "sha256",
        "files": {name: _sha256(output / name) for name in artifact_names},
    }
    _write(output / "checksums.json", checksums)


def main() -> int:
    parser = argparse.ArgumentParser(description="capture a compact historical profile baseline")
    parser.add_argument("--profile", required=True)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    capture(args.run, args.output, args.profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
