#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tool"))

from equiv_checker.blaster import RealBlasterBackend  # noqa: E402
from equiv_checker.config import load_blaster_config  # noqa: E402
from equiv_checker.models import ScriptArtifact, ScriptPair  # noqa: E402
from equiv_checker.semantics import validator_input_model  # noqa: E402

DEFAULT_OUTPUT = ROOT / "results" / "baselines" / "aiken-v1.1.22-v1.1.23"
FIXTURES = ROOT / "tool" / "tests" / "fixtures" / "uplc"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact(name: str) -> ScriptArtifact:
    path = FIXTURES / name
    serialized = bytes.fromhex(path.read_text(encoding="ascii").strip())
    return ScriptArtifact(
        path=path,
        relative_path=f"tool/tests/fixtures/uplc/{name}",
        sha256=hashlib.sha256(serialized).hexdigest(),
        size=len(serialized),
    )


def validator_pair(pair_id: str, old: str, new: str) -> ScriptPair:
    return ScriptPair(
        pair_id=pair_id,
        validator_identity={"blueprint_title": f"baseline.{pair_id}.spend"},
        old_script=artifact(old),
        new_script=artifact(new),
        purpose="spending",
        parameters=({"title": "parameter", "schema": {}},),
        plutus_version="v3",
    )


def portable(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: portable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [portable(item) for item in value]
    if isinstance(value, str):
        root = str(ROOT)
        home = str(Path.home())
        if value == root or value.startswith(root + "/"):
            return "${REPOSITORY_ROOT}" + value[len(root) :]
        if value == home or value.startswith(home + "/"):
            return "${HOME}" + value[len(home) :]
    return value


def semantic_examples(work_root: Path) -> dict[str, Any]:
    shutil.rmtree(work_root, ignore_errors=True)
    for name in ("logs", "generated-lean", "counterexamples"):
        (work_root / name).mkdir(parents=True, exist_ok=True)
    config = load_blaster_config(
        evaluator_executable=ROOT / "bin" / "aiken-v1.1.23"
    )
    backend = RealBlasterBackend(config)

    equivalent_pair = validator_pair(
        "baseline-equivalent-validator",
        "validator-success.flat",
        "validator-success-beta.flat",
    )
    equivalent_model = validator_input_model(equivalent_pair)
    equivalent = backend.compare(equivalent_pair, equivalent_model, work_root)

    different_pair = validator_pair(
        "baseline-non-equivalent-validator",
        "validator-success.flat",
        "validator-error.flat",
    )
    different_model = validator_input_model(different_pair)
    different = backend.compare(different_pair, different_model, work_root)
    replay = backend.replay(
        different_pair,
        different_model,
        different.witness or {},
        work_root,
    )
    final_status = (
        "confirmed_non_equivalent"
        if different.status == "blaster_falsified_unreplayed" and replay["confirmed"]
        else "blaster_falsified_unreplayed"
    )
    return portable(
        {
            "schema_version": 1,
            "bounded_equivalent_validator": {
                "pair": equivalent_pair.to_dict(),
                "input_model": equivalent_model.to_dict(),
                "result": equivalent.to_dict(),
                "strict_pass": False,
            },
            "independently_replayed_non_equivalent_validator": {
                "pair": different_pair.to_dict(),
                "input_model": different_model.to_dict(),
                "blaster_result": different.to_dict(),
                "counterexample_replay": replay,
                "final_status": final_status,
                "strict_pass": False,
            },
        }
    )


def repository_results(corpus: dict[str, Any], lock: dict[str, Any]) -> dict[str, Any]:
    revisions = {source["id"]: source["revision"] for source in lock["sources"]}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for result in corpus["results"]:
        grouped.setdefault(result["source_id"], []).append(result)
    records = []
    for source_id in sorted(revisions):
        rows = grouped.get(source_id, [])
        classifications = Counter(row["classification"] for row in rows)
        lanes = Counter(row["lane"] for row in rows)
        semantic_statuses: Counter[str] = Counter()
        paired = 0
        for row in rows:
            semantic = row.get("semantic_summary")
            if isinstance(semantic, dict):
                semantic_statuses.update(semantic.get("status_counts", {}))
                paired += int(semantic.get("counts", {}).get("validators_paired", 0))
        strict_pass = bool(rows) and all(row["strict_pass"] for row in rows)
        records.append(
            {
                "source_id": source_id,
                "revision": revisions[source_id],
                "task_count": len(rows),
                "lane_counts": dict(sorted(lanes.items())),
                "classification_counts": dict(sorted(classifications.items())),
                "validator_pairs": paired,
                "semantic_status_counts": dict(sorted(semantic_statuses.items())),
                "final_classification": "passed" if strict_pass else "fail_closed",
                "strict_pass": strict_pass,
            }
        )
    return {"schema_version": 1, "source_count": len(records), "records": records}


def summary_markdown(summary: dict[str, Any]) -> str:
    corpus = summary["mandatory_corpus"]
    sentinel = summary["sentinel"]
    return "\n".join(
        [
            "# Aiken v1.1.22 to v1.1.23 Equivalence Baseline",
            "",
            f"- Sentinel strict pass: `{str(sentinel['strict_pass']).lower()}`",
            f"- Sentinel validator pairs: `{sentinel['validator_pairs']}`",
            f"- Sentinel shared features: `{sentinel['shared_features_covered']}`",
            f"- Mandatory sources classified: `{corpus['source_count']}`",
            f"- Mandatory tasks completed: `{corpus['completed_tasks']}`",
            f"- Mandatory corpus strict pass: `{str(corpus['strict_pass']).lower()}`",
            f"- Fail-closed mandatory tasks: `{corpus['nonpassing_tasks']}`",
            "",
            "The non-identical equivalent example is classified `bounded_equivalent` and does not pass strict mode. The validator-shaped negative example is `confirmed_non_equivalent` only after independent Aiken CEK replay.",
            "",
        ]
    )


def lean_provenance(backend_root: Path) -> dict[str, str]:
    version_result = subprocess.run(
        ["lake", "env", "lean", "--version"],
        cwd=backend_root,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    match = re.fullmatch(
        r"Lean \(version ([^,]+), .* commit ([0-9a-f]{40}), [^)]+\)\n?",
        version_result.stdout,
    )
    if match is None:
        raise RuntimeError(f"unrecognized Lean version output: {version_result.stdout!r}")
    path_result = subprocess.run(
        ["lake", "env", "which", "lean"],
        cwd=backend_root,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    executable = Path(path_result.stdout.strip()).resolve()
    if not executable.is_file():
        raise RuntimeError(f"Lean executable is missing: {executable}")
    return {
        "version": match.group(1),
        "revision": match.group(2),
        "binary_sha256": sha256_file(executable),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sentinel-run", type=Path, required=True)
    parser.add_argument("--corpus-run", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    sentinel_root = args.sentinel_run.expanduser().resolve()
    corpus_root = args.corpus_run.expanduser().resolve()
    output = args.output.expanduser().resolve()
    sentinel = read_json(sentinel_root / "summary.json")
    corpus = read_json(corpus_root / "summary.json")
    lock_path = ROOT / "corpus" / "aiken_mandatory_corpus.lock.json"
    lock = read_json(lock_path)
    if not sentinel.get("strict_pass"):
        raise RuntimeError("sentinel evidence is not strict-passing")
    if corpus.get("completed_count") != corpus.get("selected_count"):
        raise RuntimeError("mandatory corpus evidence is incomplete")

    shutil.rmtree(output, ignore_errors=True)
    output.mkdir(parents=True)
    shutil.copy2(lock_path, output / "manifest.lock.json")
    shutil.copy2(sentinel_root / "feature-coverage.json", output / "feature-coverage.json")

    repositories = repository_results(corpus, lock)
    write_json(output / "repository-results.json", repositories)
    examples = semantic_examples(ROOT / "work" / "baseline-semantic-examples")
    write_json(output / "semantic-examples.json", examples)

    sentinel_run = read_json(sentinel_root / "run.json")
    compiler_pair = read_json(ROOT / "corpus" / "compiler_pair.json")
    blaster_config = read_json(ROOT / "tool" / "blaster_config.json")
    lean = lean_provenance(ROOT / "tool" / "blaster-backend")
    if lean["version"] != blaster_config["lean_version"]:
        raise RuntimeError(
            f"Lean configuration mismatch: expected {blaster_config['lean_version']}, "
            f"got {lean['version']}"
        )
    environment = {
        "schema_version": 1,
        "platform": {
            "system": platform.system().lower(),
            "machine": platform.machine().lower(),
        },
        "compilers": compiler_pair,
        "compiler_binary_hashes": corpus["compiler_hashes"],
        "lean_version": blaster_config["lean_version"],
        "lean": lean,
        "blaster_revisions": blaster_config["revisions"],
        "z3_version": blaster_config["z3_version"],
        "z3_binary_sha256": sentinel_run["blaster_configuration"]["solver_binary_sha256"],
        "evaluator": sentinel_run["blaster_configuration"]["evaluator"],
        "semantic_runtime_step_bound": blaster_config["semantic_runtime_step_bound"],
        "timeouts": blaster_config["timeouts"],
        "random_seed": blaster_config["random_seed"],
    }
    write_json(output / "environment.json", portable(environment))

    nonpassing_tasks = sum(not row["strict_pass"] for row in corpus["results"])
    summary = {
        "schema_version": 1,
        "baseline": "aiken-v1.1.22-v1.1.23",
        "sentinel": {
            "run_id": sentinel["run_id"],
            "strict_pass": sentinel["strict_pass"],
            "validator_pairs": sentinel["counts"]["validators_paired"],
            "identical_pairs": sentinel["counts"]["identical_pairs"],
            "shared_features_covered": sentinel["counts"]["shared_features_covered"],
            "shared_features_missing": sentinel["counts"]["shared_features_missing"],
        },
        "mandatory_corpus": {
            "run_id": corpus["run_id"],
            "source_count": repositories["source_count"],
            "selected_tasks": corpus["selected_count"],
            "completed_tasks": corpus["completed_count"],
            "reused_tasks": corpus["reused_count"],
            "nonpassing_tasks": nonpassing_tasks,
            "strict_pass": corpus["strict_pass"],
        },
        "semantic_examples": {
            "bounded_equivalent_validator": examples["bounded_equivalent_validator"]["result"]["status"],
            "non_equivalent_validator": examples["independently_replayed_non_equivalent_validator"]["final_status"],
            "independent_replay_confirmed": examples["independently_replayed_non_equivalent_validator"]["counterexample_replay"]["confirmed"],
        },
    }
    write_json(output / "summary.json", summary)
    (output / "summary.md").write_text(summary_markdown(summary), encoding="utf-8")

    artifact_names = sorted(
        path.name for path in output.iterdir() if path.is_file() and path.name not in {"index.json", "checksums.json"}
    )
    index = {
        "schema_version": 1,
        "baseline": summary["baseline"],
        "artifacts": [
            {"path": name, "sha256": sha256_file(output / name)}
            for name in artifact_names
        ],
    }
    write_json(output / "index.json", index)
    checksum_names = sorted(path.name for path in output.iterdir() if path.is_file() and path.name != "checksums.json")
    write_json(
        output / "checksums.json",
        {
            "schema_version": 1,
            "sha256": {
                name: sha256_file(output / name) for name in checksum_names
            },
        },
    )
    print(json.dumps({"output": str(output), "summary": summary}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
