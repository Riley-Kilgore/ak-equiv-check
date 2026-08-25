from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from equiv_checker.baseline import baseline_content_id, verify_baseline
from equiv_checker.evidence import (
    GENERATED_LEAN_SCHEMA_VERSION,
    RESULT_PROTOCOL,
    WITNESS_PROTOCOL,
    canonical_json,
    checker_configuration_id,
    execution_attempt_id_from_record,
    logical_obligation_id,
    obligation_attempt_id_from_record,
    obligation_result_id,
    program_artifact_id,
    program_pair_id,
    semantic_model_id,
    verified_abi_id,
)


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_ndjson(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in records),
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class BaselineVerificationTests(unittest.TestCase):
    def _baseline(self, root: Path) -> None:
        checker_implementation = "1" * 64
        configuration_payload = {
            "checker_implementation_id": checker_implementation,
            "generated_lean_schema_version": GENERATED_LEAN_SCHEMA_VERSION,
            "result_protocol": RESULT_PROTOCOL,
            "witness_protocol": WITNESS_PROTOCOL,
            "lean_version": "4.19.0",
            "lean_blaster_revision": "2" * 40,
            "plutus_core_blaster_revision": "3" * 40,
            "cardano_ledger_api_blaster_revision": "4" * 40,
            "uplc_importer_revision": "3" * 40,
            "uplc_preparer_revision": "3" * 40,
            "z3_version": "4.13.4",
            "solver": "z3",
            "solver_binary_sha256": "5" * 64,
            "solver_configuration": {"fuel_semantics": "bounded"},
        }
        configuration_id = checker_configuration_id(configuration_payload)
        blaster_configuration = configuration_payload | {
            "checker_configuration_id": configuration_id,
            "semantic_runtime_step_bound": 10,
            "fuel_semantics": "bounded",
            "timeouts": {"z3": 2.0},
            "random_seed": 1,
            "evaluator": None,
            "secondary_evaluator": None,
        }
        serialized = b"\x01"
        artifact_id = program_artifact_id(serialized, "v3", "single-cbor-hex")
        artifact = {
            "program_artifact_id": artifact_id,
            "serialized_script_bytes_hex": serialized.hex(),
            "script_sha256": hashlib.sha256(serialized).hexdigest(),
            "script_size": len(serialized),
            "plutus_version": "v3",
            "serialization_format": "single-cbor-hex",
        }
        abi = {
            "status": "verified",
            "top_level_callable_arity": 1,
            "applied_parameter_count": 0,
            "remaining_runtime_argument_count": 1,
            "argument_order": ["datum"],
            "argument_value_representation": ["data"],
            "parameter_schemas": [],
            "plutus_version": "v3",
        }
        abi_id = verified_abi_id(abi)
        pair_id = program_pair_id(artifact_id, artifact_id, abi_id)
        model = {
            "profile": "raw-uplc-v1",
            "version": "1",
            "purpose": "spend",
            "variables": [{"name": "datum", "type": "Data"}],
            "argument_order": ["datum"],
            "arity": 1,
            "domain_expression": "True",
            "domain_assumptions": [],
            "observation": "evaluate",
        }
        model_id = semantic_model_id(model, 10)
        obligation_id = logical_obligation_id(
            pair_id, model_id, "observational_equivalence"
        )
        execution = {
            "checker_configuration_id": configuration_id,
            "checker_implementation_id": checker_implementation,
            "execution_plan": {
                "kind": "generated_lean_process",
                "program_pair_id": pair_id,
                "semantic_model_id": model_id,
                "planned_logical_obligation_ids": [obligation_id],
                "phase": "equivalence",
                "command": ["lake", "env", "lean", "Generated.lean"],
                "effective_options": {"timeout": 2.0},
            },
            "generated_source_sha256": None,
            "process_timeouts": {"lean": 3.0, "z3": 2.0},
            "random_seed": 1,
            "platform_identity": {
                "system": "linux",
                "machine": "x86_64",
                "python_implementation": "CPython",
                "python_version": "3.12.0",
            },
            "execution_sequence": 1,
            "command": ["lake", "env", "lean", "Generated.lean"],
            "exit_code": 0,
            "timed_out": False,
            "duration_seconds": 0.1,
            "stdout_path": "logs/stdout.log",
            "stderr_path": "logs/stderr.log",
        }
        execution["execution_attempt_id"] = execution_attempt_id_from_record(execution)
        result = {
            "logical_obligation_id": obligation_id,
            "execution_attempt_id": execution["execution_attempt_id"],
            "checker_configuration_id": configuration_id,
            "checker_implementation_id": checker_implementation,
            "program_pair_id": pair_id,
            "semantic_model_id": model_id,
            "obligation_kind": "observational_equivalence",
            "status": "proven",
            "generated_source_sha256": None,
            "solver_status": "valid",
            "witness_reference": None,
            "replay_reference": None,
            "relevant_solver_options": {"solver": "z3", "solver_timeout": 2.0},
            "attempt_sequence": 1,
            "generated_source_schema_version": GENERATED_LEAN_SCHEMA_VERSION,
            "generated_source_path": None,
            "reused": False,
        }
        result["obligation_attempt_id"] = obligation_attempt_id_from_record(result)
        result["evidence_result_id"] = obligation_result_id(result)
        handler_id = "6" * 64
        feature_id = "FEATURE"
        records = {
            "handler-pairs.ndjson": [
                {
                    "handler_pair_id": handler_id,
                    "program_pair_id": pair_id,
                    "feature_ids": [feature_id],
                }
            ],
            "program-artifacts.ndjson": [artifact],
            "program-pairs.ndjson": [
                {
                    "program_pair_id": pair_id,
                    "old_program_artifact": artifact,
                    "new_program_artifact": artifact,
                    "verified_abi_id": abi_id,
                    "verified_abi": abi,
                    "handler_pair_ids": [handler_id],
                    "covered_feature_ids": [feature_id],
                }
            ],
            "semantic-obligations.ndjson": [
                {
                    "logical_obligation_id": obligation_id,
                    "program_pair_id": pair_id,
                    "semantic_model_id": model_id,
                    "obligation_kind": "observational_equivalence",
                    "input_model": model,
                    "semantic_runtime_bound": 10,
                }
            ],
            "obligation-results.ndjson": [result],
            "execution-attempts.ndjson": [execution],
            "witnesses.ndjson": [],
            "replays.ndjson": [],
            "evidence-lineage.ndjson": [
                {
                    "evidence_result_id": result["evidence_result_id"],
                    "logical_obligation_id": obligation_id,
                    "program_pair_id": pair_id,
                    "obligation_attempt_id": result["obligation_attempt_id"],
                    "execution_attempt_id": execution["execution_attempt_id"],
                    "checker_configuration_id": configuration_id,
                    "checker_implementation_id": checker_implementation,
                    "witness_reference": None,
                    "replay_reference": None,
                    "reused": False,
                }
            ],
            "validator-links.ndjson": [
                {
                    "handler_pair_id": handler_id,
                    "program_pair_id": pair_id,
                    "feature_ids": [feature_id],
                    "logical_obligation_ids": [obligation_id],
                    "evidence_result_ids": [result["evidence_result_id"]],
                }
            ],
            "feature-links.ndjson": [
                {
                    "feature_id": feature_id,
                    "handler_pair_ids": [handler_id],
                    "program_pair_ids": [pair_id],
                    "semantic_obligation_ids": [obligation_id],
                    "required_evidence": [result["evidence_result_id"]],
                    "authoritative_evidence": [result["evidence_result_id"]],
                    "all_linked_evidence": [result["evidence_result_id"]],
                }
            ],
            "task-results.ndjson": [{"task_id": "historical", "strict_pass": True}],
        }
        for filename, rows in records.items():
            _write_ndjson(root / filename, rows)

        def compiler(label: str, digit: str) -> dict[str, object]:
            source = {
                "dirty": False,
                "source_tree_sha256": digit * 64,
                "commit_sha": digit * 40,
            }
            binary = {"sha256": (str(int(digit) + 1)) * 64}
            target = {"triple": "x86_64-unknown-linux-gnu"}
            command = ["cargo", "build", "--release", "--locked"]
            identity = {
                "artifact_kind": "release",
                "source_tree_sha256": source["source_tree_sha256"],
                "commit_sha": source["commit_sha"],
                "binary_sha256": binary["sha256"],
                "target": target,
                "build_command": command,
            }
            return {
                "artifact_id": hashlib.sha256(canonical_json(identity).encode()).hexdigest(),
                "artifact_kind": "release",
                "binary": binary,
                "build": {"command": command},
                "cache_key": digit * 64,
                "label": label,
                "reproducibility": {"reproducible_from_commit": True},
                "source": source,
                "target": target,
                "toolchain": {"rustc": "1.90.0"},
            }

        _write_json(
            root / "compiler-lock.json",
            {
                "schema_version": 3,
                "profile_lock": {"id": "historical"},
                "compilers": {"old": compiler("old", "7"), "new": compiler("new", "8")},
            },
        )
        _write_json(
            root / "source-lock.json",
            {
                "schema_version": 3,
                "fixture": "fixtures/historical",
                "package": "historical",
                "source_hash": "9" * 64,
                "dependency_lock_hash": "a" * 64,
                "source_immutable": True,
                "source_provenance": {"dirty": False},
                "old_new_source_hash_equal": True,
                "old_new_dependency_lock_equal": True,
            },
        )
        _write_json(
            root / "environment.json",
            {
                "schema_version": 3,
                "blaster_configuration": blaster_configuration,
                "checker_configuration": {"runner_sha256": "b" * 64},
                "checker_implementation_id": checker_implementation,
                "replay_trust": [],
            },
        )
        counts = {
            "handler_pairs": 1,
            "handler_pair_records": 1,
            "unique_program_pairs": 1,
            "program_pair_records": 1,
            "program_artifact_records": 1,
            "program_state_total": 1,
            "semantic_obligation_records": 1,
            "obligation_result_records": 1,
            "execution_attempt_records": 1,
            "witness_records": 0,
            "replay_records": 0,
            "obligation_state_total": 1,
            "validator_handlers": 1,
            "validator_link_records": 1,
            "feature_rows": 1,
            "feature_link_records": 1,
        }
        _write_json(
            root / "summary.json",
            {
                "schema_version": 3,
                "profile": {"profile_id": "historical"},
                "run_id": "c" * 64,
                "checker_implementation_id": checker_implementation,
                "source_provenance": {"dirty": False},
                "counts": counts,
                "count_invariants": {
                    "obligation_final_states_equal_unique_obligations": True,
                    "program_final_states_equal_unique_program_pairs": True,
                },
            },
        )
        (root / "summary.md").write_text("# Historical baseline\n", encoding="utf-8")
        self._rebind(root)

    def _rebind(self, root: Path) -> None:
        checksummed = sorted(
            path.name
            for path in root.iterdir()
            if path.is_file() and path.name not in {"checksums.json", "ci-attestation.json"}
        )
        files = {name: _sha256(root / name) for name in checksummed}
        content_id = baseline_content_id(files)
        _write_json(
            root / "checksums.json",
            {
                "schema_version": 3,
                "algorithm": "sha256",
                "baseline_content_id": content_id,
                "files": files,
            },
        )
        _write_json(
            root / "ci-attestation.json",
            {
                "schema_version": 3,
                "attestation_kind": "public_ci_reproduction",
                "profile_id": "historical",
                "baseline_content_id": content_id,
                "repository_commit": "d" * 40,
                "workflow_revision": "d" * 40,
                "github_run_id": 1,
                "job_id": 2,
                "artifact_id": 3,
                "artifact_sha256": "e" * 64,
                "platform": "ubuntu-24.04",
                "capture_command": "capture historical",
                "verification_result": "verified",
            },
        )

    def _mutate(self, root: Path, filename: str, mutate: object) -> None:
        path = root / filename
        if filename.endswith(".ndjson"):
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            mutate(rows)  # type: ignore[operator]
            _write_ndjson(path, rows)
        else:
            value = json.loads(path.read_text())
            mutate(value)  # type: ignore[operator]
            _write_json(path, value)
        self._rebind(root)

    def test_complete_v3_baseline_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._baseline(root)
            result = verify_baseline(root)
            self.assertTrue(result["valid"])
            self.assertEqual(result["schema_version"], 3)
            self.assertEqual(result["counts"]["execution_attempts"], 1)

    def test_capture_and_verifier_share_content_identity(self) -> None:
        script = Path(__file__).resolve().parents[2] / "scripts" / "capture_historical_baseline.py"
        spec = importlib.util.spec_from_file_location("capture_historical_baseline", script)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        files = {"summary.json": "a" * 64}
        self.assertEqual(
            baseline_content_id(files),
            module._identity(
                "baseline-content",
                {"schema_version": 3, "algorithm": "sha256", "files": files},
            ),
        )

    def test_legacy_v2_baseline_is_explicitly_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._baseline(root)
            checksums = json.loads((root / "checksums.json").read_text())
            checksums["schema_version"] = 2
            _write_json(root / "checksums.json", checksums)
            with self.assertRaisesRegex(ValueError, "legacy baseline schema_version 2"):
                verify_baseline(root)

    def test_execution_identity_tampering_is_rejected(self) -> None:
        mutations = (
            lambda row: row["process_timeouts"].update({"z3": 99.0}),
            lambda row: row.update({"random_seed": 7}),
            lambda row: row["platform_identity"].update({"machine": "tampered"}),
            lambda row: row.update({"execution_sequence": 9}),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self._baseline(root)
                self._mutate(root, "execution-attempts.ndjson", lambda rows: mutate(rows[0]))
                with self.assertRaisesRegex(ValueError, "execution attempt identity mismatch"):
                    verify_baseline(root)

    def test_obligation_attempt_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._baseline(root)
            self._mutate(
                root,
                "obligation-results.ndjson",
                lambda rows: rows[0]["relevant_solver_options"].update({"solver_timeout": 9.0}),
            )
            with self.assertRaisesRegex(ValueError, "obligation attempt identity mismatch"):
                verify_baseline(root)

    def test_compiler_and_source_input_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._baseline(root)
            self._mutate(
                root,
                "compiler-lock.json",
                lambda value: value["compilers"]["old"]["binary"].update({"sha256": "f" * 64}),
            )
            with self.assertRaisesRegex(ValueError, "compiler identity mismatch"):
                verify_baseline(root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._baseline(root)
            self._mutate(
                root,
                "source-lock.json",
                lambda value: value.update({"source_immutable": False}),
            )
            with self.assertRaisesRegex(ValueError, "not immutable"):
                verify_baseline(root)

    def test_link_and_count_tampering_is_rejected_after_rebinding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._baseline(root)
            self._mutate(
                root,
                "feature-links.ndjson",
                lambda rows: rows[0].update({"required_evidence": []}),
            )
            with self.assertRaisesRegex(ValueError, "missing authoritative evidence"):
                verify_baseline(root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._baseline(root)
            self._mutate(
                root,
                "summary.json",
                lambda value: value["counts"].update({"unique_program_pairs": 2}),
            )
            with self.assertRaisesRegex(ValueError, "count mismatch"):
                verify_baseline(root)


if __name__ == "__main__":
    unittest.main()
