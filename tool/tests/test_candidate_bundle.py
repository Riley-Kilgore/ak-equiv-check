from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from typing import Any, Callable

from equiv_checker.candidate_bundle import (
    CANDIDATE_BUNDLE_SCHEMA_VERSION,
    finalize_candidate_bundle,
    verify_attested_candidate_archive,
    verify_candidate_bundle,
)
from equiv_checker.candidate_policy import (
    classify_changed_pairs,
    derive_candidate_decisions,
)
from equiv_checker.evidence import (
    GENERATED_LEAN_SCHEMA_VERSION,
    RESULT_PROTOCOL,
    WITNESS_PROTOCOL,
    canonical_json,
    checker_configuration_id,
    evidence_run_id,
    execution_attempt_id_from_record,
    logical_obligation_id,
    obligation_attempt_id_from_record,
    obligation_result_id,
    program_artifact_id,
    program_pair_id,
    semantic_model_id,
    verified_abi_id,
)


def _write(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _records(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": CANDIDATE_BUNDLE_SCHEMA_VERSION,
        "record_count": len(rows),
        "records": rows,
    }


class CandidateBundleVerificationTests(unittest.TestCase):
    def _bundle(
        self, root: Path, *, github_provenance: bool = False
    ) -> dict[str, Any]:
        implementation_id = "1" * 64
        configuration_payload = {
            "checker_implementation_id": implementation_id,
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
        checker_configuration = configuration_payload | {
            "checker_configuration_id": configuration_id
        }
        serialized_old = b"\x01"
        serialized_new = b"\x02"

        def artifact(serialized: bytes) -> dict[str, Any]:
            return {
                "program_artifact_id": program_artifact_id(
                    serialized, "v3", "single-cbor-hex"
                ),
                "serialized_script_bytes_hex": serialized.hex(),
                "script_sha256": hashlib.sha256(serialized).hexdigest(),
                "script_size": len(serialized),
                "plutus_version": "v3",
                "serialization_format": "single-cbor-hex",
            }

        old_artifact = artifact(serialized_old)
        new_artifact = artifact(serialized_new)
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
        pair_id = program_pair_id(
            old_artifact["program_artifact_id"],
            new_artifact["program_artifact_id"],
            abi_id,
        )
        pair = {
            "program_pair_id": pair_id,
            "old_program_artifact": old_artifact,
            "new_program_artifact": new_artifact,
            "verified_abi_id": abi_id,
            "verified_abi": abi,
            "handler_pair_ids": [],
            "covered_feature_ids": [],
        }
        input_model = {
            "profile": "raw-uplc-v1",
            "version": "1",
            "purpose": "spend",
            "variables": [{"name": "datum", "type": "Data"}],
            "argument_order": ["datum"],
            "arity": 1,
            "domain_expression": "True",
            "domain_assumptions": [],
            "observation": "evaluate",
            "supported": True,
        }
        model_id = semantic_model_id(input_model, 10)
        model = {
            "semantic_model_id": model_id,
            "program_pair_id": pair_id,
            "semantic_runtime_bound": 10,
            "input_model": input_model,
        }
        kinds = [
            "domain_non_vacuity",
            "old_program_completion",
            "new_program_completion",
            "observational_equivalence",
        ]
        obligations = [
            {
                "logical_obligation_id": logical_obligation_id(
                    pair_id, model_id, kind
                ),
                "program_pair_id": pair_id,
                "semantic_model_id": model_id,
                "obligation_kind": kind,
                "input_model": input_model,
                "semantic_runtime_bound": 10,
            }
            for kind in kinds
        ]
        planned_ids = sorted(
            row["logical_obligation_id"] for row in obligations
        )
        execution = {
            "checker_configuration_id": configuration_id,
            "checker_implementation_id": implementation_id,
            "execution_plan": {
                "kind": "generated_lean_process",
                "program_pair_id": pair_id,
                "semantic_model_id": model_id,
                "planned_logical_obligation_ids": planned_ids,
                "phase": "raw_model",
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
        execution["execution_attempt_id"] = execution_attempt_id_from_record(
            execution
        )
        results: list[dict[str, Any]] = []
        for obligation in obligations:
            status = (
                "valid"
                if obligation["obligation_kind"]
                == "observational_equivalence"
                else "proven"
            )
            result = {
                "logical_obligation_id": obligation["logical_obligation_id"],
                "execution_attempt_id": execution["execution_attempt_id"],
                "checker_configuration_id": configuration_id,
                "checker_implementation_id": implementation_id,
                "program_pair_id": pair_id,
                "semantic_model_id": model_id,
                "obligation_kind": obligation["obligation_kind"],
                "status": status,
                "generated_source_sha256": None,
                "solver_status": "valid",
                "witness_reference": None,
                "replay_reference": None,
                "relevant_solver_options": {
                    "solver": "z3",
                    "solver_timeout": 2.0,
                },
                "attempt_sequence": 1,
                "generated_source_schema_version": GENERATED_LEAN_SCHEMA_VERSION,
                "generated_source_path": None,
                "reused": False,
            }
            result["obligation_attempt_id"] = obligation_attempt_id_from_record(
                result
            )
            result["evidence_result_id"] = obligation_result_id(result)
            results.append(result)
        results.sort(key=lambda row: row["logical_obligation_id"])
        result_by_obligation = {
            row["logical_obligation_id"]: row["evidence_result_id"]
            for row in results
        }
        task = {
            "task_id": "task",
            "source_id": "source",
            "lane": "equivalence",
            "classification": "equivalence_passed",
            "original_classification": "equivalence_passed",
            "source_hash_before": "a" * 64,
            "source_hash_after": "a" * 64,
            "dependency_graph_before": "b" * 64,
            "dependency_graph_after": "b" * 64,
            "dependency_graph_kind": "lockfile",
            "adapter_hash": None,
            "source_immutable": True,
            "inputs_verified": True,
            "strict_relevance": True,
            "program_pair_ids": [pair_id],
            "logical_obligation_ids": planned_ids,
            "evidence_result_ids": [
                result_by_obligation[key] for key in planned_ids
            ],
        }
        source = {
            "source_id": "source",
            "task_ids": ["task"],
            "source_inputs": [
                canonical_json(
                    {
                        "source_hash": "a" * 64,
                        "dependency_graph": "b" * 64,
                        "adapter_hash": None,
                    }
                )
            ],
            "inputs_verified": True,
            "program_pair_ids": [pair_id],
            "logical_obligation_ids": planned_ids,
            "evidence_result_ids": [
                result_by_obligation[key] for key in planned_ids
            ],
        }
        lineages = [
            {
                "evidence_result_id": result["evidence_result_id"],
                "logical_obligation_id": result["logical_obligation_id"],
                "obligation_attempt_id": result["obligation_attempt_id"],
                "execution_attempt_id": result["execution_attempt_id"],
                "cache_reused": False,
                "cache_entry": "evidence-store/entry",
            }
            for result in results
        ]
        pair_classifications, changed_counts = classify_changed_pairs(
            [pair], [model], obligations, results
        )
        plan_counts = {
            "program_artifacts": 2,
            "unique_program_pairs": 1,
            "semantic_models": 1,
            "unique_semantic_obligations": 4,
            "model_omissions": 0,
            "validator_links": 0,
            "feature_links": 0,
            "task_links": 1,
            "source_links": 1,
            "pending_obligations": 0,
        }
        counts = plan_counts | changed_counts | {
            "cache_reused_obligations": 0,
            "executed_unique_obligations": 4,
            "semantic_execution_batches": 1,
            "duplicate_solver_invocations_prevented": 0,
            "obligation_results": 4,
        }
        def compiler_identity(kind: str, digit: str) -> dict[str, Any]:
            target = {"triple": "x86_64-unknown-linux-gnu"}
            build_command = ["cargo", "build", "--release", "--locked"]
            identity = {
                "artifact_kind": kind,
                "source_tree_sha256": digit * 64,
                "commit_sha": digit * 40,
                "binary_sha256": str(int(digit) + 1) * 64,
                "target": target,
                "build_command": build_command,
            }
            return {
                "artifact_id": hashlib.sha256(
                    canonical_json(identity).encode("utf-8")
                ).hexdigest(),
                "artifact_kind": kind,
                "target": target,
                "build_command": build_command,
                "binary_sha256": identity["binary_sha256"],
                "reported_version": "aiken test",
                "source_tree_sha256": identity["source_tree_sha256"],
                "source_commit": identity["commit_sha"],
                "cargo_lock_sha256": "f" * 64,
                "dirty": False,
                "tracked_diff_sha256": hashlib.sha256(b"").hexdigest(),
                "untracked_source_manifest": [],
                "reproducible_from_commit": True,
            }

        base_compiler = compiler_identity("release", "6")
        candidate_compiler = compiler_identity("local", "7")
        old_artifact["compiler_artifact_id"] = base_compiler["artifact_id"]
        new_artifact["compiler_artifact_id"] = candidate_compiler["artifact_id"]
        for filename, value in (
            ("feature-contract.json", {"features": []}),
            ("corpus-lock.json", {"sources": [], "tasks": []}),
            ("compiler-release-lock.json", {"releases": []}),
        ):
            _write(root / filename, value)
        identity_inputs = {
            "base_compiler_artifact_id": base_compiler["artifact_id"],
            "candidate_compiler_artifact_id": candidate_compiler["artifact_id"],
            "source_and_dependency_inputs": [
                {"source_id": "source", "source_inputs": ["locked"], "task_ids": ["task"]}
            ],
            "feature_contract_sha256": hashlib.sha256(
                (root / "feature-contract.json").read_bytes()
            ).hexdigest(),
            "corpus_lock_sha256": hashlib.sha256(
                (root / "corpus-lock.json").read_bytes()
            ).hexdigest(),
            "release_lock_sha256": hashlib.sha256(
                (root / "compiler-release-lock.json").read_bytes()
            ).hexdigest(),
            "scope": ["mandatory", "sentinel"],
            "checker_implementation_id": implementation_id,
            "checker_configuration_id": configuration_id,
            "semantic_models": [model_id],
            "runtime_bounds": {"semantic_runtime_step_bound": 10},
        }
        run_id = evidence_run_id(identity_inputs)
        decisions = derive_candidate_decisions(
            evidence_run_id=run_id,
            selected_policy="strict",
            pair_classifications=pair_classifications,
            task_results=[task],
            source_results=[source],
            counts=counts,
            candidate_clean=True,
            candidate_committed=True,
            evidence_verified=True,
            ci_provenance_valid=False,
        )
        record_files = {
            "program-artifacts.json": [old_artifact, new_artifact],
            "program-pairs.json": [pair],
            "global-program-pairs.json": [pair],
            "semantic-models.json": [model],
            "semantic-model-omissions.json": [],
            "semantic-obligations.json": obligations,
            "global-semantic-obligations.json": obligations,
            "obligation-results.json": results,
            "execution-attempts.json": [execution],
            "witnesses.json": [],
            "replays.json": [],
            "validator-links.json": [],
            "feature-links.json": [],
            "task-results.json": [task],
            "source-results.json": [source],
            "evidence-lineage.json": lineages,
            "pair-classifications.json": pair_classifications,
        }
        for filename, rows in record_files.items():
            _write(root / filename, _records(rows))
        _write(
            root / "global-plan.json",
            {
                "schema_version": CANDIDATE_BUNDLE_SCHEMA_VERSION,
                "evidence_run_id": run_id,
                "identity_conflicts": [],
                "phase_order": [
                    "build_and_discovery",
                    "global_obligation_plan",
                    "global_evidence_lookup",
                    "semantic_execution",
                    "linking_and_decisions",
                ],
                "semantic_execution_started_after_plan_write": True,
                "counts": plan_counts,
            },
        )
        _write(root / "strict-decision.json", decisions["strict"])
        _write(root / "screening-decision.json", decisions["screening"])
        _write(root / "selected-decision.json", decisions["selected"])
        _write(
            root / "environment.json",
            {
                "schema_version": CANDIDATE_BUNDLE_SCHEMA_VERSION,
                "checker_implementation_id": implementation_id,
            },
        )
        manifest = {
            "evidence_run_id": run_id,
            "evidence_identity_inputs": identity_inputs,
            "base_compiler": base_compiler,
            "candidate_compiler": candidate_compiler,
            "checker_configuration": checker_configuration,
            "selected_policy": "strict",
            "candidate_source_clean": True,
            "candidate_source_committed": True,
            "development_only": False,
            "counts": counts,
        }
        attestation = {
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
        if github_provenance:
            attestation = {
                "schema_version": "equiv-ci-attestation/v1",
                "provenance_kind": "github_actions",
                "repository_commit": "a" * 40,
                "workflow_revision": "a" * 40,
                "github_run_id": 123,
                "github_run_attempt": 1,
                "job_name": "candidate-gate-full",
                "trusted_event": True,
                "signed_attestation_expected": True,
                "artifact_sha256": None,
                "verification_result": "external_attestation_required",
            }
        return finalize_candidate_bundle(
            root, manifest=manifest, ci_attestation=attestation
        )

    def _rebind(self, root: Path) -> None:
        manifest = json.loads((root / "candidate-manifest.json").read_text())
        manifest.pop("candidate_bundle_content_id", None)
        attestation = json.loads((root / "ci-attestation.json").read_text())
        attestation.pop("candidate_bundle_content_id", None)
        finalize_candidate_bundle(
            root, manifest=manifest, ci_attestation=attestation
        )

    def _mutate(
        self, root: Path, filename: str, mutation: Callable[[dict[str, Any]], None]
    ) -> None:
        path = root / filename
        value = json.loads(path.read_text())
        mutation(value)
        _write(path, value)
        self._rebind(root)

    def test_complete_bundle_verifies_and_shares_one_execution_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._bundle(root)
            verification = verify_candidate_bundle(root)
            self.assertTrue(verification["valid"])
            self.assertEqual(verification["strict_decision"], "pass")
            self.assertEqual(verification["counts"]["execution_attempts"] if "execution_attempts" in verification["counts"] else 1, 1)
            results = json.loads((root / "obligation-results.json").read_text())["records"]
            self.assertEqual(len({row["execution_attempt_id"] for row in results}), 1)
            self.assertEqual(len({row["obligation_attempt_id"] for row in results}), 4)

    def test_unrebound_checksum_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._bundle(root)
            path = root / "selected-decision.json"
            value = json.loads(path.read_text())
            value["selected_decision"] = "fail"
            _write(path, value)
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                verify_candidate_bundle(root)

    def test_rebound_decision_link_and_count_tampering_are_rejected(self) -> None:
        cases = (
            (
                "selected-decision.json",
                lambda value: value.update({"selected_decision": "fail"}),
                "selected decision mismatch",
            ),
            (
                "task-results.json",
                lambda value: value["records"][0].update({"evidence_result_ids": []}),
                "inconsistent evidence parents",
            ),
            (
                "task-results.json",
                lambda value: value["records"][0].update(
                    {
                        "old_result": {
                            "source_hash_before": "c" * 64,
                            "source_hash_after": "c" * 64,
                            "dependency_graph_before": "b" * 64,
                            "dependency_graph_after": "b" * 64,
                            "exit_code": 0,
                        }
                    }
                ),
                "candidate task classification mismatch",
            ),
            (
                "candidate-manifest.json",
                lambda value: value["counts"].update({"obligation_results": 3}),
                "obligation count invariants",
            ),
        )
        for filename, mutation, message in cases:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self._bundle(root)
                self._mutate(root, filename, mutation)
                with self.assertRaisesRegex(ValueError, message):
                    verify_candidate_bundle(root)

    def test_rebound_execution_and_obligation_attempt_tampering_are_rejected(self) -> None:
        cases = (
            (
                "execution-attempts.json",
                lambda value: value["records"][0]["process_timeouts"].update({"z3": 99.0}),
                "execution attempt identity mismatch",
            ),
            (
                "obligation-results.json",
                lambda value: value["records"][0]["relevant_solver_options"].update({"solver_timeout": 99.0}),
                "obligation attempt identity mismatch",
            ),
        )
        for filename, mutation, message in cases:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self._bundle(root)
                self._mutate(root, filename, mutation)
                with self.assertRaisesRegex(ValueError, message):
                    verify_candidate_bundle(root)

    def test_publishability_requires_verified_signed_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "bundle"
            root.mkdir()
            self._bundle(root, github_provenance=True)
            self.assertFalse(verify_candidate_bundle(root)["publishable"])
            archive = temporary_root / "candidate-bundle.tar.gz"
            with tarfile.open(archive, mode="w:gz") as output:
                for child in sorted(root.iterdir()):
                    output.add(child, arcname=child.name)
            completed = subprocess.CompletedProcess(
                args=["gh"], returncode=0, stdout="[]", stderr=""
            )
            with patch(
                "equiv_checker.candidate_bundle.subprocess.run",
                return_value=completed,
            ) as run:
                verification = verify_attested_candidate_archive(
                    archive, repository="owner/repository"
                )
            self.assertTrue(verification["publishable"])
            command = run.call_args.args[0]
            self.assertIn("--signer-workflow", command)
            self.assertIn("--source-ref", command)


if __name__ == "__main__":
    unittest.main()
