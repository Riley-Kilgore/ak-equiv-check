from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from equiv_checker.candidate import (
    _duplicate_solver_invocations_prevented,
    _global_execution_schedule,
    _merge_program_pair,
    _task_record,
    run_candidate_gate,
)
from equiv_checker.candidate_policy import (
    classify_changed_pairs,
    derive_candidate_decisions,
)
from equiv_checker.evidence import evidence_run_id
from equiv_checker.candidate_bundle import expected_task_classification


class CandidateGateTests(unittest.TestCase):
    def test_candidate_gate_rejects_nonlocal_candidate_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch(
                "equiv_checker.candidate.verify_compiler_manifest",
                side_effect=[
                    {"artifact_id": "a" * 64, "artifact_kind": "release"},
                    {"artifact_id": "b" * 64, "artifact_kind": "release"},
                ],
            ), self.assertRaisesRegex(ValueError, "not a local build"):
                run_candidate_gate(
                    base_compiler_manifest=root / "base.json",
                    candidate_compiler_manifest=root / "candidate.json",
                    feature_contract=root / "features.json",
                    corpus_lock=root / "corpus.json",
                    scope={"sentinel"},
                    resume=True,
                    policy="strict",
                    work_root=root / "work",
                )

    def test_program_pair_merge_unions_all_consumer_references(self) -> None:
        artifact = {
            "program_artifact_id": "a" * 64,
            "script_sha256": "b" * 64,
            "source_validator_references": ["handler-a"],
        }
        previous = {
            "program_pair_id": "c" * 64,
            "old_program_artifact": dict(artifact),
            "new_program_artifact": dict(artifact),
            "handler_pair_ids": ["handler-a"],
            "handler_references": [{"handler_pair_id": "handler-a"}],
            "covered_feature_ids": ["feature-a"],
        }
        current = {
            **previous,
            "old_program_artifact": artifact
            | {"source_validator_references": ["handler-b"]},
            "new_program_artifact": artifact
            | {"source_validator_references": ["handler-b"]},
            "handler_pair_ids": ["handler-b"],
            "handler_references": [{"handler_pair_id": "handler-b"}],
            "covered_feature_ids": ["feature-b"],
        }
        _merge_program_pair(previous, current)
        self.assertEqual(previous["handler_pair_ids"], ["handler-a", "handler-b"])
        self.assertEqual(
            previous["old_program_artifact"]["source_validator_references"],
            ["handler-a", "handler-b"],
        )
        self.assertEqual(previous["covered_feature_ids"], ["feature-a", "feature-b"])

    def test_same_obligation_from_two_packages_is_scheduled_once(self) -> None:
        pair_id = "d" * 64
        obligation = {
            "logical_obligation_id": "e" * 64,
            "program_pair_id": pair_id,
            "semantic_model_id": "f" * 64,
            "obligation_kind": "observational_equivalence",
        }
        schedule = _global_execution_schedule([obligation, dict(obligation)])
        self.assertEqual(schedule, {(pair_id, "f" * 64): ("e" * 64,)})
        self.assertEqual(
            _duplicate_solver_invocations_prevented(
                schedule,
                {
                    pair_id: [
                        {"source_id": "package-a", "task_id": "task-a"},
                        {"source_id": "package-b", "task_id": "task-b"},
                    ]
                },
                0,
            ),
            1,
        )

    def test_same_obligation_from_sentinel_and_corpus_is_scheduled_once(
        self,
    ) -> None:
        pair_id = "1" * 64
        obligation = {
            "logical_obligation_id": "2" * 64,
            "program_pair_id": pair_id,
            "semantic_model_id": "3" * 64,
            "obligation_kind": "old_program_completion",
        }
        schedule = _global_execution_schedule([obligation, dict(obligation)])
        self.assertEqual(schedule, {(pair_id, "3" * 64): ("2" * 64,)})
        self.assertEqual(
            _duplicate_solver_invocations_prevented(
                schedule,
                {
                    pair_id: [
                        {
                            "source_id": "feature-sentinel",
                            "task_id": "feature-sentinel",
                        },
                        {
                            "source_id": "mandatory-source",
                            "task_id": "mandatory-task",
                        },
                    ]
                },
                0,
            ),
            1,
        )

    def test_identical_shared_pair_does_not_claim_prevented_solver_work(
        self,
    ) -> None:
        self.assertEqual(
            _duplicate_solver_invocations_prevented(
                {},
                {
                    "4" * 64: [
                        {"source_id": "source-a", "task_id": "task-a"},
                        {"source_id": "source-b", "task_id": "task-b"},
                    ]
                },
                0,
            ),
            0,
        )

    def test_no_lockfile_is_bound_as_a_verified_empty_dependency_graph(self) -> None:
        task = _task_record(
            {
                "task_id": "task",
                "source_id": "source",
                "lane": "compile",
                "classification": "compile_passed",
                "source_hash_before": "a" * 64,
                "source_hash_after": "a" * 64,
                "dependency_graph_before": None,
                "dependency_graph_after": None,
                "source_immutable": True,
            },
            program_pair_ids=[],
            logical_obligation_ids=[],
        )
        self.assertEqual(task["dependency_graph_kind"], "verified_empty")
        self.assertEqual(
            task["dependency_graph_before"], task["dependency_graph_after"]
        )
        self.assertIsNotNone(task["dependency_graph_before"])

    def test_task_input_verification_binds_each_compiler_copy(self) -> None:
        task = _task_record(
            {
                "task_id": "task",
                "source_id": "source",
                "lane": "compile",
                "classification": "compile_passed",
                "source_hash_before": "a" * 64,
                "source_hash_after": "a" * 64,
                "dependency_graph_before": "b" * 64,
                "dependency_graph_after": "b" * 64,
                "source_immutable": True,
                "old_result": {
                    "source_hash_before": "c" * 64,
                    "source_hash_after": "c" * 64,
                    "dependency_graph_before": "b" * 64,
                    "dependency_graph_after": "b" * 64,
                    "exit_code": 0,
                },
                "new_result": {
                    "source_hash_before": "a" * 64,
                    "source_hash_after": "a" * 64,
                    "dependency_graph_before": "b" * 64,
                    "dependency_graph_after": "b" * 64,
                    "exit_code": 0,
                },
            },
            program_pair_ids=[],
            logical_obligation_ids=[],
        )
        self.assertFalse(task["inputs_verified"])
        self.assertFalse(task["source_immutable"])

    def test_equivalence_discovery_failures_cannot_become_not_applicable(
        self,
    ) -> None:
        successful_build = {
            "primary_exit_code": 0,
            "build_timed_out": False,
            "uplc_extraction_exit_code": None,
            "uplc_extraction_timed_out": False,
            "blueprint_present": True,
            "blueprint_malformed": False,
            "abi_inspection": {},
            "source_hash_before": "a" * 64,
            "source_hash_after": "a" * 64,
            "dependency_graph_before": "b" * 64,
            "dependency_graph_after": "b" * 64,
        }
        cases = (
            ("old", {"primary_exit_code": 1}, "old_build_failed"),
            ("new", {"primary_exit_code": 1}, "new_build_failed"),
            (
                "new",
                {"uplc_extraction_exit_code": 1},
                "new_uplc_extraction_failed",
            ),
            ("new", {"blueprint_present": False}, "new_blueprint_missing"),
            ("new", {"abi_inspection": None}, "compiled_abi_unverified"),
        )
        for side, mutation, expected in cases:
            with self.subTest(expected=expected):
                task = _task_record(
                    {
                        "task_id": "feature-sentinel",
                        "source_id": "feature-sentinel",
                        "lane": "equivalence",
                        "classification": "discovery_completed",
                        "source_hash_before": "a" * 64,
                        "source_hash_after": "a" * 64,
                        "dependency_graph_before": "b" * 64,
                        "dependency_graph_after": "b" * 64,
                        "source_immutable": True,
                        "equivalence_required": True,
                        "old_result": successful_build
                        | (mutation if side == "old" else {}),
                        "new_result": successful_build
                        | (mutation if side == "new" else {}),
                    },
                    program_pair_ids=[],
                    logical_obligation_ids=[],
                )
                self.assertEqual(
                    expected_task_classification(task, {}),
                    expected,
                )
        task = _task_record(
            {
                "task_id": "feature-sentinel",
                "source_id": "feature-sentinel",
                "lane": "equivalence",
                "classification": "discovery_completed",
                "source_hash_before": "a" * 64,
                "source_hash_after": "a" * 64,
                "dependency_graph_before": "b" * 64,
                "dependency_graph_after": "b" * 64,
                "source_immutable": True,
                "old_result": successful_build,
                "new_result": successful_build,
            },
            program_pair_ids=[],
            logical_obligation_ids=[],
        )
        self.assertEqual(
            expected_task_classification(task, {}),
            "not_applicable",
        )
        task["equivalence_required"] = True
        self.assertEqual(
            expected_task_classification(task, {}),
            "missing_evidence",
        )

    def test_evidence_identity_rejects_policy_inputs(self) -> None:
        neutral_inputs = {
            "base_compiler_artifact_id": "a" * 64,
            "candidate_compiler_artifact_id": "b" * 64,
            "scope": ["mandatory", "sentinel"],
            "checker_configuration_id": "c" * 64,
        }
        run_id = evidence_run_id(neutral_inputs)
        self.assertEqual(run_id, evidence_run_id(dict(neutral_inputs)))
        for field in ("policy", "selected_policy", "strict_policy", "screening_policy"):
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, "release policy is not evidence identity input"
            ):
                evidence_run_id(neutral_inputs | {field: "strict"})

    def test_strict_and_screening_decisions_share_evidence_but_not_identity(self) -> None:
        run_id = "d" * 64
        pair = {
            "program_pair_id": "e" * 64,
            "classification": "bounded_equivalent",
            "strict_blocking_evidence_ids": ["f" * 64],
            "screening_blocking_evidence_ids": [],
        }
        task = {
            "task_id": "task",
            "lane": "equivalence",
            "classification": "equivalence_passed",
            "strict_relevance": True,
        }
        source = {"source_id": "source", "inputs_verified": True}
        decisions = derive_candidate_decisions(
            evidence_run_id=run_id,
            selected_policy="screening",
            pair_classifications=[pair],
            task_results=[task],
            source_results=[source],
            counts={"pending_obligations": 0},
            candidate_clean=True,
            candidate_committed=True,
            evidence_verified=True,
            ci_provenance_valid=True,
        )
        self.assertEqual(decisions["strict"]["decision"], "fail")
        self.assertEqual(decisions["screening"]["decision"], "pass")
        self.assertEqual(decisions["selected"]["selected_decision"], "pass")
        self.assertFalse(decisions["selected"]["publishable"])
        self.assertNotEqual(
            decisions["strict"]["decision_id"],
            decisions["screening"]["decision_id"],
        )
        self.assertEqual(decisions["strict"]["evidence_run_id"], run_id)
        self.assertEqual(decisions["screening"]["evidence_run_id"], run_id)

    def test_dirty_candidate_is_never_publishable(self) -> None:
        decisions = derive_candidate_decisions(
            evidence_run_id="a" * 64,
            selected_policy="strict",
            pair_classifications=[],
            task_results=[
                {
                    "task_id": "task",
                    "lane": "compile",
                    "classification": "compile_passed",
                    "strict_relevance": True,
                }
            ],
            source_results=[{"source_id": "source", "inputs_verified": True}],
            counts={"pending_obligations": 0},
            candidate_clean=False,
            candidate_committed=False,
            evidence_verified=True,
            ci_provenance_valid=True,
        )
        self.assertEqual(decisions["strict"]["decision"], "pass")
        self.assertFalse(decisions["selected"]["publishable"])
        self.assertEqual(
            decisions["selected"]["evidence_suitability"], "development_only"
        )

    def test_ledger_only_equivalence_remains_bounded_and_strictly_blocked(
        self,
    ) -> None:
        pair_id = "1" * 64
        raw_model_id = "2" * 64
        ledger_model_id = "3" * 64
        pair = {
            "program_pair_id": pair_id,
            "old_program_artifact": {"script_sha256": "4" * 64},
            "new_program_artifact": {"script_sha256": "5" * 64},
        }
        models = [
            {
                "semantic_model_id": raw_model_id,
                "input_model": {"profile": "raw-uplc/v1"},
            },
            {
                "semantic_model_id": ledger_model_id,
                "input_model": {"profile": "ledger-valid/v1"},
            },
        ]
        statuses = {
            "domain_non_vacuity": "proven",
            "old_program_completion": "falsified",
            "new_program_completion": "proven",
            "observational_equivalence": "valid",
            "ledger_domain_non_vacuity": "proven",
            "ledger_old_program_completion": "proven",
            "ledger_new_program_completion": "proven",
            "ledger_observational_equivalence": "valid",
        }
        obligations = []
        results = []
        for key, status in statuses.items():
            ledger = key.startswith("ledger_")
            kind = (
                key.removeprefix("ledger_")
                if key
                in {
                    "ledger_old_program_completion",
                    "ledger_new_program_completion",
                }
                else key
            )
            obligation_id = f"obligation-{key}"
            obligations.append(
                {
                    "logical_obligation_id": obligation_id,
                    "program_pair_id": pair_id,
                    "semantic_model_id": (
                        ledger_model_id if ledger else raw_model_id
                    ),
                    "obligation_kind": kind,
                }
            )
            results.append(
                {
                    "logical_obligation_id": obligation_id,
                    "evidence_result_id": f"evidence-{key}",
                    "obligation_kind": kind,
                    "status": status,
                    "replay_reference": None,
                }
            )
        classifications, counts = classify_changed_pairs(
            [pair], models, obligations, results
        )
        self.assertEqual(classifications[0]["classification"], "bounded_equivalent")
        self.assertEqual(counts["bounded_changed_pairs"], 1)
        self.assertEqual(counts["ledger_complete_changed_pairs"], 1)
        self.assertEqual(counts["ledger_only_changed_pairs"], 1)
        self.assertEqual(counts["raw_partition_exhaustive"], 1)
        decisions = derive_candidate_decisions(
            evidence_run_id="6" * 64,
            selected_policy="screening",
            pair_classifications=classifications,
            task_results=[],
            source_results=[],
            counts=counts,
            candidate_clean=True,
            candidate_committed=True,
            evidence_verified=True,
            ci_provenance_valid=True,
        )
        self.assertEqual(decisions["strict"]["decision"], "fail")
        self.assertEqual(decisions["screening"]["decision"], "pass")
        self.assertFalse(decisions["selected"]["publishable"])

    def test_raw_difference_with_ledger_equivalence_is_off_ledger_difference(
        self,
    ) -> None:
        pair_id = "7" * 64
        raw_model_id = "8" * 64
        ledger_model_id = "9" * 64
        pair = {
            "program_pair_id": pair_id,
            "old_program_artifact": {"script_sha256": "a" * 64},
            "new_program_artifact": {"script_sha256": "b" * 64},
        }
        models = [
            {
                "semantic_model_id": raw_model_id,
                "input_model": {"profile": "raw-uplc/v1"},
            },
            {
                "semantic_model_id": ledger_model_id,
                "input_model": {"profile": "ledger-valid/v1"},
            },
        ]
        rows = [
            (raw_model_id, "domain_non_vacuity", "proven", None),
            (raw_model_id, "old_program_completion", "proven", None),
            (raw_model_id, "new_program_completion", "proven", None),
            (
                raw_model_id,
                "observational_equivalence",
                "falsified",
                "confirmed-replay",
            ),
            (ledger_model_id, "ledger_domain_non_vacuity", "proven", None),
            (ledger_model_id, "old_program_completion", "proven", None),
            (ledger_model_id, "new_program_completion", "proven", None),
            (
                ledger_model_id,
                "ledger_observational_equivalence",
                "valid",
                None,
            ),
        ]
        obligations = []
        results = []
        for index, (model_id, kind, status, replay) in enumerate(rows):
            obligation_id = f"obligation-{index}"
            obligations.append(
                {
                    "logical_obligation_id": obligation_id,
                    "program_pair_id": pair_id,
                    "semantic_model_id": model_id,
                    "obligation_kind": kind,
                }
            )
            results.append(
                {
                    "logical_obligation_id": obligation_id,
                    "evidence_result_id": f"evidence-{index}",
                    "obligation_kind": kind,
                    "status": status,
                    "replay_reference": replay,
                }
            )
        classifications, counts = classify_changed_pairs(
            [pair], models, obligations, results
        )
        self.assertEqual(
            classifications[0]["classification"], "off_ledger_difference"
        )
        self.assertEqual(counts["confirmed_difference_changed_pairs"], 1)
        self.assertEqual(counts["ledger_complete_changed_pairs"], 1)
        self.assertEqual(counts["ledger_only_changed_pairs"], 1)
        self.assertEqual(counts["off_ledger_differences"], 1)
        self.assertEqual(counts["raw_partition_exhaustive"], 1)

    def test_candidate_policies_are_fail_closed_for_every_rejected_state(
        self,
    ) -> None:
        rejected = {
            "equivalent_under_ledger_model",
            "off_ledger_difference",
            "confirmed_non_equivalent",
            "blaster_falsified_unreplayed",
            "inconclusive",
            "unsupported",
            "timeout",
            "tool_error",
            "abi_failure",
            "build_failure",
            "compatibility_difference",
            "missing_evidence",
            "pending",
            "invalid",
        }
        for classification in sorted(rejected):
            with self.subTest(classification=classification):
                decisions = derive_candidate_decisions(
                    evidence_run_id="c" * 64,
                    selected_policy="screening",
                    pair_classifications=[
                        {
                            "program_pair_id": "d" * 64,
                            "classification": classification,
                            "blocking_evidence_ids": ["e" * 64],
                        }
                    ],
                    task_results=[],
                    source_results=[],
                    counts={"pending_obligations": 0},
                    candidate_clean=True,
                    candidate_committed=True,
                    evidence_verified=True,
                    ci_provenance_valid=True,
                )
                self.assertEqual(decisions["strict"]["decision"], "fail")
                self.assertEqual(decisions["screening"]["decision"], "fail")
                self.assertFalse(decisions["selected"]["publishable"])

    def test_clean_committed_verified_strict_pass_is_publishable(self) -> None:
        decisions = derive_candidate_decisions(
            evidence_run_id="f" * 64,
            selected_policy="strict",
            pair_classifications=[
                {
                    "program_pair_id": "1" * 64,
                    "classification": "equivalent_under_raw_model",
                    "blocking_evidence_ids": [],
                }
            ],
            task_results=[],
            source_results=[{"source_id": "source", "inputs_verified": True}],
            counts={"pending_obligations": 0},
            candidate_clean=True,
            candidate_committed=True,
            evidence_verified=True,
            ci_provenance_valid=True,
        )
        self.assertEqual(decisions["strict"]["decision"], "pass")
        self.assertEqual(decisions["screening"]["decision"], "pass")
        self.assertTrue(decisions["selected"]["publishable"])

if __name__ == "__main__":
    unittest.main()
