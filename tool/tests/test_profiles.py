from __future__ import annotations

import json
import hashlib
import unittest
from pathlib import Path

from equiv_checker.config import Compiler
from equiv_checker.baseline import REQUIRED_BASELINE_FILES, verify_baseline
from equiv_checker.profiles import (
    PROFILE_LOCK,
    PROFILE_REGISTRY,
    _validate_local_candidate,
    _validate_local_base,
    load_profile,
    profile_result,
)
from equiv_checker.runner import hash_package_tree


ROOT = Path(__file__).resolve().parents[2]
BASELINES = ROOT / "results" / "baselines"

class ProfileRegistryTests(unittest.TestCase):
    def test_required_historical_and_local_profiles_are_registered(self) -> None:
        registry = json.loads(PROFILE_REGISTRY.read_text())
        by_name = {profile["name"]: profile for profile in registry["profiles"]}
        self.assertEqual(
            set(by_name),
            {
                "historical-equivalent",
                "historical-regression",
                "local-candidate",
                "local-candidate-changed-output",
            },
        )
        self.assertEqual(by_name["historical-equivalent"]["old_ref"], "v1.1.21")
        self.assertEqual(by_name["historical-equivalent"]["new_ref"], "v1.1.22")
        self.assertEqual(by_name["historical-regression"]["old_ref"], "v1.1.22")
        self.assertEqual(by_name["historical-regression"]["new_ref"], "v1.1.23")
        changed = by_name["local-candidate-changed-output"]
        self.assertTrue(changed["require_script_difference"])
        self.assertEqual(
            changed["expected_semantic_status"],
            "equivalent_under_raw_model",
        )

    def test_historical_profile_lock_uses_full_commit_shas(self) -> None:
        lock = json.loads(PROFILE_LOCK.read_text())
        for profile in lock["profiles"].values():
            for release in profile["releases"].values():
                self.assertRegex(release["commit_sha"], r"^[0-9a-f]{40}$")
                self.assertRegex(release["source_tree_git_sha"], r"^[0-9a-f]{40}$")

    def test_aliases_load_the_versioned_profiles(self) -> None:
        self.assertEqual(
            load_profile("historical-equivalent")["id"],
            "historical-equivalent-v1.1.21-v1.1.22",
        )
        self.assertEqual(
            load_profile("historical-regression")["id"],
            "historical-regression-v1.1.22-v1.1.23",
        )


class ProfileExpectationTests(unittest.TestCase):
    def test_positive_requires_codegen_delta_and_strict_equivalence(self) -> None:
        profile = load_profile("historical-equivalent")
        summary = {"strict_pass": True, "script_difference_observed": True}
        report = profile_result(
            profile, summary, ["equivalent_under_raw_model", "equivalent_under_raw_model"]
        )
        self.assertTrue(report["profile_pass"])
        self.assertEqual(report["semantic_status"], "equivalent_under_raw_model")

        no_delta = profile_result(
            profile,
            {"strict_pass": True, "script_difference_observed": False},
            ["equivalent_under_raw_model"],
        )
        self.assertFalse(no_delta["profile_pass"])
        self.assertFalse(no_delta["expectation_matched"])

    def test_negative_expectation_never_relabels_semantics(self) -> None:
        profile = load_profile("historical-regression")
        report = profile_result(
            profile,
            {"strict_pass": False, "script_difference_observed": True},
            ["confirmed_non_equivalent"],
        )
        self.assertEqual(report["semantic_status"], "confirmed_non_equivalent")
        self.assertEqual(report["profile_expectation"], "confirmed_non_equivalent")
        self.assertEqual(report["semantic_strict_result"], "fail")
        self.assertTrue(report["expectation_matched"])
        self.assertTrue(report["profile_pass"])

    def test_wrong_historical_result_fails_the_profile(self) -> None:
        profile = load_profile("historical-regression")
        report = profile_result(
            profile,
            {"strict_pass": False, "script_difference_observed": True},
            ["blaster_falsified_unreplayed"],
        )
        self.assertFalse(report["expectation_matched"])
        self.assertFalse(report["profile_pass"])
        self.assertEqual(report["semantic_status"], "blaster_falsified_unreplayed")

    def test_local_candidate_reports_normal_semantic_status(self) -> None:
        profile = load_profile("local-candidate")
        report = profile_result(
            profile,
            {"strict_pass": True, "script_difference_observed": False},
            ["identical", "identical"],
        )
        self.assertEqual(report["semantic_status"], "identical")
        self.assertEqual(report["semantic_statuses"], ["identical", "identical"])
        self.assertIsNone(report["profile_expectation"])
        self.assertTrue(report["profile_pass"])

    def test_local_candidate_rejects_dirty_or_uncommitted_base(self) -> None:
        base = Compiler(
            label="old",
            release="local",
            reported_version="aiken v1.1.23+local",
            git_revision="a" * 40,
            binary_sha256="b" * 64,
            executable=Path("aiken"),
            provenance={
                "dirty": True,
                "reproducible_from_commit": False,
            },
        )
        with self.assertRaisesRegex(ValueError, "clean committed source"):
            _validate_local_base(base)

        release_candidate = Compiler(
            label="new",
            release="v1.1.23",
            reported_version="aiken v1.1.23+release",
            git_revision="a" * 40,
            binary_sha256="b" * 64,
            executable=Path("aiken"),
            provenance={"artifact_kind": "release"},
        )
        with self.assertRaisesRegex(ValueError, "build-local artifact"):
            _validate_local_candidate(release_candidate)


class HistoricalBaselineTests(unittest.TestCase):
    NAMES = (
        "historical-equivalent-v1.1.21-v1.1.22",
        "historical-regression-v1.1.22-v1.1.23",
    )

    @staticmethod
    def _records(root: Path, filename: str) -> list[dict[str, object]]:
        return [
            json.loads(line)
            for line in (root / filename).read_text().splitlines()
            if line
        ]

    def test_compact_baselines_have_complete_valid_checksums(self) -> None:
        for name in self.NAMES:
            with self.subTest(name=name):
                root = BASELINES / name
                verification = verify_baseline(root)
                self.assertTrue(verification["valid"])
                checksums = json.loads((root / "checksums.json").read_text())
                recorded = checksums["files"]
                actual = {
                    path.name
                    for path in root.iterdir()
                    if path.is_file()
                    and path.name
                    not in {"checksums.json", "ci-attestation.json"}
                }
                self.assertEqual(set(recorded), actual)
                for filename, expected in recorded.items():
                    self.assertEqual(
                        hashlib.sha256((root / filename).read_bytes()).hexdigest(),
                        expected,
                    )
                for path in root.iterdir():
                    if path.is_file():
                        self.assertNotIn(str(ROOT), path.read_text())

    def test_compact_baselines_include_human_and_ci_provenance(self) -> None:
        for name in self.NAMES:
            with self.subTest(name=name):
                root = BASELINES / name
                self.assertTrue(
                    REQUIRED_BASELINE_FILES.issubset(
                        path.name for path in root.iterdir()
                    )
                )
                summary_markdown = (root / "summary.md").read_text()
                self.assertIn(f"`{name}`", summary_markdown)
                attestation = json.loads(
                    (root / "ci-attestation.json").read_text()
                )
                self.assertEqual(attestation["profile_id"], name)
                self.assertEqual(
                    attestation["attestation_kind"],
                    "public_ci_reproduction",
                )
                self.assertEqual(attestation["verification_result"], "verified")
                self.assertGreater(attestation["github_run_id"], 0)
                self.assertGreater(attestation["job_id"], 0)
                self.assertGreater(attestation["artifact_id"], 0)
                self.assertRegex(
                    attestation["artifact_sha256"], r"^[0-9a-f]{64}$"
                )

    def test_compact_baselines_match_current_fixture_sources(self) -> None:
        for name in self.NAMES:
            with self.subTest(name=name):
                source_lock = json.loads(
                    (BASELINES / name / "source-lock.json").read_text()
                )
                fixture = ROOT / source_lock["fixture"]
                self.assertEqual(
                    hash_package_tree(fixture, include_lock=False),
                    source_lock["source_hash"],
                )
                self.assertEqual(
                    hashlib.sha256((fixture / "aiken.lock").read_bytes()).hexdigest(),
                    source_lock["dependency_lock_hash"],
                )
                self.assertTrue(source_lock["old_new_source_hash_equal"])
                self.assertTrue(source_lock["old_new_dependency_lock_equal"])

    def test_compact_baselines_record_required_semantic_outcomes(self) -> None:
        expectations = {
            "historical-equivalent-v1.1.21-v1.1.22": (
                "equivalent_under_raw_model",
                True,
            ),
            "historical-regression-v1.1.22-v1.1.23": (
                "confirmed_non_equivalent",
                False,
            ),
        }
        for name, (expected_status, strict_pass) in expectations.items():
            with self.subTest(name=name):
                root = BASELINES / name
                summary = json.loads((root / "summary.json").read_text())
                handlers = self._records(root, "handler-pairs.ndjson")
                programs = self._records(root, "program-pairs.ndjson")
                obligations = self._records(
                    root, "semantic-obligations.ndjson"
                )
                results = self._records(root, "obligation-results.ndjson")
                counts = summary["counts"]
                self.assertTrue(summary["script_difference_observed"])
                self.assertEqual(summary["strict_pass"], strict_pass)
                self.assertEqual(
                    summary["status_counts"],
                    {expected_status: len(programs)},
                )
                self.assertTrue(summary["profile"]["profile_pass"])
                self.assertEqual(counts["handler_pairs"], len(handlers))
                self.assertEqual(counts["unique_program_pairs"], len(programs))
                self.assertEqual(
                    counts["unique_raw_obligations"],
                    sum(
                        row["input_model"]["profile"] == "raw-uplc/v1"
                        for row in obligations
                    ),
                )
                self.assertEqual(
                    counts["unique_ledger_obligations"],
                    sum(
                        row["input_model"]["profile"] == "ledger-valid/v1"
                        for row in obligations
                    ),
                )
                self.assertEqual(len(results), len(obligations))
                self.assertEqual(
                    counts["deduplicated_invocations"],
                    len(handlers) - len(programs),
                )

    def test_historical_feature_rows_link_all_evidence_layers(self) -> None:
        root = BASELINES / "historical-equivalent-v1.1.21-v1.1.22"
        trigger_document = json.loads(
            (
                ROOT
                / "fixtures/historical-codegen-equivalent/codegen-triggers.json"
            ).read_text()
        )
        triggers = {
            row["feature_id"]: row for row in trigger_document["records"]
        }
        feature_links = {
            row["feature_id"]: row
            for row in self._records(root, "feature-links.ndjson")
        }
        handlers = {
            row["handler_pair_id"]: row
            for row in self._records(root, "handler-pairs.ndjson")
        }
        validator_links = {
            row["handler_pair_id"]: row
            for row in self._records(root, "validator-links.ndjson")
        }
        programs = {
            row["program_pair_id"]: row
            for row in self._records(root, "program-pairs.ndjson")
        }
        obligations = self._records(root, "semantic-obligations.ndjson")
        results = {
            row["logical_obligation_id"]: row
            for row in self._records(root, "obligation-results.ndjson")
        }
        self.assertEqual(set(feature_links), set(triggers))
        self.assertEqual(
            set(trigger_document["shared_feature_contract"]["feature_ids"]),
            set(feature_links),
        )
        for feature_id, link in feature_links.items():
            with self.subTest(feature_id=feature_id):
                trigger = triggers[feature_id]
                self.assertEqual(link["status"], "pair_complete_equivalent")
                self.assertEqual(
                    link["old_script_sha256"],
                    trigger["old_compiled_code_sha256"],
                )
                self.assertEqual(
                    link["new_script_sha256"],
                    trigger["new_compiled_code_sha256"],
                )
                self.assertEqual(len(link["program_pair_ids"]), 1)
                program = programs[link["program_pair_ids"][0]]
                self.assertEqual(
                    program["old_program_artifact"]["script_sha256"],
                    link["old_script_sha256"],
                )
                self.assertEqual(
                    program["new_program_artifact"]["script_sha256"],
                    link["new_script_sha256"],
                )
                self.assertEqual(
                    set(link["handler_pair_ids"]),
                    set(program["handler_pair_ids"]),
                )
                for handler_id in link["handler_pair_ids"]:
                    self.assertIn(feature_id, handlers[handler_id]["feature_ids"])
                    self.assertIn(
                        feature_id,
                        validator_links[handler_id]["feature_ids"],
                    )
                self.assertIn(feature_id, program["covered_feature_ids"])
                linked_obligations = [
                    row
                    for row in obligations
                    if row["program_pair_id"] == program["program_pair_id"]
                ]
                self.assertEqual(
                    set(link["semantic_obligation_ids"]),
                    {
                        row["logical_obligation_id"]
                        for row in linked_obligations
                    },
                )
                raw_evidence = {
                    results[row["logical_obligation_id"]][
                        "evidence_result_id"
                    ]
                    for row in linked_obligations
                    if row["input_model"]["profile"] == "raw-uplc/v1"
                }
                all_evidence = {
                    results[row["logical_obligation_id"]][
                        "evidence_result_id"
                    ]
                    for row in linked_obligations
                }
                self.assertEqual(set(link["required_evidence"]), raw_evidence)
                self.assertEqual(
                    set(link["authoritative_evidence"]), raw_evidence
                )
                self.assertEqual(set(link["all_linked_evidence"]), all_evidence)

    def test_raw_obligations_and_negative_replay_remain_auditable(self) -> None:
        expected_raw_statuses = {
            "historical-equivalent-v1.1.21-v1.1.22": {
                "domain_non_vacuity": "proven",
                "old_program_completion": "proven",
                "new_program_completion": "proven",
                "observational_equivalence": "valid",
            },
            "historical-regression-v1.1.22-v1.1.23": {
                "domain_non_vacuity": "proven",
                "old_program_completion": "proven",
                "new_program_completion": "proven",
                "observational_equivalence": "falsified",
            },
        }
        for name, expected in expected_raw_statuses.items():
            root = BASELINES / name
            obligations = self._records(root, "semantic-obligations.ndjson")
            results = {
                row["logical_obligation_id"]: row
                for row in self._records(root, "obligation-results.ndjson")
            }
            for obligation in obligations:
                if obligation["input_model"]["profile"] != "raw-uplc/v1":
                    continue
                with self.subTest(
                    name=name,
                    obligation_id=obligation["logical_obligation_id"],
                ):
                    result = results[obligation["logical_obligation_id"]]
                    self.assertEqual(
                        result["status"],
                        expected[obligation["obligation_kind"]],
                    )

        regression_root = (
            BASELINES / "historical-regression-v1.1.22-v1.1.23"
        )
        replayed = [
            row
            for row in self._records(
                regression_root, "obligation-results.ndjson"
            )
            if "replay" in row
        ]
        self.assertEqual(len(replayed), 1)
        result = replayed[0]
        replay = result["replay"]
        witness = result["witness"]
        self.assertTrue(replay["confirmed"])
        self.assertEqual(
            replay["logical_obligation_id"],
            result["logical_obligation_id"],
        )
        self.assertEqual(replay["program_pair_id"], result["program_pair_id"])
        self.assertEqual(
            replay["semantic_model_id"], result["semantic_model_id"]
        )
        self.assertEqual(witness["protocol_version"], "EQUIV_WITNESS_V2")
        self.assertEqual(witness["witness_source"], "legacy_human_parser")
        self.assertEqual(
            witness["witness_sha256"], replay["witness_sha256"]
        )
        self.assertTrue(
            replay["legacy_witness_validation"][
                "serialization_validated"
            ]
        )
        self.assertTrue(
            replay["legacy_witness_validation"][
                "concrete_replay_validated"
            ]
        )
        primary = replay["primary_evaluator"]
        self.assertEqual(primary["old"]["outcome"], "program_success")
        self.assertEqual(primary["new"]["outcome"], "program_failure")
        for observation in (primary["old"], primary["new"]):
            for field in (
                "configured_limits",
                "effective_limits",
                "evaluator_enforced_limits",
                "externally_enforced_limits",
                "unenforced_limits",
            ):
                self.assertIn(field, observation)
            self.assertIn("command", observation)
            self.assertIn("exit_code", observation)
            self.assertIn("process_group_termination_succeeded", observation)
        self.assertEqual(
            replay["replay_confidence"], "single_evaluator_confirmed"
        )
        self.assertEqual(
            replay["replay_trust"],
            {
                "separately_pinned": True,
                "separate_binary": True,
                "separate_from_symbolic_model": True,
                "distinct_uplc_implementation": False,
            },
        )


if __name__ == "__main__":
    unittest.main()
