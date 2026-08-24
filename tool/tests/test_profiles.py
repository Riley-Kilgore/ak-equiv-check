from __future__ import annotations

import json
import hashlib
import unittest
from pathlib import Path

from equiv_checker.config import Compiler
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
    def test_compact_baselines_have_complete_valid_checksums(self) -> None:
        names = (
            "historical-equivalent-v1.1.21-v1.1.22",
            "historical-regression-v1.1.22-v1.1.23",
        )
        for name in names:
            with self.subTest(name=name):
                root = BASELINES / name
                checksums = json.loads((root / "checksums.json").read_text())
                recorded = checksums["files"]
                actual = {
                    path.name
                    for path in root.iterdir()
                    if path.is_file() and path.name != "checksums.json"
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
        expected = {
            "historical-equivalent-v1.1.21-v1.1.22": {
                "artifact_id": 9456723806,
                "artifact_name": "historical-equivalent-32508847798",
                "job": "historical-equivalent",
            },
            "historical-regression-v1.1.22-v1.1.23": {
                "artifact_id": 9457392993,
                "artifact_name": "historical-regression-32508847798",
                "job": "historical-regression",
            },
        }
        required = {
            "ci-provenance.json",
            "compiler-lock.json",
            "source-lock.json",
            "environment.json",
            "task-results.ndjson",
            "pair-results.ndjson",
            "feature-coverage.json",
            "summary.json",
            "summary.md",
            "checksums.json",
        }
        for name, evidence in expected.items():
            with self.subTest(name=name):
                root = BASELINES / name
                self.assertTrue(required.issubset(path.name for path in root.iterdir()))
                summary_markdown = (root / "summary.md").read_text()
                self.assertIn(f"`{name}`", summary_markdown)
                provenance = json.loads((root / "ci-provenance.json").read_text())
                self.assertEqual(provenance["profile_id"], name)
                self.assertEqual(
                    provenance["attestation_kind"], "public_ci_reproduction"
                )
                self.assertEqual(provenance["workflow_run"]["conclusion"], "success")
                self.assertEqual(provenance["job"]["name"], evidence["job"])
                self.assertEqual(provenance["job"]["conclusion"], "success")
                self.assertEqual(
                    provenance["artifact"]["id"], evidence["artifact_id"]
                )
                self.assertEqual(
                    provenance["artifact"]["name"], evidence["artifact_name"]
                )
                self.assertRegex(
                    provenance["artifact"]["digest"], r"^sha256:[0-9a-f]{64}$"
                )

    def test_compact_baselines_match_current_fixture_sources(self) -> None:
        names = (
            "historical-equivalent-v1.1.21-v1.1.22",
            "historical-regression-v1.1.22-v1.1.23",
        )
        for name in names:
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

    def test_compact_baselines_record_required_semantic_outcomes(self) -> None:
        equivalent = json.loads(
            (
                BASELINES
                / "historical-equivalent-v1.1.21-v1.1.22"
                / "summary.json"
            ).read_text()
        )
        regression = json.loads(
            (
                BASELINES
                / "historical-regression-v1.1.22-v1.1.23"
                / "summary.json"
            ).read_text()
        )
        self.assertTrue(equivalent["script_difference_observed"])
        self.assertTrue(equivalent["strict_pass"])
        self.assertEqual(
            equivalent["status_counts"],
            {"equivalent_under_raw_model": 6},
        )
        self.assertTrue(regression["script_difference_observed"])
        self.assertFalse(regression["strict_pass"])
        self.assertEqual(
            regression["status_counts"],
            {"confirmed_non_equivalent": 2},
        )
        self.assertTrue(equivalent["profile"]["profile_pass"])
        self.assertTrue(regression["profile"]["profile_pass"])

    def test_historical_baselines_preserve_feature_and_replay_evidence(self) -> None:
        equivalent_root = (
            BASELINES / "historical-equivalent-v1.1.21-v1.1.22"
        )
        coverage = json.loads(
            (equivalent_root / "feature-coverage.json").read_text()
        )
        contract = coverage["historical_shared_feature_contract"]
        claims = coverage["historical_coverage_claims"]
        trigger_ids = {
            row["feature_id"]
            for row in coverage["historical_codegen_triggers"]
        }
        self.assertEqual(contract["status"], "shared_subset_verified")
        self.assertEqual(set(contract["feature_ids"]), trigger_ids)
        self.assertEqual(
            set(claims["non_identical_script_feature_ids"]), trigger_ids
        )
        self.assertEqual(claims["byte_identical_script_feature_ids"], [])
        self.assertEqual(
            claims["excluded_contracts"][0]["state"],
            "not_applied_newer_release_contract",
        )
        pairs_by_id = {
            pair["pair_id"]: pair
            for pair in (
                json.loads(line)
                for line in (equivalent_root / "pair-results.ndjson")
                .read_text()
                .splitlines()
            )
        }
        for trigger in coverage["historical_codegen_triggers"]:
            pair = pairs_by_id[trigger["validator_pair_id"]]
            self.assertTrue(trigger["hashes_differ"])
            self.assertEqual(
                trigger["old_compiled_code_sha256"],
                pair["old_script_sha256"],
            )
            self.assertEqual(
                trigger["new_compiled_code_sha256"],
                pair["new_script_sha256"],
            )
        source_lock = json.loads(
            (equivalent_root / "source-lock.json").read_text()
        )
        self.assertTrue(source_lock["old_new_source_hash_equal"])
        self.assertTrue(source_lock["old_new_dependency_lock_equal"])
        equivalent_pairs = [
            json.loads(line)
            for line in (equivalent_root / "pair-results.ndjson")
            .read_text()
            .splitlines()
        ]
        for pair in equivalent_pairs:
            with self.subTest(pair_id=pair["pair_id"]):
                self.assertNotEqual(
                    pair["old_script_sha256"], pair["new_script_sha256"]
                )
                self.assertTrue(pair["abi"]["verified"])
                self.assertTrue(pair["abi"]["equal"])
                self.assertTrue(pair["abi"]["old"]["verified"])
                self.assertTrue(pair["abi"]["new"]["verified"])
                obligations = pair["proof_obligations"]
                self.assertEqual(
                    obligations["domain_non_vacuity"]["status"], "proven"
                )
                self.assertEqual(
                    obligations["old_program_completion"]["status"], "proven"
                )
                self.assertEqual(
                    obligations["new_program_completion"]["status"], "proven"
                )
                self.assertEqual(
                    obligations["observational_equivalence"]["status"],
                    "valid",
                )
                self.assertEqual(pair["status"], "equivalent_under_raw_model")

        regression_root = (
            BASELINES / "historical-regression-v1.1.22-v1.1.23"
        )
        pairs = [
            json.loads(line)
            for line in (regression_root / "pair-results.ndjson")
            .read_text()
            .splitlines()
        ]
        self.assertGreater(len(pairs), 0)
        for pair in pairs:
            with self.subTest(pair_id=pair["pair_id"]):
                self.assertNotEqual(
                    pair["old_script_sha256"], pair["new_script_sha256"]
                )
                replay = pair["counterexample_replay"]
                self.assertTrue(replay["confirmed"])
                self.assertEqual(
                    replay["old"]["outcome"], "program_success"
                )
                self.assertEqual(
                    replay["new"]["outcome"], "program_failure"
                )
                self.assertTrue(pair["abi"]["verified"])
                self.assertTrue(pair["abi"]["equal"])
                witness = pair["witness"]
                self.assertEqual(witness["pair_id"], pair["pair_id"])
                self.assertEqual(witness["theorem_hash"], pair["theorem_hash"])
                self.assertEqual(replay["pair_id"], pair["pair_id"])
                self.assertEqual(replay["theorem_hash"], pair["theorem_hash"])
                self.assertEqual(
                    replay["arguments"]["protocol"],
                    "EQUIV_REPLAY_ARGUMENTS_V1",
                )
                self.assertEqual(
                    replay["arguments"]["pair_id"], pair["pair_id"]
                )
                self.assertEqual(
                    replay["arguments"]["theorem_hash"], pair["theorem_hash"]
                )
                compared_hashes = {
                    compiler["binary_sha256"]
                    for compiler in pair["compiler_pair"].values()
                }
                self.assertNotIn(
                    replay["evaluator"]["binary_sha256"], compared_hashes
                )


if __name__ == "__main__":
    unittest.main()
