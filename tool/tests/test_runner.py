from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from equiv_checker.config import compiler_pair
from equiv_checker.runner import _feature_coverage, compare_package, hash_package_tree
from helpers import (
    IDENTITY_HEX,
    ZERO_HEX,
    FakeBackend,
    fast_config,
    validator,
    write_fake_compiler,
    write_package,
)


class PackageRunnerTests(unittest.TestCase):
    def _compilers(
        self,
        root: Path,
        old_validators: list[dict],
        new_validators: list[dict],
        *,
        old_exit: int = 0,
        new_exit: int = 0,
    ):
        old_path = write_fake_compiler(
            root / "custom-old-aiken", old_validators, build_exit_code=old_exit
        )
        new_path = write_fake_compiler(
            root / "custom-new-aiken", new_validators, build_exit_code=new_exit
        )
        return compiler_pair(
            old_aiken=old_path,
            new_aiken=new_path,
            old_revision="old-revision",
            new_revision="new-revision",
        )

    def test_arbitrary_same_version_binaries_remain_old_and_new(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pair = self._compilers(root, [validator()], [validator()])
            self.assertEqual(pair[0].label, "old")
            self.assertEqual(pair[1].label, "new")
            self.assertEqual(pair[0].reported_version, pair[1].reported_version)
            self.assertNotEqual(pair[0].binary_sha256, pair[1].binary_sha256)
            self.assertEqual(pair[0].git_revision, "old-revision")
            self.assertEqual(pair[1].git_revision, "new-revision")

    def test_identical_scripts_pass_without_calling_blaster(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root)
            pair = self._compilers(root, [validator()], [validator()])
            config = fast_config(root)
            backend = FakeBackend(config, "blaster_error")
            before = hash_package_tree(package, include_lock=True)
            summary = compare_package(
                package,
                pair,
                work_root=root / "work",
                strict=True,
                blaster_config=config,
                backend=backend,
            )
            self.assertTrue(summary["strict_pass"])
            self.assertEqual(summary["counts"]["identical_pairs"], 1)
            self.assertEqual(backend.calls, [])
            self.assertEqual(hash_package_tree(package, include_lock=True), before)
            self.assertTrue(summary["source_immutable"])

    def test_repeated_runs_keep_identity_and_structure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root)
            pair = self._compilers(root, [validator()], [validator()])
            config = fast_config(root)
            first = compare_package(
                package,
                pair,
                work_root=root / "work",
                strict=True,
                blaster_config=config,
                backend=FakeBackend(config, "blaster_error"),
            )
            second = compare_package(
                package,
                pair,
                work_root=root / "work",
                strict=True,
                blaster_config=config,
                backend=FakeBackend(config, "blaster_error"),
            )
            self.assertEqual(first["run_id"], second["run_id"])
            self.assertEqual(set(first), set(second))
            result = json.loads(
                (Path(second["output"]) / "pair-results.json").read_text()
            )
            self.assertNotIn("blaster_pending", json.dumps(result))

    def test_dynamic_validator_counts_have_no_fixed_schema_constant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root)
            rows = [validator(f"module.validator_{index}.mint") for index in range(3)]
            pair = self._compilers(root, rows, list(reversed(rows)))
            config = fast_config(root)
            summary = compare_package(
                package,
                pair,
                work_root=root / "work",
                strict=True,
                blaster_config=config,
                backend=FakeBackend(config, "blaster_error"),
            )
            self.assertEqual(summary["counts"]["validators_paired"], 3)
            pairs = json.loads(
                (Path(summary["output"]) / "script-pairs.json").read_text()
            )
            self.assertEqual(pairs["record_count"], 3)
            self.assertEqual(summary["schema_errors"], [])

    def test_missing_contract_manifest_row_is_a_coverage_failure(self) -> None:
        evidence = {
            "contract": {
                "features": [
                    {
                        "id": "FEATURE",
                        "sentinel_required": True,
                        "lanes": ["compile"],
                        "negative_compile_case": False,
                    }
                ],
                "active_uplc_builtins": [],
            },
            "census": [{"feature_id": "FEATURE"}],
            "reachability": {"old": [], "new": []},
            "lanes": {"old": {}, "new": {}},
        }
        builds = {
            "old": {"primary_exit_code": 0, "negative_runs": []},
            "new": {"primary_exit_code": 0, "negative_runs": []},
        }
        coverage = _feature_coverage(
            {"features": [], "builtins": []},
            evidence,
            [],
            builds,
        )
        self.assertEqual(coverage["record_count"], 1)
        self.assertFalse(coverage["records"][0]["manifest_present"])
        self.assertEqual(coverage["records"][0]["status"], "feature_not_shared")

    def test_build_failures_are_labeled_separately(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root)
            pair = self._compilers(
                root, [validator()], [validator()], old_exit=7, new_exit=0
            )
            config = fast_config(root)
            summary = compare_package(
                package,
                pair,
                work_root=root / "work",
                strict=True,
                blaster_config=config,
                backend=FakeBackend(config, "blaster_valid"),
            )
            self.assertFalse(summary["strict_pass"])
            self.assertEqual(summary["schema_errors"], [])
            self.assertEqual(summary["status_counts"], {"old_build_failed": 1})

    def test_new_build_failure_has_its_own_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root)
            pair = self._compilers(
                root, [validator()], [validator()], old_exit=0, new_exit=9
            )
            config = fast_config(root)
            summary = compare_package(
                package,
                pair,
                work_root=root / "work",
                strict=True,
                blaster_config=config,
                backend=FakeBackend(config, "blaster_valid"),
            )
            self.assertFalse(summary["strict_pass"])
            self.assertEqual(summary["schema_errors"], [])
            self.assertEqual(summary["status_counts"], {"new_build_failed": 1})

    def test_missing_lock_is_explicit_strict_reproducibility_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root, with_lock=False)
            pair = self._compilers(root, [validator()], [validator()])
            config = fast_config(root)
            summary = compare_package(
                package,
                pair,
                work_root=root / "work",
                strict=True,
                blaster_config=config,
                backend=FakeBackend(config, "blaster_error"),
            )
            self.assertFalse(summary["strict_pass"])
            self.assertIn("missing_dependency_lock", summary["gaps"])

    def test_strict_gate_rejects_every_nonpassing_semantic_status(self) -> None:
        statuses = (
            "blaster_unsupported",
            "blaster_inconclusive",
            "blaster_timeout",
            "blaster_error",
            "blaster_falsified_unreplayed",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root)
            pair = self._compilers(
                root,
                [validator(compiled_code=IDENTITY_HEX)],
                [validator(compiled_code=ZERO_HEX)],
            )
            config = fast_config(root)
            for status in statuses:
                with self.subTest(status=status):
                    backend = FakeBackend(config, status)
                    summary = compare_package(
                        package,
                        pair,
                        work_root=root / status,
                        strict=True,
                        blaster_config=config,
                        backend=backend,
                    )
                    self.assertFalse(summary["strict_pass"])
                    self.assertEqual(summary["status_counts"], {status: 1})

    def test_replayed_falsification_becomes_confirmed_non_equivalent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root)
            pair = self._compilers(
                root,
                [validator(compiled_code=IDENTITY_HEX)],
                [validator(compiled_code=ZERO_HEX)],
            )
            config = fast_config(root)
            witness = {"values": {"input": {"kind": "integer", "value": 1}}}
            backend = FakeBackend(
                config,
                "blaster_falsified_unreplayed",
                witness=witness,
                replay_confirmed=True,
            )
            summary = compare_package(
                package,
                pair,
                work_root=root / "work",
                strict=True,
                blaster_config=config,
                backend=backend,
            )
            self.assertFalse(summary["strict_pass"])
            self.assertEqual(summary["status_counts"], {"confirmed_non_equivalent": 1})


if __name__ == "__main__":
    unittest.main()
