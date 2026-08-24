from __future__ import annotations

import json
from dataclasses import replace
import subprocess
import tempfile
import unittest
from pathlib import Path

from equiv_checker.config import compiler_pair
from equiv_checker.runner import (
    _feature_coverage,
    compare_package,
    hash_package_tree,
    source_repository_metadata,
)
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

    def test_local_source_provenance_separates_same_binary_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root)
            pair = self._compilers(root, [validator()], [validator()])
            config = fast_config(root)
            clean = (
                pair[0],
                replace(
                    pair[1],
                    provenance={
                        "artifact_id": "clean-artifact",
                        "source_tree_sha256": "1" * 64,
                        "dirty": False,
                        "reproducible_from_commit": True,
                    },
                ),
            )
            dirty = (
                pair[0],
                replace(
                    pair[1],
                    provenance={
                        "artifact_id": "dirty-artifact",
                        "source_tree_sha256": "2" * 64,
                        "dirty": True,
                        "reproducible_from_commit": False,
                    },
                ),
            )
            clean_summary = compare_package(
                package,
                clean,
                work_root=root / "work",
                strict=True,
                blaster_config=config,
                backend=FakeBackend(config, "blaster_error"),
            )
            dirty_summary = compare_package(
                package,
                dirty,
                work_root=root / "work",
                strict=True,
                blaster_config=config,
                backend=FakeBackend(config, "blaster_error"),
            )
            self.assertNotEqual(
                clean_summary["run_id"], dirty_summary["run_id"]
            )

    def test_fixture_evidence_metadata_does_not_change_source_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = write_package(Path(temporary))
            before = hash_package_tree(package, include_lock=False)
            (package / "codegen-triggers.json").write_text(
                '{"validator_pair_id":"first"}\n', encoding="utf-8"
            )
            (package / "regression.json").write_text(
                '{"historical_bug":"typed_expect"}\n', encoding="utf-8"
            )
            self.assertEqual(
                hash_package_tree(package, include_lock=False), before
            )

    def test_logical_source_identity_survives_unrelated_commits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root)
            for arguments in (
                ("init", "-q"),
                ("config", "user.name", "Test"),
                ("config", "user.email", "test@example.invalid"),
                ("remote", "add", "origin", "git@github.com:owner/repository.git"),
                ("add", "."),
                ("commit", "-qm", "fixture"),
            ):
                subprocess.run(
                    ["git", *arguments], cwd=root, check=True, capture_output=True
                )
            before = source_repository_metadata(package)
            (root / "unrelated.txt").write_text("one\n", encoding="utf-8")
            subprocess.run(
                ["git", "add", "unrelated.txt"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "commit", "-qm", "unrelated"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            after = source_repository_metadata(package)
            self.assertNotEqual(before["identity"], after["identity"])
            self.assertEqual(before["logical_identity"], after["logical_identity"])
            self.assertEqual(
                before["logical_identity_fields"]["canonical_repository_url"],
                "https://github.com/owner/repository",
            )

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
            self.assertEqual(summary["counts"]["identical_program_pairs"], 1)
            self.assertEqual(backend.calls, [])
            self.assertEqual(hash_package_tree(package, include_lock=True), before)
            self.assertTrue(summary["source_immutable"])

            required = compare_package(
                package,
                pair,
                work_root=root / "required-work",
                strict=True,
                blaster_config=config,
                backend=backend,
                require_script_difference=True,
            )
            self.assertFalse(required["strict_pass"])
            self.assertEqual(
                required["status_counts"],
                {"expected_codegen_delta_not_observed": 1},
            )
            self.assertEqual(backend.calls, [])

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
                resume=True,
            )
            self.assertEqual(first["run_id"], second["run_id"])
            self.assertEqual(set(first) | {"reused"}, set(second))
            self.assertTrue(second["reused"])
            result = json.loads(
                (Path(second["output"]) / "pair-results.json").read_text()
            )
            self.assertNotIn("blaster_pending", json.dumps(result))

    def test_logical_ids_are_stable_across_absolute_package_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            left_package = write_package(root / "left")
            right_package = write_package(root / "right")
            compilers = self._compilers(root, [validator()], [validator()])
            config = fast_config(root)
            summaries = [
                compare_package(
                    package,
                    compilers,
                    work_root=root / side / "work",
                    strict=True,
                    blaster_config=config,
                    backend=FakeBackend(config, "blaster_error"),
                )
                for package, side in (
                    (left_package, "left"),
                    (right_package, "right"),
                )
            ]
            self.assertEqual(summaries[0]["run_id"], summaries[1]["run_id"])
            bundles = [Path(summary["output"]) for summary in summaries]
            runs = [
                json.loads((bundle / "run.json").read_text())
                for bundle in bundles
            ]
            pairs = [
                json.loads((bundle / "program-pairs.json").read_text())["records"][0]
                for bundle in bundles
            ]
            evidence = [
                json.loads((bundle / "pair-results.json").read_text())["records"][0]
                for bundle in bundles
            ]
            self.assertEqual(
                runs[0]["source"]["identity"],
                runs[1]["source"]["identity"],
            )
            self.assertEqual(pairs[0]["program_pair_id"], pairs[1]["program_pair_id"])
            self.assertEqual(evidence[0]["evidence_id"], evidence[1]["evidence_id"])

    def test_resume_reuses_valid_pairs_and_reruns_only_corrupt_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root)
            old_rows = [
                validator("module.first.mint", IDENTITY_HEX),
                validator("module.second.mint", ZERO_HEX),
            ]
            new_rows = [
                validator("module.first.mint", ZERO_HEX),
                validator("module.second.mint", IDENTITY_HEX),
            ]
            compilers = self._compilers(root, old_rows, new_rows)
            config = fast_config(root)
            first_backend = FakeBackend(config, "blaster_valid")
            first = compare_package(
                package,
                compilers,
                work_root=root / "work",
                strict=True,
                blaster_config=config,
                backend=first_backend,
            )
            bundle = Path(first["output"])
            pair_ids = [
                row["program_pair_id"]
                for row in json.loads(
                    (bundle / "pair-results.json").read_text()
                )["records"]
            ]
            (bundle / "pairs" / pair_ids[0] / "result.json").write_text(
                "{not-json",
                encoding="utf-8",
            )

            resumed_backend = FakeBackend(config, "blaster_valid")
            resumed = compare_package(
                package,
                compilers,
                work_root=root / "work",
                strict=True,
                blaster_config=config,
                backend=resumed_backend,
                resume=True,
            )
            self.assertEqual(resumed["reused_pair_count"], 1)
            self.assertEqual(resumed["reused_pair_ids"], [pair_ids[1]])
            self.assertEqual(resumed_backend.calls, [pair_ids[0], pair_ids[0]])
            self.assertEqual(resumed["schema_errors"], [])

    def test_force_only_pair_preserves_unselected_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root)
            old_rows = [
                validator("module.first.mint", IDENTITY_HEX),
                validator("module.second.mint", ZERO_HEX),
            ]
            new_rows = [
                validator("module.first.mint", ZERO_HEX),
                validator("module.second.mint", IDENTITY_HEX),
            ]
            compilers = self._compilers(root, old_rows, new_rows)
            config = fast_config(root)
            first = compare_package(
                package,
                compilers,
                work_root=root / "work",
                strict=True,
                blaster_config=config,
                backend=FakeBackend(config, "blaster_valid"),
            )
            records = json.loads(
                (Path(first["output"]) / "pair-results.json").read_text()
            )["records"]
            selected = records[0]["program_pair_id"]
            unselected = records[1]["program_pair_id"]

            backend = FakeBackend(config, "blaster_valid")
            partial = compare_package(
                package,
                compilers,
                work_root=root / "work",
                strict=True,
                blaster_config=config,
                backend=backend,
                force=True,
                only_pairs={selected},
            )
            self.assertEqual(partial["selected_pair_ids"], [selected])
            self.assertEqual(partial["reused_pair_ids"], [unselected])
            self.assertEqual(backend.calls, [selected, selected])
            self.assertEqual(partial["counts"]["handler_pairs"], 2)

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
            self.assertEqual(summary["counts"]["handler_pairs"], 3)
            pairs = json.loads(
                (Path(summary["output"]) / "program-pairs.json").read_text()
            )
            self.assertEqual(pairs["record_count"], 1)
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
        self.assertEqual(coverage["records"][0]["status"], "pair_missing")

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

    def test_uplc_extraction_failure_has_its_own_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root)
            old = write_fake_compiler(
                root / "old-aiken", [validator()], uplc_exit_code=17
            )
            new = write_fake_compiler(root / "new-aiken", [validator()])
            compilers = compiler_pair(
                old_aiken=old,
                new_aiken=new,
                old_revision="old-revision",
                new_revision="new-revision",
            )
            config = fast_config(root)
            summary = compare_package(
                package,
                compilers,
                work_root=root / "work",
                strict=True,
                blaster_config=config,
                backend=FakeBackend(config, "blaster_valid"),
            )
            self.assertFalse(summary["strict_pass"])
            self.assertEqual(
                summary["status_counts"], {"old_uplc_extraction_failed": 1}
            )

    def test_missing_and_malformed_blueprints_are_distinct(self) -> None:
        for mode, status in (
            ("missing", "old_blueprint_missing"),
            ("malformed", "blueprint_schema_unsupported"),
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                package = write_package(root)
                old = write_fake_compiler(
                    root / "old-aiken", [validator()], blueprint_mode=mode
                )
                new = write_fake_compiler(root / "new-aiken", [validator()])
                compilers = compiler_pair(
                    old_aiken=old,
                    new_aiken=new,
                    old_revision="old-revision",
                    new_revision="new-revision",
                )
                config = fast_config(root)
                summary = compare_package(
                    package,
                    compilers,
                    work_root=root / "work",
                    strict=True,
                    blaster_config=config,
                    backend=FakeBackend(config, "blaster_valid"),
                )
                self.assertFalse(summary["strict_pass"])
                self.assertEqual(summary["status_counts"], {status: 1})


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
