from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from equiv_checker.candidate import _merge_unique, run_candidate_gate
from equiv_checker.config import Compiler
from helpers import fast_config


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


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

    def test_program_pair_merge_unions_nested_source_references(self) -> None:
        artifact = {
            "program_artifact_id": "a" * 64,
            "script_sha256": "b" * 64,
            "source_validator_references": ["handler-a"],
        }
        first = {
            "program_pair_id": "c" * 64,
            "old_program_artifact": artifact,
            "new_program_artifact": artifact,
            "handler_pair_ids": ["handler-a"],
        }
        second = json.loads(json.dumps(first))
        second["handler_pair_ids"] = ["handler-b"]
        second["old_program_artifact"]["source_validator_references"] = [
            "handler-b"
        ]
        second["new_program_artifact"]["source_validator_references"] = [
            "handler-b"
        ]

        merged, conflicts = _merge_unique(
            [first, second],
            "program_pair_id",
            merge_fields=(
                "handler_pair_ids",
                "old_program_artifact.source_validator_references",
                "new_program_artifact.source_validator_references",
            ),
        )

        self.assertEqual(conflicts, [])
        self.assertEqual(merged[0]["handler_pair_ids"], ["handler-a", "handler-b"])
        self.assertEqual(
            merged[0]["old_program_artifact"]["source_validator_references"],
            ["handler-a", "handler-b"],
        )


    def test_dirty_candidate_runs_semantics_but_is_development_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base_path = root / "base.json"
            candidate_path = root / "candidate.json"
            feature = root / "features.json"
            corpus = root / "corpus.json"
            release_lock = root / "release-lock.json"
            for path in (
                base_path,
                candidate_path,
                feature,
                corpus,
                release_lock,
            ):
                path.write_text("{}\n", encoding="utf-8")
            child = root / "child"
            pair_id = "1" * 64
            obligation_id = "2" * 64
            evidence_id = "3" * 64
            _write(
                child / "summary.json",
                {
                    "run_id": "4" * 64,
                    "strict_pass": True,
                    "source_immutable": True,
                    "dependency_lock_shared": True,
                    "counts": {"deduplicated_invocation_count": 1},
                },
            )
            artifact = {
                "program_artifact_id": "5" * 64,
                "script_sha256": "6" * 64,
                "script_size": 1,
            }
            record_sets = {
                "program-pairs.json": [
                    {
                        "program_pair_id": pair_id,
                        "old_program_artifact": artifact,
                        "new_program_artifact": artifact
                        | {"script_sha256": "7" * 64},
                        "verified_abi_id": "8" * 64,
                        "handler_pair_ids": ["handler"],
                        "handler_references": [],
                        "covered_feature_ids": ["FEATURE"],
                    }
                ],
                "semantic-obligations.json": [
                    {
                        "logical_obligation_id": obligation_id,
                        "program_pair_id": pair_id,
                    }
                ],
                "obligation-results.json": [
                    {
                        "logical_obligation_id": obligation_id,
                        "evidence_result_id": evidence_id,
                        "attempt_id": "9" * 64,
                        "program_pair_id": pair_id,
                        "reused": False,
                    }
                ],
                "validator-links.json": [
                    {
                        "handler_pair_id": "handler",
                        "program_pair_id": pair_id,
                        "feature_ids": ["FEATURE"],
                        "logical_obligation_ids": [obligation_id],
                        "evidence_result_ids": [evidence_id],
                    }
                ],
                "feature-links.json": [
                    {
                        "feature_id": "FEATURE",
                        "row_kind": "feature",
                        "status": "pair_complete_equivalent",
                        "handler_pair_ids": ["handler"],
                        "program_pair_ids": [pair_id],
                        "semantic_obligation_ids": [obligation_id],
                        "all_linked_evidence": [evidence_id],
                        "required_evidence": [evidence_id],
                        "authoritative_evidence": [evidence_id],
                    }
                ],
                "pair-results.json": [
                    {
                        "status": "equivalent_under_raw_model",
                        "program_pair_id": pair_id,
                        "evidence_reuse": None,
                        "model_results": {
                            "model": {
                                "backend": {"command": ["blaster"]}
                            }
                        },
                    }
                ],
            }
            for filename, records in record_sets.items():
                _write(
                    child / filename,
                    {
                        "schema_version": 2,
                        "record_count": len(records),
                        "records": records,
                    },
                )
            base_manifest = {
                "artifact_id": "a" * 64,
                "source": {"dirty": False},
            }
            candidate_manifest = {
                "artifact_id": "b" * 64,
                "artifact_kind": "local",
                "source": {"dirty": True},
            }
            compilers = {
                "old": Compiler(
                    label="old",
                    release="base",
                    reported_version="base",
                    git_revision="c" * 40,
                    binary_sha256="d" * 64,
                    executable=root / "old",
                ),
                "new": Compiler(
                    label="new",
                    release="candidate",
                    reported_version="candidate",
                    git_revision="e" * 40,
                    binary_sha256="f" * 64,
                    executable=root / "new",
                ),
            }
            sentinel_result = {
                "strict_pass": True,
                "run_id": "4" * 64,
                "output": str(child),
            }
            with (
                patch(
                    "equiv_checker.candidate.verify_compiler_manifest",
                    side_effect=[base_manifest, candidate_manifest],
                ),
                patch(
                    "equiv_checker.candidate.verify_release_lock",
                    return_value={"valid": True, "release_lock_sha256": "9" * 64},
                ),
                patch(
                    "equiv_checker.candidate.compiler_from_manifest",
                    side_effect=lambda label, _path: compilers[label],
                ),
                patch(
                    "equiv_checker.candidate.load_blaster_config",
                    return_value=fast_config(root),
                ),
                patch(
                    "equiv_checker.candidate.compare_sentinel",
                    return_value=sentinel_result,
                ),
            ):
                decision = run_candidate_gate(
                    base_compiler_manifest=base_path,
                    candidate_compiler_manifest=candidate_path,
                    feature_contract=feature,
                    corpus_lock=corpus,
                    scope={"sentinel"},
                    resume=True,
                    policy="strict",
                    work_root=root / "work",
                    release_lock=release_lock,
                    sentinel_package=root,
                )
            self.assertEqual(decision["decision"], "fail")
            self.assertEqual(
                decision["evidence_suitability"], "development_only"
            )
            self.assertEqual(decision["strict_decision"], "fail")
            self.assertEqual(
                decision["counts"]["complete_equivalent_changed_pairs"], 1
            )
            self.assertEqual(decision["counts"]["shared_language_features"], 1)
            self.assertEqual(decision["mandatory_repository_outcomes"], [])
            self.assertTrue(
                decision["stage_results"]["sentinel"]["strict_pass"]
            )
            output = Path(decision["output"])
            required = {
                "release-decision.json",
                "release-decision.md",
                "program-pairs.json",
                "semantic-obligations.json",
                "obligation-results.json",
                "validator-links.json",
                "feature-links.json",
                "task-results.json",
                "evidence-lineage.json",
                "environment.json",
                "checksums.json",
            }
            self.assertEqual(required, {path.name for path in output.iterdir()})


if __name__ == "__main__":
    unittest.main()
