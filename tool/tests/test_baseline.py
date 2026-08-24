from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from equiv_checker.baseline import baseline_content_id, verify_baseline


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_ndjson(path: Path, records: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in records),
        encoding="utf-8",
    )


ROOT = Path(__file__).resolve().parents[2]


class BaselineVerificationTests(unittest.TestCase):
    def _baseline(self, root: Path) -> None:
        pair_id = "1" * 64
        obligation_id = "2" * 64
        evidence_id = "3" * 64
        _write_ndjson(
            root / "handler-pairs.ndjson",
            [
                {
                    "handler_pair_id": "handler",
                    "program_pair_id": pair_id,
                    "feature_ids": ["feature"],
                }
            ],
        )
        _write_ndjson(
            root / "program-pairs.ndjson",
            [
                {
                    "program_pair_id": pair_id,
                    "handler_pair_ids": ["handler"],
                    "covered_feature_ids": ["feature"],
                }
            ],
        )
        _write_ndjson(
            root / "semantic-obligations.ndjson",
            [
                {
                    "logical_obligation_id": obligation_id,
                    "program_pair_id": pair_id,
                }
            ],
        )
        _write_ndjson(
            root / "obligation-results.ndjson",
            [
                {
                    "logical_obligation_id": obligation_id,
                    "evidence_result_id": evidence_id,
                }
            ],
        )
        _write_ndjson(
            root / "evidence-lineage.ndjson",
            [{"evidence_result_id": evidence_id}],
        )
        _write_ndjson(
            root / "validator-links.ndjson",
            [
                {
                    "handler_pair_id": "handler",
                    "program_pair_id": pair_id,
                    "logical_obligation_ids": [obligation_id],
                    "evidence_result_ids": [evidence_id],
                    "feature_ids": ["feature"],
                }
            ],
        )
        _write_ndjson(
            root / "feature-links.ndjson",
            [
                {
                    "feature_id": "feature",
                    "handler_pair_ids": ["handler"],
                    "program_pair_ids": [pair_id],
                    "semantic_obligation_ids": [obligation_id],
                    "required_evidence": [evidence_id],
                    "authoritative_evidence": [evidence_id],
                    "all_linked_evidence": [evidence_id],
                }
            ],
        )
        _write_ndjson(root / "task-results.ndjson", [{"task": "build"}])
        _write_json(root / "compiler-lock.json", {"schema_version": 2})
        _write_json(root / "source-lock.json", {"schema_version": 2})
        _write_json(root / "environment.json", {"schema_version": 2})
        _write_json(
            root / "summary.json",
            {
                "schema_version": 2,
                "profile": {"profile_id": "profile"},
                "source_provenance": {"dirty": False},
                "counts": {
                    "handler_pairs": 1,
                    "handler_pair_records": 1,
                    "unique_program_pairs": 1,
                    "program_pair_records": 1,
                    "program_state_total": 1,
                    "semantic_obligation_records": 1,
                    "obligation_result_records": 1,
                    "obligation_state_total": 1,
                    "validator_handlers": 1,
                    "validator_link_records": 1,
                    "feature_rows": 1,
                    "feature_link_records": 1,
                },
                "count_invariants": {
                    "obligation_final_states_equal_unique_obligations": True,
                    "program_final_states_equal_unique_program_pairs": True,
                },
            },
        )
        (root / "summary.md").write_text("# Baseline\n", encoding="utf-8")
        checksums = {
            child.name: hashlib.sha256(child.read_bytes()).hexdigest()
            for child in root.iterdir()
            if child.is_file()
        }
        content_id = baseline_content_id(checksums)
        _write_json(
            root / "checksums.json",
            {
                "schema_version": 2,
                "algorithm": "sha256",
                "baseline_content_id": content_id,
                "files": checksums,
            },
        )
        _write_json(
            root / "ci-attestation.json",
            {
                "schema_version": 2,
                "attestation_kind": "public_ci_reproduction",
                "profile_id": "profile",
                "baseline_content_id": content_id,
                "repository_commit": "4" * 40,
                "workflow_revision": "5" * 40,
                "github_run_id": 1,
                "job_id": 2,
                "artifact_id": 3,
                "artifact_sha256": "6" * 64,
                "platform": "ubuntu-24.04",
                "capture_command": "capture",
                "verification_result": "verified",
            },
        )

    def _rebind(self, root: Path) -> None:
        previous = json.loads(
            (root / "checksums.json").read_text(encoding="utf-8")
        )
        checksums = {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in previous["files"]
        }
        content_id = baseline_content_id(checksums)
        _write_json(
            root / "checksums.json",
            {
                "schema_version": 2,
                "algorithm": "sha256",
                "baseline_content_id": content_id,
                "files": checksums,
            },
        )
        attestation = json.loads(
            (root / "ci-attestation.json").read_text(encoding="utf-8")
        )
        attestation["baseline_content_id"] = content_id
        _write_json(root / "ci-attestation.json", attestation)

    def test_capture_and_verifier_share_content_identity(self) -> None:
        script = ROOT / "scripts" / "capture_historical_baseline.py"
        specification = importlib.util.spec_from_file_location(
            "capture_historical_baseline", script
        )
        assert specification is not None and specification.loader is not None
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        checksums = {"summary.json": "1" * 64}
        self.assertEqual(
            module._identity(
                "baseline-content",
                {
                    "schema_version": 2,
                    "algorithm": "sha256",
                    "files": checksums,
                },
            ),
            baseline_content_id(checksums),
        )

    def test_complete_baseline_and_attestation_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._baseline(root)
            result = verify_baseline(root)
            self.assertTrue(result["valid"])
            self.assertEqual(result["counts"]["semantic_obligations"], 1)

    def test_tampered_content_and_attestation_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._baseline(root)
            (root / "summary.md").write_text("tampered\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                verify_baseline(root)
            self._baseline(root)
            attestation = json.loads(
                (root / "ci-attestation.json").read_text(encoding="utf-8")
            )
            attestation["baseline_content_id"] = "0" * 64
            _write_json(root / "ci-attestation.json", attestation)
            with self.assertRaises(ValueError):
                verify_baseline(root)

    def test_ci_attestation_identity_fields_are_strictly_validated(self) -> None:
        cases = (
            ("profile_id", "other", "profile identity"),
            ("repository_commit", "not-a-commit", "repository_commit"),
            ("job_id", 0, "job_id"),
            ("artifact_sha256", "z" * 64, "artifact SHA-256"),
        )
        for field, value, message in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self._baseline(root)
                attestation = json.loads(
                    (root / "ci-attestation.json").read_text(encoding="utf-8")
                )
                attestation[field] = value
                _write_json(root / "ci-attestation.json", attestation)
                with self.assertRaisesRegex(ValueError, message):
                    verify_baseline(root)


    def test_tampered_evidence_links_are_rejected_after_rebinding(self) -> None:
        cases = (
            (
                "feature-links.ndjson",
                "program_pair_ids",
                ["9" * 64],
                "invalid program_pair_ids",
            ),
            (
                "feature-links.ndjson",
                "required_evidence",
                [],
                "missing authoritative evidence",
            ),
            (
                "validator-links.ndjson",
                "evidence_result_ids",
                [],
                "wrong parent",
            ),
            (
                "program-pairs.ndjson",
                "handler_pair_ids",
                [],
                "handler links are incomplete",
            ),
            (
                "handler-pairs.ndjson",
                "feature_ids",
                [],
                "feature links are incomplete",
            ),
        )
        for filename, field, value, message in cases:
            with self.subTest(
                filename=filename,
                field=field,
            ), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self._baseline(root)
                records = [
                    json.loads(line)
                    for line in (root / filename).read_text().splitlines()
                    if line
                ]
                records[0][field] = value
                _write_ndjson(root / filename, records)
                self._rebind(root)
                with self.assertRaisesRegex(ValueError, message):
                    verify_baseline(root)


    def test_tampered_report_counts_are_rejected_after_rebinding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._baseline(root)
            summary = json.loads(
                (root / "summary.json").read_text(encoding="utf-8")
            )
            summary["counts"]["unique_program_pairs"] = 2
            _write_json(root / "summary.json", summary)
            self._rebind(root)
            with self.assertRaisesRegex(ValueError, "count mismatch"):
                verify_baseline(root)


if __name__ == "__main__":
    unittest.main()
