from __future__ import annotations

import hashlib
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


class BaselineVerificationTests(unittest.TestCase):
    def _baseline(self, root: Path) -> None:
        pair_id = "1" * 64
        obligation_id = "2" * 64
        evidence_id = "3" * 64
        _write_ndjson(
            root / "handler-pairs.ndjson",
            [{"handler_pair_id": "handler", "program_pair_id": pair_id}],
        )
        _write_ndjson(
            root / "program-pairs.ndjson",
            [{"program_pair_id": pair_id}],
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
        _write_json(root / "compiler-lock.json", {"schema_version": 2})
        _write_json(root / "source-lock.json", {"schema_version": 2})
        _write_json(root / "environment.json", {"schema_version": 2})
        _write_json(
            root / "summary.json",
            {
                "schema_version": 2,
                "profile": {"profile_id": "profile"},
                "source_provenance": {"dirty": False},
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


if __name__ == "__main__":
    unittest.main()
