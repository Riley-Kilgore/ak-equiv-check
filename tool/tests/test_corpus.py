from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from equiv_checker.config import Compiler, compiler_pair
from equiv_checker.corpus import (
    _equivalence_lane,
    _expanded_targets,
    _materialize_dependency_lock,
    load_corpus_lock,
    run_corpus,
)
from helpers import FakeBackend, fast_config, validator, write_fake_compiler, write_package


class CorpusRunnerTests(unittest.TestCase):
    def test_checked_in_mandatory_lock_has_thirteen_full_sha_sources(self) -> None:
        lock_path = (
            Path(__file__).resolve().parents[2]
            / "corpus"
            / "aiken_mandatory_corpus.lock.json"
        )
        lock = load_corpus_lock(lock_path)
        self.assertEqual(lock["schema_version"], 2)
        self.assertEqual(len(lock["sources"]), 13)
        for source in lock["sources"]:
            revision = source["revision"]
            self.assertEqual(len(revision), 40)
            int(revision, 16)
            self.assertTrue(source["targets"])

    def test_locked_local_corpus_runs_generic_package_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root)
            manifest = root / "corpus-lock.json"
            manifest.write_text(
                json.dumps(
                    {
                        "packages": [
                            {
                                "id": "LOCAL",
                                "path": str(package),
                                "revision": "locked-local-source",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            old = write_fake_compiler(root / "old-aiken", [validator()])
            new = write_fake_compiler(root / "new-aiken", [validator()])
            compilers = compiler_pair(old_aiken=old, new_aiken=new)
            config = fast_config(root)
            report = run_corpus(
                manifest,
                compilers,
                work_root=root / "work",
                strict=True,
                blaster_config=config,
                backend=FakeBackend(config, "blaster_error"),
            )
            self.assertTrue(report["strict_pass"])
            self.assertEqual(report["completed_count"], 1)
            self.assertEqual(report["results"][0]["status"], "completed")

    def test_lock_rejects_duplicate_targets_and_invalid_diagnostic_lane(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = {
                "schema_version": 2,
                "compiler_baseline": {"old": "v1.1.22", "new": "v1.1.23"},
                "sources": [
                    {
                        "id": "SOURCE_A",
                        "url": "https://example.invalid/a",
                        "revision": "a" * 40,
                        "targets": [
                            {
                                "id": "DUPLICATE",
                                "package_subpath": ".",
                                "lanes": ["compile"],
                                "adapter": None,
                                "source_type": "root-package",
                            }
                        ],
                    },
                    {
                        "id": "SOURCE_B",
                        "url": "https://example.invalid/b",
                        "revision": "b" * 40,
                        "targets": [
                            {
                                "id": "DUPLICATE",
                                "package_subpath": ".",
                                "lanes": ["negative-diagnostic"],
                                "adapter": None,
                                "source_type": "root-package",
                            }
                        ],
                    },
                ],
            }
            path = root / "lock.json"
            path.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate target id"):
                load_corpus_lock(path)
            lock["sources"][1]["targets"][0]["id"] = "NEGATIVE"
            path.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError,
                "negative-diagnostic without expected_outcome=diagnostic",
            ):
                load_corpus_lock(path)

    def test_target_expansion_classifies_missing_and_ambiguous_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            for nested in ("one", "two"):
                package = checkout / "missing" / nested
                package.mkdir(parents=True)
                (package / "aiken.toml").write_text(
                    'name = "test/package"\n',
                    encoding="utf-8",
                )
            source = {
                "id": "SOURCE",
                "targets": [
                    {
                        "id": "AMBIGUOUS",
                        "package_subpath": "missing",
                        "lanes": ["compile"],
                        "adapter": None,
                        "source_type": "multi-package",
                    },
                    {
                        "id": "ABSENT",
                        "package_subpath": "absent",
                        "lanes": ["compile"],
                        "adapter": None,
                        "source_type": "nested-package",
                    },
                ],
            }
            expanded, errors = _expanded_targets(source, checkout)
            self.assertEqual(expanded, [])
            self.assertEqual(
                {
                    (row["target_id"], row["classification"])
                    for row in errors
                },
                {
                    ("AMBIGUOUS", "ambiguous_package_discovery"),
                    ("ABSENT", "missing_package_path"),
                },
            )

    def test_missing_dependency_lock_is_materialized_before_comparison(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root, with_lock=False)
            executable = root / "aiken"
            executable.write_text(
                "#!/bin/sh\n"
                "printf 'packages = []\\n' > aiken.lock\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            compiler = Compiler(
                label="old",
                release="test",
                reported_version="test",
                git_revision="1" * 40,
                binary_sha256="2" * 64,
                executable=executable,
            )
            record = _materialize_dependency_lock(
                package,
                compiler,
                root / "task",
                10,
            )
            self.assertEqual(record["status"], "materialized")
            self.assertTrue((package / "aiken.lock").is_file())
            self.assertEqual(
                record["dependency_lock_sha256"],
                hashlib.sha256(
                    (package / "aiken.lock").read_bytes()
                ).hexdigest(),
            )
            self.assertFalse((package / "build").exists())

    def test_optional_equivalence_without_compiled_validators_is_not_applicable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root)
            (package / "validators" / "empty.ak").write_text(
                "validator empty { }\n", encoding="utf-8"
            )
            output = root / "run"
            output.mkdir()
            _write = lambda name, value: (output / name).write_text(
                json.dumps(value), encoding="utf-8"
            )
            build = {
                "primary_exit_code": 0,
            }
            _write("build-old.json", build)
            _write("build-new.json", build)
            _write(
                "pair-results.json",
                {"schema_version": 2, "record_count": 0, "records": []},
            )
            summary = {
                "output": str(output),
                "gaps": [],
                "counts": {
                    "validator_records_old": 0,
                    "validator_records_new": 0,
                },
            }
            compiler = Compiler(
                label="old",
                release="test",
                reported_version="test",
                git_revision="1" * 40,
                binary_sha256="2" * 64,
                executable=root / "aiken",
            )
            with patch(
                "equiv_checker.corpus.compare_package",
                return_value=summary,
            ):
                result = _equivalence_lane(
                    {
                        "equivalence_required": False,
                    },
                    package,
                    (compiler, compiler),
                    root / "work",
                    True,
                    fast_config(root),
                    None,
                    False,
                    False,
                    None,
                    {},
                )
            self.assertEqual(result["classification"], "not_applicable")
            self.assertTrue(result["strict_pass"])


if __name__ == "__main__":
    unittest.main()
