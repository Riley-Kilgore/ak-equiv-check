from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from equiv_checker.config import compiler_pair
from equiv_checker.corpus import run_corpus
from helpers import FakeBackend, fast_config, validator, write_fake_compiler, write_package


class CorpusRunnerTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
