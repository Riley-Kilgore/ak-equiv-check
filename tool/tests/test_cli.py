from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from equiv_checker.cli import main
from helpers import fast_config, validator, write_fake_compiler, write_package


class CompilerOverrideCliTests(unittest.TestCase):
    def test_compare_accepts_arbitrary_same_version_compiler_paths_and_revisions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = write_package(root)
            old = write_fake_compiler(root / "old-custom", [validator()])
            new = write_fake_compiler(root / "new-custom", [validator()])
            output = io.StringIO()
            config = fast_config(root)
            with (
                patch("equiv_checker.cli.load_blaster_config", return_value=config),
                contextlib.redirect_stdout(output),
            ):
                exit_code = main(
                    [
                        "compare",
                        str(package),
                        "--old-aiken",
                        str(old),
                        "--new-aiken",
                        str(new),
                        "--old-revision",
                        "old-rev",
                        "--new-revision",
                        "new-rev",
                        "--work",
                        str(root / "work"),
                        "--strict",
                    ]
                )
            self.assertEqual(exit_code, 0)
            summary = json.loads(output.getvalue())
            run = json.loads((Path(summary["output"]) / "run.json").read_text())
            self.assertEqual(run["compiler_pair"]["old"]["label"], "old")
            self.assertEqual(run["compiler_pair"]["new"]["label"], "new")
            self.assertEqual(
                run["compiler_pair"]["old"]["reported_version"],
                run["compiler_pair"]["new"]["reported_version"],
            )
            self.assertEqual(run["compiler_pair"]["old"]["git_revision"], "old-rev")
            self.assertEqual(run["compiler_pair"]["new"]["git_revision"], "new-rev")


if __name__ == "__main__":
    unittest.main()
