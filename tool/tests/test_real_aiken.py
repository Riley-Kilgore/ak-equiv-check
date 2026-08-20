from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from equiv_checker.config import compiler_pair, load_blaster_config
from equiv_checker.pairing import discover_validators
from equiv_checker.runner import compare_package


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which("aiken"), "aiken executable is required")
class RealAikenGoldenTests(unittest.TestCase):
    def test_parameterized_manifest_free_package_uses_generic_path(self) -> None:
        executable = Path(shutil.which("aiken") or "")
        compilers = compiler_pair(
            old_aiken=executable,
            new_aiken=executable,
            old_revision="real-golden",
            new_revision="real-golden",
        )
        package = Path(__file__).parent / "fixtures" / "aiken-package"
        with tempfile.TemporaryDirectory() as temporary:
            summary = compare_package(
                package,
                compilers,
                work_root=Path(temporary),
                strict=True,
                blaster_config=load_blaster_config(),
            )
            self.assertTrue(summary["strict_pass"])
            self.assertEqual(summary["counts"]["validators_paired"], 2)
            pairs = json.loads(
                (Path(summary["output"]) / "script-pairs.json").read_text()
            )["records"]
            parameterized = [row for row in pairs if row["parameters"]]
            self.assertEqual(len(parameterized), 2)
            self.assertIn("minting", {row["purpose"] for row in parameterized})

    def test_checked_sentinel_blueprint_contains_real_spending_purpose(self) -> None:
        validators = discover_validators(REPOSITORY_ROOT / "sentinel" / "plutus.json")
        self.assertIn("spending", {validator.purpose for validator in validators})


if __name__ == "__main__":
    unittest.main()
