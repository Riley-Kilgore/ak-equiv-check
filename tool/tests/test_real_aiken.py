from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from equiv_checker.config import compiler_pair, load_blaster_config
from equiv_checker.pairing import discover_validators
from equiv_checker.runner import compare_package


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class RealAikenGoldenTests(unittest.TestCase):
    def test_distinct_pinned_compilers_build_and_pair_same_package(self) -> None:
        compilers = compiler_pair()
        package = Path(__file__).parent / "fixtures" / "aiken-package"
        with tempfile.TemporaryDirectory() as temporary:
            summary = compare_package(
                package,
                compilers,
                work_root=Path(temporary),
                strict=True,
                blaster_config=load_blaster_config(
                    evaluator_executable=compilers[1].executable
                ),
            )
            self.assertTrue(summary["strict_pass"])
            self.assertEqual(summary["counts"]["handler_pairs"], 2)
            pairs = json.loads(
                (Path(summary["output"]) / "program-pairs.json").read_text()
            )["records"]
            parameterized = [
                row
                for row in pairs
                if row["verified_abi"]["parameter_schemas"]
            ]
            self.assertTrue(parameterized)
            links = json.loads(
                (Path(summary["output"]) / "validator-links.json").read_text()
            )["records"]
            self.assertIn("minting", {row["purpose"] for row in links})

    def test_checked_sentinel_blueprint_contains_real_spending_purpose(self) -> None:
        validators = discover_validators(REPOSITORY_ROOT / "sentinel" / "plutus.json")
        self.assertIn("spending", {validator.purpose for validator in validators})


if __name__ == "__main__":
    unittest.main()
