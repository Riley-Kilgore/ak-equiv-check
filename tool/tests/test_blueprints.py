from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from equiv_checker.blueprints import inspect_blueprint, parse_blueprint
from equiv_checker.pairing import discover_validators, pair_validators


FIXTURES = Path(__file__).parent / "fixtures" / "blueprints"


class BlueprintCompatibilityTests(unittest.TestCase):
    def test_release_goldens_preserve_pairing_fields(self) -> None:
        for release in ("v1.1.21", "v1.1.22", "v1.1.23"):
            path = FIXTURES / f"aiken-{release}.json"
            blueprint, compatibility = parse_blueprint(path)
            validators = discover_validators(path)
            self.assertEqual(compatibility["status"], "blueprint_schema_supported")
            self.assertEqual(compatibility["schema_family"], f"aiken-blueprint-{release}")
            self.assertEqual(len(validators), len(blueprint["validators"]))
            for validator in validators:
                source = next(row for row in blueprint["validators"] if row["title"] == validator.title)
                self.assertEqual(validator.compiled_code, source["compiledCode"])
                self.assertEqual(list(validator.parameters), source["parameters"])
                self.assertEqual(
                    validator.signature["datum"],
                    source.get("datum"),
                )
                self.assertEqual(
                    validator.signature["redeemer"]["schema"],
                    source["redeemer"]["schema"],
                )
                self.assertEqual(
                    validator.signature["redeemer"]["title"],
                    source["redeemer"].get("title"),
                )
                self.assertIn(validator.purpose, {"minting", "fallback"})

    def test_current_development_schema_family_is_explicit(self) -> None:
        value = json.loads((FIXTURES / "aiken-v1.1.23.json").read_text())
        value["preamble"]["compiler"]["version"] = "v1.1.24-dev+local"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "development.json"
            path.write_text(json.dumps(value))
            result = inspect_blueprint(path)
        self.assertEqual(result["status"], "blueprint_schema_supported")
        self.assertEqual(result["schema_family"], "aiken-blueprint-development-v1")

    def test_current_schema_allows_omitted_empty_parameters(self) -> None:
        value = json.loads((FIXTURES / "aiken-v1.1.23.json").read_text())
        del value["validators"][0]["parameters"]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "no-parameters.json"
            path.write_text(json.dumps(value))
            compatibility = inspect_blueprint(path)
            validators = discover_validators(path)
        self.assertEqual(compatibility["status"], "blueprint_schema_supported")
        self.assertEqual(validators[0].parameters, ())

    def test_unknown_shape_is_not_silently_accepted(self) -> None:
        value = json.loads((FIXTURES / "aiken-v1.1.23.json").read_text())
        value["futureShape"] = {}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "unsupported.json"
            path.write_text(json.dumps(value))
            result = inspect_blueprint(path)
        self.assertEqual(result["status"], "blueprint_schema_unsupported")

    def test_missing_required_field_has_distinct_state(self) -> None:
        value = json.loads((FIXTURES / "aiken-v1.1.23.json").read_text())
        del value["validators"][0]["redeemer"]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "missing.json"
            path.write_text(json.dumps(value))
            result = inspect_blueprint(path)
        self.assertEqual(result["status"], "blueprint_missing_required_field")

    def test_invalid_compiled_code_has_distinct_state(self) -> None:
        value = json.loads((FIXTURES / "aiken-v1.1.23.json").read_text())
        value["validators"][0]["compiledCode"] = "not-hex"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.json"
            path.write_text(json.dumps(value))
            result = inspect_blueprint(path)
        self.assertEqual(result["status"], "blueprint_compiled_code_invalid")


class CompiledAbiTests(unittest.TestCase):
    def _inspection(self, path: Path, arity: int = 2) -> dict:
        return {
            "validators": [
                {
                    "title": validator.title,
                    "top_level_callable_arity": arity,
                    "abi_derivation_method": "decoded_uplc_top_level_lambda_spine",
                    "abi_verifier_revision": "aiken-equiv-shim/v2",
                }
                for validator in discover_validators(path)
            ]
        }

    def test_compiled_abi_is_verified_and_recorded(self) -> None:
        path = FIXTURES / "aiken-v1.1.22.json"
        with tempfile.TemporaryDirectory() as temporary:
            result = pair_validators(
                path,
                path,
                Path(temporary),
                package_identity="fixture",
                package_path=".",
                plutus_version="v3",
                old_abi_inspection=self._inspection(path),
                new_abi_inspection=self._inspection(path),
            )
        self.assertTrue(result.program_pairs)
        for pair in result.program_pairs:
            self.assertEqual(pair.verified_abi["status"], "verified")
            self.assertEqual(
                pair.verified_abi["top_level_callable_arity"], 2
            )
            self.assertEqual(
                pair.verified_abi["remaining_runtime_argument_count"], 1
            )
            self.assertEqual(
                pair.verified_abi["argument_order"][-1],
                "script_context_data",
            )

    def test_compiled_abi_mismatch_fails_before_semantics(self) -> None:
        path = FIXTURES / "aiken-v1.1.22.json"
        with tempfile.TemporaryDirectory() as temporary:
            result = pair_validators(
                path,
                path,
                Path(temporary),
                package_identity="fixture",
                package_path=".",
                plutus_version="v3",
                old_abi_inspection=self._inspection(path, 2),
                new_abi_inspection=self._inspection(path, 3),
            )
        self.assertFalse(result.program_pairs)
        self.assertEqual(
            {row["status"] for row in result.compatibility_results},
            {"raw_abi_mismatch"},
        )


if __name__ == "__main__":
    unittest.main()
