from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from equiv_checker.pairing import discover_validators, pair_validators
from equiv_checker.semantics import validator_input_models
from helpers import IDENTITY_HEX, validator


class ValidatorPairingTests(unittest.TestCase):
    def _blueprint(self, path: Path, validators: list[dict]) -> Path:
        path.write_text(
            json.dumps(
                {
                    "preamble": {
                        "title": "test/package",
                        "description": "Test package",
                        "version": "0.0.0",
                        "license": "Apache-2.0",
                        "compiler": {"name": "Aiken", "version": "v1.1.23"},
                        "plutusVersion": "v3",
                    },
                    "validators": validators,
                    "definitions": {},
                }
            ),
            encoding="utf-8",
        )
        return path

    def _pair(
        self,
        old: Path,
        new: Path,
        bundle: Path,
        **kwargs: object,
    ):
        def inspection(path: Path) -> dict:
            rows = json.loads(path.read_text(encoding="utf-8"))["validators"]
            return {
                "validators": [
                    {
                        "title": row["title"],
                        "top_level_callable_arity": len(
                            row.get("parameters", [])
                        )
                        + 1,
                        "abi_derivation_method": "test_fixture",
                        "abi_verifier_revision": "test",
                    }
                    for row in rows
                ]
            }

        return pair_validators(
            old,
            new,
            bundle,
            old_abi_inspection=inspection(old),
            new_abi_inspection=inspection(new),
            **kwargs,
        )

    def test_pairing_is_stable_and_independent_of_array_position(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = validator("alpha.first.mint")
            second = validator("beta.second.spend")
            old = self._blueprint(root / "old.json", [first, second])
            new = self._blueprint(root / "new.json", [second, first])
            result = self._pair(
                old,
                new,
                root / "bundle-a",
                package_identity="repo@commit:package",
                package_path="/package",
                plutus_version="v3",
            )
            repeated = self._pair(
                old,
                new,
                root / "bundle-b",
                package_identity="repo@commit:package",
                package_path="/package",
                plutus_version="v3",
            )
            self.assertEqual(
                [pair.program_pair_id for pair in result.program_pairs],
                [pair.program_pair_id for pair in repeated.program_pairs],
            )
            self.assertEqual(len(result.program_pairs), 1)
            self.assertEqual(len(result.handler_pairs), 2)
            self.assertEqual(result.compatibility_results, ())

    def test_duplicate_features_share_one_script_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = validator()
            old = self._blueprint(root / "old.json", [row])
            new = self._blueprint(root / "new.json", [row])
            result = self._pair(
                old,
                new,
                root / "bundle",
                package_identity="source",
                package_path="/package",
                plutus_version="v3",
                covered_features_by_title={row["title"]: {"FEATURE-A", "FEATURE-B", "FEATURE-A"}},
            )
            self.assertEqual(len(result.program_pairs), 1)
            self.assertEqual(
                result.program_pairs[0].covered_feature_ids,
                ("FEATURE-A", "FEATURE-B"),
            )

    def test_missing_and_changed_validators_are_compatibility_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unchanged = validator("module.unchanged.mint")
            old_only = validator("module.old_only.mint")
            new_only = validator("module.new_only.mint")
            old_changed = validator(
                "module.changed.mint",
                parameters=[{"title": "p", "schema": {"type": "integer"}}],
            )
            new_changed = validator(
                "module.changed.mint",
                parameters=[{"title": "p", "schema": {"type": "bytes"}}],
            )
            old = self._blueprint(root / "old.json", [unchanged, old_only, old_changed])
            new = self._blueprint(root / "new.json", [unchanged, new_only, new_changed])
            result = self._pair(
                old,
                new,
                root / "bundle",
                package_identity="source",
                package_path="/package",
                plutus_version="v3",
            )
            self.assertEqual(len(result.program_pairs), 1)
            self.assertEqual(
                {row["status"] for row in result.compatibility_results},
                {
                    "validator_missing_old",
                    "validator_missing_new",
                    "validator_signature_changed",
                },
            )

    def test_script_hash_uses_canonical_serialized_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = validator(compiled_code=IDENTITY_HEX.upper())
            old = self._blueprint(root / "old.json", [row])
            new = self._blueprint(root / "new.json", [row])
            result = self._pair(
                old,
                new,
                root / "bundle",
                package_identity="source",
                package_path="/package",
                plutus_version="v3",
            )
            expected = hashlib.sha256(bytes.fromhex(IDENTITY_HEX)).hexdigest()
            self.assertEqual(result.program_pairs[0].old_script.sha256, expected)
            self.assertEqual(result.program_pairs[0].new_script.sha256, expected)

    def test_mint_and_else_handlers_share_raw_pair_but_not_ledger_models(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = [
                validator("module.multi.mint"),
                validator("module.multi.else"),
            ]
            old = self._blueprint(root / "old.json", rows)
            new = self._blueprint(root / "new.json", rows)
            result = self._pair(
                old,
                new,
                root / "bundle",
                package_identity="source",
                package_path="/package",
                plutus_version="v3",
            )
            self.assertEqual(len(result.handler_pairs), 2)
            self.assertEqual(len(result.program_pairs), 1)
            raw, ledger = validator_input_models(result.program_pairs[0])
            self.assertTrue(raw.supported)
            self.assertEqual(
                {model.purpose for model in ledger},
                {"minting", "fallback"},
            )
            self.assertEqual(len({model.semantic_model_id(100) for model in ledger}), 2)

    def test_missing_partial_and_parser_error_abis_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = validator()
            old = self._blueprint(root / "old.json", [row])
            new = self._blueprint(root / "new.json", [row])
            missing = pair_validators(
                old,
                new,
                root / "missing",
                package_identity="source",
                package_path="/package",
                plutus_version="v3",
            )
            self.assertFalse(missing.program_pairs)
            self.assertEqual(
                {item["status"] for item in missing.compatibility_results},
                {"old_raw_abi_unresolved"},
            )
            partial = pair_validators(
                old,
                new,
                root / "partial",
                package_identity="source",
                package_path="/package",
                plutus_version="v3",
                old_abi_inspection={
                    "validators": [
                        {
                            "title": row["title"],
                            "top_level_callable_arity": None,
                        }
                    ]
                },
                new_abi_inspection={
                    "validators": [
                        {
                            "title": row["title"],
                            "top_level_callable_arity": 1,
                        }
                    ]
                },
            )
            self.assertEqual(
                {item["status"] for item in partial.compatibility_results},
                {"old_raw_abi_unresolved"},
            )
            parser_error = pair_validators(
                old,
                new,
                root / "parser-error",
                package_identity="source",
                package_path="/package",
                plutus_version="v3",
                old_abi_parser_error="malformed UPLC",
                new_abi_parser_error="malformed UPLC",
            )
            self.assertEqual(
                {
                    item["status"]
                    for item in parser_error.compatibility_results
                },
                {"raw_abi_parser_error"},
            )

    def test_unverified_abi_is_heuristic_diagnostics_only_in_best_effort(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = validator()
            old = self._blueprint(root / "old.json", [row])
            new = self._blueprint(root / "new.json", [row])
            result = pair_validators(
                old,
                new,
                root / "bundle",
                package_identity="source",
                package_path="/package",
                plutus_version="v3",
                require_verified_abi=False,
            )
            self.assertEqual(result.program_pairs, ())
            self.assertEqual(
                {item["status"] for item in result.compatibility_results},
                {"raw_abi_heuristic"},
            )
            diagnostic = result.compatibility_results[0]
            self.assertFalse(diagnostic["old_abi"]["verified"])
            self.assertEqual(
                diagnostic["old_abi"]["abi_derivation_method"],
                "blueprint_signature_heuristic",
            )

    def test_zero_argument_program_has_a_verified_empty_abi(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = validator()
            old = self._blueprint(root / "old.json", [row])
            new = self._blueprint(root / "new.json", [row])
            inspection = {
                "validators": [
                    {
                        "title": row["title"],
                        "top_level_callable_arity": 0,
                        "abi_derivation_method": "test_fixture",
                        "abi_verifier_revision": "test",
                    }
                ]
            }
            result = pair_validators(
                old,
                new,
                root / "bundle",
                package_identity="source",
                package_path="/package",
                plutus_version="v3",
                old_abi_inspection=inspection,
                new_abi_inspection=inspection,
            )
            self.assertEqual(len(result.program_pairs), 1)
            abi = result.program_pairs[0].verified_abi
            self.assertEqual(abi["top_level_callable_arity"], 0)
            self.assertEqual(abi["argument_order"], [])


    def test_named_handlers_and_else_keep_distinct_purposes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = [
                validator("module.multi.spend"),
                validator("module.multi.mint"),
                validator("module.multi.withdraw"),
                validator("module.multi.publish"),
                validator("module.multi.vote"),
                validator("module.multi.propose"),
                validator("module.multi.else"),
            ]
            blueprint = self._blueprint(root / "plutus.json", rows)
            discovered = discover_validators(blueprint)
            self.assertEqual(
                {row.purpose for row in discovered},
                {
                    "spending",
                    "minting",
                    "rewarding",
                    "certifying",
                    "voting",
                    "proposing",
                    "fallback",
                },
            )
            self.assertEqual(
                sum(row.purpose == "fallback" for row in discovered),
                1,
            )


if __name__ == "__main__":
    unittest.main()
