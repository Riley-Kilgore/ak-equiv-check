from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from equiv_checker.models import ScriptArtifact, ProgramPairRecord
from equiv_checker.semantics import (
    EQUIVALENCE_FORMULA,
    ledger_validator_input_model,
    pure_integer_input_model,
    raw_validator_input_model,
    validator_input_model,
)
from helpers import IDENTITY_HEX


class SemanticContractTests(unittest.TestCase):
    def _pair(
        self,
        root: Path,
        purpose: str = "spending",
        plutus_version: str = "v3",
    ) -> ProgramPairRecord:
        script = root / "script.flat"
        script.write_text(IDENTITY_HEX + "\n", encoding="ascii")
        raw = bytes.fromhex(IDENTITY_HEX)
        artifact = ScriptArtifact(
            path=script,
            relative_path="script.flat",
            sha256=hashlib.sha256(raw).hexdigest(),
            size=len(raw),
        )
        argument_order = ["parameter0", "script_context_data"]
        return ProgramPairRecord(
            program_pair_id="pair",
            old_script=artifact,
            new_script=artifact,
            verified_abi_id="abi",
            verified_abi={
                "status": "verified",
                "top_level_callable_arity": 2,
                "applied_parameter_count": 1,
                "remaining_runtime_argument_count": 1,
                "argument_order": argument_order,
                "argument_value_representation": ["PlutusData"] * 2,
                "parameter_schemas": [
                    {"title": "parameter", "schema": {}}
                ],
                "plutus_version": plutus_version,
            },
            plutus_version=plutus_version,
            handler_pair_ids=("handler",),
            handler_references=(
                {"handler_pair_id": "handler", "purpose": purpose},
            ),
        )

    def test_validator_model_quantifies_every_applicable_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            model = validator_input_model(self._pair(Path(temporary)))
            self.assertEqual(EQUIVALENCE_FORMULA.split(",", 1)[0], "forall raw_arguments")
            self.assertIn("validator_parameters", model.quantified_components)
            self.assertIn("script_context", model.quantified_components)
            self.assertEqual(
                [row["type"] for row in model.variables],
                ["Data", "Data"],
            )
            self.assertEqual(
                model.argument_order,
                ("parameter0", "script_context_data"),
            )
            self.assertEqual(model.domain_expression, "True")
            self.assertEqual(
                model.observation,
                "success_or_failure_or_runtime_bound_exhausted",
            )
            self.assertEqual(
                model.non_vacuity["status"],
                "generated_formal_witness",
            )

    def test_pure_model_observes_value_or_error(self) -> None:
        model = pure_integer_input_model()
        self.assertEqual(
            model.observation,
            "returned_value_or_evaluation_failure_or_unexpected_type_or_runtime_bound_exhausted",
        )
        self.assertEqual(model.quantified_components, ("function_argument",))
        self.assertEqual(model.non_vacuity["status"], "generated_formal_witness")
        self.assertIn("unrestricted", model.domain_assumptions[0].lower())

    def test_v3_models_cover_every_named_purpose(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for purpose in (
                "spending",
                "minting",
                "rewarding",
                "certifying",
                "voting",
                "proposing",
            ):
                with self.subTest(purpose=purpose):
                    pair = self._pair(root, purpose)
                    raw = raw_validator_input_model(pair)
                    ledger = ledger_validator_input_model(pair)
                    self.assertTrue(raw.supported)
                    self.assertEqual(
                        raw.argument_order,
                        ("parameter0", "script_context_data"),
                    )
                    self.assertEqual(raw.domain_expression, "True")
                    self.assertEqual(
                        raw.domain_witness["arguments"][1]["value"],
                        {"kind": "integer", "value": 0},
                    )
                    self.assertTrue(ledger.supported)
                    self.assertIn(
                        f"is{purpose.capitalize()}ScriptInfo",
                        ledger.domain_expression,
                    )
                    self.assertEqual(
                        ledger.non_vacuity["status"],
                        "solver_witness_required",
                    )

    def test_else_handler_is_raw_context_not_spending(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            v3_fallback = self._pair(root, "fallback")
            raw = raw_validator_input_model(v3_fallback)
            ledger = ledger_validator_input_model(v3_fallback)
            self.assertTrue(raw.supported)
            self.assertEqual(
                raw.argument_order,
                ("parameter0", "script_context_data"),
            )
            self.assertNotIn("spending", raw.quantified_components)
            self.assertFalse(ledger.supported)
            self.assertIn("no single ledger purpose", ledger.unsupported_reason)

            v2_fallback = self._pair(root, "fallback", "v2")
            self.assertTrue(raw_validator_input_model(v2_fallback).supported)
            self.assertFalse(ledger_validator_input_model(v2_fallback).supported)


if __name__ == "__main__":
    unittest.main()
