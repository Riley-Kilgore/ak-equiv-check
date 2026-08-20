from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from equiv_checker.models import ScriptArtifact, ScriptPair
from equiv_checker.semantics import (
    EQUIVALENCE_FORMULA,
    pure_integer_input_model,
    validator_input_model,
)
from helpers import IDENTITY_HEX


class SemanticContractTests(unittest.TestCase):
    def _pair(self, root: Path, purpose: str = "spending") -> ScriptPair:
        script = root / "script.flat"
        script.write_text(IDENTITY_HEX + "\n", encoding="ascii")
        raw = bytes.fromhex(IDENTITY_HEX)
        artifact = ScriptArtifact(
            path=script,
            relative_path="script.flat",
            sha256=hashlib.sha256(raw).hexdigest(),
            size=len(raw),
        )
        return ScriptPair(
            pair_id="pair",
            validator_identity={},
            old_script=artifact,
            new_script=artifact,
            purpose=purpose,
            parameters=({"title": "parameter", "schema": {}},),
            plutus_version="v3",
        )

    def test_validator_model_quantifies_every_applicable_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            model = validator_input_model(self._pair(Path(temporary)))
            self.assertEqual(EQUIVALENCE_FORMULA.split(",", 1)[0], "forall modeled_input")
            self.assertIn("validator_parameters", model.quantified_components)
            self.assertIn("datum", model.quantified_components)
            self.assertIn("redeemer", model.quantified_components)
            self.assertIn("script_context", model.quantified_components)
            self.assertIn("validator_purpose", model.quantified_components)
            self.assertEqual(model.variables[-1]["type"], "ScriptContext")
            self.assertEqual(model.domain_expression, "True")
            self.assertEqual(model.observation, "successful_or_unsuccessful")
            self.assertEqual(model.non_vacuity["status"], "checked")

    def test_pure_model_observes_value_or_error(self) -> None:
        model = pure_integer_input_model()
        self.assertEqual(model.observation, "returned_integer_or_error")
        self.assertEqual(model.quantified_components, ("function_argument",))
        self.assertEqual(model.non_vacuity["status"], "checked")
        self.assertIn("unrestricted", model.domain_assumptions[0].lower())


if __name__ == "__main__":
    unittest.main()
