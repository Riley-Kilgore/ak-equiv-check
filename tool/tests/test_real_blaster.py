from __future__ import annotations

import hashlib
from dataclasses import replace
import tempfile
import unittest
from pathlib import Path

from equiv_checker.blaster import RealBlasterBackend
from equiv_checker.config import load_blaster_config
from equiv_checker.models import STRICT_PASSING_STATUSES, ScriptArtifact, ScriptPair
from equiv_checker.semantics import pure_integer_input_model, validator_input_model


FIXTURES = Path(__file__).parent / "fixtures" / "uplc"


def _artifact(name: str) -> ScriptArtifact:
    path = (FIXTURES / name).resolve()
    raw = bytes.fromhex(path.read_text(encoding="ascii").strip())
    return ScriptArtifact(
        path=path,
        relative_path=f"fixtures/uplc/{name}",
        sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
    )


def _pair(pair_id: str, old: str, new: str) -> ScriptPair:
    return ScriptPair(
        pair_id=pair_id,
        validator_identity={"blueprint_title": f"golden.{pair_id}"},
        old_script=_artifact(old),
        new_script=_artifact(new),
        purpose="pure",
        parameters=(),
        plutus_version="v3",
    )


def _validator_pair(pair_id: str, old: str, new: str) -> ScriptPair:
    return ScriptPair(
        pair_id=pair_id,
        validator_identity={"blueprint_title": f"golden.{pair_id}.spend"},
        old_script=_artifact(old),
        new_script=_artifact(new),
        purpose="spending",
        parameters=({"title": "parameter", "schema": {}},),
        plutus_version="v3",
    )


class RealBlasterGoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.backend = RealBlasterBackend(load_blaster_config())

    def _output(self, root: Path) -> Path:
        for name in ("logs", "generated-lean", "counterexamples"):
            (root / name).mkdir(parents=True, exist_ok=True)
        return root

    def test_byte_identical_fixture_has_the_same_canonical_hash(self) -> None:
        pair = _pair("identical", "identity.flat", "identity.flat")
        self.assertEqual(pair.old_script.sha256, pair.new_script.sha256)

    def test_structurally_different_programs_are_blaster_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = self._output(Path(temporary))
            pair = _pair("equivalent", "identity.flat", "beta-identity.flat")
            self.assertNotEqual(pair.old_script.sha256, pair.new_script.sha256)
            result = self.backend.compare(pair, pure_integer_input_model(), output)
            self.assertEqual(result.status, "blaster_valid")
            self.assertEqual(result.exit_code, 0)
            self.assertTrue((output / result.generated_lean_path).is_file())

    def test_parameterized_validator_is_blaster_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = self._output(Path(temporary))
            pair = _validator_pair(
                "parameterized-validator",
                "validator-success.flat",
                "validator-success-beta.flat",
            )
            model = validator_input_model(pair)
            self.assertIn("validator_parameters", model.quantified_components)
            self.assertIn("script_context", model.quantified_components)
            result = self.backend.compare(pair, model, output)
            self.assertEqual(result.status, "blaster_valid")
            self.assertEqual(result.exit_code, 0)

    def test_noninteger_return_is_distinct_from_evaluation_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = self._output(Path(temporary))
            pair = _pair("result-kind", "return-unit.flat", "return-error.flat")
            result = self.backend.compare(pair, pure_integer_input_model(), output)
            self.assertEqual(result.status, "blaster_falsified_unreplayed")

    def test_preparation_fuel_exhaustion_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = self._output(Path(temporary))
            backend = RealBlasterBackend(replace(load_blaster_config(), fuel=20))
            result = backend.compare(
                _pair("fuel-exhaustion", "loop.flat", "identity.flat"),
                pure_integer_input_model(),
                output,
            )
            self.assertEqual(result.status, "blaster_inconclusive")
            self.assertIn("fuel", result.error or "")

    def test_falsification_is_replayed_by_the_actual_cek_evaluator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = self._output(Path(temporary))
            pair = _pair("non-equivalent", "identity.flat", "constant-zero.flat")
            result = self.backend.compare(pair, pure_integer_input_model(), output)
            self.assertEqual(result.status, "blaster_falsified_unreplayed")
            self.assertIsNotNone(result.witness)
            self.assertIsNotNone(result.solver_input_path)
            replay = self.backend.replay(
                pair, pure_integer_input_model(), result.witness, output
            )
            self.assertTrue(replay["confirmed"])
            self.assertNotEqual(replay["old_observation"], replay["new_observation"])
            self.assertTrue((output / replay["artifact_path"]).is_file())
            self.assertNotIn("confirmed_non_equivalent", STRICT_PASSING_STATUSES)


if __name__ == "__main__":
    unittest.main()
