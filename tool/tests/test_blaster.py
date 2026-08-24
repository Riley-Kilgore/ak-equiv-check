from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from equiv_checker.blaster import (
    classify_evaluator_output,
    extract_witness,
    parse_blaster_output,
    parse_result_protocol,
    parse_witness_protocol,
)
from equiv_checker.config import _installed_aiken
from equiv_checker.process import ProcessResult, run_process
from equiv_checker.evidence import witness_hash

def _marker(
    status: str,
    *,
    program_pair_id: str = "pair",
    theorem_hash: str = "theorem",
) -> str:
    payload = _expected(
        program_pair_id=program_pair_id,
        theorem_hash=theorem_hash,
    ) | {
        "protocol_version": "EQUIV_RESULT_V2",
        "solver_status": status,
    }
    return "EQUIV_RESULT_V2:" + json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    )


def _expected(
    *,
    program_pair_id: str = "pair",
    theorem_hash: str = "theorem",
) -> dict[str, str]:
    return {
        "program_pair_id": program_pair_id,
        "logical_obligation_id": "obligation",
        "semantic_model_id": "model",
        "checker_configuration_id": "checker",
        "old_script_sha256": "1" * 64,
        "new_script_sha256": "2" * 64,
        "verified_abi_id": "abi",
        "obligation_kind": "observational_equivalence",
        "theorem_statement_hash": theorem_hash,
        "generated_source_schema_version": "equiv-generated-lean/v2",
    }


def _witness_marker(**changes) -> str:
    record = {
        "protocol_version": "EQUIV_WITNESS_V2",
        "program_pair_id": "pair",
        "logical_obligation_id": "obligation",
        "theorem_statement_hash": "theorem",
        "semantic_model_id": "model",
        "ordered_argument_list": ["input"],
        "argument_names": ["input"],
        "argument_types": ["Integer"],
        "structured_argument_values": [
            {"kind": "integer", "value": -7}
        ],
        "serialized_uplc_argument_terms": ["(con integer -7)"],
        "domain_satisfaction_evidence": {
            "satisfied": True,
            "predicate": "True",
        },
        "witness_source": "native_machine_protocol",
    }
    record.update(changes)
    record["witness_sha256"] = witness_hash(record)
    return "EQUIV_WITNESS_V2:" + json.dumps(
        record, sort_keys=True, separators=(",", ":")
    )


class BlasterConfigTests(unittest.TestCase):
    def test_repository_toolchain_is_used_without_aikup_installation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            executable = repository / "bin" / "aiken-v1.1.23"
            executable.parent.mkdir()
            executable.write_bytes(b"aiken")
            with (
                patch.dict(os.environ, {"AIKEN_NEW": ""}),
                patch("equiv_checker.config.REPOSITORY_ROOT", repository),
            ):
                self.assertEqual(
                    _installed_aiken("new", "v1.1.23"),
                    executable.resolve(),
                )


class BlasterParsingTests(unittest.TestCase):
    def test_all_solver_verdicts_require_the_exact_protocol(self) -> None:
        self.assertEqual(
            parse_blaster_output(
                _marker("valid"), "", expected=_expected()
            ),
            "blaster_valid",
        )
        self.assertEqual(
            parse_blaster_output(
                _marker("falsified"), "", expected=_expected()
            ),
            "blaster_falsified_unreplayed",
        )
        self.assertEqual(
            parse_blaster_output(
                _marker("inconclusive"), "", expected=_expected()
            ),
            "blaster_inconclusive",
        )
        self.assertEqual(
            parse_blaster_output("", "", timed_out=True), "blaster_timeout"
        )
        self.assertEqual(parse_blaster_output("✅ Valid", ""), "blaster_error")

    def test_protocol_rejects_duplicates_unknown_status_and_wrong_identity(self) -> None:
        with self.assertRaises(ValueError):
            parse_result_protocol(
                _marker("valid") + "\n" + _marker("valid"),
                "",
                exit_code=0,
                expected=_expected(),
            )
        with self.assertRaises(ValueError):
            parse_result_protocol(
                _marker("unknown"),
                "",
                exit_code=0,
                expected=_expected(),
            )
        with self.assertRaises(ValueError):
            parse_result_protocol(
                _marker("valid", program_pair_id="other"),
                "",
                exit_code=0,
                expected=_expected(),
            )

    def test_witness_v2_rejects_binding_structure_and_serialization_tampering(
        self,
    ) -> None:
        expected = _expected() | {
            "ordered_argument_list": ["input"],
            "argument_names": ["input"],
            "argument_types": ["Integer"],
        }
        self.assertIsNotNone(
            parse_witness_protocol(
                _witness_marker(), "", expected=expected
            )
        )
        mutations = (
            {"program_pair_id": "other"},
            {"logical_obligation_id": "other"},
            {"theorem_statement_hash": "other"},
            {"semantic_model_id": "other"},
            {"ordered_argument_list": ["other"]},
            {"argument_names": ["other"]},
            {"argument_types": ["PlutusData"]},
            {"structured_argument_values": [{"kind": "unsupported"}]},
            {"serialized_uplc_argument_terms": ["(con integer 7)"]},
            {
                "domain_satisfaction_evidence": {
                    "satisfied": False,
                    "predicate": "False",
                }
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    parse_witness_protocol(
                        _witness_marker(**mutation),
                        "",
                        expected=expected,
                    )
        with self.assertRaises(ValueError):
            marker = _witness_marker()
            parse_witness_protocol(
                marker + "\n" + marker, "", expected=expected
            )

    def test_integer_witness_is_machine_readable(self) -> None:
        witness = extract_witness("❌ Falsified\nCounterexample:\n - input: -7\n", "")
        self.assertEqual(
            witness,
            {
                "witness_source": "legacy_human_parser",
                "values": {
                    "input": {
                        "kind": "integer",
                        "value": -7,
                        "rendered": "-7",
                    }
                },
                "raw_available": True,
            },
        )

    def test_multiline_lean_data_witness_is_machine_readable(self) -> None:
        witness = extract_witness(
            "Expected Falsified\nCounterexample:\n"
            " - parameter0: (PlutusCore.Data.PlutusCore.DataInternal.Data.B\n"
            '  (PlutusCore.ByteString.PlutusCore.ByteStringInternal.ByteString.mk "!1!"))\n'
            " - script_context_data: (PlutusCore.Data.PlutusCore.DataInternal.Data.I 7)\n"
            "Smt Query:\n",
            "",
        )
        self.assertTrue(witness["raw_available"])
        self.assertEqual(witness["values"]["parameter0"]["hex"], "213121")
        self.assertEqual(
            witness["values"]["script_context_data"]["value"],
            7,
        )

    def test_lean_let_bound_data_witness_is_machine_readable(self) -> None:
        witness = extract_witness(
            "Expected Falsified\nCounterexample:\n"
            " - script_context_data: "
            "(let ((a!1 (PlutusCore.Data.Data.Constr 0 "
            "(List.cons (PlutusCore.Data.Data.B "
            "(PlutusCore.ByteString.ByteString.mk \"!1!\")) "
            "(as List.nil (@List @PlutusCore.Data.Data)))))) "
            "(PlutusCore.Data.Data.Constr 3 "
            "(List.cons (PlutusCore.Data.Data.I 97) "
            "(List.cons a!1 (as List.nil (@List @PlutusCore.Data.Data))))))\n"
            "Smt Query:\n",
            "",
        )
        self.assertTrue(witness["raw_available"])
        context = witness["values"]["script_context_data"]
        self.assertEqual(context["variant"], "constructor")
        self.assertEqual(context["index"], 3)
        self.assertEqual(context["fields"][1]["fields"][0]["hex"], "213121")

    def test_fake_blaster_process_output_is_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process = root / "fake-blaster"
            process.write_text(
                f"#!/usr/bin/env python3\nprint({_marker('inconclusive')!r})\n",
                encoding="utf-8",
            )
            process.chmod(process.stat().st_mode | stat.S_IXUSR)
            result = run_process([process], root, 10)
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(
                parse_blaster_output(
                    result.stdout,
                    result.stderr,
                    expected=_expected(),
                ),
                "blaster_inconclusive",
            )


class EvaluatorOutcomeTests(unittest.TestCase):
    def _classify(
        self,
        *,
        exit_code: int | None,
        stdout: str = "",
        stderr: str = "",
        timed_out: bool = False,
    ) -> dict:
        return classify_evaluator_output(
            ProcessResult(
                command=["evaluator"],
                cwd=".",
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=0.01,
                timed_out=timed_out,
            )
        )

    def test_machine_readable_evaluator_taxonomy(self) -> None:
        success = "Result\n------\n(con data (I 0))\nCosts\n-----\ncpu: 1\nmemory: 2\n"
        failure = "Error\n-----\nEvaluation failure\nCosts\n-----\ncpu: 3\nmemory: 4\n"
        cases = {
            "program_success": self._classify(exit_code=0, stdout=success),
            "program_failure": self._classify(exit_code=1, stderr=failure),
            "budget_exhausted": self._classify(
                exit_code=1, stderr="execution budget exhausted"
            ),
            "decode_error": self._classify(
                exit_code=1, stderr="failed to deserialise program"
            ),
            "argument_error": self._classify(
                exit_code=1, stderr="failed to parse argument"
            ),
            "unsupported_language": self._classify(
                exit_code=1, stderr="unsupported Plutus language version"
            ),
            "cli_error": self._classify(exit_code=1, stderr="usage error"),
            "evaluator_crash": self._classify(exit_code=-6, stderr="abort"),
            "timeout": self._classify(exit_code=None, timed_out=True),
            "invalid_output": self._classify(exit_code=0, stdout="not a result"),
        }
        self.assertEqual({name: row["outcome"] for name, row in cases.items()}, {
            name: name for name in cases
        })
        self.assertTrue(cases["program_success"]["ok"])
        self.assertTrue(cases["program_failure"]["ok"])
        for name in set(cases) - {"program_success", "program_failure"}:
            self.assertFalse(cases[name]["ok"])

    def test_aiken_json_success_is_program_success(self) -> None:
        result = self._classify(
            exit_code=0,
            stdout='{"result":"(con unit ())","cpu":2612242,"mem":9219}\n',
        )
        self.assertEqual(result["outcome"], "program_success")
        self.assertEqual(result["result_value"], "(con unit ())")
        self.assertEqual(result["cost"], {"cpu": 2612242, "memory": 9219})


class ProcessTimeoutTests(unittest.TestCase):
    def test_clean_environment_does_not_inherit_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            secret_name = "EQUIV_TEST_ACCOUNT_CREDENTIAL"
            previous = os.environ.get(secret_name)
            os.environ[secret_name] = "must-not-leak"
            try:
                result = run_process(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import os; "
                            f"print(os.environ.get({secret_name!r}, 'absent')); "
                            "print(bool(os.environ.get('PATH')))"
                        ),
                    ],
                    Path(temporary),
                    10,
                    inherit_environment=False,
                )
            finally:
                if previous is None:
                    os.environ.pop(secret_name, None)
                else:
                    os.environ[secret_name] = previous
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.stdout.splitlines(), ["absent", "True"])

    def test_timeout_kills_the_complete_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "child-finished"
            process = root / "process-tree"
            process.write_text(
                "#!/usr/bin/env python3\n"
                "import subprocess, sys, time\n"
                f"subprocess.Popen([sys.executable, '-c', \"import time; time.sleep(0.6); open({str(marker)!r}, 'w').write('alive')\"])\n"
                "time.sleep(10)\n",
                encoding="utf-8",
            )
            process.chmod(process.stat().st_mode | stat.S_IXUSR)
            result = run_process([process], root, 0.1)
            self.assertTrue(result.timed_out)
            time.sleep(0.8)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
