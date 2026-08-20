from __future__ import annotations

import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

from equiv_checker.blaster import (
    extract_witness,
    parse_blaster_output,
    parse_result_protocol,
)
from equiv_checker.process import run_process

def _marker(status: str, *, pair_id: str = "pair", theorem_hash: str = "theorem") -> str:
    return (
        "EQUIV_RESULT_V1:"
        f'{{"kind":"equivalence","pair_id":"{pair_id}","profile":"raw-uplc/v1",'
        f'"status":"{status}","theorem_hash":"{theorem_hash}"}}'
    )


class BlasterParsingTests(unittest.TestCase):
    def test_all_solver_verdicts_require_the_exact_protocol(self) -> None:
        self.assertEqual(parse_blaster_output(_marker("valid"), ""), "blaster_valid")
        self.assertEqual(
            parse_blaster_output(_marker("falsified"), ""),
            "blaster_falsified_unreplayed",
        )
        self.assertEqual(
            parse_blaster_output(_marker("inconclusive"), ""),
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
                expected_pair_id="pair",
                expected_theorem_hash="theorem",
            )
        with self.assertRaises(ValueError):
            parse_result_protocol(
                _marker("unknown"),
                "",
                exit_code=0,
                expected_pair_id="pair",
                expected_theorem_hash="theorem",
            )
        with self.assertRaises(ValueError):
            parse_result_protocol(
                _marker("valid", pair_id="other"),
                "",
                exit_code=0,
                expected_pair_id="pair",
                expected_theorem_hash="theorem",
            )

    def test_integer_witness_is_machine_readable(self) -> None:
        witness = extract_witness("❌ Falsified\nCounterexample:\n - input: -7\n", "")
        self.assertEqual(
            witness,
            {
                "protocol": "EQUIV_WITNESS_V1",
                "values": {"input": {"kind": "integer", "value": -7, "rendered": "-7"}},
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
                parse_blaster_output(result.stdout, result.stderr),
                "blaster_inconclusive",
            )


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
