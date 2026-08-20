from __future__ import annotations

import stat
import tempfile
import time
import unittest
from pathlib import Path

from equiv_checker.blaster import extract_witness, parse_blaster_output
from equiv_checker.process import run_process


class BlasterParsingTests(unittest.TestCase):
    def test_all_solver_verdicts_are_distinct(self) -> None:
        self.assertEqual(parse_blaster_output("✅ Valid", ""), "blaster_valid")
        self.assertEqual(
            parse_blaster_output("❌ Falsified", ""),
            "blaster_falsified_unreplayed",
        )
        self.assertEqual(
            parse_blaster_output("Expected Undetermined", ""),
            "blaster_inconclusive",
        )
        self.assertEqual(
            parse_blaster_output("unsupported UPLC builtin", ""),
            "blaster_unsupported",
        )
        self.assertEqual(
            parse_blaster_output("", "", timed_out=True), "blaster_timeout"
        )
        self.assertEqual(parse_blaster_output("tool crashed", ""), "blaster_error")

    def test_insufficient_preparation_fuel_is_inconclusive(self) -> None:
        self.assertEqual(
            parse_blaster_output("preparation fuel exhausted", ""),
            "blaster_inconclusive",
        )

    def test_integer_witness_is_machine_readable(self) -> None:
        witness = extract_witness("❌ Falsified\nCounterexample:\n - input: -7\n", "")
        self.assertEqual(
            witness,
            {
                "values": {"input": {"kind": "integer", "value": -7, "rendered": "-7"}},
                "raw_available": True,
            },
        )

    def test_fake_blaster_process_output_is_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process = root / "fake-blaster"
            process.write_text(
                "#!/usr/bin/env python3\nprint('Expected Undetermined')\n",
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
