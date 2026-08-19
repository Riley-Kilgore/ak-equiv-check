from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from equiv_checker.config import sha256_tree
from equiv_checker.gate import _surface_audit_errors


class SurfaceAuditGateTests(unittest.TestCase):
    def test_empty_unmapped_lists_pass(self) -> None:
        audit = {
            "unmapped_surface_variants": [],
            "unmapped_keywords_or_aliases": [],
        }

        self.assertEqual(_surface_audit_errors(audit), [])

    def test_each_unmapped_surface_blocks_the_gate(self) -> None:
        audit = {
            "unmapped_surface_variants": ["TypedExpr::NewVariant"],
            "unmapped_keywords_or_aliases": ["new_keyword"],
        }

        self.assertEqual(
            _surface_audit_errors(audit),
            [
                "compiler surface audit has unmapped variants",
                "compiler surface audit has unmapped keywords or aliases",
            ],
        )


class SentinelHashTests(unittest.TestCase):
    def test_generated_outputs_do_not_change_content_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "lib").mkdir()
            (root / "lib" / "fixture.ak").write_text("pub fn fixture() { True }\n")
            original = sha256_tree(root)

            (root / "build").mkdir()
            (root / "build" / "generated.uplc").write_text("generated")
            (root / "plutus.json").write_text("{}")

            self.assertEqual(sha256_tree(root), original)

            (root / "lib" / "fixture.ak").write_text("pub fn fixture() { False }\n")
            self.assertNotEqual(sha256_tree(root), original)


if __name__ == "__main__":
    unittest.main()
