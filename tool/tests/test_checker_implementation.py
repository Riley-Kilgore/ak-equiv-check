from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from equiv_checker.evidence import (
    checker_implementation_id,
    checker_implementation_manifest,
)


_INCLUDED_FILES = {
    "tool/equiv_checker/checker.py": "VALUE = 1\n",
    "tool/schemas/results.schema.json": '{"type": "object"}\n',
    "tool/aiken-shim/Cargo.toml": '[package]\nname = "aiken-shim"\n',
    "tool/aiken-shim/src/main.rs": "fn main() {}\n",
    "tool/blaster-backend/lean-toolchain": "leanprover/lean4:v4.19.0\n",
    "tool/blaster-backend/lake-manifest.json": '{"version": "1.1.0"}\n',
    "tool/blaster-backend/lakefile.lean": 'package "blaster-backend"\n',
    "tool/blaster-backend/Blaster/Checker.lean": "def check := true\n",
    "tool/blaster-backend/templates/Obligation.lean": "theorem generated : True := by trivial\n",
    "tool/blaster_config.json": '{"backend": "lean"}\n',
    "tool/pyproject.toml": '[project]\nname = "equiv-checker"\n',
    "tool/uv.lock": "version = 1\n",
}


def _write(root: Path, relative: str | Path, contents: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    return path


def _make_repository(root: Path) -> None:
    for relative, contents in _INCLUDED_FILES.items():
        _write(root, relative, contents)


class CheckerImplementationIdentityTests(unittest.TestCase):
    def test_each_implementation_input_changes_the_identity_independently(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _make_repository(root)
            baseline = checker_implementation_id(root)

            for relative in _INCLUDED_FILES:
                with self.subTest(relative=relative):
                    path = root / relative
                    original = path.read_bytes()
                    path.write_bytes(original + b"modified\n")
                    self.assertNotEqual(baseline, checker_implementation_id(root))
                    path.write_bytes(original)
                    self.assertEqual(baseline, checker_implementation_id(root))

    def test_recursive_roots_and_top_level_metadata_are_discovered_automatically(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _make_repository(root)
            baseline = checker_implementation_id(root)
            dynamic_name = f"new_{root.name}"
            additions = (
                Path("tool/equiv_checker/extensions") / f"{dynamic_name}.py",
                Path("tool/schemas/future") / f"{dynamic_name}.json",
                Path("tool/aiken-shim/src/generated") / f"{dynamic_name}.rs",
                Path("tool/blaster-backend/Blaster/Generated")
                / f"{dynamic_name}.lean",
                Path("tool") / f"{dynamic_name}.toml",
            )

            for relative in additions:
                with self.subTest(relative=relative):
                    path = _write(root, relative, "new implementation input\n")
                    manifest = checker_implementation_manifest(root)
                    manifest_paths = {entry["path"] for entry in manifest["files"]}
                    self.assertIn(relative.as_posix(), manifest_paths)
                    self.assertNotEqual(
                        baseline, manifest["checker_implementation_id"]
                    )
                    path.unlink()
                    self.assertEqual(baseline, checker_implementation_id(root))

    def test_generated_cache_build_log_and_work_paths_are_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _make_repository(root)
            baseline = checker_implementation_id(root)
            excluded = (
                "tool/equiv_checker/__pycache__/checker.cpython-313.pyc",
                "tool/equiv_checker/.mypy_cache/checker.json",
                "tool/equiv_checker/.pytest_cache/state",
                "tool/equiv_checker/.ruff_cache/state",
                "tool/equiv_checker/build/generated.py",
                "tool/schemas/dist/generated.schema.json",
                "tool/aiken-shim/target/debug/aiken-shim",
                "tool/blaster-backend/.lake/build/Generated.olean",
                "tool/blaster-backend/logs/checker.log",
                "tool/blaster-backend/work/Generated.lean",
            )

            paths = [_write(root, relative, "generated output\n") for relative in excluded]
            self.assertEqual(baseline, checker_implementation_id(root))
            for path in paths:
                path.write_text("changed generated output\n", encoding="utf-8")
            self.assertEqual(baseline, checker_implementation_id(root))


if __name__ == "__main__":
    unittest.main()
