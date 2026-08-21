from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from equiv_checker.compiler_artifacts import (
    _stable_hash,
    build_local,
    build_release,
    compiler_from_manifest,
    resolve_release_ref,
    verify_compiler_manifest,
)


TOOLCHAIN = {
    "rustc_verbose": "rustc 1.97.1\nhost: test-target",
    "cargo_version": "cargo 1.97.1",
    "rustup_active_toolchain": "stable-test",
    "target_triple": "test-target",
}


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", root, *args], text=True).strip()


def _repository(root: Path) -> None:
    subprocess.run(["git", "init", "-q", root], check=True)
    _git(root, "config", "user.name", "Test")
    _git(root, "config", "user.email", "test@example.invalid")
    (root / "Cargo.toml").write_text(
        '[workspace]\nmembers = []\n[workspace.package]\nrust-version = "1.86.0"\n',
        encoding="utf-8",
    )
    (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
    (root / "source.rs").write_text("pub const VALUE: u8 = 1;\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "initial")
    for tag in ("v1.1.21", "v1.1.22", "v1.1.23"):
        _git(root, "tag", "-a", tag, "-m", tag)


def _fake_builder(binary_payload: bytes = b"compiler-a"):
    def build(*, checkout: Path, output: Path, target_directory: Path, expected_version: str | None):
        del checkout
        binary = output / "bin" / "aiken"
        binary.parent.mkdir(parents=True, exist_ok=True)
        reported = expected_version or "aiken v1.1.23+local"
        binary.write_text(
            "#!/bin/sh\n"
            f"# {binary_payload.hex()}\n"
            f"printf '%s\\n' '{reported}'\n",
            encoding="utf-8",
        )
        binary.chmod(0o755)
        stdout = output / "logs" / "cargo-build.stdout.log"
        stderr = output / "logs" / "cargo-build.stderr.log"
        stdout.parent.mkdir(parents=True, exist_ok=True)
        stdout.write_text("", encoding="utf-8")
        stderr.write_text("", encoding="utf-8")
        return (
            {
                "command": ["cargo", "build", "--release", "--locked"],
                "cargo_target_directory": target_directory.relative_to(output).as_posix(),
                "exit_code": 0,
                "duration_seconds": 0.01,
                "timestamp_utc": "2026-01-01T00:00:00+00:00",
                "logs": {
                    "stdout": stdout.relative_to(output).as_posix(),
                    "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                    "stderr": stderr.relative_to(output).as_posix(),
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                },
            },
            {
                "path": binary.relative_to(output).as_posix(),
                "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "size": binary.stat().st_size,
                "reported_version": reported,
            },
        )

    return build


class CompilerArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "aiken"
        _repository(self.source)
        self.toolchain = patch(
            "equiv_checker.compiler_artifacts._toolchain_environment",
            return_value=TOOLCHAIN,
        )
        self.toolchain.start()
        self.addCleanup(self.toolchain.stop)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_tag_resolution_uses_full_commit_and_annotated_target(self) -> None:
        resolved = resolve_release_ref(ref="v1.1.21", aiken_source=self.source)
        self.assertRegex(resolved["commit_sha"], r"^[0-9a-f]{40}$")
        self.assertRegex(resolved["source_tree_git_sha"], r"^[0-9a-f]{40}$")
        self.assertEqual(resolved["tag_target_type"], "annotated_tag")

    @patch("equiv_checker.compiler_artifacts._build_binary", side_effect=_fake_builder())
    def test_release_manifest_and_separate_target_directories(self, _build) -> None:
        first = build_release(
            ref="v1.1.21", output=self.root / "one", aiken_source=self.source
        )
        second = build_release(
            ref="v1.1.22", output=self.root / "two", aiken_source=self.source
        )
        self.assertEqual(first["source"]["commit_sha"], _git(self.source, "rev-parse", "HEAD"))
        self.assertNotEqual(
            first["build"]["cargo_target_directory"],
            second["build"]["cargo_target_directory"],
        )
        verify_compiler_manifest(self.root / "one" / "compiler.json")

    @patch("equiv_checker.compiler_artifacts._build_binary", side_effect=_fake_builder())
    def test_matching_release_artifact_is_reused(self, build) -> None:
        output = self.root / "release"
        build_release(ref="v1.1.21", output=output, aiken_source=self.source)
        result = build_release(
            ref="v1.1.21",
            output=output,
            aiken_source=self.source,
            label="renamed-release",
        )
        self.assertTrue(result["cache_reused"])
        self.assertEqual(result["label"], "renamed-release")
        self.assertEqual(
            json.loads((output / "compiler.json").read_text())["label"],
            "renamed-release",
        )
        self.assertEqual(build.call_count, 1)

    @patch("equiv_checker.compiler_artifacts._build_binary", side_effect=_fake_builder())
    def test_cached_release_with_unexpected_version_is_rejected(self, build) -> None:
        output = self.root / "release"
        manifest = build_release(
            ref="v1.1.21", output=output, aiken_source=self.source
        )
        binary = output / manifest["binary"]["path"]
        binary.write_text(
            "#!/bin/sh\nprintf '%s\\n' 'aiken v9.9.9+wrong'\n",
            encoding="utf-8",
        )
        binary.chmod(0o755)
        manifest["binary"]["reported_version"] = "aiken v9.9.9+wrong"
        manifest["binary"]["sha256"] = hashlib.sha256(
            binary.read_bytes()
        ).hexdigest()
        manifest["binary"]["size"] = binary.stat().st_size
        manifest["artifact_id"] = _stable_hash(
            {
                "artifact_kind": manifest["artifact_kind"],
                "source_tree_sha256": manifest["source"]["source_tree_sha256"],
                "commit_sha": manifest["source"]["commit_sha"],
                "binary_sha256": manifest["binary"]["sha256"],
                "target": manifest["target"],
                "build_command": manifest["build"]["command"],
            }
        )
        (output / "compiler.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        with self.assertRaisesRegex(RuntimeError, "unexpected Aiken version"):
            build_release(
                ref="v1.1.21", output=output, aiken_source=self.source
            )
        self.assertEqual(build.call_count, 1)

    @patch(
        "equiv_checker.compiler_artifacts._build_binary",
        side_effect=RuntimeError("unexpected Aiken version"),
    )
    def test_unexpected_release_version_is_rejected(self, _build) -> None:
        with self.assertRaisesRegex(RuntimeError, "unexpected Aiken version"):
            build_release(
                ref="v1.1.21", output=self.root / "bad", aiken_source=self.source
            )

    @patch("equiv_checker.compiler_artifacts._build_binary", side_effect=_fake_builder())
    def test_clean_local_source_records_commit_and_detached_state(self, _build) -> None:
        manifest = build_local(
            aiken_source=self.source, output=self.root / "clean", label="clean"
        )
        self.assertFalse(manifest["source"]["dirty"])
        self.assertTrue(manifest["reproducibility"]["reproducible_from_commit"])
        self.assertEqual(
            manifest["source"]["branch"],
            _git(self.source, "symbolic-ref", "--short", "HEAD"),
        )
        self.assertFalse(manifest["source"]["detached"])
        compiler = compiler_from_manifest("new", self.root / "clean" / "compiler.json")
        self.assertEqual(compiler.git_revision, _git(self.source, "rev-parse", "HEAD"))

    @patch("equiv_checker.compiler_artifacts._build_binary", side_effect=_fake_builder())
    def test_detached_local_source_is_supported(self, _build) -> None:
        _git(self.source, "checkout", "--detach")
        manifest = build_local(
            aiken_source=self.source,
            output=self.root / "detached",
            label="detached",
        )
        self.assertIsNone(manifest["source"]["branch"])
        self.assertTrue(manifest["source"]["detached"])
        self.assertEqual(
            manifest["source"]["commit_sha"],
            _git(self.source, "rev-parse", "HEAD"),
        )

    @patch("equiv_checker.compiler_artifacts._build_binary", side_effect=_fake_builder())
    def test_matching_local_artifact_reuses_binary_and_updates_label(self, build) -> None:
        output = self.root / "local"
        build_local(aiken_source=self.source, output=output, label="first")
        result = build_local(aiken_source=self.source, output=output, label="candidate")
        self.assertTrue(result["cache_reused"])
        self.assertEqual(result["label"], "candidate")
        self.assertEqual(build.call_count, 1)

    def test_dirty_local_source_requires_permission(self) -> None:
        (self.source / "source.rs").write_text("pub const VALUE: u8 = 2;\n")
        with self.assertRaisesRegex(ValueError, "--allow-dirty"):
            build_local(
                aiken_source=self.source, output=self.root / "dirty", label="dirty"
            )

    @patch("equiv_checker.compiler_artifacts._build_binary", side_effect=_fake_builder())
    def test_dirty_and_untracked_sources_are_bundled(self, _build) -> None:
        (self.source / "source.rs").write_text("pub const VALUE: u8 = 2;\n")
        (self.source / "untracked.rs").write_text("pub const EXTRA: u8 = 3;\n")
        manifest = build_local(
            aiken_source=self.source,
            output=self.root / "dirty",
            label="dirty",
            allow_dirty=True,
        )
        bundle = manifest["reproducibility"]["bundle"]
        self.assertFalse(manifest["reproducibility"]["reproducible_from_commit"])
        self.assertEqual(
            [row["path"] for row in bundle["untracked_files"]], ["untracked.rs"]
        )
        self.assertTrue((self.root / "dirty" / bundle["tracked_diff"]).is_file())
        self.assertTrue((self.root / "dirty" / "reproducibility/untracked/untracked.rs").is_file())

    def test_same_reported_version_different_binaries_remain_distinct(self) -> None:
        with patch(
            "equiv_checker.compiler_artifacts._build_binary",
            side_effect=_fake_builder(b"first"),
        ):
            first = build_local(
                aiken_source=self.source, output=self.root / "first", label="candidate"
            )
        with patch(
            "equiv_checker.compiler_artifacts._build_binary",
            side_effect=_fake_builder(b"second"),
        ):
            second = build_local(
                aiken_source=self.source, output=self.root / "second", label="candidate"
            )
        self.assertEqual(first["binary"]["reported_version"], second["binary"]["reported_version"])
        self.assertNotEqual(first["binary"]["sha256"], second["binary"]["sha256"])
        self.assertNotEqual(first["artifact_id"], second["artifact_id"])

    @patch("equiv_checker.compiler_artifacts._build_binary", side_effect=_fake_builder())
    def test_source_change_forces_local_rebuild(self, build) -> None:
        output = self.root / "candidate"
        build_local(aiken_source=self.source, output=output, label="candidate")
        (self.source / "source.rs").write_text("pub const VALUE: u8 = 9;\n")
        build_local(
            aiken_source=self.source,
            output=output,
            label="candidate",
            allow_dirty=True,
        )
        self.assertEqual(build.call_count, 2)

    @patch("equiv_checker.compiler_artifacts._build_binary", side_effect=_fake_builder())
    def test_identity_is_stable_across_checkout_paths(self, _build) -> None:
        clone = self.root / "clone"
        subprocess.run(["git", "clone", "-q", self.source, clone], check=True)
        first = build_local(
            aiken_source=self.source, output=self.root / "path-one", label="candidate"
        )
        second = build_local(
            aiken_source=clone, output=self.root / "path-two", label="candidate"
        )
        self.assertEqual(first["source"]["source_tree_sha256"], second["source"]["source_tree_sha256"])
        self.assertEqual(first["artifact_id"], second["artifact_id"])


if __name__ == "__main__":
    unittest.main()
