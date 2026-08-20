from __future__ import annotations

import hashlib
import json
import os
import platform
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .models import BlasterConfig, Timeouts
from .process import run_process


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CORPUS_ROOT = REPOSITORY_ROOT / "corpus"
TOOL_ROOT = REPOSITORY_ROOT / "tool"
DEFAULT_WORK_ROOT = REPOSITORY_ROOT / "work"
CONTRACT_PATH = CORPUS_ROOT / "aiken_language_features_v1_1_23.json"
COMPILER_PAIR_PATH = CORPUS_ROOT / "compiler_pair.json"
SCANNER_CONFIG_PATH = TOOL_ROOT / "scanner_config.json"
BLASTER_CONFIG_PATH = TOOL_ROOT / "blaster_config.json"
SHIM_MANIFEST = TOOL_ROOT / "aiken-shim" / "Cargo.toml"
SHIM_BINARY = TOOL_ROOT / "aiken-shim" / "target" / "release" / (
    "aiken-equiv-shim.exe" if os.name == "nt" else "aiken-equiv-shim"
)


@dataclass(frozen=True)
class Compiler:
    label: str
    release: str
    reported_version: str
    git_revision: str | None
    binary_sha256: str
    executable: Path

    def identity(self) -> dict[str, Any]:
        return asdict(self) | {"executable": str(self.executable)}


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def package_name(package: Path) -> str:
    with (package / "aiken.toml").open("rb") as stream:
        manifest = tomllib.load(stream)
    name = manifest.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError(f"missing package name in {package / 'aiken.toml'}")
    return name


def package_key(name: str) -> str:
    return name.replace("/", "__")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(root: Path) -> str:
    digest = hashlib.sha256()
    ignored_parts = {".git", "artifacts", "build", "docs", "__pycache__"}
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        relative = path.relative_to(root)
        if any(part in ignored_parts for part in relative.parts):
            continue
        if relative.name == "plutus.json" or (
            relative.name.startswith("plutus-") and relative.suffix == ".json"
        ):
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _installed_aiken(label: str, release: str) -> Path:
    override = os.getenv(f"AIKEN_{label.upper()}")
    if override:
        return Path(override).expanduser().resolve()

    version_root = Path.home() / ".aiken" / "versions" / release
    executable_name = "aiken.exe" if os.name == "nt" else "aiken"
    matches = sorted(version_root.glob(f"aiken-*/{executable_name}"))
    if not matches:
        machine = platform.machine()
        raise FileNotFoundError(
            f"aikup installation for {release} not found under {version_root} ({machine})"
        )
    return matches[0]


def _compiler(
    label: str,
    configured: dict[str, Any],
    executable_override: Path | None,
    revision_override: str | None,
) -> Compiler:
    is_default = executable_override is None
    executable = (
        _installed_aiken(label, configured["release"])
        if is_default
        else executable_override.expanduser().resolve()
    )
    if not executable.is_file():
        raise FileNotFoundError(f"{label} compiler does not exist: {executable}")
    actual_hash = sha256_file(executable)
    expected_hash = configured.get("binary_sha256") if is_default else None
    if expected_hash and actual_hash != expected_hash:
        raise RuntimeError(
            f"{label} compiler hash mismatch: expected {expected_hash}, got {actual_hash}"
        )
    version = run_process([executable, "--version"], REPOSITORY_ROOT, 30.0)
    if version.timed_out or version.exit_code != 0:
        detail = version.stderr.strip() or version.stdout.strip() or "no diagnostic"
        raise RuntimeError(f"{label} compiler --version failed: {detail}")
    reported_version = (version.stdout or version.stderr).strip().splitlines()[0]
    return Compiler(
        label=label,
        release=configured["release"] if is_default else "custom",
        reported_version=reported_version,
        git_revision=(
            revision_override
            if revision_override is not None
            else configured.get("git_revision")
            if is_default
            else None
        ),
        binary_sha256=actual_hash,
        executable=executable,
    )


def compiler_pair(
    *,
    old_aiken: Path | None = None,
    new_aiken: Path | None = None,
    old_revision: str | None = None,
    new_revision: str | None = None,
) -> tuple[Compiler, Compiler]:
    pair = load_json(COMPILER_PAIR_PATH)
    return (
        _compiler("old", pair["old"], old_aiken, old_revision),
        _compiler("new", pair["new"], new_aiken, new_revision),
    )


def load_blaster_config(path: Path = BLASTER_CONFIG_PATH) -> BlasterConfig:
    value = load_json(path)
    backend_root = Path(value["backend_root"]).expanduser()
    if not backend_root.is_absolute():
        backend_root = (REPOSITORY_ROOT / backend_root).resolve()
    fuel = value.get("fuel")
    if not isinstance(fuel, int) or fuel <= 0:
        raise ValueError("Blaster preparation fuel must be a positive integer")
    return BlasterConfig(
        backend_root=backend_root,
        revisions=dict(value["revisions"]),
        lean_version=str(value["lean_version"]),
        z3_version=str(value["z3_version"]),
        solver=str(value.get("solver", "z3")),
        fuel=fuel,
        timeouts=Timeouts.from_dict(value.get("timeouts", {})),
        random_seed=int(value.get("random_seed", 1)),
    )
