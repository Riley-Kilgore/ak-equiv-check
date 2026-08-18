from __future__ import annotations

import hashlib
import json
import os
import platform
import tomllib
from dataclasses import dataclass
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CORPUS_ROOT = REPOSITORY_ROOT / "corpus"
TOOL_ROOT = REPOSITORY_ROOT / "tool"
DEFAULT_WORK_ROOT = REPOSITORY_ROOT / "work"
CONTRACT_PATH = CORPUS_ROOT / "aiken_language_features_v1_1_23.json"
COMPILER_PAIR_PATH = CORPUS_ROOT / "compiler_pair.json"
SCANNER_CONFIG_PATH = TOOL_ROOT / "scanner_config.json"
SHIM_MANIFEST = TOOL_ROOT / "aiken-shim" / "Cargo.toml"
SHIM_BINARY = TOOL_ROOT / "aiken-shim" / "target" / "release" / (
    "aiken-equiv-shim.exe" if os.name == "nt" else "aiken-equiv-shim"
)


@dataclass(frozen=True)
class Compiler:
    label: str
    release: str
    reported_version: str
    binary_sha256: str
    executable: Path


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


def _installed_aiken(release: str) -> Path:
    override = os.getenv(f"AIKEN_{'OLD' if release == load_json(COMPILER_PAIR_PATH)['old']['release'] else 'NEW'}")
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


def compiler_pair() -> tuple[Compiler, Compiler]:
    pair = load_json(COMPILER_PAIR_PATH)
    compilers = []
    for label in ("old", "new"):
        row = pair[label]
        executable = _installed_aiken(row["release"])
        actual_hash = sha256_file(executable)
        if actual_hash != row["binary_sha256"]:
            raise RuntimeError(
                f"{label} compiler hash mismatch: expected {row['binary_sha256']}, got {actual_hash}"
            )
        compilers.append(
            Compiler(
                label=label,
                release=row["release"],
                reported_version=row["reported_version"],
                binary_sha256=row["binary_sha256"],
                executable=executable,
            )
        )
    return compilers[0], compilers[1]
