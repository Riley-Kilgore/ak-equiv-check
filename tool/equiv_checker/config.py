from __future__ import annotations

import hashlib
import json
import os
import platform
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .models import BlasterConfig, EvaluatorConfig, Timeouts
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
    provenance: dict[str, Any] = field(default_factory=dict)

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


def platform_key() -> str:
    return f"{platform.system().lower()}-{platform.machine().lower()}"


def _configured_binary_hash(configured: dict[str, Any]) -> str:
    artifacts = configured.get("artifacts")
    if isinstance(artifacts, dict):
        key = platform_key()
        artifact = artifacts.get(key)
        if not isinstance(artifact, dict) or not isinstance(
            artifact.get("binary_sha256"), str
        ):
            raise ValueError(f"no pinned compiler artifact for {key}")
        return str(artifact["binary_sha256"])
    expected = configured.get("binary_sha256")
    if not isinstance(expected, str):
        raise ValueError("compiler binary hash is missing")
    return expected


def _known_binary_hashes(configured: dict[str, Any]) -> set[str]:
    artifacts = configured.get("artifacts")
    if isinstance(artifacts, dict):
        return {
            str(artifact["binary_sha256"])
            for artifact in artifacts.values()
            if isinstance(artifact, dict)
            and isinstance(artifact.get("binary_sha256"), str)
        }
    return {_configured_binary_hash(configured)}


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
    uses_installed_default = executable_override is None
    executable = (
        _installed_aiken(label, configured["release"])
        if uses_installed_default
        else executable_override.expanduser().resolve()
    )
    if not executable.is_file():
        raise FileNotFoundError(f"{label} compiler does not exist: {executable}")
    actual_hash = sha256_file(executable)
    expected_hash = _configured_binary_hash(configured)
    if uses_installed_default and actual_hash != expected_hash:
        raise RuntimeError(
            f"{label} compiler hash mismatch: expected {expected_hash}, got {actual_hash}"
        )
    is_baseline = actual_hash in _known_binary_hashes(configured)
    version = run_process([executable, "--version"], REPOSITORY_ROOT, 30.0)
    if version.timed_out or version.exit_code != 0:
        detail = version.stderr.strip() or version.stdout.strip() or "no diagnostic"
        raise RuntimeError(f"{label} compiler --version failed: {detail}")
    reported_version = (version.stdout or version.stderr).strip().splitlines()[0]
    if is_baseline and reported_version != configured["reported_version"]:
        raise RuntimeError(
            f"{label} compiler version mismatch: expected "
            f"{configured['reported_version']}, got {reported_version}"
        )
    return Compiler(
        label=label,
        release=configured["release"] if is_baseline else "custom",
        reported_version=reported_version,
        git_revision=(
            revision_override
            if revision_override is not None
            else configured.get("git_revision")
            if is_baseline
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
    old_manifest: Path | None = None,
    new_manifest: Path | None = None,
) -> tuple[Compiler, Compiler]:
    if old_aiken is not None and old_manifest is not None:
        raise ValueError("--old-aiken and --old-compiler-manifest are mutually exclusive")
    if new_aiken is not None and new_manifest is not None:
        raise ValueError("--new-aiken and --new-compiler-manifest are mutually exclusive")
    pair = load_json(COMPILER_PAIR_PATH)
    if old_manifest is not None or new_manifest is not None:
        from .compiler_artifacts import compiler_from_manifest

    return (
        compiler_from_manifest("old", old_manifest)
        if old_manifest is not None
        else _compiler("old", pair["old"], old_aiken, old_revision),
        compiler_from_manifest("new", new_manifest)
        if new_manifest is not None
        else _compiler("new", pair["new"], new_aiken, new_revision),
    )


def load_blaster_config(
    path: Path = BLASTER_CONFIG_PATH,
    *,
    evaluator_executable: Path | None = None,
) -> BlasterConfig:
    value = load_json(path)
    backend_root = Path(value["backend_root"]).expanduser()
    if not backend_root.is_absolute():
        backend_root = (REPOSITORY_ROOT / backend_root).resolve()
    runtime_step_bound = value.get("semantic_runtime_step_bound")
    if not isinstance(runtime_step_bound, int) or runtime_step_bound <= 0:
        raise ValueError("semantic runtime step bound must be a positive integer")
    evaluator_value = value.get("evaluator")
    evaluator: EvaluatorConfig | None = None
    if evaluator_value is not None:
        if not isinstance(evaluator_value, dict):
            raise ValueError("evaluator configuration must be an object")
        evaluator_executable = (
            _installed_aiken("new", str(evaluator_value["release"]))
            if evaluator_executable is None
            else evaluator_executable.expanduser().resolve()
        )
        evaluator_hash = sha256_file(evaluator_executable)
        expected_evaluator_hash = _configured_binary_hash(evaluator_value)
        if evaluator_hash != expected_evaluator_hash:
            raise RuntimeError(
                "evaluator binary hash mismatch: "
                f"expected {expected_evaluator_hash}, got {evaluator_hash}"
            )
        evaluator = EvaluatorConfig(
            name=str(evaluator_value["name"]),
            version=str(evaluator_value["version"]),
            revision=str(evaluator_value["revision"]),
            binary_sha256=evaluator_hash,
            executable=evaluator_executable,
            evaluation_limits=dict(evaluator_value["evaluation_limits"]),
        )
    solver_artifacts = value.get("solver_artifacts")
    platform_key_value = platform_key()
    if (
        not isinstance(solver_artifacts, dict)
        or platform_key_value not in solver_artifacts
    ):
        raise ValueError(f"no pinned solver artifact for {platform_key_value}")
    solver_artifact = solver_artifacts[platform_key_value]
    solver_executable = Path(str(solver_artifact["path"])).expanduser()
    if not solver_executable.is_absolute():
        solver_executable = (REPOSITORY_ROOT / solver_executable).resolve()
    if not solver_executable.is_file():
        raise FileNotFoundError(
            f"pinned solver executable is missing: {solver_executable}"
        )
    solver_hash = sha256_file(solver_executable)
    if solver_hash != solver_artifact["binary_sha256"]:
        raise RuntimeError(
            "solver binary hash mismatch: "
            f"expected {solver_artifact['binary_sha256']}, got {solver_hash}"
        )
    return BlasterConfig(
        backend_root=backend_root,
        revisions=dict(value["revisions"]),
        lean_version=str(value["lean_version"]),
        z3_version=str(value["z3_version"]),
        solver=str(value.get("solver", "z3")),
        solver_executable=solver_executable,
        solver_binary_sha256=solver_hash,
        runtime_step_bound=runtime_step_bound,
        timeouts=Timeouts.from_dict(value.get("timeouts", {})),
        random_seed=int(value.get("random_seed", 1)),
        evaluator=evaluator,
    )
