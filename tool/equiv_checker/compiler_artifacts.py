from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from .config import Compiler, sha256_file
from .pairing import canonical_json
from .process import ProcessResult, run_process, write_process_logs

SCHEMA_VERSION = 1
DEFAULT_AIKEN_REPOSITORY = "https://github.com/aiken-lang/aiken"
BUILD_COMMAND = ("cargo", "build", "--release", "--locked")
_EXCLUDED_SOURCE_PARTS = {".git", ".ak-equiv", "target", "__pycache__"}
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SAFE_LABEL = re.compile(r"[^A-Za-z0-9_.-]+")


def _stable_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _checked(
    command: Iterable[str | Path],
    cwd: Path,
    *,
    timeout: float = 120.0,
    environment: dict[str, str] | None = None,
) -> ProcessResult:
    result = run_process(list(command), cwd, timeout, environment=environment)
    if result.timed_out or result.exit_code != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        raise RuntimeError(f"command failed ({' '.join(result.command)}): {detail}")
    return result


def _git(source: Path, *arguments: str, timeout: float = 120.0) -> str:
    return _checked(["git", "-C", source, *arguments], source, timeout=timeout).stdout.strip()


def _git_bytes(source: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", source, *arguments],
        cwd=source,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git {' '.join(arguments)} failed: {detail or 'no diagnostic'}")
    return completed.stdout


def _repository_url(source: Path) -> str:
    result = run_process(["git", "-C", source, "remote", "get-url", "origin"], source, 30.0)
    if not result.timed_out and result.exit_code == 0 and result.stdout.strip():
        return result.stdout.strip()
    return source.resolve().as_uri()


def _remote_tag(repository: str, ref: str) -> tuple[str, str, str]:
    tag_ref = f"refs/tags/{ref}"
    result = _checked(
        ["git", "ls-remote", "--tags", repository, tag_ref, f"{tag_ref}^{{}}"],
        Path.cwd(),
    )
    rows: dict[str, str] = {}
    for line in result.stdout.splitlines():
        sha, separator, name = line.partition("\t")
        if separator and _SHA1.fullmatch(sha):
            rows[name] = sha
    tag_object = rows.get(tag_ref)
    if tag_object is None:
        raise ValueError(f"release tag does not exist: {ref}")
    peeled = rows.get(f"{tag_ref}^{{}}")
    return tag_object, peeled or tag_object, "annotated_tag" if peeled else "commit"


def resolve_release_ref(
    *,
    ref: str,
    aiken_source: Path | None = None,
    aiken_repository: str = DEFAULT_AIKEN_REPOSITORY,
) -> dict[str, Any]:
    if not ref or ref.startswith("-") or "/" in ref:
        raise ValueError(f"release ref must be an exact tag name: {ref!r}")
    if aiken_source is None:
        tag_object, commit, target_type = _remote_tag(aiken_repository, ref)
        return {
            "repository_url": aiken_repository,
            "ref": ref,
            "tag_object_sha": tag_object,
            "commit_sha": commit,
            "tag_target_type": target_type,
            "source_tree_git_sha": None,
        }

    source = aiken_source.expanduser().resolve()
    if not (source / ".git").exists():
        raise ValueError(f"Aiken source is not a Git checkout: {source}")
    tag_name = f"refs/tags/{ref}"
    tag_object = _git(source, "rev-parse", "--verify", tag_name)
    target_type = _git(source, "cat-file", "-t", tag_object)
    if target_type not in {"tag", "commit"}:
        raise ValueError(f"release ref {ref} has unsupported target type {target_type}")
    commit = _git(source, "rev-parse", "--verify", f"{tag_name}^{{commit}}")
    tree = _git(source, "rev-parse", "--verify", f"{commit}^{{tree}}")
    if not _SHA1.fullmatch(commit) or not _SHA1.fullmatch(tree):
        raise RuntimeError(f"release ref {ref} did not resolve to full Git object IDs")
    return {
        "repository_url": _repository_url(source),
        "ref": ref,
        "tag_object_sha": tag_object,
        "commit_sha": commit,
        "tag_target_type": "annotated_tag" if target_type == "tag" else "commit",
        "source_tree_git_sha": tree,
    }


def _is_excluded(relative: Path, excluded_roots: tuple[Path, ...]) -> bool:
    if any(part in _EXCLUDED_SOURCE_PARTS for part in relative.parts):
        return True
    return any(relative == root or root in relative.parents for root in excluded_roots)


def _source_manifest(root: Path, *, excluded_paths: Iterable[Path] = ()) -> list[dict[str, Any]]:
    root = root.resolve()
    excluded_roots: list[Path] = []
    for path in excluded_paths:
        try:
            excluded_roots.append(path.resolve().relative_to(root))
        except ValueError:
            continue
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if _is_excluded(relative, tuple(excluded_roots)) or not (path.is_file() or path.is_symlink()):
            continue
        if path.is_symlink():
            data = os.readlink(path).encode("utf-8")
            kind = "symlink"
        else:
            data = path.read_bytes()
            kind = "file"
        records.append(
            {
                "path": relative.as_posix(),
                "kind": kind,
                "mode": stat.S_IMODE(path.lstat().st_mode),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return records


def _source_tree_sha256(records: list[dict[str, Any]]) -> str:
    identity = [
        {key: row[key] for key in ("path", "kind", "mode", "size", "sha256")}
        for row in records
    ]
    return _stable_hash(identity)


def _copy_complete_source(source: Path, destination: Path, records: list[dict[str, Any]]) -> None:
    for child in destination.iterdir():
        if child.name == ".git":
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()
    for record in records:
        relative = Path(record["path"])
        origin = source / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if record["kind"] == "symlink":
            target.symlink_to(os.readlink(origin))
        else:
            shutil.copy2(origin, target)
            target.chmod(record["mode"])


def _toolchain_environment() -> dict[str, Any]:
    rustc = _checked(["rustc", "-Vv"], Path.cwd(), timeout=30.0).stdout.strip()
    cargo = _checked(["cargo", "-V"], Path.cwd(), timeout=30.0).stdout.strip()
    rustup = run_process(["rustup", "show", "active-toolchain"], Path.cwd(), 30.0)
    host = next(
        (line.partition(":")[2].strip() for line in rustc.splitlines() if line.startswith("host:")),
        None,
    )
    return {
        "rustc_verbose": rustc,
        "cargo_version": cargo,
        "rustup_active_toolchain": (
            rustup.stdout.strip()
            if not rustup.timed_out and rustup.exit_code == 0
            else None
        ),
        "target_triple": host,
    }


def _required_rust_version(source: Path) -> str | None:
    text = (source / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'^rust-version\s*=\s*"([^"]+)"', text, flags=re.MULTILINE)
    return match.group(1) if match else None


def _target_environment(toolchain: dict[str, Any]) -> dict[str, Any]:
    return {
        "platform": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "target_triple": toolchain.get("target_triple"),
    }


def _build_identity(
    *,
    kind: str,
    source: dict[str, Any],
    toolchain: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": kind,
        "source": source,
        "toolchain": toolchain,
        "target": target,
        "build_command": list(BUILD_COMMAND),
    }


def _manifest_binary_path(manifest_path: Path, manifest: dict[str, Any]) -> Path:
    value = manifest.get("binary", {}).get("path")
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ValueError(f"compiler manifest has invalid relative binary path: {manifest_path}")
    return manifest_path.parent / value


def verify_compiler_manifest(
    manifest_path: Path,
    *,
    expected_cache_key: str | None = None,
) -> dict[str, Any]:
    manifest_path = manifest_path.expanduser().resolve()
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(
            f"failed to read compiler manifest {manifest_path}: {error}"
        ) from error
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported compiler manifest schema: {manifest.get('schema_version')}"
        )
    required_top_level = {
        "artifact_kind",
        "artifact_id",
        "label",
        "cache_key",
        "source",
        "toolchain",
        "target",
        "build",
        "binary",
        "reproducibility",
    }
    missing = sorted(required_top_level - manifest.keys())
    if missing:
        raise ValueError(
            "compiler manifest is missing required fields: "
            + ", ".join(missing)
        )
    if manifest["artifact_kind"] not in {"release", "local"}:
        raise ValueError("compiler manifest has invalid artifact_kind")
    for field_name in ("source", "toolchain", "target", "build", "binary"):
        if not isinstance(manifest[field_name], dict):
            raise ValueError(
                f"compiler manifest field {field_name} must be an object"
            )
    source = manifest["source"]
    required_source = {
        "repository_url",
        "commit_sha",
        "source_tree_sha256",
        "cargo_lock_sha256",
        "required_rust_version",
        "dirty",
    }
    if manifest["artifact_kind"] == "release":
        required_source |= {
            "ref",
            "tag_object_sha",
            "tag_target_type",
            "source_tree_git_sha",
        }
    missing_source = sorted(required_source - source.keys())
    if missing_source:
        raise ValueError(
            "compiler manifest source is missing required fields: "
            + ", ".join(missing_source)
        )
    if manifest["build"].get("command") != list(BUILD_COMMAND):
        raise RuntimeError("compiler manifest build command is not the locked class")
    expected_identity = _build_identity(
        kind=manifest["artifact_kind"],
        source=source,
        toolchain=manifest["toolchain"],
        target=manifest["target"],
    )
    actual_cache_key = _stable_hash(expected_identity)
    if manifest.get("cache_key") != actual_cache_key:
        raise RuntimeError(
            "compiler artifact inputs no longer match the recorded cache key"
        )
    if (
        expected_cache_key is not None
        and manifest.get("cache_key") != expected_cache_key
    ):
        raise ValueError(
            "compiler artifact inputs no longer match the expected cache key"
        )
    binary = _manifest_binary_path(manifest_path, manifest)
    if not binary.is_file():
        raise FileNotFoundError(
            f"compiler artifact binary is missing: {binary}"
        )
    actual_hash = sha256_file(binary)
    expected_hash = manifest["binary"].get("sha256")
    if actual_hash != expected_hash:
        raise RuntimeError(
            f"compiler artifact hash mismatch: expected {expected_hash}, got {actual_hash}"
        )
    if manifest["binary"].get("size") != binary.stat().st_size:
        raise RuntimeError("compiler artifact binary size mismatch")
    version = _checked([binary, "--version"], manifest_path.parent, timeout=30.0)
    reported = (version.stdout or version.stderr).strip().splitlines()[0]
    if reported != manifest["binary"].get("reported_version"):
        raise RuntimeError(
            "compiler artifact version mismatch: expected "
            f"{manifest['binary'].get('reported_version')}, got {reported}"
        )
    artifact_identity = {
        "artifact_kind": manifest["artifact_kind"],
        "source_tree_sha256": source["source_tree_sha256"],
        "commit_sha": source["commit_sha"],
        "binary_sha256": actual_hash,
        "target": manifest["target"],
        "build_command": manifest["build"]["command"],
    }
    if manifest["artifact_id"] != _stable_hash(artifact_identity):
        raise RuntimeError(
            "compiler artifact identity does not match its recorded evidence"
        )
    checkout = manifest_path.parent / "source"
    if checkout.is_dir():
        if _git(checkout, "rev-parse", "--verify", "HEAD^{commit}") != source[
            "commit_sha"
        ]:
            raise RuntimeError("compiler source checkout commit mismatch")
        tree = _git(checkout, "rev-parse", "HEAD^{tree}")
        if source.get("source_tree_git_sha") not in {None, tree}:
            raise RuntimeError("compiler source checkout Git tree mismatch")
        records = _source_manifest(
            checkout, excluded_paths=(manifest_path.parent,)
        )
        if _source_tree_sha256(records) != source["source_tree_sha256"]:
            raise RuntimeError("compiler source checkout content mismatch")
        if sha256_file(checkout / "Cargo.lock") != source[
            "cargo_lock_sha256"
        ]:
            raise RuntimeError("compiler source checkout Cargo.lock mismatch")
        if manifest["artifact_kind"] == "release":
            tag_object = _git(
                checkout,
                "rev-parse",
                "--verify",
                f"refs/tags/{source['ref']}^{{tag}}",
            )
            if tag_object != source["tag_object_sha"]:
                raise RuntimeError("compiler release tag object mismatch")
    return manifest


def _canonical_repository_url(value: str) -> str:
    normalized = value.strip().removesuffix("/").removesuffix(".git")
    if normalized.startswith("git@github.com:"):
        normalized = (
            "https://github.com/" + normalized.removeprefix("git@github.com:")
        )
    return normalized.lower()


def verify_release_lock(
    manifest_path: Path,
    release_lock_path: Path,
) -> dict[str, Any]:
    manifest = verify_compiler_manifest(manifest_path)
    if manifest["artifact_kind"] != "release":
        raise ValueError("base compiler manifest is not a release artifact")
    release_lock_path = release_lock_path.expanduser().resolve()
    try:
        lock = json.loads(release_lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(
            f"failed to read compiler release lock {release_lock_path}: {error}"
        ) from error
    if lock.get("schema_version") != 1:
        raise ValueError(
            f"unsupported compiler release lock schema: {lock.get('schema_version')}"
        )
    source = manifest["source"]
    release = lock.get("releases", {}).get(source["ref"])
    if not isinstance(release, dict):
        raise ValueError(
            f"compiler release {source['ref']} is absent from the complete release lock"
        )
    stable_actual = {
        "canonical_upstream_repository": _canonical_repository_url(
            source["repository_url"]
        ),
        "release_tag": source["ref"],
        "annotated_tag_object": source["tag_object_sha"],
        "tag_target_type": source["tag_target_type"],
        "resolved_commit_sha": source["commit_sha"],
        "git_tree_sha": source["source_tree_git_sha"],
        "source_tree_sha256": source["source_tree_sha256"],
        "cargo_lock_sha256": source["cargo_lock_sha256"],
        "reported_aiken_version": manifest["binary"]["reported_version"],
        "required_rust_version": source["required_rust_version"],
        "build_command_class": manifest["build"]["command"],
    }
    stable_expected = release.get("stable")
    if not isinstance(stable_expected, dict):
        raise ValueError("compiler release lock has no stable field set")
    for key, actual in stable_actual.items():
        if stable_expected.get(key) != actual:
            raise RuntimeError(
                f"compiler release lock mismatch for {key}: "
                f"expected {stable_expected.get(key)!r}, got {actual!r}"
            )
    target = manifest["target"]
    platform_key = "-".join(
        str(target.get(key)) for key in ("platform", "architecture", "target_triple")
    )
    platform_record = release.get("platform_artifacts", {}).get(platform_key)
    if not isinstance(platform_record, dict):
        raise RuntimeError(
            f"compiler release lock has no artifact for platform {platform_key}"
        )
    platform_actual = {
        "platform": target.get("platform"),
        "architecture": target.get("architecture"),
        "target_triple": target.get("target_triple"),
        "binary_sha256": manifest["binary"]["sha256"],
        "compiler_artifact_id": manifest["artifact_id"],
    }
    for key, actual in platform_actual.items():
        if platform_record.get(key) != actual:
            raise RuntimeError(
                f"compiler platform release lock mismatch for {key}: "
                f"expected {platform_record.get(key)!r}, got {actual!r}"
            )
    return {
        "valid": True,
        "release_lock": str(release_lock_path),
        "release_lock_sha256": sha256_file(release_lock_path),
        "release": source["ref"],
        "stable": stable_actual,
        "platform_artifact": platform_actual,
    }


def compiler_from_manifest(label: str, manifest_path: Path) -> Compiler:
    manifest_path = manifest_path.expanduser().resolve()
    manifest = verify_compiler_manifest(manifest_path)
    binary = _manifest_binary_path(manifest_path, manifest).resolve()
    source = manifest["source"]
    provenance = {
        "artifact_id": manifest["artifact_id"],
        "artifact_kind": manifest["artifact_kind"],
        "manifest_path": str(manifest_path),
        "manifest_sha256": sha256_file(manifest_path),
        "source_tree_sha256": source["source_tree_sha256"],
        "cargo_lock_sha256": source["cargo_lock_sha256"],
        "dirty": source.get("dirty", False),
        "reproducible_from_commit": manifest.get("reproducibility", {}).get(
            "reproducible_from_commit", False
        ),
    }
    reported_version = manifest["binary"]["reported_version"]
    reported_release_match = re.search(r"\bv\d+\.\d+\.\d+\b", reported_version)
    reported_release = reported_release_match.group(0) if reported_release_match else None
    return Compiler(
        label=label,
        release=source.get("ref") or reported_release or manifest.get("label") or "local",
        reported_version=reported_version,
        git_revision=source.get("commit_sha"),
        binary_sha256=manifest["binary"]["sha256"],
        executable=binary,
        provenance=provenance,
    )


def _existing_cache(output: Path, cache_key: str) -> dict[str, Any] | None:
    manifest_path = output / "compiler.json"
    if not manifest_path.is_file():
        return None
    try:
        return verify_compiler_manifest(manifest_path, expected_cache_key=cache_key)
    except (FileNotFoundError, RuntimeError, ValueError):
        return None


def _reuse_cache(output: Path, cached: dict[str, Any], label: str) -> dict[str, Any]:
    if cached.get("label") != label:
        cached = cached | {"label": label}
        _write_json(output / "compiler.json", cached)
    return cached | {"cache_reused": True}


def _prepare_output(output: Path) -> None:
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)


def _clone_checkout(source: Path | None, repository: str, checkout: Path, commit: str) -> None:
    if source is not None:
        command = ["git", "clone", "--no-checkout", "--shared", str(source), str(checkout)]
    else:
        command = ["git", "clone", "--no-checkout", "--filter=blob:none", repository, str(checkout)]
    _checked(command, checkout.parent, timeout=600.0)
    _checked(["git", "-C", checkout, "checkout", "--detach", commit], checkout, timeout=300.0)
    actual = _git(checkout, "rev-parse", "HEAD")
    if actual != commit:
        raise RuntimeError(f"isolated checkout revision mismatch: expected {commit}, got {actual}")


def _build_binary(
    *,
    checkout: Path,
    output: Path,
    target_directory: Path,
    expected_version: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    environment = {"CARGO_TARGET_DIR": str(target_directory)}
    result = run_process(BUILD_COMMAND, checkout, 7200.0, environment=environment)
    logs = output / "logs"
    stdout_path = logs / "cargo-build.stdout.log"
    stderr_path = logs / "cargo-build.stderr.log"
    write_process_logs(result, stdout_path, stderr_path)
    if result.timed_out or result.exit_code != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        raise RuntimeError(f"Aiken compiler build failed: {detail}")
    built = target_directory / "release" / ("aiken.exe" if os.name == "nt" else "aiken")
    if not built.is_file():
        raise RuntimeError(f"Aiken build did not produce the expected binary: {built}")
    destination = output / "bin" / built.name
    destination.parent.mkdir(parents=True)
    shutil.copy2(built, destination)
    version = _checked([destination, "--version"], output, timeout=30.0)
    reported = (version.stdout or version.stderr).strip().splitlines()[0]
    if expected_version is not None and reported != expected_version:
        raise RuntimeError(
            f"unexpected Aiken version: expected {expected_version}, got {reported}"
        )
    build = {
        "command": list(BUILD_COMMAND),
        "cargo_target_directory": target_directory.relative_to(output).as_posix(),
        "exit_code": result.exit_code,
        "duration_seconds": result.duration_seconds,
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "logs": {
            "stdout": stdout_path.relative_to(output).as_posix(),
            "stdout_sha256": sha256_file(stdout_path),
            "stderr": stderr_path.relative_to(output).as_posix(),
            "stderr_sha256": sha256_file(stderr_path),
        },
    }
    binary = {
        "path": destination.relative_to(output).as_posix(),
        "sha256": sha256_file(destination),
        "size": destination.stat().st_size,
        "reported_version": reported,
    }
    return build, binary


def _write_manifest(
    *,
    output: Path,
    kind: str,
    label: str,
    source: dict[str, Any],
    toolchain: dict[str, Any],
    target: dict[str, Any],
    cache_key: str,
    build: dict[str, Any],
    binary: dict[str, Any],
    reproducibility: dict[str, Any],
) -> dict[str, Any]:
    artifact_identity = {
        "artifact_kind": kind,
        "source_tree_sha256": source["source_tree_sha256"],
        "commit_sha": source.get("commit_sha"),
        "binary_sha256": binary["sha256"],
        "target": target,
        "build_command": build["command"],
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": kind,
        "artifact_id": _stable_hash(artifact_identity),
        "label": label,
        "cache_key": cache_key,
        "source": source,
        "toolchain": toolchain,
        "target": target,
        "build": build,
        "binary": binary,
        "reproducibility": reproducibility,
    }
    _write_json(output / "compiler.json", manifest)
    return manifest


def build_release(
    *,
    ref: str,
    output: Path,
    aiken_source: Path | None = None,
    aiken_repository: str = DEFAULT_AIKEN_REPOSITORY,
    label: str | None = None,
) -> dict[str, Any]:
    output = output.expanduser().resolve()
    local_source = aiken_source.expanduser().resolve() if aiken_source else None
    resolved = resolve_release_ref(
        ref=ref,
        aiken_source=local_source,
        aiken_repository=aiken_repository,
    )
    expected_version = f"aiken {ref}+{resolved['commit_sha'][:7]}"
    toolchain = _toolchain_environment()
    target = _target_environment(toolchain)
    preliminary_source = {
        "repository_url": resolved["repository_url"],
        "ref": ref,
        "tag_object_sha": resolved["tag_object_sha"],
        "tag_target_type": resolved["tag_target_type"],
        "commit_sha": resolved["commit_sha"],
        "source_tree_git_sha": resolved.get("source_tree_git_sha"),
    }
    existing_path = output / "compiler.json"
    if existing_path.is_file():
        try:
            previous = json.loads(existing_path.read_text(encoding="utf-8"))
            previous_source = previous["source"]
            source_match = all(
                previous_source.get(key) == value
                for key, value in preliminary_source.items()
                if value is not None
            )
            if source_match:
                identity = _build_identity(
                    kind="release",
                    source={
                        key: previous_source[key]
                        for key in (
                            "repository_url",
                            "ref",
                            "tag_object_sha",
                            "tag_target_type",
                            "commit_sha",
                            "source_tree_git_sha",
                            "source_tree_sha256",
                            "cargo_lock_sha256",
                            "required_rust_version",
                            "dirty",
                        )
                    },
                    toolchain=toolchain,
                    target=target,
                )
                cached = _existing_cache(output, _stable_hash(identity))
                if cached is not None:
                    if cached["binary"]["reported_version"] != expected_version:
                        raise RuntimeError(
                            "unexpected Aiken version for "
                            f"{ref}: {cached['binary']['reported_version']}"
                        )
                    return _reuse_cache(output, cached, label or ref)
        except (KeyError, OSError, json.JSONDecodeError, TypeError):
            pass

    _prepare_output(output)
    checkout = output / "source"
    _clone_checkout(local_source, resolved["repository_url"], checkout, resolved["commit_sha"])
    tree = _git(checkout, "rev-parse", "HEAD^{tree}")
    if resolved.get("source_tree_git_sha") not in {None, tree}:
        raise RuntimeError("release source tree changed between resolution and checkout")
    records = _source_manifest(checkout, excluded_paths=(output,))
    source = preliminary_source | {
        "source_tree_git_sha": tree,
        "source_tree_sha256": _source_tree_sha256(records),
        "cargo_lock_sha256": sha256_file(checkout / "Cargo.lock"),
        "required_rust_version": _required_rust_version(checkout),
        "dirty": False,
    }
    identity = _build_identity(kind="release", source=source, toolchain=toolchain, target=target)
    cache_key = _stable_hash(identity)
    target_directory = output / "cargo-target" / _SAFE_LABEL.sub("-", ref).strip("-")
    build, binary = _build_binary(
        checkout=checkout,
        output=output,
        target_directory=target_directory,
        expected_version=expected_version,
    )
    return _write_manifest(
        output=output,
        kind="release",
        label=label or ref,
        source=source,
        toolchain=toolchain,
        target=target,
        cache_key=cache_key,
        build=build,
        binary=binary,
        reproducibility={
            "reproducible_from_commit": True,
            "clean_committed_source": True,
            "bundle": None,
        },
    ) | {"cache_reused": False}


def _untracked_paths(source: Path, *, excluded_paths: Iterable[Path]) -> list[Path]:
    output = _git_bytes(source, "ls-files", "--others", "--exclude-standard", "-z")
    excluded_resolved = tuple(path.resolve() for path in excluded_paths)
    paths: list[Path] = []
    for raw in output.split(b"\0"):
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        path = (source / relative).resolve()
        if any(path == root or root in path.parents for root in excluded_resolved):
            continue
        if any(part in _EXCLUDED_SOURCE_PARTS for part in relative.parts):
            continue
        if path.is_file() or path.is_symlink():
            paths.append(relative)
    return sorted(paths)


def _dirty_bundle(
    *,
    output: Path,
    source: Path,
    diff: bytes,
    untracked: list[Path],
    records: list[dict[str, Any]],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    bundle = output / "reproducibility"
    bundle.mkdir(parents=True, exist_ok=True)
    diff_path = bundle / "tracked.diff"
    diff_path.write_bytes(diff)
    for relative in untracked:
        origin = source / relative
        destination = bundle / "untracked" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if origin.is_symlink():
            destination.symlink_to(os.readlink(origin))
        else:
            shutil.copy2(origin, destination)
    source_manifest_path = bundle / "source-manifest.json"
    _write_json(source_manifest_path, {"schema_version": 1, "records": records})
    metadata_path = bundle / "build-metadata.json"
    _write_json(metadata_path, metadata)
    return {
        "path": bundle.relative_to(output).as_posix(),
        "tracked_diff": diff_path.relative_to(output).as_posix(),
        "tracked_diff_sha256": sha256_file(diff_path),
        "source_manifest": source_manifest_path.relative_to(output).as_posix(),
        "source_manifest_sha256": sha256_file(source_manifest_path),
        "build_metadata": metadata_path.relative_to(output).as_posix(),
        "build_metadata_sha256": sha256_file(metadata_path),
        "untracked_files": [
            {
                "path": relative.as_posix(),
                "sha256": sha256_file(source / relative),
            }
            for relative in untracked
        ],
    }


def build_local(
    *,
    aiken_source: Path,
    output: Path,
    label: str,
    allow_dirty: bool = False,
) -> dict[str, Any]:
    source_path = aiken_source.expanduser().resolve()
    output = output.expanduser().resolve()
    if not (source_path / ".git").exists():
        raise ValueError(f"Aiken source is not a Git checkout: {source_path}")
    head = _git(source_path, "rev-parse", "--verify", "HEAD^{commit}")
    branch_result = run_process(
        ["git", "-C", source_path, "symbolic-ref", "--short", "-q", "HEAD"],
        source_path,
        30.0,
    )
    branch = branch_result.stdout.strip() if branch_result.exit_code == 0 else None
    diff = _git_bytes(source_path, "diff", "--binary", "HEAD", "--")
    untracked = _untracked_paths(source_path, excluded_paths=(output,))
    records = _source_manifest(source_path, excluded_paths=(output,))
    dirty = bool(diff or untracked)
    if dirty and not allow_dirty:
        raise ValueError("local Aiken source is dirty; pass --allow-dirty to preserve source evidence")
    source_tree_sha256 = _source_tree_sha256(records)
    toolchain = _toolchain_environment()
    target = _target_environment(toolchain)
    source = {
        "repository_url": _repository_url(source_path),
        "ref": None,
        "commit_sha": head,
        "branch": branch,
        "detached": branch is None,
        "dirty": dirty,
        "tracked_diff_sha256": hashlib.sha256(diff).hexdigest(),
        "untracked_source_manifest": [
            {"path": relative.as_posix(), "sha256": sha256_file(source_path / relative)}
            for relative in untracked
        ],
        "source_tree_sha256": source_tree_sha256,
        "cargo_lock_sha256": sha256_file(source_path / "Cargo.lock"),
        "required_rust_version": _required_rust_version(source_path),
    }
    identity = _build_identity(kind="local", source=source, toolchain=toolchain, target=target)
    cache_key = _stable_hash(identity)
    cached = _existing_cache(output, cache_key)
    if cached is not None:
        return _reuse_cache(output, cached, label)

    _prepare_output(output)
    checkout = output / "source"
    _clone_checkout(source_path, _repository_url(source_path), checkout, head)
    _copy_complete_source(source_path, checkout, records)
    copied_records = _source_manifest(checkout, excluded_paths=(output,))
    if _source_tree_sha256(copied_records) != source_tree_sha256:
        raise RuntimeError("isolated local source capture does not match the input worktree")
    metadata = {
        "schema_version": 1,
        "head_commit_sha": head,
        "branch": branch,
        "dirty": dirty,
        "source_tree_sha256": source_tree_sha256,
        "cargo_lock_sha256": source["cargo_lock_sha256"],
        "toolchain": toolchain,
        "target": target,
        "build_command": list(BUILD_COMMAND),
    }
    bundle = (
        _dirty_bundle(
            output=output,
            source=source_path,
            diff=diff,
            untracked=untracked,
            records=records,
            metadata=metadata,
        )
        if dirty
        else None
    )
    target_directory = output / "cargo-target" / _SAFE_LABEL.sub("-", label).strip("-")
    build, binary = _build_binary(
        checkout=checkout,
        output=output,
        target_directory=target_directory,
        expected_version=None,
    )
    return _write_manifest(
        output=output,
        kind="local",
        label=label,
        source=source,
        toolchain=toolchain,
        target=target,
        cache_key=cache_key,
        build=build,
        binary=binary,
        reproducibility={
            "reproducible_from_commit": not dirty,
            "clean_committed_source": not dirty,
            "bundle": bundle,
        },
    ) | {"cache_reused": False}
