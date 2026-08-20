#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DOWNLOADS = ROOT / "work" / "downloads"
BIN = ROOT / "bin"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def platform_key() -> str:
    return f"{platform.system().lower()}-{platform.machine().lower()}"


def download(url: str, expected_sha256: str) -> Path:
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    destination = DOWNLOADS / f"{expected_sha256}-{url.rsplit('/', 1)[-1]}"
    if not destination.is_file() or sha256_file(destination) != expected_sha256:
        temporary = destination.with_suffix(destination.suffix + ".partial")
        temporary.unlink(missing_ok=True)
        with urllib.request.urlopen(url) as response, temporary.open("wb") as output:
            shutil.copyfileobj(response, output)
        actual = sha256_file(temporary)
        if actual != expected_sha256:
            temporary.unlink(missing_ok=True)
            raise RuntimeError(
                f"archive hash mismatch for {url}: expected {expected_sha256}, got {actual}"
            )
        temporary.replace(destination)
    return destination


def extract(archive: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as source:
            source.extractall(destination)
    else:
        with tarfile.open(archive, "r:gz") as source:
            source.extractall(destination)


def install_aiken(label: str, configured: dict[str, Any], key: str) -> Path:
    artifact = configured["artifacts"][key]
    archive = download(artifact["url"], artifact["archive_sha256"])
    destination = ROOT / "work" / "toolchains" / f"aiken-{configured['release']}-{key}"
    candidates = list(destination.rglob("aiken")) if destination.exists() else []
    if len(candidates) != 1 or sha256_file(candidates[0]) != artifact["binary_sha256"]:
        extract(archive, destination)
        candidates = [candidate for candidate in destination.rglob("aiken") if candidate.is_file()]
    if len(candidates) != 1:
        raise RuntimeError(f"expected one aiken binary in {archive}, found {len(candidates)}")
    executable = candidates[0]
    actual = sha256_file(executable)
    if actual != artifact["binary_sha256"]:
        raise RuntimeError(
            f"{label} compiler hash mismatch: expected {artifact['binary_sha256']}, got {actual}"
        )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    BIN.mkdir(parents=True, exist_ok=True)
    link = BIN / f"aiken-{configured['release']}"
    link.unlink(missing_ok=True)
    link.symlink_to(os.path.relpath(executable, BIN))
    return link


def install_z3(configured: dict[str, Any], key: str) -> Path:
    artifact = configured["solver_artifacts"][key]
    archive = download(artifact["url"], artifact["archive_sha256"])
    executable = ROOT / artifact["path"]
    if not executable.is_file() or sha256_file(executable) != artifact["binary_sha256"]:
        solver_root = executable.parent.parent
        shutil.rmtree(solver_root, ignore_errors=True)
        solver_root.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as source:
            source.extractall(solver_root.parent)
    if not executable.is_file():
        raise RuntimeError(f"Z3 archive did not create {executable}")
    actual = sha256_file(executable)
    if actual != artifact["binary_sha256"]:
        raise RuntimeError(
            f"Z3 hash mismatch: expected {artifact['binary_sha256']}, got {actual}"
        )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return executable


def main() -> int:
    key = platform_key()
    pair = json.loads((ROOT / "corpus" / "compiler_pair.json").read_text())
    blaster = json.loads((ROOT / "tool" / "blaster_config.json").read_text())
    if key not in pair["old"]["artifacts"] or key not in pair["new"]["artifacts"]:
        raise RuntimeError(f"no pinned Aiken compiler artifacts for {key}")
    if key not in blaster["solver_artifacts"]:
        raise RuntimeError(f"no pinned Z3 artifact for {key}")
    old = install_aiken("old", pair["old"], key)
    new = install_aiken("new", pair["new"], key)
    z3 = install_z3(blaster, key)
    print(json.dumps({"platform": key, "old_aiken": str(old), "new_aiken": str(new), "z3": str(z3)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
