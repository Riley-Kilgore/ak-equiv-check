from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any, Iterable

from .config import DEFAULT_WORK_ROOT, Compiler, load_blaster_config
from .models import BlasterBackend, BlasterConfig
from .pairing import canonical_json
from .process import run_process
from .runner import compare_package, write_json


def _entries(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    values = manifest.get("packages")
    if values is None:
        values = manifest.get("public_sources")
    if not isinstance(values, list):
        raise ValueError("corpus lock must contain a packages or public_sources array")
    return [row for row in values if isinstance(row, dict)]


def _entry_id(row: dict[str, Any], index: int) -> str:
    value = row.get("id") or row.get("repository") or f"package-{index}"
    return str(value)


def _safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.") or "package"


def _local_candidates(
    manifest_path: Path,
    row: dict[str, Any],
    work_root: Path,
) -> Iterable[Path]:
    explicit = row.get("path") or row.get("package_path")
    if isinstance(explicit, str):
        path = Path(explicit).expanduser()
        yield path if path.is_absolute() else (manifest_path.parent / path).resolve()
    repository = row.get("repository")
    if isinstance(repository, str):
        name = repository.rsplit("/", 1)[-1]
        yield work_root / name
        yield work_root / repository.replace("/", "-")
        yield work_root / repository.replace("/", "__")


def _materialize(
    manifest_path: Path,
    row: dict[str, Any],
    entry_id: str,
    work_root: Path,
) -> tuple[Path | None, str | None]:
    for candidate in _local_candidates(manifest_path, row, work_root):
        if (candidate / "aiken.toml").is_file():
            return candidate.resolve(), None
    url = row.get("url")
    revision = row.get("revision") or row.get("ref")
    if not isinstance(url, str) or not isinstance(revision, str):
        return None, "locked corpus entry has no local path or pinned URL revision"
    identity = hashlib.sha256(f"{url}\0{revision}".encode("utf-8")).hexdigest()[:16]
    checkout = work_root / "corpus-sources" / f"{_safe(entry_id)}-{identity}"
    if not checkout.exists():
        checkout.parent.mkdir(parents=True, exist_ok=True)
        clone = run_process(["git", "clone", "--no-checkout", url, checkout], work_root, 300.0)
        if clone.timed_out or clone.exit_code != 0:
            return None, f"clone failed: {clone.stderr.strip() or clone.stdout.strip()}"
        checkout_result = run_process(
            ["git", "checkout", "--detach", revision], checkout, 120.0
        )
        if checkout_result.timed_out or checkout_result.exit_code != 0:
            shutil.rmtree(checkout)
            return None, f"checkout failed: {checkout_result.stderr.strip() or checkout_result.stdout.strip()}"
    subpath = row.get("package_subpath")
    package = checkout / subpath if isinstance(subpath, str) else checkout
    if (package / "aiken.toml").is_file():
        return package.resolve(), None
    manifests = sorted(checkout.rglob("aiken.toml"))
    if len(manifests) == 1:
        return manifests[0].parent.resolve(), None
    return None, f"checkout contains {len(manifests)} Aiken packages; package_subpath is required"


def run_corpus(
    manifest_path: Path,
    compilers: tuple[Compiler, Compiler],
    *,
    work_root: Path = DEFAULT_WORK_ROOT,
    strict: bool = False,
    only: set[str] | None = None,
    blaster_config: BlasterConfig | None = None,
    backend: BlasterBackend | None = None,
) -> dict[str, Any]:
    manifest_path = manifest_path.expanduser().resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    config = blaster_config or load_blaster_config()
    selected = [
        (index, row, _entry_id(row, index))
        for index, row in enumerate(_entries(manifest))
        if only is None or _entry_id(row, index) in only
    ]
    manifest_hash = hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest()
    corpus_root = work_root.expanduser().resolve() / "corpus-runs" / manifest_hash
    corpus_root.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for _index, row, entry_id in selected:
        package, error = _materialize(
            manifest_path, row, entry_id, work_root.expanduser().resolve()
        )
        if package is None:
            results.append(
                {
                    "id": entry_id,
                    "status": "source_unavailable",
                    "strict_pass": False,
                    "error": error,
                    "output": None,
                }
            )
            continue
        try:
            summary = compare_package(
                package,
                compilers,
                work_root=work_root,
                strict=strict,
                blaster_config=config,
                backend=backend,
            )
            results.append(
                {
                    "id": entry_id,
                    "status": "completed",
                    "strict_pass": summary["strict_pass"],
                    "error": None,
                    "output": summary["output"],
                    "run_id": summary["run_id"],
                }
            )
        except (FileNotFoundError, RuntimeError, ValueError) as error_value:
            results.append(
                {
                    "id": entry_id,
                    "status": "runner_error",
                    "strict_pass": False,
                    "error": str(error_value),
                    "output": None,
                }
            )
    report = {
        "schema_version": 1,
        "manifest": str(manifest_path),
        "manifest_sha256": manifest_hash,
        "selected_count": len(selected),
        "completed_count": sum(row["status"] == "completed" for row in results),
        "strict_requested": strict,
        "strict_pass": bool(results) and all(row["strict_pass"] for row in results),
        "results": results,
    }
    write_json(corpus_root / "summary.json", report)
    return report
