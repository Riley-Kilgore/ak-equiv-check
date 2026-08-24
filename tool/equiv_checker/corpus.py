from __future__ import annotations

import hashlib
import json
import re
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator

from .config import DEFAULT_WORK_ROOT, TOOL_ROOT, Compiler, load_blaster_config, sha256_file
from .models import STRICT_PASSING_STATUSES, BlasterBackend, BlasterConfig
from .pairing import canonical_json
from .process import ProcessResult, run_process, write_process_logs
from .runner import (
    checker_implementation_sha256,
    compare_package,
    hash_package_tree,
    write_json,
)


CORPUS_LOCK_SCHEMA = TOOL_ROOT / "schemas" / "corpus-lock.schema.json"
SUPPORTED_LANES = frozenset(
    {"compile", "check", "bench", "config", "docs", "equivalence", "negative-diagnostic"}
)
LANE_STRICT_POLICY = {
    "compile": "both_compilers_must_succeed",
    "check": "both_compilers_must_succeed",
    "bench": "both_compilers_must_succeed",
    "config": "both_compilers_must_succeed",
    "docs": "both_compilers_must_succeed_nonsemantic",
    "equivalence": "every_required_pair_must_pass_raw_model",
    "negative-diagnostic": "both_compilers_must_emit_expected_diagnostic",
}


def _safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.") or "package"


def _hash_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _tree_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file())


def _tree_hash(root: Path) -> str | None:
    if not root.is_dir():
        return None
    rows = [
        {"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path)}
        for path in _tree_files(root)
    ]
    return _hash_json(rows)


def _schema_error_message(error: Any) -> str:
    location = "/".join(str(part) for part in error.absolute_path) or "$"
    return f"{location}: {error.message}"


def load_corpus_lock(path: Path) -> dict[str, Any]:
    lock_path = path.expanduser().resolve()
    value = json.loads(lock_path.read_text(encoding="utf-8"))
    schema = json.loads(CORPUS_LOCK_SCHEMA.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(value),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        raise ValueError(
            "invalid corpus lock:\n" + "\n".join(_schema_error_message(error) for error in errors)
        )

    source_ids: set[str] = set()
    target_ids: set[str] = set()
    semantic_errors: list[str] = []
    for source in value["sources"]:
        source_id = source["id"]
        if source_id in source_ids:
            semantic_errors.append(f"duplicate source id: {source_id}")
        source_ids.add(source_id)
        for target in source["targets"]:
            target_id = target["id"]
            if target_id in target_ids:
                semantic_errors.append(f"duplicate target id: {target_id}")
            target_ids.add(target_id)
            lanes = set(target["lanes"])
            if not lanes <= SUPPORTED_LANES:
                semantic_errors.append(f"unsupported lanes for {target_id}: {sorted(lanes - SUPPORTED_LANES)}")
            if "negative-diagnostic" in lanes and target.get("expected_outcome", "success") != "diagnostic":
                semantic_errors.append(
                    f"target {target_id} uses negative-diagnostic without expected_outcome=diagnostic"
                )
            if target.get("expected_outcome") == "diagnostic" and "negative-diagnostic" not in lanes:
                semantic_errors.append(
                    f"target {target_id} expects a diagnostic without the negative-diagnostic lane"
                )
            if "negative-diagnostic" in lanes and not target.get("expected_diagnostic"):
                semantic_errors.append(f"target {target_id} has no expected_diagnostic expression")
    if semantic_errors:
        raise ValueError("invalid corpus lock:\n" + "\n".join(sorted(semantic_errors)))
    return value


def _checkout_path(work_root: Path, source: dict[str, Any]) -> Path:
    return work_root / "corpus-sources" / f"{_safe(source['id'])}-{source['revision'][:16]}"


def _git_head(checkout: Path) -> str | None:
    result = run_process(["git", "rev-parse", "HEAD"], checkout, 30.0)
    if result.timed_out or result.exit_code != 0:
        return None
    return result.stdout.strip()


def _materialize_source(
    source: dict[str, Any], work_root: Path
) -> tuple[Path | None, str, str | None]:
    checkout = _checkout_path(work_root, source)
    expected = source["revision"]
    if checkout.exists():
        actual = _git_head(checkout)
        if actual != expected:
            return None, "source_revision_mismatch", f"expected {expected}, found {actual or 'unreadable'}"
        return checkout.resolve(), "resolved", None

    checkout.parent.mkdir(parents=True, exist_ok=True)
    clone = run_process(
        ["git", "clone", "--filter=blob:none", "--no-checkout", source["url"], checkout],
        work_root,
        300.0,
        environment={
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/usr/bin/false",
            "SSH_ASKPASS": "/usr/bin/false",
        },
    )
    if clone.timed_out or clone.exit_code != 0:
        if checkout.exists():
            shutil.rmtree(checkout)
        detail = clone.stderr.strip() or clone.stdout.strip() or "no diagnostic"
        return None, "source_checkout_failed", detail
    checked_out = run_process(["git", "checkout", "--detach", expected], checkout, 180.0)
    if checked_out.timed_out or checked_out.exit_code != 0:
        shutil.rmtree(checkout)
        detail = checked_out.stderr.strip() or checked_out.stdout.strip() or "no diagnostic"
        return None, "source_checkout_failed", detail
    actual = _git_head(checkout)
    if actual != expected:
        return None, "source_revision_mismatch", f"expected {expected}, found {actual or 'unreadable'}"
    return checkout.resolve(), "resolved", None


def _adapter_root(adapter_id: str) -> Path:
    return TOOL_ROOT.parent / "corpus" / "adapters" / adapter_id


def adapter_identity(adapter_id: str | None) -> dict[str, Any] | None:
    if adapter_id is None:
        return None
    root = _adapter_root(adapter_id)
    metadata_path = root / "adapter.json"
    if not metadata_path.is_file():
        raise ValueError(f"adapter {adapter_id} is missing {metadata_path}")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("id") != adapter_id:
        raise ValueError(f"adapter id mismatch for {adapter_id}")
    if not isinstance(metadata.get("version"), int) or metadata["version"] <= 0:
        raise ValueError(f"adapter {adapter_id} must have a positive integer version")
    files = [
        {"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path)}
        for path in _tree_files(root)
    ]
    return {
        "id": adapter_id,
        "version": metadata["version"],
        "files": files,
        "adapter_sha256": _hash_json(files),
        "overlay_sha256": _tree_hash(root / "overlay"),
        "patch_sha256": _tree_hash(root / "patches"),
        "harness_sha256": _tree_hash(root / "harness"),
        "target_package": metadata.get("target_package", "."),
        "imported_source_modules": sorted(metadata.get("imported_source_modules", [])),
    }


def _expanded_targets(
    source: dict[str, Any], checkout: Path
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    expanded: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for target in source["targets"]:
        if "package_subpath" in target:
            relative = Path(target["package_subpath"])
            package = checkout / relative
            if not (package / "aiken.toml").is_file():
                nested = sorted(package.rglob("aiken.toml")) if package.is_dir() else []
                classification = "ambiguous_package_discovery" if len(nested) > 1 else "missing_package_path"
                errors.append(
                    {
                        "source_id": source["id"],
                        "target_id": target["id"],
                        "classification": classification,
                        "detail": target["package_subpath"],
                    }
                )
                continue
            expanded.append(target | {"package_subpath": relative.as_posix()})
            continue

        matches = sorted(
            path
            for path in checkout.glob(target["package_glob"])
            if path.is_file() and path.name == "aiken.toml"
        )
        if not matches:
            errors.append(
                {
                    "source_id": source["id"],
                    "target_id": target["id"],
                    "classification": "missing_package_path",
                    "detail": target["package_glob"],
                }
            )
            continue
        seen_subpaths: set[str] = set()
        for manifest in matches:
            relative = manifest.parent.relative_to(checkout).as_posix() or "."
            if relative in seen_subpaths:
                errors.append(
                    {
                        "source_id": source["id"],
                        "target_id": target["id"],
                        "classification": "ambiguous_package_discovery",
                        "detail": relative,
                    }
                )
                continue
            seen_subpaths.add(relative)
            suffix = relative.replace("/", "--").replace(".", "root")
            expanded.append(
                {key: value for key, value in target.items() if key != "package_glob"}
                | {"id": f"{target['id']}:{suffix}", "package_subpath": relative}
            )
    return expanded, errors


def plan_corpus(
    lock_path: Path,
    *,
    work_root: Path = DEFAULT_WORK_ROOT,
    resolve_sources: bool = True,
) -> dict[str, Any]:
    path = lock_path.expanduser().resolve()
    lock = load_corpus_lock(path)
    root = work_root.expanduser().resolve()
    lock_hash = _hash_json(lock)
    source_records: list[dict[str, Any]] = []
    tasks: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    for source in lock["sources"]:
        checkout: Path | None
        if resolve_sources:
            checkout, status, detail = _materialize_source(source, root)
        else:
            candidate = _checkout_path(root, source)
            checkout = candidate if candidate.is_dir() else None
            status = "resolved" if checkout else "source_checkout_required"
            detail = None
        source_record = {
            "id": source["id"],
            "url": source["url"],
            "revision": source["revision"],
            "tag": source.get("tag"),
            "status": status,
        }
        if detail:
            source_record["detail"] = detail
        source_records.append(source_record)
        if checkout is None:
            errors.append(
                {
                    "source_id": source["id"],
                    "target_id": "",
                    "classification": status,
                    "detail": detail or "source is not materialized",
                }
            )
            continue

        expanded, expansion_errors = _expanded_targets(source, checkout)
        errors.extend(expansion_errors)
        for target in expanded:
            try:
                adapter = adapter_identity(target.get("adapter"))
            except (OSError, ValueError, json.JSONDecodeError) as error:
                errors.append(
                    {
                        "source_id": source["id"],
                        "target_id": target["id"],
                        "classification": "adapter_failed",
                        "detail": str(error),
                    }
                )
                continue
            package = checkout / target["package_subpath"]
            package_hash = hash_package_tree(package, include_lock=False)
            lock_file = package / "aiken.lock"
            dependency_lock_hash = sha256_file(lock_file) if lock_file.is_file() else None
            for lane in target["lanes"]:
                payload = {
                    "source": {
                        "url": source["url"].removesuffix(".git"),
                        "revision": source["revision"],
                    },
                    "target_id": target["id"],
                    "package_subpath": target["package_subpath"],
                    "source_hash": package_hash,
                    "dependency_lock_hash": dependency_lock_hash,
                    "adapter_hash": adapter["adapter_sha256"] if adapter else None,
                    "lane": lane,
                }
                tasks.append(
                    {
                        "task_id": _hash_json(payload),
                        "source_id": source["id"],
                        "target_id": target["id"],
                        "package_subpath": target["package_subpath"],
                        "source_type": target["source_type"],
                        "lane": lane,
                        "expected_outcome": target.get("expected_outcome", "success"),
                        "expected_diagnostic": target.get("expected_diagnostic"),
                        "timeout_seconds": target.get("timeout_seconds"),
                        "equivalence_required": target.get(
                            "equivalence_required",
                            target["source_type"] in {"validator", "library-harness"},
                        ),
                        "feature_ids": sorted(target.get("feature_ids", [])),
                        "source_hash": package_hash,
                        "dependency_lock_hash": dependency_lock_hash,
                        "adapter": adapter,
                    }
                )

    source_records.sort(key=lambda row: row["id"])
    tasks.sort(key=lambda row: (row["source_id"], row["target_id"], row["lane"]))
    errors.sort(key=lambda row: (row["source_id"], row["target_id"], row["classification"], row["detail"]))
    logical_plan = {
        "schema_version": 1,
        "lock_sha256": lock_hash,
        "compiler_baseline": lock["compiler_baseline"],
        "sources": source_records,
        "tasks": tasks,
        "errors": errors,
    }
    return logical_plan | {
        "plan_id": _hash_json(logical_plan),
        "valid": not errors,
        "source_count": len(source_records),
        "target_count": len({row["target_id"] for row in tasks}),
        "task_count": len(tasks),
    }


def _copy_overlay(source: Path, destination: Path) -> None:
    for path in _tree_files(source):
        relative = path.relative_to(source)
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, output)


def _apply_adapter(
    checkout: Path,
    package_subpath: str,
    adapter: dict[str, Any] | None,
    destination: Path,
) -> tuple[Path | None, dict[str, Any]]:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(checkout, destination, ignore=shutil.ignore_patterns(".git"))
    package = destination / package_subpath
    if adapter is None:
        return package, {"status": "not_applicable", "identity": None}
    root = _adapter_root(adapter["id"])
    target_relative = adapter.get("target_package", ".")
    target_package = package if target_relative == "." else destination / target_relative
    try:
        if (root / "overlay").is_dir():
            _copy_overlay(root / "overlay", target_package)
        if (root / "harness").is_dir():
            _copy_overlay(root / "harness", target_package)
        patches = (
            sorted((root / "patches").glob("*.patch"))
            if (root / "patches").is_dir()
            else []
        )
        patch_records: list[dict[str, Any]] = []
        if patches:
            initialized = run_process(["git", "init", "--quiet"], destination, 30.0)
            if initialized.timed_out or initialized.exit_code != 0:
                return None, {
                    "status": "adapter_failed",
                    "identity": adapter,
                    "detail": initialized.stderr.strip() or "failed to initialize isolated patch tree",
                }
        try:
            for patch in patches:
                result = run_process(["git", "apply", "--check", patch], destination, 30.0)
                if result.timed_out or result.exit_code != 0:
                    return None, {
                        "status": "adapter_failed",
                        "identity": adapter,
                        "detail": result.stderr.strip() or result.stdout.strip(),
                    }
                applied = run_process(["git", "apply", patch], destination, 30.0)
                if applied.timed_out or applied.exit_code != 0:
                    return None, {
                        "status": "adapter_failed",
                        "identity": adapter,
                        "detail": applied.stderr.strip() or applied.stdout.strip(),
                    }
                patch_records.append({"path": patch.name, "sha256": sha256_file(patch)})
        finally:
            if patches:
                shutil.rmtree(destination / ".git", ignore_errors=True)
        return target_package, {
            "status": "applied",
            "identity": adapter,
            "patches": patch_records,
        }
    except OSError as error:
        return None, {"status": "adapter_failed", "identity": adapter, "detail": str(error)}


def _lane_command(lane: str, compiler: Compiler) -> list[str]:
    executable = str(compiler.executable)
    if lane in {"compile", "config"}:
        return [executable, "build", "--out", "plutus.json"]
    if lane == "check" or lane == "negative-diagnostic":
        return [executable, "check"]
    if lane == "bench":
        return [executable, "bench"]
    if lane == "docs":
        return [executable, "docs"]
    raise ValueError(f"lane {lane} has no direct compiler command")


def _run_lane_compiler(
    lane: str,
    compiler: Compiler,
    package: Path,
    lane_root: Path,
    timeout: float,
) -> dict[str, Any]:
    compiler_package = lane_root / compiler.label / "package"
    shutil.copytree(package, compiler_package)
    command = _lane_command(lane, compiler)
    result = run_process(command, compiler_package, timeout, inherit_environment=False)
    logs = lane_root / "logs"
    stdout_path = logs / f"{compiler.label}.stdout.log"
    stderr_path = logs / f"{compiler.label}.stderr.log"
    write_process_logs(result, stdout_path, stderr_path)
    return result.to_dict() | {
        "compiler": compiler.identity(),
        "command": command,
        "timeout_seconds": timeout,
        "stdout_path": stdout_path.relative_to(lane_root).as_posix(),
        "stderr_path": stderr_path.relative_to(lane_root).as_posix(),
        "stdout_sha256": sha256_file(stdout_path),
        "stderr_sha256": sha256_file(stderr_path),
        "diagnostic_text": (result.stdout + "\n" + result.stderr).strip(),
        "environment_inherited": False,
    }


def _materialize_dependency_lock(
    package: Path,
    compiler: Compiler,
    task_root: Path,
    timeout: float,
) -> dict[str, Any]:
    lock_path = package / "aiken.lock"
    if lock_path.is_file():
        return {
            "status": "already_locked",
            "compiler": compiler.identity(),
            "dependency_lock_sha256": sha256_file(lock_path),
            "command": None,
            "exit_code": None,
            "timed_out": False,
        }
    materialization_root = task_root / "dependency-materialization"
    compiler_package = materialization_root / "package"
    if materialization_root.exists():
        shutil.rmtree(materialization_root)
    compiler_package.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(package, compiler_package)
    command = [str(compiler.executable), "check"]
    process = run_process(
        command,
        compiler_package,
        timeout,
        inherit_environment=False,
    )
    logs = materialization_root / "logs"
    stdout_path = logs / "stdout.log"
    stderr_path = logs / "stderr.log"
    write_process_logs(process, stdout_path, stderr_path)
    generated_lock = compiler_package / "aiken.lock"
    status = (
        "materialized"
        if process.exit_code == 0
        and not process.timed_out
        and generated_lock.is_file()
        else "materialization_failed"
    )
    lock_sha256 = (
        sha256_file(generated_lock)
        if status == "materialized"
        else None
    )
    if status == "materialized":
        shutil.copy2(generated_lock, lock_path)
    return {
        "status": status,
        "compiler": compiler.identity(),
        "dependency_lock_sha256": lock_sha256,
        "command": command,
        "exit_code": process.exit_code,
        "timed_out": process.timed_out,
        "duration_seconds": process.duration_seconds,
        "stdout_path": stdout_path.relative_to(task_root).as_posix(),
        "stderr_path": stderr_path.relative_to(task_root).as_posix(),
        "stdout_sha256": sha256_file(stdout_path),
        "stderr_sha256": sha256_file(stderr_path),
        "process_group_termination_succeeded": (
            process.process_group_termination_succeeded
        ),
    }


def _direct_lane_classification(
    task: dict[str, Any], old: dict[str, Any], new: dict[str, Any]
) -> tuple[str, bool]:
    lane = task["lane"]
    if lane == "negative-diagnostic":
        expression = re.compile(task["expected_diagnostic"])
        old_match = old["exit_code"] not in {None, 0} and bool(expression.search(old["diagnostic_text"]))
        new_match = new["exit_code"] not in {None, 0} and bool(expression.search(new["diagnostic_text"]))
        if old_match and new_match:
            return "expected_negative_diagnostic", True
        if not old_match:
            return "old_lane_failed", False
        return "new_lane_failed", False
    if old["timed_out"] or old["exit_code"] != 0:
        return ("old_build_failed" if lane in {"compile", "config"} else "old_lane_failed"), False
    if new["timed_out"] or new["exit_code"] != 0:
        return ("new_build_failed" if lane in {"compile", "config"} else "new_lane_failed"), False
    return {
        "compile": "compile_passed",
        "check": "check_passed",
        "bench": "benchmark_passed",
        "config": "configuration_passed",
        "docs": "documentation_passed",
    }[lane], True


def _has_validator_sources(package: Path) -> bool:
    root = package / "validators"
    return root.is_dir() and any(root.rglob("*.ak"))


def _equivalence_lane(
    task: dict[str, Any],
    package: Path,
    compilers: tuple[Compiler, Compiler],
    work_root: Path,
    strict: bool,
    config: BlasterConfig,
    backend: BlasterBackend | None,
    resume: bool,
    force: bool,
    only_pairs: set[str] | None,
    source_identity: dict[str, Any],
) -> dict[str, Any]:
    if not _has_validator_sources(package) and not task["equivalence_required"]:
        return {
            "classification": "not_applicable",
            "strict_pass": True,
            "old_result": None,
            "new_result": None,
            "semantic_summary": None,
        }
    summary = compare_package(
        package,
        compilers,
        work_root=work_root,
        strict=strict,
        blaster_config=config,
        backend=backend,
        resume=resume,
        force=force,
        only_pairs=only_pairs,
        source_identity_override=source_identity,
    )
    output = Path(summary["output"])
    old_result = json.loads((output / "build-old.json").read_text(encoding="utf-8"))
    new_result = json.loads((output / "build-new.json").read_text(encoding="utf-8"))
    pair_data = json.loads((output / "pair-results.json").read_text(encoding="utf-8"))
    evaluated_rows = [
        row
        for row in pair_data["records"]
        if not only_pairs or row["program_pair_id"] in only_pairs
    ]
    if (
        not task["equivalence_required"]
        and not evaluated_rows
        and summary["counts"]["validator_records_old"] == 0
        and summary["counts"]["validator_records_new"] == 0
        and old_result["primary_exit_code"] == 0
        and new_result["primary_exit_code"] == 0
    ):
        return {
            "classification": "not_applicable",
            "strict_pass": True,
            "old_result": old_result,
            "new_result": new_result,
            "semantic_summary": summary,
        }

    lane_strict_pass = (
        not summary["gaps"]
        and bool(evaluated_rows)
        and all(row["status"] in STRICT_PASSING_STATUSES for row in evaluated_rows)
    )
    classification = "equivalence_passed"
    if not lane_strict_pass:
        nonpassing = [
            row["status"]
            for row in evaluated_rows
            if row["status"] not in STRICT_PASSING_STATUSES
        ]
        classification = (
            nonpassing[0]
            if nonpassing
            else summary["gaps"][0]
            if summary["gaps"]
            else "lane_failed"
        )
    return {
        "classification": classification,
        "strict_pass": lane_strict_pass,
        "old_result": old_result,
        "new_result": new_result,
        "semantic_summary": summary,
    }


def _execute_task(
    task: dict[str, Any],
    source: dict[str, Any],
    compilers: tuple[Compiler, Compiler],
    corpus_root: Path,
    work_root: Path,
    strict: bool,
    config: BlasterConfig,
    backend: BlasterBackend | None,
    resume: bool,
    force: bool,
    only_pairs: set[str] | None,
) -> dict[str, Any]:
    checkout = _checkout_path(work_root, source)
    task_root = corpus_root / "tasks" / task["task_id"]
    staging = task_root / "source"
    package, adapter_record = _apply_adapter(
        checkout, task["package_subpath"], task["adapter"], staging
    )
    adapter_identity = adapter_record.get("identity")
    adapter_hash = (
        adapter_identity.get("adapter_sha256")
        if isinstance(adapter_identity, dict)
        else None
    )
    source_identity_fields = {
        "canonical_repository_url": source["url"],
        "revision": source["revision"],
        "package_subpath": task["package_subpath"],
        "source_hash": task["source_hash"],
        "dependency_lock_hash": task["dependency_lock_hash"],
        "adapter_hash": adapter_hash,
    }
    source_identity = {
        "kind": "locked_corpus",
        "identity": _hash_json(source_identity_fields),
        "identity_fields": source_identity_fields,
        "repository_root": None,
        "package_path": task["package_subpath"],
        "commit": source["revision"],
        "dirty": False,
        "remote": source["url"],
    }
    base = {
        "schema_version": 1,
        "task_id": task["task_id"],
        "source_id": task["source_id"],
        "target_id": task["target_id"],
        "package_subpath": task["package_subpath"],
        "lane": task["lane"],
        "expected_outcome": task["expected_outcome"],
        "strict_policy": LANE_STRICT_POLICY[task["lane"]],
        "adapter": adapter_record,
        "source_hash": task["source_hash"],
        "dependency_lock_hash": task["dependency_lock_hash"],
        "execution_policy": {
            "isolated_source_copy": True,
            "inherited_environment": False,
            "network": (
                "available only to the Aiken compiler for dependency "
                "materialization; source files are never executed"
            ),
        },
    }
    if package is None:
        result = base | {
            "classification": "adapter_failed",
            "strict_pass": False,
            "old_result": None,
            "new_result": None,
        }
        write_json(task_root / "result.json", result)
        return result

    if task["lane"] == "equivalence":
        materialization = _materialize_dependency_lock(
            package,
            compilers[0],
            task_root,
            float(task["timeout_seconds"] or config.timeouts.aiken_build),
        )
        base["dependency_materialization"] = materialization
        if materialization["status"] == "materialization_failed":
            result = base | {
                "classification": "dependency_materialization_failed",
                "strict_pass": False,
                "old_result": None,
                "new_result": None,
            }
            write_json(task_root / "result.json", result)
            return result
        effective_lock_hash = materialization["dependency_lock_sha256"]
        base["dependency_lock_hash"] = effective_lock_hash
        source_identity_fields["dependency_lock_hash"] = effective_lock_hash
        source_identity["identity"] = _hash_json(source_identity_fields)

    source_before = hash_package_tree(checkout / task["package_subpath"], include_lock=True)
    if task["lane"] == "equivalence":
        lane_result = _equivalence_lane(
            task,
            package,
            compilers,
            work_root,
            strict,
            config,
            backend,
            resume,
            force,
            only_pairs,
            source_identity,
        )
        result = base | lane_result
    else:
        timeout = float(task["timeout_seconds"] or config.timeouts.aiken_build)
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                compiler.label: executor.submit(
                    _run_lane_compiler, task["lane"], compiler, package, task_root, timeout
                )
                for compiler in compilers
            }
            compiler_results = {label: future.result() for label, future in futures.items()}
        classification, strict_pass = _direct_lane_classification(
            task, compiler_results["old"], compiler_results["new"]
        )
        result = base | {
            "classification": classification,
            "strict_pass": strict_pass,
            "old_result": compiler_results["old"],
            "new_result": compiler_results["new"],
        }
    source_after = hash_package_tree(checkout / task["package_subpath"], include_lock=True)
    result["source_immutable"] = source_before == source_after
    if not result["source_immutable"]:
        result["classification"] = "source_mutated"
        result["strict_pass"] = False
    write_json(task_root / "result.json", result)
    return result


def _legacy_entries(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    values = manifest.get("packages")
    if not isinstance(values, list):
        raise ValueError("legacy corpus lock must contain a packages array")
    return [row for row in values if isinstance(row, dict)]


def _legacy_materialize(
    manifest_path: Path, row: dict[str, Any], entry_id: str, work_root: Path
) -> tuple[Path | None, str | None]:
    explicit = row.get("path") or row.get("package_path")
    if isinstance(explicit, str):
        path = Path(explicit).expanduser()
        candidate = path if path.is_absolute() else (manifest_path.parent / path).resolve()
        if (candidate / "aiken.toml").is_file():
            return candidate, None
    return None, f"legacy corpus entry {entry_id} has no local Aiken package"


def _run_legacy_corpus(
    manifest_path: Path,
    compilers: tuple[Compiler, Compiler],
    *,
    work_root: Path,
    strict: bool,
    only: set[str] | None,
    config: BlasterConfig,
    backend: BlasterBackend | None,
) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    selected = [
        (index, row, str(row.get("id") or f"package-{index}"))
        for index, row in enumerate(_legacy_entries(manifest))
        if only is None or str(row.get("id") or f"package-{index}") in only
    ]
    results: list[dict[str, Any]] = []
    for _index, row, entry_id in selected:
        package, error = _legacy_materialize(manifest_path, row, entry_id, work_root)
        if package is None:
            results.append({"id": entry_id, "status": "source_unavailable", "strict_pass": False, "error": error, "output": None})
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
            results.append({"id": entry_id, "status": "completed", "strict_pass": summary["strict_pass"], "error": None, "output": summary["output"], "run_id": summary["run_id"]})
        except (FileNotFoundError, RuntimeError, ValueError) as error_value:
            results.append({"id": entry_id, "status": "runner_error", "strict_pass": False, "error": str(error_value), "output": None})
    report = {
        "schema_version": 1,
        "manifest": str(manifest_path),
        "manifest_sha256": _hash_json(manifest),
        "selected_count": len(selected),
        "completed_count": sum(row["status"] == "completed" for row in results),
        "strict_requested": strict,
        "strict_pass": bool(results) and all(row["strict_pass"] for row in results),
        "results": results,
    }
    write_json(work_root / "corpus-runs" / report["manifest_sha256"] / "summary.json", report)
    return report


def run_corpus(
    manifest_path: Path,
    compilers: tuple[Compiler, Compiler],
    *,
    work_root: Path = DEFAULT_WORK_ROOT,
    strict: bool = False,
    only: set[str] | None = None,
    only_pair: set[str] | None = None,
    shard_index: int | None = None,
    shard_count: int | None = None,
    jobs: int = 1,
    resume: bool = False,
    force: bool = False,
    blaster_config: BlasterConfig | None = None,
    backend: BlasterBackend | None = None,
) -> dict[str, Any]:
    path = manifest_path.expanduser().resolve()
    root = work_root.expanduser().resolve()
    config = blaster_config or load_blaster_config()
    raw_manifest = json.loads(path.read_text(encoding="utf-8"))
    if raw_manifest.get("schema_version") != 2:
        return _run_legacy_corpus(
            path,
            compilers,
            work_root=root,
            strict=strict,
            only=only,
            config=config,
            backend=backend,
        )
    if (shard_index is None) != (shard_count is None):
        raise ValueError("--shard-index and --shard-count must be provided together")
    if shard_count is not None and (shard_count <= 0 or shard_index is None or not 0 <= shard_index < shard_count):
        raise ValueError("shard index must satisfy 0 <= index < shard count")
    if jobs <= 0:
        raise ValueError("--jobs must be positive")

    plan = plan_corpus(path, work_root=root)
    if not plan["valid"]:
        return {
            "schema_version": 2,
            "plan_id": plan["plan_id"],
            "strict_requested": strict,
            "strict_pass": False,
            "classification": "corpus_plan_failed",
            "plan": plan,
            "results": [],
        }
    lock = load_corpus_lock(path)
    source_by_id = {source["id"]: source for source in lock["sources"]}
    tasks = [
        task
        for task in plan["tasks"]
        if only is None or task["target_id"] in only or task["source_id"] in only
    ]
    if shard_count is not None and shard_index is not None:
        tasks = [task for task in tasks if int(task["task_id"], 16) % shard_count == shard_index]
    compiler_hashes = {compiler.label: compiler.binary_sha256 for compiler in compilers}
    run_identity = _hash_json(
        {
            "plan_id": plan["plan_id"],
            "compiler_hashes": compiler_hashes,
            "blaster": config.identity(),
            "runner_sha256": checker_implementation_sha256(),
        }
    )
    corpus_root = root / "corpus-runs" / run_identity
    corpus_existed = corpus_root.is_dir()
    if corpus_existed and not (resume or force):
        raise ValueError(f"corpus run already exists: {corpus_root}; use --resume or --force")
    if only_pair and not corpus_existed:
        raise ValueError(
            f"no completed corpus evidence exists for --only-pair: {corpus_root}"
        )
    corpus_root.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    selected_pair_results: list[dict[str, Any]] = []
    if only_pair:
        if not (resume or force):
            raise ValueError("--only-pair requires --resume or --force")
        requested_pairs = set(only_pair)
        matched_task_ids: set[str] = set()
        for task in tasks:
            if task["lane"] != "equivalence":
                continue
            task_result_path = (
                corpus_root / "tasks" / task["task_id"] / "result.json"
            )
            if not task_result_path.is_file():
                continue
            task_result = json.loads(task_result_path.read_text(encoding="utf-8"))
            semantic_summary = task_result.get("semantic_summary")
            if not isinstance(semantic_summary, dict):
                continue
            output_value = semantic_summary.get("output")
            if not isinstance(output_value, str):
                continue
            aggregate_path = Path(output_value) / "pair-results.json"
            if not aggregate_path.is_file():
                continue
            aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
            for row in aggregate.get("records", []):
                if row.get("program_pair_id") in requested_pairs:
                    selected_pair_results.append(row)
                    matched_task_ids.add(task["task_id"])
        found_pairs = {row["program_pair_id"] for row in selected_pair_results}
        missing_pairs = sorted(requested_pairs - found_pairs)
        if missing_pairs:
            raise ValueError(
                "missing final evidence for requested pair(s): "
                + ", ".join(missing_pairs)
            )
        tasks = [task for task in tasks if task["task_id"] in matched_task_ids]
    pending: list[dict[str, Any]] = []
    for task in tasks:
        result_path = corpus_root / "tasks" / task["task_id"] / "result.json"
        if resume and not force and not only_pair and result_path.is_file():
            try:
                previous = json.loads(result_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pending.append(task)
            else:
                if (
                    previous.get("task_id") == task["task_id"]
                    and previous.get("source_hash") == task["source_hash"]
                    and previous.get("classification")
                    not in {None, "pending", "runner_error"}
                ):
                    results.append(previous | {"reused": True})
                else:
                    pending.append(task)
        else:
            pending.append(task)

    def execute(task: dict[str, Any]) -> dict[str, Any]:
        try:
            return _execute_task(
                task,
                source_by_id[task["source_id"]],
                compilers,
                corpus_root,
                root,
                strict,
                config,
                backend,
                resume,
                force,
                set(only_pair) if only_pair else None,
            ) | {"reused": False}
        except (FileNotFoundError, RuntimeError, ValueError, OSError) as error:
            result = {
                "schema_version": 1,
                "task_id": task["task_id"],
                "source_id": task["source_id"],
                "target_id": task["target_id"],
                "package_subpath": task["package_subpath"],
                "lane": task["lane"],
                "classification": "runner_error",
                "strict_pass": False,
                "error": str(error),
                "source_hash": task["source_hash"],
                "dependency_lock_hash": task["dependency_lock_hash"],
                "reused": False,
            }
            write_json(corpus_root / "tasks" / task["task_id"] / "result.json", result)
            return result

    with ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = [executor.submit(execute, task) for task in pending]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda row: row["task_id"])
    if only_pair:
        selected_pair_results = []
        for result in results:
            semantic_summary = result.get("semantic_summary")
            if not isinstance(semantic_summary, dict):
                continue
            output_value = semantic_summary.get("output")
            if not isinstance(output_value, str):
                continue
            aggregate_path = Path(output_value) / "pair-results.json"
            if not aggregate_path.is_file():
                continue
            aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
            selected_pair_results.extend(
                row
                for row in aggregate.get("records", [])
                if row.get("program_pair_id") in requested_pairs
            )
        missing_pairs = sorted(
            requested_pairs
            - {row["program_pair_id"] for row in selected_pair_results}
        )
        if missing_pairs:
            raise ValueError(
                "requested pair(s) produced no final evidence: "
                + ", ".join(missing_pairs)
            )
    report = {
        "schema_version": 2,
        "run_id": run_identity,
        "plan_id": plan["plan_id"],
        "manifest_sha256": plan["lock_sha256"],
        "compiler_hashes": compiler_hashes,
        "selected_count": len(tasks),
        "completed_count": len(results),
        "reused_count": sum(bool(row.get("reused")) for row in results),
        "strict_requested": strict,
        "strict_pass": bool(results)
        and all(row["strict_pass"] for row in results)
        and all(
            row.get("status") in STRICT_PASSING_STATUSES
            for row in selected_pair_results
        ),
        "classification": "completed",
        "only_pairs": sorted(only_pair) if only_pair else [],
        "selected_pair_results": selected_pair_results,
        "results": results,
        "output": str(corpus_root),
    }
    if only_pair:
        selection_id = _hash_json({"only_pairs": sorted(only_pair)})
        write_json(corpus_root / "partials" / f"{selection_id}.json", report)
    else:
        write_json(corpus_root / "plan.json", plan)
        write_json(corpus_root / "summary.json", report)
    return report
