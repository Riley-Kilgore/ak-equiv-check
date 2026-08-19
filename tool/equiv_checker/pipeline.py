from __future__ import annotations

import errno
import json
import os
import re
import pty
import shutil
import subprocess
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator

from .census import census, ensure_shim
from .config import (
    CONTRACT_PATH,
    DEFAULT_WORK_ROOT,
    REPOSITORY_ROOT,
    SCANNER_CONFIG_PATH,
    TOOL_ROOT,
    Compiler,
    compiler_pair,
    load_json,
    package_key,
    package_name,
    sha256_file,
)


RESULT_STATES = {
    "equivalent",
    "non_equivalent",
    "blaster_unsupported",
    "blaster_inconclusive",
    "old_language_feature_unsupported",
    "old_compile_failed",
    "new_compile_failed",
    "feature_missing",
    "dead_code_only",
    "expected_negative_diagnostic",
}


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run(command: list[str], cwd: Path) -> dict[str, Any]:
    environment = os.environ.copy()
    environment.update({"NO_COLOR": "1", "CLICOLOR": "0", "TERM": "dumb"})
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    return {
        "command": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _run_tty(command: list[str], cwd: Path) -> dict[str, Any]:
    environment = os.environ.copy()
    environment.update({"NO_COLOR": "1", "CLICOLOR": "0", "TERM": "dumb"})
    master, slave = pty.openpty()
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdout=slave,
            stderr=slave,
        )
    finally:
        os.close(slave)
    chunks: list[bytes] = []
    try:
        while True:
            try:
                chunk = os.read(master, 65_536)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(master)
    exit_code = process.wait()
    return {
        "command": command,
        "exit_code": exit_code,
        "stdout": b"".join(chunks).decode("utf-8", errors="replace"),
        "stderr": "",
    }


def _copy_package(source: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns(
            ".git",
            "build",
            "artifacts",
            "docs",
            "plutus.json",
            "plutus-*.json",
            "__pycache__",
        ),
    )


def _artifact_record(
    path: Path,
    base: Path,
    kind: str,
    trace_level: str,
    trace_filter: str = "all",
) -> dict[str, Any]:
    return {
        "path": path.relative_to(base).as_posix(),
        "kind": kind,
        "trace_level": trace_level,
        "trace_filter": trace_filter,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def _blueprint_titles(path: Path) -> list[str]:
    try:
        blueprint = load_json(path)
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    return [
        validator["title"]
        for validator in blueprint.get("validators", [])
        if isinstance(validator, dict) and isinstance(validator.get("title"), str)
    ]


def _trace_levels(census_records: list[dict[str, Any]]) -> list[str]:
    ids = {record["feature_id"] for record in census_records}
    levels = ["silent"]
    if ids & {"TRACE-LEVEL-COMPACT", "TRACE-LEVEL-VERBOSE", "TRACE-LEVEL-SILENT"}:
        levels.extend(["compact", "verbose"])
    return levels


def _trace_filters(census_records: list[dict[str, Any]]) -> list[str]:
    ids = {record["feature_id"] for record in census_records}
    if ids & {"TRACE-SOURCE-USER", "TRACE-SOURCE-COMPILER", "TRACE-SOURCE-ALL"}:
        return ["all", "user-defined", "compiler-generated"]
    return ["all"]


def _capture_negative_cases(
    compiler: Compiler, package: Path, output: Path
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    negative_root = package / "negative" / "cases"
    if not negative_root.exists():
        return [], []
    runs: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    for case_root in sorted(path for path in negative_root.iterdir() if path.is_dir()):
        expectation_path = case_root / "expected.json"
        if not expectation_path.exists():
            continue
        expectation = load_json(expectation_path)
        command = [str(compiler.executable), "build", "--trace-level", "silent"]
        run = _run_tty(command, case_root)
        combined = run["stdout"] + "\n" + run["stderr"]
        diagnostic_pattern = expectation.get("diagnostic_patterns", {}).get(
            compiler.label, expectation["diagnostic_pattern"]
        )
        expected_failure_kind = expectation.get("failure_kinds", {}).get(
            compiler.label, "diagnostic"
        )
        source_pattern = expectation["source_pattern"]
        diagnostic_match = re.search(
            diagnostic_pattern, combined, flags=re.IGNORECASE
        )
        source_match = re.search(source_pattern, combined, flags=re.IGNORECASE)
        diagnostic_code = re.search(
            r"Error[ \t]+([^\s(]+)", combined
        )
        observed_failure_kind = (
            "compiler_panic"
            if "aiken::fatal::error" in combined
            else "diagnostic"
            if diagnostic_code
            else "unknown"
        )
        run_root = output / "raw" / "negative" / expectation["feature_id"]
        run_root.mkdir(parents=True, exist_ok=True)
        stdout_path = run_root / "stdout.txt"
        stderr_path = run_root / "stderr.txt"
        stdout_path.write_text(run["stdout"], encoding="utf-8")
        stderr_path.write_text(run["stderr"], encoding="utf-8")
        artifacts.extend(
            [
                _artifact_record(stdout_path, output, "expected_negative_stdout", "silent"),
                _artifact_record(stderr_path, output, "expected_negative_stderr", "silent"),
            ]
        )
        runs.append(
            {
                "feature_id": expectation["feature_id"],
                "command": command,
                "exit_code": run["exit_code"],
                "diagnostic_pattern": diagnostic_pattern,
                "source_pattern": source_pattern,
                "expected_failure_kind": expected_failure_kind,
                "observed_failure_kind": observed_failure_kind,
                "diagnostic_code": diagnostic_code.group(1) if diagnostic_code else None,
                "diagnostic_matched": diagnostic_match is not None,
                "source_matched": source_match is not None,
                "pass": (
                    run["exit_code"] != 0
                    and diagnostic_match is not None
                    and observed_failure_kind == expected_failure_kind
                    and (
                        source_match is not None
                        or expected_failure_kind == "compiler_panic"
                    )
                ),
                "stdout_path": stdout_path.relative_to(output).as_posix(),
                "stderr_path": stderr_path.relative_to(output).as_posix(),
            }
        )
    return runs, artifacts


def capture_build(
    compiler: Compiler,
    package: Path,
    output: Path,
    census_records: list[dict[str, Any]],
) -> dict[str, Any]:
    raw_root = output / "raw"
    runs: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []

    for trace_level in _trace_levels(census_records):
        for trace_filter in _trace_filters(census_records):
            canonical = trace_filter == "all"
            trace_root = (
                raw_root / trace_level
                if canonical
                else raw_root / trace_level / trace_filter
            )
            trace_root.mkdir(parents=True, exist_ok=True)
            blueprint_name = (
                "plutus.json"
                if canonical and trace_level == "silent"
                else f"plutus-{trace_level}.json"
                if canonical
                else f"plutus-{trace_level}-{trace_filter}.json"
            )
            command = [
                str(compiler.executable),
                "build",
                "--trace-level",
                trace_level,
                "--trace-filter",
                trace_filter,
                "--out",
                blueprint_name,
            ]
            first = _run(command, package)
            blueprint_path = package / blueprint_name

            dump: dict[str, Any] | None = None
            if first["exit_code"] == 0 and blueprint_path.exists():
                artifact_dir = package / "artifacts"
                if artifact_dir.exists():
                    shutil.rmtree(artifact_dir)
                for title in _blueprint_titles(blueprint_path):
                    title_parent = Path(title).parent
                    (artifact_dir / title_parent).mkdir(parents=True, exist_ok=True)
                dump = _run([*command, "--uplc"], package)

            stdout_path = trace_root / "stdout.txt"
            stderr_path = trace_root / "stderr.txt"
            stdout_text = first["stdout"] + (dump["stdout"] if dump else "")
            stderr_text = first["stderr"] + (dump["stderr"] if dump else "")
            stdout_path.write_text(stdout_text, encoding="utf-8")
            stderr_path.write_text(stderr_text, encoding="utf-8")
            artifacts.extend(
                [
                    _artifact_record(
                        stdout_path,
                        output,
                        "compiler_stdout",
                        trace_level,
                        trace_filter,
                    ),
                    _artifact_record(
                        stderr_path,
                        output,
                        "compiler_stderr",
                        trace_level,
                        trace_filter,
                    ),
                ]
            )

            if blueprint_path.exists():
                copied_blueprint = trace_root / blueprint_name
                shutil.copy2(blueprint_path, copied_blueprint)
                artifacts.append(
                    _artifact_record(
                        copied_blueprint,
                        output,
                        "plutus_blueprint",
                        trace_level,
                        trace_filter,
                    )
                )

            artifact_dir = package / "artifacts"
            if artifact_dir.exists():
                for uplc_path in sorted(artifact_dir.rglob("*.uplc")):
                    relative = uplc_path.relative_to(artifact_dir)
                    copied_uplc = trace_root / "uplc" / relative
                    copied_uplc.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(uplc_path, copied_uplc)
                    artifacts.append(
                        _artifact_record(
                            copied_uplc,
                            output,
                            "textual_uplc",
                            trace_level,
                            trace_filter,
                        )
                    )

            lock_path = package / "aiken.lock"
            if lock_path.exists():
                copied_lock = trace_root / "aiken.lock"
                shutil.copy2(lock_path, copied_lock)
                artifacts.append(
                    _artifact_record(
                        copied_lock,
                        output,
                        "dependency_lock",
                        trace_level,
                        trace_filter,
                    )
                )

            runs.append(
                {
                    "trace_level": trace_level,
                    "trace_filter": trace_filter,
                    "command": command,
                    "exit_code": first["exit_code"],
                    "uplc_dump_exit_code": dump["exit_code"] if dump else None,
                    "stdout_path": stdout_path.relative_to(output).as_posix(),
                    "stderr_path": stderr_path.relative_to(output).as_posix(),
                }
            )

    negative_runs, negative_artifacts = _capture_negative_cases(
        compiler, package, output
    )
    artifacts.extend(negative_artifacts)

    primary = next(
        run
        for run in runs
        if run["trace_level"] == "silent" and run["trace_filter"] == "all"
    )
    result = {
        "package": package_name(package),
        "compiler": asdict(compiler) | {"executable": str(compiler.executable)},
        "primary_exit_code": primary["exit_code"],
        "runs": runs,
        "negative_runs": negative_runs,
        "artifacts": sorted(
            artifacts,
            key=lambda row: (
                row["trace_level"],
                row["trace_filter"],
                row["path"],
            ),
        ),
    }
    _write_json(output / "build.json", result)
    return result


def _inspect_blueprint(blueprint: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [str(ensure_shim()), "inspect-uplc", str(blueprint)],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"UPLC inspection failed for {blueprint}\n{completed.stdout}{completed.stderr}"
        )
    return json.loads(completed.stdout)


def _manifest_entries(package: Path) -> list[dict[str, Any]]:
    path = package / "coverage" / "feature-manifest.json"
    if not path.exists():
        return []
    manifest = load_json(path)
    entries = []
    for kind, key in (("feature", "features"), ("builtin", "builtins")):
        for entry in manifest.get(key, []):
            entries.append({"row_kind": kind, **entry})
    return entries


def _uplc_file(output: Path, title: str) -> Path | None:
    path = output / "raw" / "silent" / "uplc" / f"{title}.uplc"
    if path.exists():
        return path
    return None


def _evaluation_proof(
    compiler: Compiler,
    package: Path,
    output: Path,
    title: str,
    evaluation: dict[str, Any] | None,
    export_cache: dict[tuple[str, str], Path],
) -> tuple[bool, dict[str, Any] | None, dict[str, Any] | None]:
    if not evaluation:
        return False, None, None

    cbor = False
    export_module = evaluation.get("module")
    export_name = evaluation.get("name")
    if isinstance(export_module, str) and isinstance(export_name, str):
        key = (export_module, export_name)
        script = export_cache.get(key)
        if script is None:
            command = [
                str(compiler.executable),
                "export",
                "--module",
                export_module,
                "--name",
                export_name,
            ]
            exported = _run(command, package)
            if exported["exit_code"] != 0:
                return False, {
                    "command": command,
                    "exit_code": exported["exit_code"],
                    "stdout": exported["stdout"],
                    "stderr": exported["stderr"],
                }, None
            try:
                compiled_code = json.loads(exported["stdout"])["compiledCode"]
            except (json.JSONDecodeError, KeyError, TypeError):
                return False, {
                    "command": command,
                    "exit_code": exported["exit_code"],
                    "stdout": exported["stdout"],
                    "stderr": exported["stderr"],
                }, None
            safe_name = f"{export_module.replace('/', '__')}__{export_name}.cbor"
            script = output / "raw" / "silent" / "exports" / safe_name
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(compiled_code, encoding="utf-8")
            export_cache[key] = script
        cbor = True
    else:
        script = _uplc_file(output, title)
        if script is None:
            return False, None, None

    def evaluate(args: Iterable[str]) -> dict[str, Any]:
        command = [str(compiler.executable), "uplc", "eval"]
        if cbor:
            command.append("--cbor")
        command.extend([str(script), *args])
        run = _run(command, output)
        try:
            parsed = json.loads(run["stdout"]) if run["stdout"] else None
        except json.JSONDecodeError:
            parsed = None
        return {
            "command": command,
            "exit_code": run["exit_code"],
            "result": parsed.get("result") if isinstance(parsed, dict) else None,
            "cpu": parsed.get("cpu") if isinstance(parsed, dict) else None,
            "mem": parsed.get("mem") if isinstance(parsed, dict) else None,
            "stdout": run["stdout"],
            "stderr": run["stderr"],
            "script_sha256": sha256_file(script),
        }

    selected = evaluate(evaluation.get("selected_args", []))
    baseline = evaluate(evaluation.get("baseline_args", []))
    if evaluation.get("allow_selected_failure"):
        passed = selected["exit_code"] != 0 and baseline["exit_code"] == 0
    else:
        passed = (
            selected["exit_code"] == 0
            and baseline["exit_code"] == 0
            and selected["result"] is not None
            and selected["result"] != baseline["result"]
        )
    return passed, selected, baseline


def prove_reachability(
    compiler: Compiler,
    package: Path,
    output: Path,
    build: dict[str, Any],
) -> list[dict[str, Any]]:
    blueprint = output / "raw" / "silent" / "plutus.json"
    if build["primary_exit_code"] != 0 or not blueprint.exists():
        _write_json(output / "reachability.json", [])
        return []

    inspected = _inspect_blueprint(blueprint)
    by_title = {validator["title"]: validator for validator in inspected["validators"]}
    records: list[dict[str, Any]] = []
    export_cache: dict[tuple[str, str], Path] = {}
    for entry in (
        item
        for item in _manifest_entries(package)
        if item.get("reachability_required", True)
    ):
        row_id = entry["feature_id"]
        title = entry.get("validator_title") or entry.get("uplc_path")
        validator = by_title.get(title)
        expected_builtin = entry.get("uplc_name")
        builtin_paths = []
        if validator and expected_builtin:
            builtin_paths = [
                occurrence["path"]
                for occurrence in validator["builtins"]
                if occurrence["uplc_name"] == expected_builtin
            ]
        structural_pass = validator is not None and (not expected_builtin or bool(builtin_paths))
        differential_pass, selected, baseline = _evaluation_proof(
            compiler,
            package,
            output,
            title or "",
            entry.get("evaluation"),
            export_cache,
        )
        records.append(
            {
                "feature_id": row_id,
                "row_kind": entry["row_kind"],
                "uplc_path": title,
                "branch_selector": entry.get("branch_selector"),
                "proof_kind": (
                    "uplc_builtin_path_and_exported_handler_differential"
                    if expected_builtin and entry.get("evaluation", {}).get("module")
                    else "uplc_builtin_path_and_validator_differential"
                    if expected_builtin
                    else "exported_handler_differential"
                    if entry.get("evaluation", {}).get("module")
                    else "validator_differential"
                ),
                "expected_builtin": expected_builtin,
                "builtin_ast_paths": builtin_paths,
                "structural_pass": structural_pass,
                "selected_evaluation": selected,
                "baseline_evaluation": baseline,
                "differential_pass": differential_pass,
                "pass": structural_pass and differential_pass,
            }
        )
    _write_json(output / "reachability.json", records)
    return records


def _has_lane(census_records: list[dict[str, Any]], contract: dict[str, Any], lane: str) -> bool:
    ids = {record["feature_id"] for record in census_records}
    rows = [*contract["features"], *contract["active_uplc_builtins"]]
    return any(row["id"] in ids and lane in row["lanes"] for row in rows)

def _structured_summary(output: str) -> dict[str, Any] | None:
    try:
        value = json.loads(output)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    summary = value.get("summary")
    return summary if isinstance(summary, dict) else value



def _config_lane(
    compiler: Compiler, package: Path, output: Path
) -> dict[str, Any]:
    config_root = output / "raw" / "lanes" / "config"
    config_root.mkdir(parents=True, exist_ok=True)
    matrix: list[dict[str, Any]] = []

    def run_case(
        name: str,
        command: list[str],
        cwd: Path,
        expected_success: bool,
    ) -> None:
        result = _run(command, cwd)
        stdout_path = config_root / f"{name}.stdout"
        stderr_path = config_root / f"{name}.stderr"
        stdout_path.write_text(result["stdout"], encoding="utf-8")
        stderr_path.write_text(result["stderr"], encoding="utf-8")
        passed = (
            result["exit_code"] == 0
            if expected_success
            else result["exit_code"] != 0
        )
        matrix.append(
            {
                "name": name,
                "command": command,
                "exit_code": result["exit_code"],
                "expected_success": expected_success,
                "pass": passed,
                "stdout_path": stdout_path.relative_to(output).as_posix(),
                "stderr_path": stderr_path.relative_to(output).as_posix(),
            }
        )

    for environment_name in ("default", "preview"):
        run_case(
            f"environment_{environment_name}",
            [
                str(compiler.executable),
                "build",
                "--env",
                environment_name,
                "--trace-level",
                "silent",
                "--out",
                f"config-{environment_name}.json",
            ],
            package,
            True,
        )

    for target in ("v1", "v2"):
        target_root = config_root / f"target_{target}"
        _copy_package(package, target_root)
        manifest_path = target_root / "aiken.toml"
        manifest = manifest_path.read_text(encoding="utf-8")
        manifest_path.write_text(
            re.sub(
                r'(?m)^plutus\s*=\s*"v3"$',
                f'plutus = "{target}"',
                manifest,
            ),
            encoding="utf-8",
        )
        run_case(
            f"target_{target}_rejected",
            [str(compiler.executable), "build", "--trace-level", "silent"],
            target_root,
            False,
        )

    workspace_root = config_root / "workspace"
    member_root = workspace_root / "pkgs" / "member"
    _copy_package(package, member_root)
    for name, members in (
        ("monorepo_explicit", 'members = ["pkgs/member"]\n'),
        ("monorepo_glob", 'members = ["pkgs/*"]\n'),
    ):
        (workspace_root / "aiken.toml").write_text(members, encoding="utf-8")
        run_case(
            name,
            [str(compiler.executable), "build"],
            workspace_root,
            True,
        )

    return {
        "required": True,
        "matrix": matrix,
        "exit_code": 0 if all(row["pass"] for row in matrix) else 1,
    }


def run_lanes(
    compiler: Compiler,
    package: Path,
    output: Path,
    census_records: list[dict[str, Any]],
    contract: dict[str, Any],
    scanner_config: dict[str, Any],
) -> dict[str, Any]:
    lane_root = output / "raw" / "lanes"
    lane_root.mkdir(parents=True, exist_ok=True)
    check_command = [
        str(compiler.executable),
        "check",
        "--seed",
        str(scanner_config["fixed_seed"]),
        "--max-success",
        str(scanner_config["property_max_success"]),
        "--trace-level",
        "silent",
        "--plain-numbers",
    ]
    check = _run(check_command, package)
    lanes: dict[str, Any] = {
        "check": {
            "required": _has_lane(census_records, contract, "check"),
            "command": check_command,
            "exit_code": check["exit_code"],
            "summary": _structured_summary(check["stdout"]),
        }
    }
    (lane_root / "check.stdout").write_text(check["stdout"], encoding="utf-8")
    (lane_root / "check.stderr").write_text(check["stderr"], encoding="utf-8")

    if _has_lane(census_records, contract, "bench"):
        command = [
            str(compiler.executable),
            "bench",
            "--seed",
            str(scanner_config["fixed_seed"]),
            "--max-size",
            str(scanner_config["benchmark_max_size"]),
            "--trace-level",
            "silent",
            "--plain-numbers",
        ]
        bench = _run(command, package)
        lanes["bench"] = {
            "required": True,
            "command": command,
            "exit_code": bench["exit_code"],
            "summary": _structured_summary(bench["stdout"]),
        }
        (lane_root / "bench.stdout").write_text(bench["stdout"], encoding="utf-8")
        (lane_root / "bench.stderr").write_text(bench["stderr"], encoding="utf-8")
    else:
        lanes["bench"] = {
            "required": False,
            "command": None,
            "exit_code": None,
            "summary": None,
        }

    if _has_lane(census_records, contract, "docs"):
        docs_destination = output / "raw" / "docs"
        command = [str(compiler.executable), "docs", "--out", str(docs_destination)]
        docs = _run(command, package)
        lanes["docs"] = {
            "required": True,
            "command": command,
            "exit_code": docs["exit_code"],
        }
        (lane_root / "docs.stdout").write_text(docs["stdout"], encoding="utf-8")
        (lane_root / "docs.stderr").write_text(docs["stderr"], encoding="utf-8")
    else:
        lanes["docs"] = {"required": False, "command": None, "exit_code": None}

    lanes["config"] = (
        _config_lane(compiler, package, output)
        if _has_lane(census_records, contract, "config")
        else {"required": False, "matrix": [], "exit_code": None}
    )
    return lanes


def _artifact_refs(build: dict[str, Any], kind: str) -> list[str]:
    return [artifact["path"] for artifact in build["artifacts"] if artifact["kind"] == kind]


def _negative_run(build: dict[str, Any], row_id: str) -> dict[str, Any] | None:
    return next(
        (
            run
            for run in build.get("negative_runs", [])
            if run["feature_id"] == row_id
        ),
        None,
    )


def _rule_evidence(
    rule: str,
    source: list[dict[str, Any]],
    row_id: str,
    negative_compile_case: bool,
    old_build: dict[str, Any],
    new_build: dict[str, Any],
    old_reach: dict[str, Any] | None,
    new_reach: dict[str, Any] | None,
    old_lanes: dict[str, Any],
    new_lanes: dict[str, Any],
) -> dict[str, Any]:
    lower = rule.lower()
    state = "missing"
    references: list[str] = []
    if "source path" in lower or "reachable aiken wrapper" in lower:
        state = "satisfied" if source else "missing"
        references = [f"census.json#{record['file']}:{record['line_start']}" for record in source]
    elif "old-compiler" in lower or "old compiler" in lower:
        negative = _negative_run(old_build, row_id)
        passed = negative["pass"] if negative_compile_case and negative else (
            old_build["primary_exit_code"] == 0
        )
        state = "satisfied" if passed else "missing"
        references = [
            negative["stderr_path"] if negative else "old/build.json"
        ]
    elif "new-compiler" in lower or "new compiler" in lower:
        negative = _negative_run(new_build, row_id)
        passed = negative["pass"] if negative_compile_case and negative else (
            new_build["primary_exit_code"] == 0
        )
        state = "satisfied" if passed else "missing"
        references = [
            negative["stderr_path"] if negative else "new/build.json"
        ]
    elif "old and new uplc" in lower:
        old_refs = _artifact_refs(old_build, "plutus_blueprint")
        new_refs = _artifact_refs(new_build, "plutus_blueprint")
        state = "satisfied" if old_refs and new_refs else "missing"
        references = [*[f"old/{path}" for path in old_refs], *[f"new/{path}" for path in new_refs]]
    elif "uplc contains builtin" in lower or "structural proof" in lower:
        state = "satisfied" if old_reach and new_reach and old_reach["pass"] and new_reach["pass"] else "missing"
        references = ["old/reachability.json", "new/reachability.json"]
    elif "lean-blaster" in lower:
        state = "missing"
        references = ["blaster_pending"]
    elif "diagnostic" in lower:
        old_negative = _negative_run(old_build, row_id)
        new_negative = _negative_run(new_build, row_id)
        passed = (
            old_negative
            and new_negative
            and old_negative["pass"]
            and new_negative["pass"]
        )
        state = "satisfied" if passed else "missing"
        references = [
            run["stderr_path"]
            for run in (old_negative, new_negative)
            if run
        ]
    elif "check" in lower or "test" in lower:
        required = old_lanes["check"]["required"] or new_lanes["check"]["required"]
        passed = old_lanes["check"]["exit_code"] == 0 and new_lanes["check"]["exit_code"] == 0
        state = "satisfied" if required and passed else "not_applicable" if not required else "missing"
        references = ["old/raw/lanes/check.stdout", "new/raw/lanes/check.stdout"] if required else []
    elif "benchmark" in lower or "sampler" in lower:
        required = old_lanes["bench"]["required"] or new_lanes["bench"]["required"]
        passed = old_lanes["bench"]["exit_code"] == 0 and new_lanes["bench"]["exit_code"] == 0
        state = "satisfied" if required and passed else "not_applicable" if not required else "missing"
    elif "package/configuration selection" in lower:
        required = old_lanes["config"]["required"] or new_lanes["config"]["required"]
        passed = (
            old_lanes["config"]["exit_code"] == 0
            and new_lanes["config"]["exit_code"] == 0
        )
        state = (
            "satisfied"
            if required and passed
            else "not_applicable"
            if not required
            else "missing"
        )
        references = ["old/raw/lanes/config", "new/raw/lanes/config"]
    elif "documentation" in lower or "docs" in lower:
        required = old_lanes["docs"]["required"] or new_lanes["docs"]["required"]
        passed = old_lanes["docs"]["exit_code"] == 0 and new_lanes["docs"]["exit_code"] == 0
        state = "satisfied" if required and passed else "not_applicable" if not required else "missing"
    else:
        state = "satisfied" if source and old_build["primary_exit_code"] == 0 and new_build["primary_exit_code"] == 0 else "missing"
        references = ["census.json", "old/build.json", "new/build.json"]
    return {"rule": rule, "state": state, "references": references}


def merge_evidence(
    package: str,
    contract: dict[str, Any],
    census_records: list[dict[str, Any]],
    builds: dict[str, dict[str, Any]],
    reachability: dict[str, list[dict[str, Any]]],
    lanes: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    census_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in census_records:
        census_by_id[record["feature_id"]].append(record)
    reach_by_compiler = {
        label: {record["feature_id"]: record for record in records}
        for label, records in reachability.items()
    }

    records = []
    rows = [
        *({"row_kind": "feature", **row} for row in contract["features"]),
        *({"row_kind": "builtin", **row} for row in contract["active_uplc_builtins"]),
    ]
    for row in rows:
        row_id = row["id"]
        source = census_by_id[row_id]
        old_reach = reach_by_compiler["old"].get(row_id)
        new_reach = reach_by_compiler["new"].get(row_id)
        evidence_rules = [
            _rule_evidence(
                rule,
                source,
                row_id,
                bool(row.get("negative_compile_case")),
                builds["old"],
                builds["new"],
                old_reach,
                new_reach,
                lanes["old"],
                lanes["new"],
            )
            for rule in row["required_evidence"]
        ]
        pre_blaster_complete = all(
            item["state"] in {"satisfied", "not_applicable"}
            for item in evidence_rules
            if "lean-blaster" not in item["rule"].lower()
        )
        blaster_required = "blaster" in row["lanes"]
        blaster_pending = blaster_required and pre_blaster_complete

        if not source:
            result: str | None = "feature_missing"
        elif builds["new"]["primary_exit_code"] != 0:
            result = "new_compile_failed"
        elif builds["old"]["primary_exit_code"] != 0:
            result = (
                "old_language_feature_unsupported"
                if builds["new"]["primary_exit_code"] == 0
                else "old_compile_failed"
            )
        elif row.get("negative_compile_case"):
            result = "expected_negative_diagnostic" if pre_blaster_complete else None
        elif blaster_required and not (old_reach and new_reach and old_reach["pass"] and new_reach["pass"]):
            result = "dead_code_only"
        elif blaster_required:
            result = None
        elif pre_blaster_complete:
            result = "equivalent"
        else:
            result = None

        records.append(
            {
                "feature_id": row_id,
                "row_kind": row["row_kind"],
                "package": package,
                "lanes": row["lanes"],
                "impact": row["impact"],
                "required_evidence": evidence_rules,
                "result": result,
                "blaster_pending": blaster_pending,
                "verification_status": (
                    "manifested_verified" if pre_blaster_complete else "manifested_unverified"
                ),
            }
        )

    return {
        "schema_version": 1,
        "package": package,
        "compiler_pair": {
            "old": builds["old"]["compiler"]["reported_version"],
            "new": builds["new"]["compiler"]["reported_version"],
        },
        "lane_runs": lanes,
        "record_count": len(records),
        "records": records,
    }


def sync_feature_manifest(
    package: Path,
    census_records: list[dict[str, Any]],
    builds: dict[str, dict[str, Any]],
    reachability: dict[str, list[dict[str, Any]]],
) -> None:
    manifest_path = package / "coverage" / "feature-manifest.json"
    if not manifest_path.exists():
        return
    manifest = load_json(manifest_path)
    census_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in census_records:
        census_by_id[record["feature_id"]].append(record)
    reach_by_id = {
        label: {record["feature_id"]: record for record in records}
        for label, records in reachability.items()
    }

    for key in ("features", "builtins"):
        for entry in manifest.get(key, []):
            row_id = entry["feature_id"]
            sources = census_by_id.get(row_id, [])
            source = next(
                (
                    record
                    for record in sources
                    if record["file"] == entry.get("source_path")
                    and (record["marker_bound"] or len(sources) == 1)
                ),
                sources[0] if sources else None,
            )
            if source:
                entry["source_path"] = source["file"]
                entry["line_start"] = source["line_start"]
                entry["line_end"] = source["line_end"]
                entry["ast_evidence"] = {
                    "node_kind": source["ast_node_kind"],
                    "path": source["ast_path"],
                    "detector_rule": source["detector_rule"],
                }

            reachability_required = entry.get("reachability_required", True)
            title = entry.get("validator_title") or entry.get("uplc_path")
            hashes: dict[str, str | None] = {}
            for label in ("old", "new"):
                artifact = next(
                    (
                        row
                        for row in builds[label]["artifacts"]
                        if row["kind"] == "textual_uplc"
                        and row["trace_level"] == "silent"
                        and row["trace_filter"] == "all"
                        and title
                        and row["path"].endswith(f"uplc/{title}.uplc")
                    ),
                    None,
                )
                hashes[label] = artifact["sha256"] if artifact else None
            entry["artifact_hashes"] = hashes
            old_proof = reach_by_id["old"].get(row_id)
            new_proof = reach_by_id["new"].get(row_id)
            build_pass = all(
                builds[label]["primary_exit_code"] == 0 for label in ("old", "new")
            )
            negative_pass = all(
                (run := _negative_run(builds[label], row_id)) is not None
                and run["pass"]
                for label in ("old", "new")
            )
            proof_pass = (
                old_proof
                and new_proof
                and old_proof["pass"]
                and new_proof["pass"]
                and all(hashes.values())
            )
            entry["verification_status"] = (
                "manifested_verified"
                if source
                and build_pass
                and (
                    proof_pass
                    if reachability_required
                    else negative_pass
                    if entry.get("negative_compile_case")
                    else True
                )
                else "manifested_unverified"
            )
    _write_json(manifest_path, manifest)


def write_handoff(
    package: Path,
    package_root: Path,
    builds: dict[str, dict[str, Any]],
    reachability: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    reach_by_id = {
        label: {record["feature_id"]: record for record in records}
        for label, records in reachability.items()
    }
    records: list[dict[str, Any]] = []
    for entry in _manifest_entries(package):
        if not entry.get("reachability_required", True):
            continue
        row_id = entry["feature_id"]
        title = entry.get("validator_title") or entry.get("uplc_path")
        if not title:
            raise RuntimeError(f"handoff entry {row_id} has no UPLC title")
        paired: dict[str, Any] = {}
        for label in ("old", "new"):
            artifact = next(
                (
                    row
                    for row in builds[label]["artifacts"]
                    if row["kind"] == "textual_uplc"
                    and row["trace_level"] == "silent"
                    and row["trace_filter"] == "all"
                    and row["path"].endswith(f"uplc/{title}.uplc")
                ),
                None,
            )
            proof = reach_by_id[label].get(row_id)
            if artifact is None or proof is None or not proof["pass"]:
                raise RuntimeError(
                    f"handoff entry {row_id} lacks {label} artifact or proof"
                )
            paired[label] = {
                "path": f"{label}/{artifact['path']}",
                "sha256": artifact["sha256"],
                "reachability_pass": True,
            }
        records.append(
            {
                "feature_id": row_id,
                "row_kind": entry["row_kind"],
                "uplc_path": title,
                "old": paired["old"],
                "new": paired["new"],
                "blaster_pending": True,
            }
        )
    handoff = {
        "schema_version": 1,
        "package": package_name(package),
        "compiler_pair": {
            "old": builds["old"]["compiler"]["reported_version"],
            "new": builds["new"]["compiler"]["reported_version"],
        },
        "record_count": len(records),
        "records": records,
    }
    _write_json(package_root / "handoff.json", handoff)
    return handoff


def validate_outputs(package_root: Path) -> list[str]:
    schemas = {
        "census.json": TOOL_ROOT / "schemas" / "census.schema.json",
        "build.json": TOOL_ROOT / "schemas" / "build.schema.json",
        "reachability.json": TOOL_ROOT / "schemas" / "reachability.schema.json",
        "evidence.json": TOOL_ROOT / "schemas" / "evidence.schema.json",
    }
    errors: list[str] = []
    for compiler_label in ("old", "new"):
        compiler_root = package_root / compiler_label
        for filename, schema_path in schemas.items():
            instance_path = compiler_root / filename
            schema = load_json(schema_path)
            instance = load_json(instance_path)
            validator = Draft202012Validator(schema)
            for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.path)):
                location = "/".join(str(part) for part in error.path)
                errors.append(f"{instance_path}:{location}: {error.message}")
    handoff_path = package_root / "handoff.json"
    handoff_schema = load_json(TOOL_ROOT / "schemas" / "handoff.schema.json")
    handoff_validator = Draft202012Validator(handoff_schema)
    for error in sorted(
        handoff_validator.iter_errors(load_json(handoff_path)),
        key=lambda item: list(item.path),
    ):
        location = "/".join(str(part) for part in error.path)
        errors.append(f"{handoff_path}:{location}: {error.message}")
    return errors


def scan(package: Path, work_root: Path = DEFAULT_WORK_ROOT) -> dict[str, Any]:
    package = package.resolve()
    name = package_name(package)
    package_root = work_root.resolve() / package_key(name)
    contract = load_json(CONTRACT_PATH)
    scanner_config = load_json(SCANNER_CONFIG_PATH)
    old, new = compiler_pair()

    source_copies: dict[str, Path] = {}
    for compiler in (old, new):
        compiler_root = package_root / compiler.label
        source = compiler_root / "package"
        _copy_package(package, source)
        source_copies[compiler.label] = source

    census_records, census_metadata = census(source_copies["new"])
    for compiler in (old, new):
        _write_json(package_root / compiler.label / "census.json", census_records)

    builds = {
        compiler.label: capture_build(
            compiler,
            source_copies[compiler.label],
            package_root / compiler.label,
            census_records,
        )
        for compiler in (old, new)
    }
    reachability = {
        compiler.label: prove_reachability(
            compiler,
            source_copies[compiler.label],
            package_root / compiler.label,
            builds[compiler.label],
        )
        for compiler in (old, new)
    }
    lanes = {
        compiler.label: run_lanes(
            compiler,
            source_copies[compiler.label],
            package_root / compiler.label,
            census_records,
            contract,
            scanner_config,
        )
        for compiler in (old, new)
    }
    evidence = merge_evidence(name, contract, census_records, builds, reachability, lanes)
    for compiler in (old, new):
        _write_json(package_root / compiler.label / "evidence.json", evidence)
    sync_feature_manifest(package, census_records, builds, reachability)
    handoff = write_handoff(package, package_root, builds, reachability)

    validation_errors = validate_outputs(package_root)
    summary = {
        "package": name,
        "output": str(package_root),
        "census": census_metadata | {"record_count": len(census_records)},
        "builds": {label: build["primary_exit_code"] for label, build in builds.items()},
        "reachability_records": {label: len(rows) for label, rows in reachability.items()},
        "evidence_records": evidence["record_count"],
        "handoff_records": handoff["record_count"],
        "schema_errors": validation_errors,
    }
    _write_json(package_root / "summary.json", summary)
    if validation_errors:
        raise RuntimeError("schema validation failed\n" + "\n".join(validation_errors))
    return summary
