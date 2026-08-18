from __future__ import annotations

import json
import os
import re
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


def _artifact_record(path: Path, base: Path, kind: str, trace_level: str) -> dict[str, Any]:
    return {
        "path": path.relative_to(base).as_posix(),
        "kind": kind,
        "trace_level": trace_level,
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
        trace_root = raw_root / trace_level
        trace_root.mkdir(parents=True, exist_ok=True)
        blueprint_name = "plutus.json" if trace_level == "silent" else f"plutus-{trace_level}.json"
        command = [
            str(compiler.executable),
            "build",
            "--trace-level",
            trace_level,
            "--out",
            blueprint_name,
        ]
        first = _run(command, package)
        blueprint_path = package / blueprint_name

        dump: dict[str, Any] | None = None
        if first["exit_code"] == 0 and blueprint_path.exists():
            for title in _blueprint_titles(blueprint_path):
                title_parent = Path(title).parent
                (package / "artifacts" / title_parent).mkdir(parents=True, exist_ok=True)
            dump = _run([*command, "--uplc"], package)

        stdout_path = trace_root / "stdout.txt"
        stderr_path = trace_root / "stderr.txt"
        stdout_text = first["stdout"] + (dump["stdout"] if dump else "")
        stderr_text = first["stderr"] + (dump["stderr"] if dump else "")
        stdout_path.write_text(stdout_text, encoding="utf-8")
        stderr_path.write_text(stderr_text, encoding="utf-8")
        artifacts.extend(
            [
                _artifact_record(stdout_path, output, "compiler_stdout", trace_level),
                _artifact_record(stderr_path, output, "compiler_stderr", trace_level),
            ]
        )

        if blueprint_path.exists():
            copied_blueprint = trace_root / blueprint_name
            shutil.copy2(blueprint_path, copied_blueprint)
            artifacts.append(_artifact_record(copied_blueprint, output, "plutus_blueprint", trace_level))

        artifact_dir = package / "artifacts"
        if artifact_dir.exists():
            for uplc_path in sorted(artifact_dir.rglob("*.uplc")):
                relative = uplc_path.relative_to(artifact_dir)
                copied_uplc = trace_root / "uplc" / relative
                copied_uplc.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(uplc_path, copied_uplc)
                artifacts.append(_artifact_record(copied_uplc, output, "textual_uplc", trace_level))

        lock_path = package / "aiken.lock"
        if lock_path.exists():
            copied_lock = trace_root / "aiken.lock"
            shutil.copy2(lock_path, copied_lock)
            artifacts.append(_artifact_record(copied_lock, output, "dependency_lock", trace_level))

        runs.append(
            {
                "trace_level": trace_level,
                "command": command,
                "exit_code": first["exit_code"],
                "uplc_dump_exit_code": dump["exit_code"] if dump else None,
                "stdout_path": stdout_path.relative_to(output).as_posix(),
                "stderr_path": stderr_path.relative_to(output).as_posix(),
            }
        )

    primary = next(run for run in runs if run["trace_level"] == "silent")
    result = {
        "package": package_name(package),
        "compiler": asdict(compiler) | {"executable": str(compiler.executable)},
        "primary_exit_code": primary["exit_code"],
        "runs": runs,
        "artifacts": sorted(artifacts, key=lambda row: (row["trace_level"], row["path"])),
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
    output: Path,
    title: str,
    evaluation: dict[str, Any] | None,
) -> tuple[bool, dict[str, Any] | None, dict[str, Any] | None]:
    if not evaluation:
        return False, None, None
    script = _uplc_file(output, title)
    if script is None:
        return False, None, None

    def evaluate(args: Iterable[str]) -> dict[str, Any]:
        command = [str(compiler.executable), "uplc", "eval", str(script), *args]
        run = _run(command, output)
        return {
            "command": command,
            "exit_code": run["exit_code"],
            "stdout": run["stdout"],
            "stderr": run["stderr"],
        }

    selected = evaluate(evaluation.get("selected_args", []))
    baseline = evaluate(evaluation.get("baseline_args", []))
    selected_observation = (selected["exit_code"], selected["stdout"], selected["stderr"])
    baseline_observation = (baseline["exit_code"], baseline["stdout"], baseline["stderr"])
    return selected_observation != baseline_observation, selected, baseline


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
    for entry in _manifest_entries(package):
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
            output,
            title or "",
            entry.get("evaluation"),
        )
        records.append(
            {
                "feature_id": row_id,
                "row_kind": entry["row_kind"],
                "uplc_path": title,
                "branch_selector": entry.get("branch_selector"),
                "proof_kind": (
                    "uplc_builtin_path_and_validator_differential"
                    if expected_builtin
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

    lanes["config"] = {
        "required": _has_lane(census_records, contract, "config"),
        "matrix": [],
        "exit_code": None,
    }
    return lanes


def _artifact_refs(build: dict[str, Any], kind: str) -> list[str]:
    return [artifact["path"] for artifact in build["artifacts"] if artifact["kind"] == kind]


def _rule_evidence(
    rule: str,
    source: list[dict[str, Any]],
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
        state = "satisfied" if old_build["primary_exit_code"] == 0 else "missing"
        references = ["old/build.json"]
    elif "new-compiler" in lower or "new compiler" in lower:
        state = "satisfied" if new_build["primary_exit_code"] == 0 else "missing"
        references = ["new/build.json"]
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
        state = "missing"
    elif "check" in lower or "test" in lower:
        required = old_lanes["check"]["required"] or new_lanes["check"]["required"]
        passed = old_lanes["check"]["exit_code"] == 0 and new_lanes["check"]["exit_code"] == 0
        state = "satisfied" if required and passed else "not_applicable" if not required else "missing"
        references = ["old/raw/lanes/check.stdout", "new/raw/lanes/check.stdout"] if required else []
    elif "benchmark" in lower or "sampler" in lower:
        required = old_lanes["bench"]["required"] or new_lanes["bench"]["required"]
        passed = old_lanes["bench"]["exit_code"] == 0 and new_lanes["bench"]["exit_code"] == 0
        state = "satisfied" if required and passed else "not_applicable" if not required else "missing"
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
            result = None
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

    validation_errors = validate_outputs(package_root)
    summary = {
        "package": name,
        "output": str(package_root),
        "census": census_metadata | {"record_count": len(census_records)},
        "builds": {label: build["primary_exit_code"] for label, build in builds.items()},
        "reachability_records": {label: len(rows) for label, rows in reachability.items()},
        "evidence_records": evidence["record_count"],
        "schema_errors": validation_errors,
    }
    _write_json(package_root / "summary.json", summary)
    if validation_errors:
        raise RuntimeError("schema validation failed\n" + "\n".join(validation_errors))
    return summary
