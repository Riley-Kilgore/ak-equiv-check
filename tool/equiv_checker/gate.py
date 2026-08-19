from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import (
    CORPUS_ROOT,
    DEFAULT_WORK_ROOT,
    load_json,
    package_key,
    package_name,
    sha256_file,
    sha256_tree,
)
from .pipeline import scan


class GateFailure(RuntimeError):
    def __init__(self, report: dict[str, Any]):
        self.report = report
        super().__init__("gate failed: " + "; ".join(report["errors"]))


def _manifest_rows(package: Path) -> list[dict[str, Any]]:
    manifest = load_json(package / "coverage" / "feature-manifest.json")
    return [
        *({"row_kind": "feature", **row} for row in manifest.get("features", [])),
        *({"row_kind": "builtin", **row} for row in manifest.get("builtins", [])),
    ]


def _surface_audit_errors(surface_audit: dict[str, Any]) -> list[str]:
    errors = []
    if surface_audit.get("unmapped_surface_variants") != []:
        errors.append("compiler surface audit has unmapped variants")
    if surface_audit.get("unmapped_keywords_or_aliases") != []:
        errors.append("compiler surface audit has unmapped keywords or aliases")
    return errors


def gate(
    package: Path,
    work_root: Path = DEFAULT_WORK_ROOT,
    *,
    allow_blaster_pending: bool = False,
    run_scan: bool = True,
) -> dict[str, Any]:
    package = package.resolve()
    if run_scan:
        scan(package, work_root)
    name = package_name(package)
    package_root = work_root.resolve() / package_key(name)
    contract = load_json(CORPUS_ROOT / "aiken_language_features_v1_1_23.json")
    evidence = load_json(package_root / "new" / "evidence.json")
    builds = {
        label: load_json(package_root / label / "build.json")
        for label in ("old", "new")
    }
    reachability = {
        label: load_json(package_root / label / "reachability.json")
        for label in ("old", "new")
    }
    handoff = load_json(package_root / "handoff.json")
    manifest_rows = _manifest_rows(package)
    errors: list[str] = []

    required_feature_ids = {
        row["id"]
        for row in contract["features"]
        if row["sentinel_required"] or row["negative_compile_case"]
    }
    required_builtin_ids = {row["id"] for row in contract["active_uplc_builtins"]}
    manifest_feature_ids = {
        row["feature_id"] for row in manifest_rows if row["row_kind"] == "feature"
    }
    manifest_builtin_ids = {
        row["feature_id"] for row in manifest_rows if row["row_kind"] == "builtin"
    }
    if manifest_feature_ids != required_feature_ids:
        errors.append(
            "feature manifest ID mismatch: "
            f"missing={sorted(required_feature_ids - manifest_feature_ids)}, "
            f"extra={sorted(manifest_feature_ids - required_feature_ids)}"
        )
    if manifest_builtin_ids != required_builtin_ids:
        errors.append(
            "builtin manifest ID mismatch: "
            f"missing={sorted(required_builtin_ids - manifest_builtin_ids)}, "
            f"extra={sorted(manifest_builtin_ids - required_builtin_ids)}"
        )
    duplicate_count = len(manifest_rows) - len(
        {(row["row_kind"], row["feature_id"]) for row in manifest_rows}
    )
    if duplicate_count:
        errors.append(f"manifest contains {duplicate_count} duplicate rows")
    unverified = [
        row["feature_id"]
        for row in manifest_rows
        if row.get("verification_status") != "manifested_verified"
    ]
    if unverified:
        errors.append(f"manifest has {len(unverified)} unverified rows: {unverified}")

    for label, build in builds.items():
        if build["primary_exit_code"] != 0:
            errors.append(f"{label} positive package build failed")
        failed_profiles = [
            f"{run['trace_level']}/{run['trace_filter']}"
            for run in build["runs"]
            if run["exit_code"] != 0 or run["uplc_dump_exit_code"] != 0
        ]
        if failed_profiles:
            errors.append(f"{label} trace builds failed: {failed_profiles}")
        failed_negative = [
            run["feature_id"] for run in build["negative_runs"] if not run["pass"]
        ]
        if failed_negative or len(build["negative_runs"]) != 12:
            errors.append(
                f"{label} expected-negative failures: "
                f"matched={12 - len(failed_negative)}/12, failed={failed_negative}"
            )
        failed_reachability = [
            row["feature_id"] for row in reachability[label] if not row["pass"]
        ]
        if failed_reachability or len(reachability[label]) != 306:
            errors.append(
                f"{label} reachability failures: "
                f"records={len(reachability[label])}, failed={failed_reachability}"
            )

    evidence_by_id = {row["feature_id"]: row for row in evidence["records"]}
    for row_id in required_feature_ids:
        row = evidence_by_id[row_id]
        if row["verification_status"] != "manifested_verified":
            errors.append(f"feature evidence is incomplete: {row_id}")
    for row_id in required_builtin_ids:
        row = evidence_by_id[row_id]
        if row["verification_status"] != "manifested_verified":
            errors.append(f"builtin evidence is incomplete: {row_id}")
    negative_results = [
        row_id
        for row_id in required_feature_ids
        if evidence_by_id[row_id]["impact"] == "compile_only"
        and row_id.startswith("NEG-")
        and evidence_by_id[row_id]["result"] != "expected_negative_diagnostic"
    ]
    if negative_results:
        errors.append(f"negative verdicts incomplete: {negative_results}")

    config_runs = evidence["lane_runs"]
    for label in ("old", "new"):
        config = config_runs[label]["config"]
        if config["required"] and config["exit_code"] != 0:
            errors.append(f"{label} configuration matrix failed")

    surface_audit = load_json(CORPUS_ROOT / "aiken_compiler_surface_audit.json")
    errors.extend(_surface_audit_errors(surface_audit))

    if handoff["record_count"] != 306:
        errors.append(f"handoff has {handoff['record_count']} records, expected 306")
    for row in handoff["records"]:
        for label in ("old", "new"):
            artifact = package_root / row[label]["path"]
            if not artifact.exists():
                errors.append(f"handoff artifact is missing: {artifact}")
            elif sha256_file(artifact) != row[label]["sha256"]:
                errors.append(f"handoff artifact hash mismatch: {artifact}")

    coverage_validation = load_json(
        CORPUS_ROOT / "aiken_feature_coverage_validation.json"
    )
    sentinel_hash = sha256_tree(package)
    expected_hash = coverage_validation.get("sha256", {}).get("sentinel/")
    expected_status = f"pinned:{sentinel_hash}"
    if expected_hash != sentinel_hash:
        errors.append(
            f"sentinel hash is not pinned: expected={expected_hash}, actual={sentinel_hash}"
        )
    if (
        coverage_validation["checks"].get("required_internal_source_status")
        != expected_status
    ):
        errors.append("required internal source status does not match sentinel hash")

    pending = [row["feature_id"] for row in evidence["records"] if row["blaster_pending"]]
    if pending and not allow_blaster_pending:
        errors.append(f"{len(pending)} required Blaster results are pending")

    report = {
        "package": name,
        "mode": "pre_blaster" if allow_blaster_pending else "release",
        "pass": not errors,
        "manifest_records": len(manifest_rows),
        "reachability_records": len(reachability["new"]),
        "negative_records": len(builds["new"]["negative_runs"]),
        "handoff_records": handoff["record_count"],
        "blaster_pending": len(pending),
        "sentinel_sha256": sentinel_hash,
        "errors": errors,
    }
    from .pipeline import _write_json

    _write_json(package_root / "gate-report.json", report)
    if errors:
        raise GateFailure(report)
    return report
