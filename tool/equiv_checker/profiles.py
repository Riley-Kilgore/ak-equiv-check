from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .compiler_artifacts import (
    DEFAULT_AIKEN_REPOSITORY,
    build_release,
    compiler_from_manifest,
    resolve_release_ref,
)
from .config import (
    BLASTER_CONFIG_PATH,
    Compiler,
    CORPUS_ROOT,
    DEFAULT_WORK_ROOT,
    REPOSITORY_ROOT,
    load_blaster_config,
    sha256_file,
)
from .pairing import canonical_json
from .process import run_process
from .runner import compare_package, compare_sentinel, write_json

PROFILE_REGISTRY = CORPUS_ROOT / "compiler_profiles.json"
PROFILE_LOCK = CORPUS_ROOT / "compiler_profiles.lock.json"


def _stable_hash(value: Any) -> str:
    import hashlib

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _registry() -> dict[str, Any]:
    value = json.loads(PROFILE_REGISTRY.read_text(encoding="utf-8"))
    if value.get("schema_version") != 1 or not isinstance(value.get("profiles"), list):
        raise ValueError(f"invalid compiler profile registry: {PROFILE_REGISTRY}")
    return value


def load_profile(identifier: str) -> dict[str, Any]:
    matches = [
        row
        for row in _registry()["profiles"]
        if row.get("id") == identifier or row.get("name") == identifier
    ]
    if len(matches) != 1:
        raise ValueError(f"unknown or ambiguous compiler profile: {identifier}")
    return matches[0]


def _complete_resolution(
    *, aiken_source: Path | None, repository: str, ref: str
) -> dict[str, Any]:
    if aiken_source is not None:
        return resolve_release_ref(ref=ref, aiken_source=aiken_source)
    with tempfile.TemporaryDirectory(prefix="ak-equiv-profile-lock-") as temporary:
        checkout = Path(temporary) / "aiken"
        clone = run_process(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                repository,
                checkout,
            ],
            Path(temporary),
            600.0,
            inherit_environment=False,
        )
        if clone.timed_out or clone.exit_code != 0:
            detail = clone.stderr.strip() or clone.stdout.strip() or "no diagnostic"
            raise RuntimeError(f"failed to clone Aiken for profile locking: {detail}")
        return resolve_release_ref(ref=ref, aiken_source=checkout)


def lock_profile(
    identifier: str,
    *,
    output: Path = PROFILE_LOCK,
    aiken_source: Path | None = None,
    aiken_repository: str = DEFAULT_AIKEN_REPOSITORY,
) -> dict[str, Any]:
    profile = load_profile(identifier)
    refs = [profile.get("old_ref"), profile.get("new_ref")]
    releases = {
        ref: _complete_resolution(
            aiken_source=aiken_source,
            repository=aiken_repository,
            ref=ref,
        )
        for ref in refs
        if isinstance(ref, str)
    }
    output = output.expanduser().resolve()
    existing: dict[str, Any] = {"schema_version": 1, "profiles": {}}
    if output.is_file():
        existing = json.loads(output.read_text(encoding="utf-8"))
        if existing.get("schema_version") != 1 or not isinstance(
            existing.get("profiles"), dict
        ):
            raise ValueError(f"invalid compiler profile lock: {output}")
    lock_record = {
        "profile_id": profile["id"],
        "profile_registry_sha256": sha256_file(PROFILE_REGISTRY),
        "profile_definition_sha256": _stable_hash(profile),
        "releases": releases,
    }
    existing["profiles"][profile["id"]] = lock_record
    write_json(output, existing)
    return lock_record


def _locked_profile(profile: dict[str, Any], lock_path: Path) -> dict[str, Any]:
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    record = lock.get("profiles", {}).get(profile["id"])
    if not isinstance(record, dict):
        raise ValueError(f"profile is not locked: {profile['id']}")
    if record.get("profile_definition_sha256") != _stable_hash(profile):
        raise ValueError(f"profile definition changed after locking: {profile['id']}")
    return record


def _release_compiler(
    ref: str,
    *,
    aiken_source: Path | None,
    aiken_repository: str,
) -> tuple[Path, Any]:
    output = REPOSITORY_ROOT / ".ak-equiv" / "compilers" / ref
    manifest_path = output / "compiler.json"
    if not manifest_path.is_file():
        build_release(
            ref=ref,
            output=output,
            aiken_source=aiken_source,
            aiken_repository=aiken_repository,
        )
    return manifest_path, compiler_from_manifest(ref, manifest_path)


def _validate_locked_compiler(
    *, ref: str, compiler: Any, lock_record: dict[str, Any]
) -> None:
    release = lock_record.get("releases", {}).get(ref)
    if not isinstance(release, dict):
        raise ValueError(f"profile lock has no release record for {ref}")
    if compiler.git_revision != release.get("commit_sha"):
        raise ValueError(
            f"compiler manifest revision does not match profile lock for {ref}: "
            f"{compiler.git_revision} != {release.get('commit_sha')}"
        )


def _validate_local_base(compiler: Compiler) -> None:
    if (
        compiler.git_revision is None
        or compiler.provenance.get("dirty") is True
        or compiler.provenance.get("reproducible_from_commit") is not True
    ):
        raise ValueError(
            "local-candidate base compiler must come from a clean committed source"
        )


def _validate_local_candidate(compiler: Compiler) -> None:
    if compiler.provenance.get("artifact_kind") != "local":
        raise ValueError(
            "local-candidate candidate compiler must use a build-local artifact"
        )


def _semantic_statuses(
    bundle: Path, *, include_identical: bool = False
) -> list[str]:
    value = json.loads(
        (bundle / "pair-results.json").read_text(encoding="utf-8")
    )
    statuses: list[str] = []
    for row in value["records"]:
        old = row.get("old_program_artifact") or row.get("old_script")
        new = row.get("new_program_artifact") or row.get("new_script")
        old_hash = (
            old.get("script_sha256", old.get("sha256"))
            if isinstance(old, dict)
            else None
        )
        new_hash = (
            new.get("script_sha256", new.get("sha256"))
            if isinstance(new, dict)
            else None
        )
        if include_identical or (
            isinstance(old_hash, str)
            and isinstance(new_hash, str)
            and old_hash != new_hash
        ):
            statuses.append(row["status"])
    return statuses


def profile_result(
    profile: dict[str, Any],
    summary: dict[str, Any],
    semantic_statuses: list[str],
) -> dict[str, Any]:
    expected_semantic = profile.get("expected_semantic_status")
    observed_semantic = (
        semantic_statuses[0]
        if semantic_statuses and len(set(semantic_statuses)) == 1
        else None
    )
    strict_result = "pass" if summary["strict_pass"] else "fail"
    expected_strict = profile.get("expected_strict_result")
    expectation_matched = (
        summary.get("script_difference_observed")
        or not profile.get("require_script_difference", False)
    ) and (
        expected_semantic is None
        or bool(semantic_statuses)
        and all(status == expected_semantic for status in semantic_statuses)
    ) and (expected_strict is None or strict_result == expected_strict)
    return {
        "schema_version": 1,
        "profile_id": profile["id"],
        "profile_name": profile["name"],
        "semantic_status": observed_semantic,
        "semantic_statuses": semantic_statuses,
        "profile_expectation": expected_semantic,
        "expectation_matched": expectation_matched,
        "semantic_strict_result": strict_result,
        "expected_strict_result": expected_strict,
        "profile_pass": expectation_matched
        if expected_semantic is not None
        else summary["strict_pass"],
        "underlying_summary": summary,
    }


def run_profile(
    identifier: str,
    *,
    work_root: Path = DEFAULT_WORK_ROOT,
    lock_path: Path = PROFILE_LOCK,
    aiken_source: Path | None = None,
    aiken_repository: str = DEFAULT_AIKEN_REPOSITORY,
    old_manifest: Path | None = None,
    new_manifest: Path | None = None,
    resume: bool = False,
    force: bool = False,
    strict: bool = True,
    blaster_config: Path = BLASTER_CONFIG_PATH,
) -> dict[str, Any]:
    profile = load_profile(identifier)
    config = load_blaster_config(blaster_config)
    if profile["kind"] == "historical":
        locked = _locked_profile(profile, lock_path.expanduser().resolve())
        old_path, old = _release_compiler(
            profile["old_ref"],
            aiken_source=aiken_source,
            aiken_repository=aiken_repository,
        )
        new_path, new = _release_compiler(
            profile["new_ref"],
            aiken_source=aiken_source,
            aiken_repository=aiken_repository,
        )
        _validate_locked_compiler(ref=profile["old_ref"], compiler=old, lock_record=locked)
        _validate_locked_compiler(ref=profile["new_ref"], compiler=new, lock_record=locked)
        compilers = (
            compiler_from_manifest("old", old_path),
            compiler_from_manifest("new", new_path),
        )
        summary = compare_package(
            REPOSITORY_ROOT / profile["fixture"],
            compilers,
            work_root=work_root,
            strict=True,
            blaster_config=config,
            resume=resume,
            force=force,
            require_script_difference=bool(profile["require_script_difference"]),
        )
    else:
        if old_manifest is None or new_manifest is None:
            raise ValueError(
                "local-candidate requires --old-compiler-manifest and --new-compiler-manifest"
            )
        compilers = (
            compiler_from_manifest("old", old_manifest),
            compiler_from_manifest("new", new_manifest),
        )
        _validate_local_base(compilers[0])
        _validate_local_candidate(compilers[1])
        feature_contract = profile.get("feature_contract")
        if isinstance(feature_contract, str):
            summary = compare_sentinel(
                REPOSITORY_ROOT / profile["fixture"],
                compilers,
                work_root=work_root,
                strict=strict,
                blaster_config=config,
                feature_contract=REPOSITORY_ROOT / feature_contract,
                resume=resume,
                force=force,
            )
        else:
            summary = compare_package(
                REPOSITORY_ROOT / profile["fixture"],
                compilers,
                work_root=work_root,
                strict=strict,
                blaster_config=config,
                resume=resume,
                force=force,
                require_script_difference=bool(
                    profile["require_script_difference"]
                ),
            )

    bundle = Path(summary["output"])
    semantic_statuses = _semantic_statuses(
        bundle, include_identical=profile["kind"] == "local"
    )
    report = profile_result(profile, summary, semantic_statuses)
    write_json(bundle / "profile-result.json", report)
    return report
