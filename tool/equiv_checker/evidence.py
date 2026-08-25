from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Mapping

EVIDENCE_IDENTITY_SCHEMA_VERSION = "equiv-evidence-identity/v3"
GENERATED_LEAN_SCHEMA_VERSION = "equiv-generated-lean/v3"
RESULT_PROTOCOL_V2 = "EQUIV_RESULT_V2"
RESULT_PROTOCOL_V3 = "EQUIV_RESULT_V3"
WITNESS_PROTOCOL_V2 = "EQUIV_WITNESS_V2"
WITNESS_PROTOCOL_V3 = "EQUIV_WITNESS_V3"
RESULT_PROTOCOL = RESULT_PROTOCOL_V3
WITNESS_PROTOCOL = WITNESS_PROTOCOL_V3

OBLIGATION_KINDS = frozenset(
    {
        "domain_non_vacuity",
        "old_program_completion",
        "new_program_completion",
        "observational_equivalence",
        "ledger_domain_non_vacuity",
        "ledger_observational_equivalence",
    }
)
SOLVER_STATUSES = frozenset({"valid", "falsified", "inconclusive"})

RESULT_MARKER_FIELDS_V2 = frozenset(
    {
        "protocol_version",
        "program_pair_id",
        "logical_obligation_id",
        "semantic_model_id",
        "checker_configuration_id",
        "old_script_sha256",
        "new_script_sha256",
        "verified_abi_id",
        "obligation_kind",
        "theorem_statement_hash",
        "generated_source_schema_version",
        "solver_status",
    }
)
RESULT_MARKER_FIELDS = RESULT_MARKER_FIELDS_V2 | {"checker_implementation_id"}

WITNESS_FIELDS_V2 = frozenset(
    {
        "protocol_version",
        "program_pair_id",
        "logical_obligation_id",
        "theorem_statement_hash",
        "semantic_model_id",
        "ordered_argument_list",
        "argument_names",
        "argument_types",
        "structured_argument_values",
        "serialized_uplc_argument_terms",
        "domain_satisfaction_evidence",
        "witness_source",
        "witness_sha256",
    }
)
WITNESS_FIELDS = WITNESS_FIELDS_V2 | {"checker_implementation_id"}


def canonical_json(value: Any) -> str:
    if is_dataclass(value):
        value = asdict(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def identity_hash(kind: str, value: Mapping[str, Any]) -> str:
    return sha256_text(
        canonical_json(
            {
                "identity_schema_version": EVIDENCE_IDENTITY_SCHEMA_VERSION,
                "identity_kind": kind,
                "value": dict(value),
            }
        )
    )


_EXCLUDED_IMPLEMENTATION_PARTS = frozenset(
    {
        ".git",
        ".lake",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "build",
        "dist",
        "logs",
        "target",
        "work",
    }
)


def checker_implementation_manifest(
    repository_root: Path | None = None,
) -> dict[str, Any]:
    """Return the deterministic, content-addressed checker source tree."""
    root = (
        repository_root.expanduser().resolve()
        if repository_root is not None
        else Path(__file__).resolve().parents[2]
    )
    tool_root = root / "tool"
    candidates: set[Path] = set()
    recursive_roots = (
        tool_root / "equiv_checker",
        tool_root / "schemas",
        tool_root / "aiken-shim",
        tool_root / "blaster-backend",
    )
    for source_root in recursive_roots:
        if source_root.is_dir():
            candidates.update(path for path in source_root.rglob("*") if path.is_file())
    if tool_root.is_dir():
        candidates.update(
            path
            for path in tool_root.iterdir()
            if path.is_file() and path.suffix in {".json", ".lock", ".toml"}
        )

    files = []
    for path in sorted(candidates):
        relative = path.relative_to(root)
        if any(part in _EXCLUDED_IMPLEMENTATION_PARTS for part in relative.parts):
            continue
        if relative.parts[:2] == ("tool", "equiv_checker") and path.suffix != ".py":
            continue
        if relative.parts[:2] == ("tool", "schemas") and path.suffix != ".json":
            continue
        files.append(
            {
                "path": relative.as_posix(),
                "sha256": sha256_bytes(path.read_bytes()),
                "size": path.stat().st_size,
            }
        )
    if not files:
        raise ValueError(f"checker implementation tree is empty under {root}")
    payload = {"tree_schema_version": 1, "files": files}
    return payload | {
        "checker_implementation_id": identity_hash(
            "checker_implementation", payload
        )
    }


def checker_implementation_id(repository_root: Path | None = None) -> str:
    return str(
        checker_implementation_manifest(repository_root)["checker_implementation_id"]
    )


def program_artifact_id(
    serialized_script_bytes: bytes,
    plutus_version: str,
    serialization_format: str,
) -> str:
    return identity_hash(
        "program_artifact",
        {
            "serialized_script_sha256": sha256_bytes(serialized_script_bytes),
            "plutus_version": plutus_version,
            "serialization_format": serialization_format,
        },
    )


def verified_abi_id(abi: Mapping[str, Any]) -> str:
    if abi.get("status") != "verified":
        raise ValueError("verified ABI identity requires status=verified")
    return identity_hash(
        "verified_abi",
        {
            "top_level_callable_arity": abi["top_level_callable_arity"],
            "applied_parameter_count": abi["applied_parameter_count"],
            "remaining_runtime_argument_count": abi[
                "remaining_runtime_argument_count"
            ],
            "argument_order": list(abi["argument_order"]),
            "argument_value_representation": list(
                abi["argument_value_representation"]
            ),
            "parameter_schemas": list(abi["parameter_schemas"]),
            "plutus_version": abi["plutus_version"],
        },
    )


def program_pair_id(
    old_program_artifact_id: str,
    new_program_artifact_id: str,
    abi_id: str,
) -> str:
    return identity_hash(
        "program_pair",
        {
            "old_program_artifact_id": old_program_artifact_id,
            "new_program_artifact_id": new_program_artifact_id,
            "verified_abi_id": abi_id,
        },
    )


def semantic_model_payload(
    model: Mapping[str, Any], semantic_runtime_bound: int
) -> dict[str, Any]:
    profile = str(model["profile"])
    payload: dict[str, Any] = {
        "profile_version": model["version"],
        "profile": profile,
        "variable_types": [row["type"] for row in model["variables"]],
        "argument_order": list(model["argument_order"]),
        "arity": model["arity"],
        "domain_predicate": model["domain_expression"],
        "domain_assumptions": list(model["domain_assumptions"]),
        "observation_function": model["observation"],
        "semantic_runtime_bound": semantic_runtime_bound,
    }
    if profile.startswith("ledger-valid"):
        payload["purpose_specific_ledger_predicate"] = {
            "purpose": model["purpose"],
            "domain_predicate": model["domain_expression"],
        }
    return payload


def semantic_model_id(
    model: Mapping[str, Any], semantic_runtime_bound: int
) -> str:
    return identity_hash(
        "semantic_model", semantic_model_payload(model, semantic_runtime_bound)
    )


def logical_obligation_id(
    pair_id: str, model_id: str, obligation_kind: str
) -> str:
    if obligation_kind not in OBLIGATION_KINDS:
        raise ValueError(f"unknown obligation kind: {obligation_kind}")
    return identity_hash(
        "logical_obligation",
        {
            "program_pair_id": pair_id,
            "semantic_model_id": model_id,
            "obligation_kind": obligation_kind,
        },
    )


def checker_configuration_payload(
    *,
    lean_version: str,
    revisions: Mapping[str, str],
    z3_version: str,
    solver: str,
    solver_binary_sha256: str,
    solver_configuration: Mapping[str, Any] | None = None,
    checker_implementation_id_value: str | None = None,
) -> dict[str, Any]:
    plutus_revision = revisions.get("PlutusCoreBlaster")
    return {
        "checker_implementation_id": (
            checker_implementation_id_value or checker_implementation_id()
        ),
        "generated_lean_schema_version": GENERATED_LEAN_SCHEMA_VERSION,
        "result_protocol": RESULT_PROTOCOL,
        "witness_protocol": WITNESS_PROTOCOL,
        "lean_version": lean_version,
        "lean_blaster_revision": revisions.get("Lean-blaster"),
        "plutus_core_blaster_revision": plutus_revision,
        "cardano_ledger_api_blaster_revision": revisions.get(
            "CardanoLedgerApiBlaster"
        ),
        "uplc_importer_revision": revisions.get("UPLC importer", plutus_revision),
        "uplc_preparer_revision": revisions.get("UPLC preparer", plutus_revision),
        "z3_version": z3_version,
        "solver": solver,
        "solver_binary_sha256": solver_binary_sha256,
        "solver_configuration": dict(solver_configuration or {}),
    }


def checker_configuration_id(payload: Mapping[str, Any]) -> str:
    return identity_hash("checker_configuration", payload)


def platform_identity() -> dict[str, str]:
    return {
        "system": platform.system().lower(),
        "machine": platform.machine().lower(),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
    }


def execution_attempt_id(
    *,
    execution_plan: Mapping[str, Any],
    generated_source_sha256: str | None,
    checker_configuration_id_value: str,
    checker_implementation_id_value: str,
    process_timeouts: Mapping[str, Any],
    random_seed: int,
    platform_identity_value: Mapping[str, Any],
    execution_sequence: int,
) -> str:
    return identity_hash(
        "execution_attempt",
        {
            "execution_plan": dict(execution_plan),
            "generated_source_sha256": generated_source_sha256,
            "checker_configuration_id": checker_configuration_id_value,
            "checker_implementation_id": checker_implementation_id_value,
            "process_timeouts": dict(process_timeouts),
            "random_seed": random_seed,
            "platform_identity": dict(platform_identity_value),
            "execution_sequence": execution_sequence,
        },
    )


def obligation_attempt_id(
    *,
    logical_obligation_id_value: str,
    checker_configuration_id_value: str,
    execution_attempt_id_value: str,
    relevant_solver_options: Mapping[str, Any],
    attempt_sequence: int,
) -> str:
    return identity_hash(
        "obligation_attempt",
        {
            "logical_obligation_id": logical_obligation_id_value,
            "checker_configuration_id": checker_configuration_id_value,
            "execution_attempt_id": execution_attempt_id_value,
            "relevant_solver_options": dict(relevant_solver_options),
            "attempt_sequence": attempt_sequence,
        },
    )


def attempt_id(
    *,
    logical_obligation_id_value: str,
    checker_configuration_id_value: str,
    random_seed: int,
    solver_timeout: float,
    process_timeouts: Mapping[str, Any],
    platform_identity_value: Mapping[str, Any],
    attempt_sequence: int,
) -> str:
    """Legacy V2 attempt identity retained for baseline compatibility."""
    return identity_hash(
        "attempt",
        {
            "logical_obligation_id": logical_obligation_id_value,
            "checker_configuration_id": checker_configuration_id_value,
            "random_seed": random_seed,
            "solver_timeout": solver_timeout,
            "process_timeouts": dict(process_timeouts),
            "platform_identity": dict(platform_identity_value),
            "attempt_sequence": attempt_sequence,
        },
    )


def evidence_run_id(payload: Mapping[str, Any]) -> str:
    forbidden = {
        "policy",
        "selected_policy",
        "strict_policy",
        "screening_policy",
        "exit_preference",
    }
    present = sorted(forbidden & set(payload))
    if present:
        raise ValueError(
            "release policy is not evidence identity input: " + ", ".join(present)
        )
    return identity_hash("evidence_run", payload)


def release_decision_id(
    *,
    evidence_run_id_value: str,
    policy_name: str,
    policy_schema_version: str,
    policy_configuration: Mapping[str, Any],
) -> str:
    return identity_hash(
        "release_decision",
        {
            "evidence_run_id": evidence_run_id_value,
            "policy_name": policy_name,
            "policy_schema_version": policy_schema_version,
            "policy_configuration": dict(policy_configuration),
        },
    )


def theorem_statement_hash(statement: str) -> str:
    return sha256_text(statement)

def execution_attempt_id_from_record(record: Mapping[str, Any]) -> str:
    return execution_attempt_id(
        execution_plan=record["execution_plan"],
        generated_source_sha256=record.get("generated_source_sha256"),
        checker_configuration_id_value=record["checker_configuration_id"],
        checker_implementation_id_value=record["checker_implementation_id"],
        process_timeouts=record["process_timeouts"],
        random_seed=int(record["random_seed"]),
        platform_identity_value=record["platform_identity"],
        execution_sequence=int(record["execution_sequence"]),
    )


def obligation_attempt_id_from_record(record: Mapping[str, Any]) -> str:
    return obligation_attempt_id(
        logical_obligation_id_value=record["logical_obligation_id"],
        checker_configuration_id_value=record["checker_configuration_id"],
        execution_attempt_id_value=record["execution_attempt_id"],
        relevant_solver_options=record["relevant_solver_options"],
        attempt_sequence=int(record["attempt_sequence"]),
    )


def obligation_result_id(record: Mapping[str, Any]) -> str:
    payload = {
        "logical_obligation_id": record["logical_obligation_id"],
        "obligation_attempt_id": record["obligation_attempt_id"],
        "execution_attempt_id": record["execution_attempt_id"],
        "checker_configuration_id": record["checker_configuration_id"],
        "checker_implementation_id": record["checker_implementation_id"],
        "program_pair_id": record["program_pair_id"],
        "semantic_model_id": record["semantic_model_id"],
        "obligation_kind": record["obligation_kind"],
        "status": record["status"],
        "generated_source_sha256": record.get("generated_source_sha256"),
        "solver_status": record.get("solver_status"),
        "witness_reference": record.get("witness_reference"),
        "replay_reference": record.get("replay_reference"),
        "relevant_solver_options": record["relevant_solver_options"],
        "attempt_sequence": int(record["attempt_sequence"]),
    }
    return identity_hash("obligation_result", payload)


def validate_result_marker(
    marker: Mapping[str, Any], expected: Mapping[str, Any]
) -> dict[str, Any]:
    protocol = marker.get("protocol_version")
    required_fields = (
        RESULT_MARKER_FIELDS_V2
        if protocol == RESULT_PROTOCOL_V2
        else RESULT_MARKER_FIELDS
        if protocol == RESULT_PROTOCOL_V3
        else frozenset()
    )
    if not required_fields:
        raise ValueError("unknown result protocol version")
    fields = set(marker)
    if fields != required_fields:
        missing = sorted(required_fields - fields)
        unknown = sorted(fields - required_fields)
        raise ValueError(
            f"invalid result marker schema; missing={missing}, unknown={unknown}"
        )
    if marker.get("solver_status") not in SOLVER_STATUSES:
        raise ValueError("unknown solver status")
    if marker.get("obligation_kind") not in OBLIGATION_KINDS:
        raise ValueError("unknown obligation kind")
    mismatches = [
        field
        for field in sorted(required_fields - {"solver_status", "protocol_version"})
        if field in expected and marker.get(field) != expected.get(field)
    ]
    if mismatches:
        raise ValueError("result marker binding mismatch: " + ", ".join(mismatches))
    return dict(marker)


def witness_hash(record: Mapping[str, Any]) -> str:
    return sha256_text(
        canonical_json({key: value for key, value in record.items() if key != "witness_sha256"})
    )


def validate_witness_record(
    witness: Mapping[str, Any], expected: Mapping[str, Any]
) -> dict[str, Any]:
    protocol = witness.get("protocol_version")
    required_fields = (
        WITNESS_FIELDS_V2
        if protocol == WITNESS_PROTOCOL_V2
        else WITNESS_FIELDS
        if protocol == WITNESS_PROTOCOL_V3
        else frozenset()
    )
    if not required_fields:
        raise ValueError("unknown witness protocol version")
    fields = set(witness)
    if fields != required_fields:
        missing = sorted(required_fields - fields)
        unknown = sorted(fields - required_fields)
        raise ValueError(
            f"invalid witness schema; missing={missing}, unknown={unknown}"
        )
    for field in (
        "program_pair_id",
        "logical_obligation_id",
        "theorem_statement_hash",
        "semantic_model_id",
        "ordered_argument_list",
        "argument_names",
        "argument_types",
        "checker_implementation_id",
    ):
        if field in expected and witness.get(field) != expected.get(field):
            raise ValueError(f"witness binding mismatch: {field}")
    names = witness["argument_names"]
    types = witness["argument_types"]
    values = witness["structured_argument_values"]
    terms = witness["serialized_uplc_argument_terms"]
    ordered = witness["ordered_argument_list"]
    if not all(isinstance(value, list) for value in (names, types, values, terms, ordered)):
        raise ValueError("witness arguments must be ordered arrays")
    if not (len(names) == len(types) == len(values) == len(terms) == len(ordered)):
        raise ValueError("witness arity mismatch")
    if ordered != names:
        raise ValueError("witness ordered argument list does not match argument names")
    domain = witness["domain_satisfaction_evidence"]
    if not isinstance(domain, dict) or domain.get("satisfied") is not True:
        raise ValueError("witness does not satisfy the semantic domain")
    if witness.get("witness_sha256") != witness_hash(witness):
        raise ValueError("witness checksum mismatch")
    return dict(witness)


def candidate_witness_id(record: Mapping[str, Any]) -> str:
    return identity_hash(
        "candidate_witness",
        {key: value for key, value in record.items() if key != "witness_id"},
    )


def replay_id(record: Mapping[str, Any]) -> str:
    return identity_hash(
        "counterexample_replay",
        {key: value for key, value in record.items() if key != "replay_id"},
    )
