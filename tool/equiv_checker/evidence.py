from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import asdict, is_dataclass
from typing import Any, Mapping

EVIDENCE_IDENTITY_SCHEMA_VERSION = "equiv-evidence-identity/v2"
GENERATED_LEAN_SCHEMA_VERSION = "equiv-generated-lean/v2"
RESULT_PROTOCOL = "EQUIV_RESULT_V2"
WITNESS_PROTOCOL = "EQUIV_WITNESS_V2"

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

RESULT_MARKER_FIELDS = frozenset(
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

WITNESS_FIELDS = frozenset(
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
) -> dict[str, Any]:
    plutus_revision = revisions.get("PlutusCoreBlaster")
    return {
        "generated_lean_schema_version": GENERATED_LEAN_SCHEMA_VERSION,
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


def theorem_statement_hash(statement: str) -> str:
    return sha256_text(statement)


def validate_result_marker(
    marker: Mapping[str, Any], expected: Mapping[str, Any]
) -> dict[str, Any]:
    fields = set(marker)
    if fields != RESULT_MARKER_FIELDS:
        missing = sorted(RESULT_MARKER_FIELDS - fields)
        unknown = sorted(fields - RESULT_MARKER_FIELDS)
        raise ValueError(
            f"invalid result marker schema; missing={missing}, unknown={unknown}"
        )
    if marker.get("protocol_version") != RESULT_PROTOCOL:
        raise ValueError("unknown result protocol version")
    if marker.get("solver_status") not in SOLVER_STATUSES:
        raise ValueError("unknown solver status")
    if marker.get("obligation_kind") not in OBLIGATION_KINDS:
        raise ValueError("unknown obligation kind")
    mismatches = [
        field
        for field in sorted(RESULT_MARKER_FIELDS - {"solver_status", "protocol_version"})
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
    fields = set(witness)
    if fields != WITNESS_FIELDS:
        missing = sorted(WITNESS_FIELDS - fields)
        unknown = sorted(fields - WITNESS_FIELDS)
        raise ValueError(
            f"invalid witness schema; missing={missing}, unknown={unknown}"
        )
    if witness.get("protocol_version") != WITNESS_PROTOCOL:
        raise ValueError("unknown witness protocol version")
    for field in (
        "program_pair_id",
        "logical_obligation_id",
        "theorem_statement_hash",
        "semantic_model_id",
        "ordered_argument_list",
        "argument_names",
        "argument_types",
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
