from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .evidence import (
    attempt_id,
    checker_configuration_id,
    checker_configuration_payload,
    logical_obligation_id,
    platform_identity,
    program_artifact_id,
    semantic_model_id,
)


FINAL_STATUSES = frozenset(
    {
        "identical",
        "equivalent_under_raw_model",
        "equivalent_under_ledger_model",
        "off_ledger_difference",
        "bounded_equivalent",
        "blaster_valid",
        "blaster_falsified_unreplayed",
        "confirmed_non_equivalent",
        "blaster_inconclusive",
        "expected_codegen_delta_not_observed",
        "blaster_unsupported",
        "blaster_timeout",
        "blaster_error",
        "raw_model_unsupported",
        "ledger_model_unsupported",
        "fallback_purpose_unsupported",
        "model_unsupported",
        "domain_non_vacuous_failed",
        "source_checkout_failed",
        "source_revision_mismatch",
        "dependency_materialization_failed",
        "missing_dependency_lock",
        "old_build_failed",
        "new_build_failed",
        "old_uplc_extraction_failed",
        "new_uplc_extraction_failed",
        "old_blueprint_missing",
        "old_raw_abi_unresolved",
        "new_raw_abi_unresolved",
        "raw_abi_mismatch",
        "raw_abi_parser_error",
        "raw_model_not_bound_to_abi",
        "new_blueprint_missing",
        "old_blueprint_malformed",
        "new_blueprint_malformed",
        "blueprint_schema_supported",
        "blueprint_schema_unsupported",
        "blueprint_schema_ambiguous",
        "blueprint_missing_required_field",
        "blueprint_compiled_code_invalid",
        "compiled_abi_unverified",
        "compiled_abi_mismatch",
        "validator_missing_old",
        "pair_identical",
        "pair_complete_equivalent",
        "pair_bounded_equivalent",
        "pair_confirmed_non_equivalent",
        "pair_inconclusive",
        "pair_unsupported",
        "pair_missing",
        "old_reachability_failed",
        "new_reachability_failed",
        "feature_old_only",
        "feature_new_only",
        "validator_missing_new",
        "validator_signature_changed",
        "adapter_failed",
        "lane_failed",
        "contract_mismatch",
        "environment_mismatch",
        "missing_evidence",
        "pending_evidence",
        "expected_negative_diagnostic",
        "not_applicable",
    }
)

STRICT_PASSING_STATUSES = frozenset(
    {
        "identical",
        "equivalent_under_raw_model",
        "expected_negative_diagnostic",
        "not_applicable",
        "pair_identical",
        "pair_complete_equivalent",
    }
)


@dataclass(frozen=True)
class Timeouts:
    aiken_build: float = 300.0
    uplc_extraction: float = 300.0
    uplc_import: float = 120.0
    uplc_preparation: float = 300.0
    lean_elaboration: float = 300.0
    blaster_optimization: float = 300.0
    z3: float = 120.0
    counterexample_replay: float = 120.0

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Timeouts:
        defaults = asdict(cls())
        unknown = set(value) - set(defaults)
        if unknown:
            raise ValueError(f"unknown timeout names: {', '.join(sorted(unknown))}")
        merged = defaults | value
        if any(not isinstance(item, (int, float)) or item <= 0 for item in merged.values()):
            raise ValueError("all phase timeouts must be positive numbers")
        return cls(**{key: float(item) for key, item in merged.items()})


@dataclass(frozen=True)
class EvaluatorConfig:
    name: str
    version: str
    revision: str
    binary_sha256: str
    executable: Path
    evaluation_limits: dict[str, Any]
    backend_kind: str = "aiken"
    separately_pinned: bool = True
    distinct_uplc_implementation: bool = False
    supported_limit_flags: tuple[str, ...] = ()

    def identity(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "revision": self.revision,
            "binary_sha256": self.binary_sha256,
            "evaluation_limits": self.evaluation_limits,
            "backend_kind": self.backend_kind,
            "separately_pinned": self.separately_pinned,
            "distinct_uplc_implementation": self.distinct_uplc_implementation,
            "supported_limit_flags": list(self.supported_limit_flags),
        }


@dataclass(frozen=True)
class BlasterConfig:
    backend_root: Path
    revisions: dict[str, str]
    lean_version: str
    z3_version: str
    solver: str
    solver_executable: Path
    solver_binary_sha256: str
    runtime_step_bound: int
    timeouts: Timeouts
    random_seed: int = 1
    evaluator: EvaluatorConfig | None = None
    secondary_evaluator: EvaluatorConfig | None = None

    def checker_configuration(self) -> dict[str, Any]:
        payload = checker_configuration_payload(
            lean_version=self.lean_version,
            revisions=self.revisions,
            z3_version=self.z3_version,
            solver=self.solver,
            solver_binary_sha256=self.solver_binary_sha256,
            solver_configuration={"fuel_semantics": "maximum CEK transitions per concrete modeled input"},
        )
        return payload | {
            "checker_configuration_id": checker_configuration_id(payload)
        }

    def identity(self) -> dict[str, Any]:
        return {
            **self.checker_configuration(),
            "semantic_runtime_step_bound": self.runtime_step_bound,
            "fuel_semantics": "maximum CEK transitions per concrete modeled input",
            "timeouts": asdict(self.timeouts),
            "random_seed": self.random_seed,
            "evaluator": self.evaluator.identity() if self.evaluator else None,
            "secondary_evaluator": (
                self.secondary_evaluator.identity() if self.secondary_evaluator else None
            ),
        }


@dataclass(frozen=True)
class ScriptArtifact:
    path: Path
    relative_path: str
    sha256: str
    size: int
    plutus_version: str = "v3"
    serialization_format: str = "single_cbor_hex"
    compiler_artifact_id: str = "unbound"
    source_validator_references: tuple[str, ...] = ()
    program_artifact_id: str = ""

    def __post_init__(self) -> None:
        if self.program_artifact_id:
            return
        serialized = bytes.fromhex(self.path.read_text(encoding="ascii").strip())
        object.__setattr__(
            self,
            "program_artifact_id",
            program_artifact_id(
                serialized,
                self.plutus_version,
                self.serialization_format,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "program_artifact_id": self.program_artifact_id,
            "path": self.relative_path,
            "script_sha256": self.sha256,
            "script_size": self.size,
            "serialization_format": self.serialization_format,
            "plutus_version": self.plutus_version,
            "source_validator_references": list(self.source_validator_references),
            "compiler_artifact_id": self.compiler_artifact_id,
        }


@dataclass(frozen=True)
class ValidatorRecord:
    validator_record_id: str
    repository: str
    package: str
    module: str
    validator: str
    handler_title: str
    purpose: str
    parameter_schemas: tuple[dict[str, Any], ...]
    datum_schema: dict[str, Any] | None
    redeemer_schema: dict[str, Any] | None
    blueprint_reference: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HandlerPairRecord:
    handler_pair_id: str
    repository: str
    package: str
    module: str
    validator: str
    handler_title: str
    purpose: str
    parameter_schemas: tuple[dict[str, Any], ...]
    datum_schema: dict[str, Any] | None
    redeemer_schema: dict[str, Any] | None
    old_blueprint_reference: dict[str, Any]
    new_blueprint_reference: dict[str, Any]
    old_validator_record_id: str
    new_validator_record_id: str
    program_pair_id: str | None
    feature_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProgramPairRecord:
    program_pair_id: str
    old_script: ScriptArtifact
    new_script: ScriptArtifact
    verified_abi_id: str
    verified_abi: dict[str, Any]
    plutus_version: str
    handler_pair_ids: tuple[str, ...]
    handler_references: tuple[dict[str, Any], ...]
    covered_feature_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "program_pair_id": self.program_pair_id,
            "old_program_artifact": self.old_script.to_dict(),
            "new_program_artifact": self.new_script.to_dict(),
            "verified_abi_id": self.verified_abi_id,
            "verified_abi": self.verified_abi,
            "plutus_version": self.plutus_version,
            "handler_pair_ids": list(self.handler_pair_ids),
            "handler_references": list(self.handler_references),
            "covered_feature_ids": list(self.covered_feature_ids),
        }


@dataclass(frozen=True)
class InputModel:
    kind: str
    profile: str
    version: str
    plutus_version: str
    purpose: str
    variables: tuple[dict[str, str], ...]
    quantified_components: tuple[str, ...]
    argument_order: tuple[str, ...]
    arity: int
    domain_expression: str
    domain_assumptions: tuple[str, ...]
    domain_witness: dict[str, Any] | None
    observation: str
    non_vacuity: dict[str, Any]
    supported: bool = True
    unsupported_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "profile": self.profile,
            "version": self.version,
            "plutus_version": self.plutus_version,
            "purpose": self.purpose,
            "variables": list(self.variables),
            "quantified_components": list(self.quantified_components),
            "argument_order": list(self.argument_order),
            "arity": self.arity,
            "domain_expression": self.domain_expression,
            "domain_assumptions": list(self.domain_assumptions),
            "domain_witness": self.domain_witness,
            "observation": self.observation,
            "non_vacuity": self.non_vacuity,
            "supported": self.supported,
            "unsupported_reason": self.unsupported_reason,
        }

    def semantic_model_id(self, semantic_runtime_bound: int) -> str:
        return semantic_model_id(self.to_dict(), semantic_runtime_bound)


@dataclass(frozen=True)
class SemanticObligationRecord:
    logical_obligation_id: str
    program_pair_id: str
    semantic_model_id: str
    obligation_kind: str
    semantic_runtime_bound: int
    input_model: dict[str, Any]

    @classmethod
    def create(
        cls,
        pair: ProgramPairRecord,
        model: InputModel,
        obligation_kind: str,
        semantic_runtime_bound: int,
    ) -> SemanticObligationRecord:
        model_id = model.semantic_model_id(semantic_runtime_bound)
        return cls(
            logical_obligation_id=logical_obligation_id(
                pair.program_pair_id, model_id, obligation_kind
            ),
            program_pair_id=pair.program_pair_id,
            semantic_model_id=model_id,
            obligation_kind=obligation_kind,
            semantic_runtime_bound=semantic_runtime_bound,
            input_model=model.to_dict(),
        )

    def attempt_id(
        self,
        config: BlasterConfig,
        attempt_sequence: int,
        *,
        platform: dict[str, Any] | None = None,
    ) -> str:
        return attempt_id(
            logical_obligation_id_value=self.logical_obligation_id,
            checker_configuration_id_value=config.checker_configuration()[
                "checker_configuration_id"
            ],
            random_seed=config.random_seed,
            solver_timeout=config.timeouts.z3,
            process_timeouts=asdict(config.timeouts),
            platform_identity_value=platform or platform_identity(),
            attempt_sequence=attempt_sequence,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FeatureEvidenceLink:
    feature_id: str
    handler_pair_ids: tuple[str, ...]
    program_pair_ids: tuple[str, ...]
    logical_obligation_ids: tuple[str, ...]
    authoritative_evidence_ids: tuple[str, ...]
    required_evidence_ids: tuple[str, ...]
    aggregate_result: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BlasterResult:
    status: str
    command: list[str] | None
    exit_code: int | None
    duration_seconds: float
    stdout_path: str | None = None
    stderr_path: str | None = None
    generated_lean_path: str | None = None
    generated_lean_sha256: str | None = None
    solver_input_path: str | None = None
    solver_input_sha256: str | None = None
    witness: dict[str, Any] | None = None
    phase_results: list[dict[str, Any]] = field(default_factory=list)
    proof_obligations: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def __post_init__(self) -> None:
        if self.status not in FINAL_STATUSES:
            raise ValueError(f"invalid final status: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BlasterBackend(Protocol):
    config: BlasterConfig

    def compare(
        self,
        pair: ProgramPairRecord,
        input_model: InputModel,
        output_root: Path,
    ) -> BlasterResult:
        ...

    def replay(
        self,
        pair: ProgramPairRecord,
        input_model: InputModel,
        witness: dict[str, Any],
        output_root: Path,
    ) -> dict[str, Any]:
        ...
