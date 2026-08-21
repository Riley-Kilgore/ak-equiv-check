from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol


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

    def identity(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "revision": self.revision,
            "binary_sha256": self.binary_sha256,
            "evaluation_limits": self.evaluation_limits,
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

    def identity(self) -> dict[str, Any]:
        return {
            "revisions": dict(sorted(self.revisions.items())),
            "lean_version": self.lean_version,
            "z3_version": self.z3_version,
            "solver": self.solver,
            "solver_binary_sha256": self.solver_binary_sha256,
            "runtime_step_bound": self.runtime_step_bound,
            "fuel_semantics": "maximum CEK transitions per concrete modeled input",
            "timeouts": asdict(self.timeouts),
            "random_seed": self.random_seed,
            "evaluator": self.evaluator.identity() if self.evaluator else None,
        }


@dataclass(frozen=True)
class ScriptArtifact:
    path: Path
    relative_path: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.relative_path,
            "sha256": self.sha256,
            "size": self.size,
            "encoding": "single_cbor_hex",
        }


@dataclass(frozen=True)
class ScriptPair:
    pair_id: str
    validator_identity: dict[str, Any]
    old_script: ScriptArtifact
    new_script: ScriptArtifact
    purpose: str
    parameters: tuple[dict[str, Any], ...]
    covered_feature_ids: tuple[str, ...] = ()
    plutus_version: str = "v3"
    abi: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pair_id": self.pair_id,
            "validator_identity": self.validator_identity,
            "old_script": self.old_script.to_dict(),
            "new_script": self.new_script.to_dict(),
            "purpose": self.purpose,
            "parameters": list(self.parameters),
            "covered_feature_ids": list(self.covered_feature_ids),
            "plutus_version": self.plutus_version,
            "abi": self.abi,
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

    def compare(self, pair: ScriptPair, input_model: InputModel, output_root: Path) -> BlasterResult:
        ...

    def replay(
        self,
        pair: ScriptPair,
        input_model: InputModel,
        witness: dict[str, Any],
        output_root: Path,
    ) -> dict[str, Any]:
        ...
