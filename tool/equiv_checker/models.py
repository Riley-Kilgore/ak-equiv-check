from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol


FINAL_STATUSES = frozenset(
    {
        "identical",
        "blaster_valid",
        "blaster_falsified_unreplayed",
        "confirmed_non_equivalent",
        "blaster_inconclusive",
        "blaster_unsupported",
        "blaster_timeout",
        "blaster_error",
        "old_build_failed",
        "new_build_failed",
        "validator_missing_old",
        "validator_missing_new",
        "validator_signature_changed",
        "feature_not_shared",
        "expected_negative_diagnostic",
        "not_applicable",
    }
)

STRICT_PASSING_STATUSES = frozenset(
    {"identical", "blaster_valid", "expected_negative_diagnostic", "not_applicable"}
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
class BlasterConfig:
    backend_root: Path
    revisions: dict[str, str]
    lean_version: str
    z3_version: str
    solver: str
    fuel: int
    timeouts: Timeouts
    random_seed: int = 1

    def identity(self) -> dict[str, Any]:
        return {
            "backend_root": str(self.backend_root),
            "revisions": dict(sorted(self.revisions.items())),
            "lean_version": self.lean_version,
            "z3_version": self.z3_version,
            "solver": self.solver,
            "fuel": self.fuel,
            "timeouts": asdict(self.timeouts),
            "random_seed": self.random_seed,
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
        }


@dataclass(frozen=True)
class InputModel:
    kind: str
    plutus_version: str
    purpose: str
    variables: tuple[dict[str, str], ...]
    quantified_components: tuple[str, ...]
    domain_expression: str
    domain_assumptions: tuple[str, ...]
    observation: str
    non_vacuity: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "plutus_version": self.plutus_version,
            "purpose": self.purpose,
            "variables": list(self.variables),
            "quantified_components": list(self.quantified_components),
            "domain_expression": self.domain_expression,
            "domain_assumptions": list(self.domain_assumptions),
            "observation": self.observation,
            "non_vacuity": self.non_vacuity,
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
