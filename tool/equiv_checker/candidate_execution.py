from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping

from .evidence import (
    GENERATED_LEAN_SCHEMA_VERSION,
    candidate_witness_id,
    obligation_result_id,
    platform_identity,
    replay_id,
)
from .models import (
    BlasterBackend,
    BlasterConfig,
    InputModel,
    ProgramPairRecord,
    SemanticObligationRecord,
)
from .runner import _replay_counterexample


def planned_model_obligations(
    pair: ProgramPairRecord,
    model: InputModel,
    semantic_runtime_bound: int,
) -> list[SemanticObligationRecord]:
    if not model.supported:
        return []
    kinds = (
        (
            "ledger_domain_non_vacuity",
            "old_program_completion",
            "new_program_completion",
            "ledger_observational_equivalence",
        )
        if model.profile.startswith("ledger-valid")
        else (
            "domain_non_vacuity",
            "old_program_completion",
            "new_program_completion",
            "observational_equivalence",
        )
    )
    return [
        SemanticObligationRecord.create(
            pair, model, kind, semantic_runtime_bound
        )
        for kind in kinds
    ]


def _terminal_status(proof_status: str | None, backend_status: str) -> str:
    if proof_status in {"proven", "valid", "falsified"}:
        return proof_status
    if proof_status == "inconclusive":
        return "inconclusive"
    if backend_status == "blaster_timeout":
        return "timeout"
    if "unsupported" in backend_status:
        return "unsupported"
    if backend_status == "bounded_equivalent":
        return "bounded"
    if backend_status == "blaster_inconclusive":
        return "inconclusive"
    if backend_status == "domain_non_vacuous_failed":
        return "invalid"
    return "tool_error"


def _logical_command(command: Any, generated_path: str | None) -> list[str] | None:
    if not isinstance(command, list):
        return None
    logical: list[str] = []
    generated_name = Path(generated_path).name if generated_path else None
    for value in command:
        text = str(value)
        candidate = Path(text)
        if candidate.is_absolute():
            logical.append(
                f"<generated-source:{generated_name}>"
                if generated_name and candidate.name == generated_name
                else f"<absolute-diagnostic:{candidate.name}>"
            )
        else:
            logical.append(text)
    return logical


def execute_model(
    *,
    pair: ProgramPairRecord,
    model: InputModel,
    config: BlasterConfig,
    backend: BlasterBackend,
    output_root: Path,
    compiler_identities: Mapping[str, dict[str, Any]],
    attempt_sequence: int = 1,
) -> dict[str, Any]:
    obligations = planned_model_obligations(
        pair, model, config.runtime_step_bound
    )
    if not obligations:
        raise ValueError("cannot execute an unsupported semantic model")
    backend_result = backend.compare(pair, model, output_root)
    backend_record = backend_result.to_dict()
    witness = backend_record.get("witness")
    counterexample_replay = None
    if backend_result.status == "blaster_falsified_unreplayed" and isinstance(
        witness, dict
    ):
        counterexample_replay = _replay_counterexample(
            backend,
            config,
            dict(compiler_identities),
            pair,
            model,
            witness,
            output_root,
        )
    proof_results = backend_record.get("proof_obligations", {})
    phases = [
        phase
        for phase in backend_record.get("phase_results", [])
        if isinstance(phase, dict)
    ]
    checker = config.checker_configuration()
    execution_platform = platform_identity()
    planned_ids = sorted(
        obligation.logical_obligation_id for obligation in obligations
    )
    results: list[dict[str, Any]] = []
    executions: dict[str, dict[str, Any]] = {}
    witnesses: dict[str, dict[str, Any]] = {}
    replays: dict[str, dict[str, Any]] = {}
    generated_sources: dict[str, bytes] = {}
    logs: dict[str, dict[str, bytes]] = {}
    for obligation in obligations:
        proof = proof_results.get(obligation.obligation_kind, {})
        generated_hash = proof.get("generated_lean_sha256")
        matches = [
            (index, phase)
            for index, phase in enumerate(phases, start=1)
            if generated_hash is not None
            and phase.get("generated_lean_sha256") == generated_hash
        ]
        if matches:
            phase_index, phase = matches[-1]
        elif phases:
            phase_index, phase = len(phases), phases[-1]
            generated_hash = phase.get("generated_lean_sha256")
        else:
            phase_index, phase = 1, {}
        generated_path = phase.get("generated_lean_path")
        execution_sequence = (attempt_sequence - 1) * 1000 + phase_index
        execution_plan = {
            "kind": (
                "generated_lean_process" if phase else "terminal_without_process"
            ),
            "program_pair_id": pair.program_pair_id,
            "semantic_model_id": obligation.semantic_model_id,
            "planned_logical_obligation_ids": planned_ids,
            "phase": phase.get("phase", "scheduler_terminalization"),
            "command": _logical_command(
                phase.get("command"), generated_path
            ),
            "effective_options": phase.get("effective_options", {}),
        }
        execution_id = obligation.execution_attempt_id(
            config,
            execution_plan=execution_plan,
            generated_source_sha256=generated_hash,
            execution_sequence=execution_sequence,
            platform=execution_platform,
        )
        execution_record = {
            "execution_attempt_id": execution_id,
            "checker_configuration_id": checker["checker_configuration_id"],
            "checker_implementation_id": checker[
                "checker_implementation_id"
            ],
            "execution_plan": execution_plan,
            "generated_source_sha256": generated_hash,
            "process_timeouts": asdict(config.timeouts),
            "random_seed": config.random_seed,
            "platform_identity": execution_platform,
            "execution_sequence": execution_sequence,
            "command": phase.get("command"),
            "exit_code": phase.get("exit_code"),
            "timed_out": bool(phase.get("timed_out", False)),
            "duration_seconds": float(phase.get("duration_seconds", 0.0)),
            "stdout_path": phase.get("stdout_path"),
            "stderr_path": phase.get("stderr_path"),
        }
        previous_execution = executions.setdefault(execution_id, execution_record)
        if previous_execution != execution_record:
            raise RuntimeError(f"conflicting execution attempt {execution_id}")
        solver_options = {
            **phase.get("effective_options", {}),
            "solver": config.solver,
            "solver_timeout": config.timeouts.z3,
        }
        obligation_attempt = obligation.obligation_attempt_id(
            config,
            execution_attempt_id_value=execution_id,
            relevant_solver_options=solver_options,
            attempt_sequence=attempt_sequence,
        )
        witness_reference = None
        if (
            obligation.obligation_kind
            in {
                "observational_equivalence",
                "ledger_observational_equivalence",
            }
            and isinstance(witness, dict)
            and witness.get("logical_obligation_id")
            == obligation.logical_obligation_id
        ):
            witness_record = {
                **witness,
                "producing_logical_obligation_id": (
                    obligation.logical_obligation_id
                ),
                "producing_obligation_attempt_id": obligation_attempt,
                "producing_execution_attempt_id": execution_id,
            }
            witness_reference = candidate_witness_id(witness_record)
            witness_record["witness_id"] = witness_reference
            witnesses[witness_reference] = witness_record
        replay_reference = None
        if (
            witness_reference is not None
            and isinstance(counterexample_replay, dict)
            and counterexample_replay.get("confirmed") is True
            and obligation.obligation_kind
            in {
                "observational_equivalence",
                "ledger_observational_equivalence",
            }
        ):
            replay_record = {
                **counterexample_replay,
                "logical_obligation_id": obligation.logical_obligation_id,
                "obligation_attempt_id": obligation_attempt,
                "execution_attempt_id": execution_id,
                "witness_id": witness_reference,
                "old_program_artifact_id": pair.old_script.program_artifact_id,
                "new_program_artifact_id": pair.new_script.program_artifact_id,
                "old_script_sha256": pair.old_script.sha256,
                "new_script_sha256": pair.new_script.sha256,
            }
            replay_reference = replay_id(replay_record)
            replay_record["replay_id"] = replay_reference
            replays[replay_reference] = replay_record
        result_record = {
            "logical_obligation_id": obligation.logical_obligation_id,
            "obligation_attempt_id": obligation_attempt,
            "execution_attempt_id": execution_id,
            "checker_configuration_id": checker["checker_configuration_id"],
            "checker_implementation_id": checker[
                "checker_implementation_id"
            ],
            "program_pair_id": pair.program_pair_id,
            "semantic_model_id": obligation.semantic_model_id,
            "obligation_kind": obligation.obligation_kind,
            "status": _terminal_status(
                proof.get("status"), backend_result.status
            ),
            "generated_source_sha256": generated_hash,
            "solver_status": proof.get("solver_status"),
            "witness_reference": witness_reference,
            "replay_reference": replay_reference,
            "relevant_solver_options": solver_options,
            "attempt_sequence": attempt_sequence,
            "generated_source_schema_version": GENERATED_LEAN_SCHEMA_VERSION,
            "generated_source_path": proof.get(
                "generated_lean_path", generated_path
            ),
            "reused": False,
        }
        result_record["evidence_result_id"] = obligation_result_id(
            result_record
        )
        results.append(result_record)
        if generated_hash is not None and generated_path:
            source_path = output_root / generated_path
            if source_path.is_file():
                generated_sources[obligation.logical_obligation_id] = (
                    source_path.read_bytes()
                )
        obligation_logs: dict[str, bytes] = {}
        for key in ("stdout_path", "stderr_path"):
            relative = phase.get(key)
            if isinstance(relative, str):
                log_path = output_root / relative
                if log_path.is_file():
                    obligation_logs[Path(relative).name] = log_path.read_bytes()
        logs[obligation.logical_obligation_id] = obligation_logs
    return {
        "obligations": [obligation.to_dict() for obligation in obligations],
        "results": sorted(results, key=lambda row: row["logical_obligation_id"]),
        "execution_attempts": sorted(
            executions.values(), key=lambda row: row["execution_attempt_id"]
        ),
        "witnesses": sorted(
            witnesses.values(), key=lambda row: row["witness_id"]
        ),
        "replays": sorted(replays.values(), key=lambda row: row["replay_id"]),
        "generated_sources": generated_sources,
        "logs": logs,
        "backend_status": backend_result.status,
    }
