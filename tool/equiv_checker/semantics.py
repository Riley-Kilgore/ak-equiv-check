from __future__ import annotations

from .models import InputModel, ProgramPairRecord


EQUIVALENCE_FORMULA = (
    "forall raw_arguments, "
    "observe(old_program(raw_arguments)) = observe(new_program(raw_arguments))"
)
VALIDATOR_OBSERVATION = "success_or_failure_or_runtime_bound_exhausted"
PURE_OBSERVATION = "returned_value_or_evaluation_failure_or_unexpected_type_or_runtime_bound_exhausted"
RAW_UPLC_PROFILE = "raw-uplc/v1"
LEDGER_VALID_PROFILE = "ledger-valid/v1"

EXCLUDED_FROM_SEMANTIC_VERDICT = (
    "cpu_cost",
    "memory_cost",
    "trace_text",
    "compiler_diagnostics",
    "generated_names",
    "file_paths",
)

_LEDGER_INPUT_TYPES = {
    "spending": "SpendingInput",
    "minting": "MintingInput",
    "rewarding": "RewardingInput",
    "certifying": "CertifyingInput",
}
_PURPOSE_STEMS = {
    "spending": "Spending",
    "minting": "Minting",
    "rewarding": "Rewarding",
    "certifying": "Certifying",
    "voting": "Voting",
    "proposing": "Proposing",
}


def _raw_data_witness(names: tuple[str, ...]) -> dict[str, object]:
    return {
        "encoding": "PlutusData",
        "arguments": [
            {"name": name, "value": {"kind": "integer", "value": 0}}
            for name in names
        ],
        "lean_expression": "PlutusCore.Data.I 0",
    }


def _raw_argument_names(pair: ProgramPairRecord) -> tuple[str, ...]:
    abi = pair.verified_abi
    if abi.get("status") != "verified":
        return ()
    order = abi.get("argument_order")
    if not isinstance(order, list) or not all(isinstance(name, str) for name in order):
        return ()
    return tuple(order)


def _parameter_count(pair: ProgramPairRecord) -> int:
    value = pair.verified_abi.get("applied_parameter_count")
    return value if isinstance(value, int) and value >= 0 else 0


def _pair_purposes(pair: ProgramPairRecord) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                str(reference["purpose"])
                for reference in pair.handler_references
                if isinstance(reference.get("purpose"), str)
            }
        )
    )


def raw_validator_input_model(pair: ProgramPairRecord) -> InputModel:
    names = _raw_argument_names(pair)
    abi_verified = (
        pair.verified_abi.get("status") == "verified"
        and bool(pair.verified_abi_id)
    )
    arity = pair.verified_abi.get("top_level_callable_arity")
    supported = (
        abi_verified
        and isinstance(arity, int)
        and arity >= 0
        and len(names) == arity
    )
    reason = None if supported else "raw_model_not_bound_to_abi"
    variables = tuple({"name": name, "type": "Data"} for name in names)
    parameter_count = _parameter_count(pair)
    components: list[str] = []
    if parameter_count:
        components.append("validator_parameters")
    components.extend(name.removesuffix("_data") for name in names[parameter_count:])
    return InputModel(
        kind="validator_raw",
        profile=RAW_UPLC_PROFILE,
        version="2",
        plutus_version=pair.plutus_version,
        purpose="raw",
        variables=variables,
        quantified_components=tuple(components),
        argument_order=names,
        arity=len(names),
        domain_expression="True",
        domain_assumptions=(
            "Every argument ranges over all Plutus Data, including malformed values for the Aiken schema.",
            "The argument order is bound to the verified compiled UPLC interface.",
            "No Cardano ledger validity predicate restricts the raw domain.",
            "Success and explicit CEK failure are logical observations; cost and trace are evidence only.",
            "Runtime-step-bound exhaustion is distinct from validator failure.",
        ),
        domain_witness=_raw_data_witness(names) if supported else None,
        observation=VALIDATOR_OBSERVATION,
        non_vacuity={
            "status": "generated_formal_witness" if supported else "unsupported",
            "method": "Lean definition plus elaborated theorem that the concrete Data.I 0 tuple satisfies True",
            "predicate": "True",
            "artifact_required": supported,
        },
        supported=supported,
        unsupported_reason=reason,
    )


def ledger_validator_input_model(
    pair: ProgramPairRecord, purpose: str | None = None
) -> InputModel:
    purposes = _pair_purposes(pair)
    selected_purpose = purpose or (purposes[0] if len(purposes) == 1 else "fallback")
    if selected_purpose not in purposes and purpose is not None:
        raise ValueError(
            f"purpose {selected_purpose} is not linked to program pair {pair.program_pair_id}"
        )
    normalized = pair.plutus_version.lower().removeprefix("plutus").removeprefix("v")
    supported = selected_purpose in _PURPOSE_STEMS and (
        normalized == "3" or selected_purpose in _LEDGER_INPUT_TYPES
    )
    reason = None
    if selected_purpose == "fallback":
        reason = "an else handler has no single ledger purpose; raw-uplc covers every encoded V3 purpose"
    elif not supported:
        reason = (
            f"ledger-valid model is unavailable for {selected_purpose} "
            f"under Plutus V{normalized}"
        )
    parameter_count = _parameter_count(pair)
    parameters = tuple(
        {"name": f"parameter{index}", "type": "Data"}
        for index in range(parameter_count)
    )
    input_type = (
        "ScriptContext"
        if normalized == "3"
        else _LEDGER_INPUT_TYPES.get(selected_purpose, "ScriptContext")
    )
    variables = parameters + ({"name": "ledger_input", "type": input_type},)
    if normalized == "3" and selected_purpose in _PURPOSE_STEMS:
        stem = _PURPOSE_STEMS[selected_purpose]
        domain = f"validScriptContext ledger_input && is{stem}ScriptInfo ledger_input"
    elif selected_purpose in _PURPOSE_STEMS:
        domain = f"valid{_PURPOSE_STEMS[selected_purpose]}Context ledger_input"
    else:
        domain = "False"
    order = tuple(row["name"] for row in variables)
    return InputModel(
        kind="validator_ledger",
        profile=LEDGER_VALID_PROFILE,
        version="2",
        plutus_version=pair.plutus_version,
        purpose=selected_purpose,
        variables=variables,
        quantified_components=(
            *(("validator_parameters",) if parameter_count else ()),
            "purpose_specific_ledger_input",
        ),
        argument_order=order,
        arity=(
            parameter_count
            + (
                1
                if normalized == "3"
                else 3
                if selected_purpose == "spending"
                else 2
            )
        ),
        domain_expression=domain,
        domain_assumptions=(
            "The purpose-specific CardanoLedgerApiBlaster conversion supplies the compiled argument order.",
            "The pinned ledger predicate constrains contexts to ledger-constructible values for the selected purpose.",
            "A ledger-valid result cannot override a raw-uplc difference.",
        ),
        domain_witness=None,
        observation=VALIDATOR_OBSERVATION,
        non_vacuity={
            "status": "solver_witness_required" if supported else "unsupported",
            "method": "Blaster falsification of universal domain emptiness, with a recorded concrete model",
            "predicate": domain,
            "artifact_required": supported,
        },
        supported=supported,
        unsupported_reason=reason,
    )


def ledger_validator_input_models(
    pair: ProgramPairRecord,
) -> tuple[InputModel, ...]:
    return tuple(
        ledger_validator_input_model(pair, purpose)
        for purpose in _pair_purposes(pair)
    )


def validator_input_models(
    pair: ProgramPairRecord,
) -> tuple[InputModel, tuple[InputModel, ...]]:
    return raw_validator_input_model(pair), ledger_validator_input_models(pair)


def validator_input_model(pair: ProgramPairRecord) -> InputModel:
    """Return the mandatory raw model."""
    return raw_validator_input_model(pair)


def pure_integer_input_model() -> InputModel:
    variables = ({"name": "input", "type": "Integer"},)
    return InputModel(
        kind="pure_integer",
        profile=RAW_UPLC_PROFILE,
        version="1",
        plutus_version="v3",
        purpose="pure",
        variables=variables,
        quantified_components=("function_argument",),
        argument_order=("input",),
        arity=1,
        domain_expression="True",
        domain_assumptions=(
            "The integer argument is unrestricted.",
            "Returned integer values, evaluation failures, unexpected result types, and runtime-bound exhaustion are distinct observations.",
        ),
        domain_witness={"arguments": [{"name": "input", "value": 0}], "lean_expression": "0"},
        observation=PURE_OBSERVATION,
        non_vacuity={
            "status": "generated_formal_witness",
            "method": "Lean elaborates the witness input = 0 for the unrestricted domain",
            "predicate": "True",
            "artifact_required": True,
        },
    )
