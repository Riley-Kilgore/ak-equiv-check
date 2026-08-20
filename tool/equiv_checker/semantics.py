from __future__ import annotations

from .models import InputModel, ScriptPair


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


def _raw_argument_names(pair: ScriptPair) -> tuple[str, ...]:
    parameters = tuple(f"parameter{index}" for index, _ in enumerate(pair.parameters))
    normalized = pair.plutus_version.lower().removeprefix("plutus").removeprefix("v")
    if normalized == "3":
        return parameters + ("script_context_data",)
    if pair.purpose == "spending":
        return parameters + ("datum_data", "redeemer_data", "script_context_data")
    if pair.purpose in {"minting", "rewarding", "certifying"}:
        return parameters + ("redeemer_data", "script_context_data")
    return parameters


def raw_validator_input_model(pair: ScriptPair) -> InputModel:
    names = _raw_argument_names(pair)
    supported = bool(names) and not (
        pair.plutus_version.lower() not in {"v3", "3", "plutusv3"}
        and pair.purpose in {"fallback", "voting", "proposing"}
    )
    reason = None
    if not supported:
        reason = (
            "fallback or governance arity is not uniquely defined for pre-V3 compiled scripts"
            if pair.purpose in {"fallback", "voting", "proposing"}
            else "the compiled raw UPLC arity is unknown"
        )
    variables = tuple({"name": name, "type": "Data"} for name in names)
    components: list[str] = []
    if pair.parameters:
        components.append("validator_parameters")
    components.extend(name.removesuffix("_data") for name in names[len(pair.parameters) :])
    return InputModel(
        kind="validator_raw",
        profile=RAW_UPLC_PROFILE,
        version="1",
        plutus_version=pair.plutus_version,
        purpose=pair.purpose,
        variables=variables,
        quantified_components=tuple(components),
        argument_order=names,
        arity=len(names),
        domain_expression="True",
        domain_assumptions=(
            "Every argument ranges over all Plutus Data, including malformed values for the Aiken schema.",
            "The argument order is the exact compiled UPLC interface after validator parameters.",
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


def ledger_validator_input_model(pair: ScriptPair) -> InputModel:
    normalized = pair.plutus_version.lower().removeprefix("plutus").removeprefix("v")
    supported = pair.purpose in _PURPOSE_STEMS and (
        normalized == "3" or pair.purpose in _LEDGER_INPUT_TYPES
    )
    reason = None
    if pair.purpose == "fallback":
        reason = "an else handler has no single ledger purpose; raw-uplc covers every encoded V3 purpose"
    elif not supported:
        reason = f"ledger-valid model is unavailable for {pair.purpose} under Plutus V{normalized}"

    parameters = tuple(
        {"name": f"parameter{index}", "type": "Data"}
        for index, _ in enumerate(pair.parameters)
    )
    input_type = "ScriptContext" if normalized == "3" else _LEDGER_INPUT_TYPES.get(pair.purpose, "ScriptContext")
    variables = parameters + ({"name": "ledger_input", "type": input_type},)
    if normalized == "3" and pair.purpose in _PURPOSE_STEMS:
        stem = _PURPOSE_STEMS[pair.purpose]
        domain = f"validScriptContext ledger_input && is{stem}ScriptInfo ledger_input"
    elif pair.purpose in _PURPOSE_STEMS:
        domain = f"valid{_PURPOSE_STEMS[pair.purpose]}Context ledger_input"
    else:
        domain = "False"
    order = tuple(row["name"] for row in variables)
    return InputModel(
        kind="validator_ledger",
        profile=LEDGER_VALID_PROFILE,
        version="1",
        plutus_version=pair.plutus_version,
        purpose=pair.purpose,
        variables=variables,
        quantified_components=(
            *(("validator_parameters",) if pair.parameters else ()),
            "purpose_specific_ledger_input",
        ),
        argument_order=order,
        arity=(len(pair.parameters) + (1 if normalized == "3" else 3 if pair.purpose == "spending" else 2)),
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


def validator_input_models(pair: ScriptPair) -> tuple[InputModel, InputModel]:
    return raw_validator_input_model(pair), ledger_validator_input_model(pair)


def validator_input_model(pair: ScriptPair) -> InputModel:
    """Return the mandatory primary model retained for existing callers."""
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
