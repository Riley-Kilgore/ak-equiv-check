from __future__ import annotations

from .models import InputModel, ScriptPair


EQUIVALENCE_FORMULA = (
    "forall modeled_input, domain(modeled_input) -> "
    "observe(old_program(modeled_input)) = observe(new_program(modeled_input))"
)

EXCLUDED_FROM_SEMANTIC_VERDICT = (
    "cpu_cost",
    "memory_cost",
    "trace_text",
    "compiler_diagnostics",
    "generated_file_names",
)


_INPUT_TYPES = {
    "spending": "SpendingInput",
    "minting": "MintingInput",
    "rewarding": "RewardingInput",
    "certifying": "CertifyingInput",
    "voting": "ScriptContext",
    "proposing": "ScriptContext",
    "fallback": "ScriptContext",
}

_NONEMPTY_MODEL_TYPES = frozenset(
    {
        "Data",
        "Integer",
        "ScriptContext",
        "SpendingInput",
        "MintingInput",
        "RewardingInput",
        "CertifyingInput",
    }
)


def _checked_non_vacuity(
    variables: tuple[dict[str, str], ...], domain: str
) -> dict[str, object]:
    unknown = sorted({row["type"] for row in variables} - _NONEMPTY_MODEL_TYPES)
    if unknown:
        raise ValueError(
            f"input model has no non-vacuity constructor check for: {', '.join(unknown)}"
        )
    if domain != "True":
        raise ValueError(
            "restricted input domains require an explicit witness implementation"
        )
    return {
        "status": "checked",
        "method": "unrestricted-domain over explicitly inhabited model types",
        "predicate": domain,
        "inhabited_types": sorted({row["type"] for row in variables}),
    }


def validator_input_model(pair: ScriptPair) -> InputModel:
    variables = tuple(
        {"name": f"parameter{index}", "type": "Data"}
        for index, _parameter in enumerate(pair.parameters)
    )
    input_type = (
        "ScriptContext"
        if pair.plutus_version.lower() in {"v3", "3", "plutusv3"}
        else _INPUT_TYPES.get(pair.purpose)
    )
    if input_type is None:
        raise ValueError(f"unsupported validator purpose: {pair.purpose}")
    variables += ({"name": "input", "type": input_type},)
    components = ["validator_parameters"] if pair.parameters else []
    if pair.purpose == "spending":
        components.append("datum")
    components.extend(["redeemer", "script_context", "validator_purpose"])
    domain = "True"
    assumptions = (
        "All validator parameters range over unrestricted Plutus Data values.",
        "Datum and redeemer values range over unrestricted Plutus Data within the selected ledger model.",
        "Script contexts range over every value representable by the pinned Cardano ledger model; no ledger-validity predicate narrows the domain.",
        "The same parameters and ledger input are applied to both UPLC programs with the same preparation fuel.",
        "Success means CEK evaluation halts with a value; every other terminal outcome is unsuccessful.",
    )
    return InputModel(
        kind="validator",
        plutus_version=pair.plutus_version,
        purpose=pair.purpose,
        variables=variables,
        quantified_components=tuple(components),
        domain_expression=domain,
        domain_assumptions=assumptions,
        observation="successful_or_unsuccessful",
        non_vacuity=_checked_non_vacuity(variables, domain),
    )


def pure_integer_input_model() -> InputModel:
    variables = ({"name": "input", "type": "Integer"},)
    domain = "True"
    return InputModel(
        kind="pure_integer",
        plutus_version="v3",
        purpose="pure",
        variables=variables,
        quantified_components=("function_argument",),
        domain_expression=domain,
        domain_assumptions=(
            "The integer argument is unrestricted.",
            "Returned integer values are compared exactly; evaluation errors are observed separately from returned values.",
            "Both programs receive the same argument and preparation fuel.",
        ),
        observation="returned_integer_or_error",
        non_vacuity=_checked_non_vacuity(variables, domain),
    )
