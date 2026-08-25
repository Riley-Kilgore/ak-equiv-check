from __future__ import annotations

import hashlib
import json
import re
import os
import shutil
from pathlib import Path
from typing import Any

from .evidence import (
    GENERATED_LEAN_SCHEMA_VERSION,
    RESULT_PROTOCOL,
    WITNESS_PROTOCOL,
    canonical_json,
    checker_implementation_id,
    theorem_statement_hash,
    validate_result_marker,
    validate_witness_record,
    witness_hash,
)
from .models import (
    BlasterConfig,
    BlasterResult,
    EvaluatorConfig,
    InputModel,
    ProgramPairRecord,
    SemanticObligationRecord,
)
from .process import ProcessResult, run_process, write_process_logs


RESULT_PREFIX = "EQUIV_RESULT_V3:"
WITNESS_PREFIX = "EQUIV_WITNESS_V3:"
LEGACY_RESULT_PREFIX = "EQUIV_RESULT_V2:"
LEGACY_WITNESS_PREFIX = "EQUIV_WITNESS_V2:"
CHECKER_IMPLEMENTATION_ID = checker_implementation_id()


def _stable_json(value: Any) -> str:
    return canonical_json(value)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def classify_evaluator_output(result: ProcessResult) -> dict[str, Any]:
    combined = f"{result.stdout}\n{result.stderr}"
    lowered = combined.lower()
    json_result: dict[str, Any] | None = None
    try:
        decoded = json.loads(result.stdout)
        if (
            isinstance(decoded, dict)
            and isinstance(decoded.get("result"), str)
            and isinstance(decoded.get("cpu"), int)
            and not isinstance(decoded.get("cpu"), bool)
            and decoded["cpu"] >= 0
            and isinstance(decoded.get("mem"), int)
            and not isinstance(decoded.get("mem"), bool)
            and decoded["mem"] >= 0
        ):
            json_result = decoded
    except json.JSONDecodeError:
        pass
    result_match = re.search(
        r"(?:^|\n)Result\s*\n-+\s*\n(.*?)(?=\n\s*Costs\s*\n-+)",
        combined,
        flags=re.DOTALL,
    )
    cpu_match = re.search(r"(?:^|\n)cpu:\s*(\d+)", combined, flags=re.IGNORECASE)
    memory_match = re.search(
        r"(?:^|\n)memory:\s*(\d+)", combined, flags=re.IGNORECASE
    )
    has_costs = cpu_match is not None and memory_match is not None
    if result.timed_out:
        outcome = "timeout"
    elif result.exit_code is not None and result.exit_code < 0:
        outcome = "evaluator_crash"
    elif result.exit_code == 0 and json_result is not None:
        outcome = "program_success"
    elif result.exit_code == 0 and result_match is not None and has_costs:
        outcome = "program_success"
    elif "budget" in lowered and any(
        word in lowered for word in ("exhaust", "exceed", "overspent")
    ):
        outcome = "budget_exhausted"
    elif result.exit_code == 1 and has_costs and re.search(
        r"(?:^|\n)Error\s*\n-+", combined
    ):
        outcome = "program_failure"
    elif any(
        word in lowered
        for word in (
            "deserialise program",
            "deserialize program",
            "decode cbor",
            "invalid cbor",
            "failed to parse program",
        )
    ):
        outcome = "decode_error"
    elif any(
        word in lowered
        for word in (
            "failed to parse argument",
            "invalid argument",
            "unexpected argument",
        )
    ):
        outcome = "argument_error"
    elif "unsupported" in lowered and any(
        word in lowered for word in ("language", "plutus", "version")
    ):
        outcome = "unsupported_language"
    elif result.exit_code not in {0, 1}:
        outcome = "evaluator_crash"
    elif result.exit_code == 0:
        outcome = "invalid_output"
    else:
        outcome = "cli_error"
    semantic = outcome in {"program_success", "program_failure"}
    return {
        "ok": semantic,
        "outcome": outcome,
        "result_value": (
            json_result["result"]
            if json_result is not None
            else result_match.group(1).strip()
            if result_match
            else None
        ),
        "cost": (
            {"cpu": json_result["cpu"], "memory": json_result["mem"]}
            if json_result is not None
            else {"cpu": int(cpu_match.group(1)), "memory": int(memory_match.group(1))}
            if has_costs
            else None
        ),
        "error_class": None if semantic else outcome,
    }


def parse_result_protocol(
    stdout: str,
    stderr: str,
    *,
    exit_code: int | None,
    expected: dict[str, Any],
) -> dict[str, Any]:
    markers = [
        line[len(prefix) :]
        for line in f"{stdout}\n{stderr}".splitlines()
        for prefix in (RESULT_PREFIX, LEGACY_RESULT_PREFIX)
        if line.startswith(prefix)
    ]
    if len(markers) != 1:
        raise ValueError(
            "expected exactly one EQUIV_RESULT protocol marker, "
            f"found {len(markers)}"
        )
    try:
        value = json.loads(markers[0])
    except json.JSONDecodeError as error:
        raise ValueError("invalid JSON in Blaster result marker") from error
    if not isinstance(value, dict):
        raise ValueError("Blaster result marker must contain an object")
    marker = validate_result_marker(value, expected)
    if exit_code != 0:
        raise ValueError("Blaster result marker conflicts with the process exit code")
    return marker


def parse_witness_protocol(
    stdout: str,
    stderr: str,
    *,
    expected: dict[str, Any],
) -> dict[str, Any] | None:
    markers = [
        line[len(prefix) :]
        for line in f"{stdout}\n{stderr}".splitlines()
        for prefix in (WITNESS_PREFIX, LEGACY_WITNESS_PREFIX)
        if line.startswith(prefix)
    ]
    if not markers:
        return None
    if len(markers) != 1:
        raise ValueError(
            "expected at most one EQUIV_WITNESS protocol marker, "
            f"found {len(markers)}"
        )
    try:
        value = json.loads(markers[0])
    except json.JSONDecodeError as error:
        raise ValueError("invalid JSON in Blaster witness marker") from error
    if not isinstance(value, dict):
        raise ValueError("Blaster witness marker must contain an object")
    validated = validate_witness_record(value, expected)
    try:
        encoded = [
            encode_uplc_term(item)
            for item in validated["structured_argument_values"]
        ]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("unsupported witness value type") from error
    if encoded != validated["serialized_uplc_argument_terms"]:
        raise ValueError("witness serialization is lossy")
    return validated


def parse_blaster_output(
    stdout: str,
    stderr: str,
    *,
    timed_out: bool = False,
    exit_code: int | None = 0,
    expected: dict[str, Any] | None = None,
) -> str:
    """Classify only a schema-valid, completely bound result marker."""
    if timed_out:
        return "blaster_timeout"
    if expected is None:
        return "blaster_error"
    try:
        marker = parse_result_protocol(
            stdout,
            stderr,
            exit_code=exit_code,
            expected=expected,
        )
    except ValueError:
        return "blaster_error"
    return {
        "valid": "blaster_valid",
        "falsified": "blaster_falsified_unreplayed",
        "inconclusive": "blaster_inconclusive",
    }[marker["solver_status"]]


class _DataParser:
    def __init__(self, text: str):
        self.text = text
        self.position = 0

    def _space(self) -> None:
        while self.position < len(self.text) and self.text[self.position].isspace():
            self.position += 1

    def _take(self, token: str) -> None:
        self._space()
        if not self.text.startswith(token, self.position):
            raise ValueError(f"expected {token!r} at offset {self.position}")
        self.position += len(token)

    def _word(self) -> str:
        self._space()
        start = self.position
        while self.position < len(self.text) and (
            self.text[self.position].isalnum() or self.text[self.position] in "_+-#"
        ):
            self.position += 1
        if self.position == start:
            raise ValueError(f"expected value at offset {self.position}")
        return self.text[start : self.position]

    def _list(self, item: Any) -> list[Any]:
        self._take("[")
        values: list[Any] = []
        self._space()
        if self.text.startswith("]", self.position):
            self.position += 1
            return values
        while True:
            values.append(item())
            self._space()
            if self.text.startswith("]", self.position):
                self.position += 1
                return values
            self._take(",")

    def _pair(self) -> tuple[dict[str, Any], dict[str, Any]]:
        self._take("(")
        first = self.data()
        self._take(",")
        second = self.data()
        self._take(")")
        return first, second

    def data(self) -> dict[str, Any]:
        self._take("(")
        constructor = self._word()
        if constructor == "I":
            value = int(self._word())
            result = {"kind": "data", "variant": "integer", "value": value}
        elif constructor == "B":
            encoded = self._word()
            if not encoded.startswith("#") or not re.fullmatch(r"[0-9a-fA-F]*", encoded[1:]):
                raise ValueError("invalid rendered Data byte array")
            result = {"kind": "data", "variant": "bytes", "hex": encoded[1:].lower()}
        elif constructor == "List":
            result = {"kind": "data", "variant": "list", "items": self._list(self.data)}
        elif constructor == "Map":
            result = {
                "kind": "data",
                "variant": "map",
                "entries": [
                    {"key": key, "value": value} for key, value in self._list(self._pair)
                ],
            }
        elif constructor == "Constr":
            index = int(self._word())
            result = {
                "kind": "data",
                "variant": "constructor",
                "index": index,
                "fields": self._list(self.data),
            }
        else:
            raise ValueError(f"unknown rendered Data constructor: {constructor}")
        self._take(")")
        return result

    def parse(self) -> dict[str, Any]:
        result = self.data()
        self._space()
        if self.position != len(self.text):
            raise ValueError(f"trailing rendered Data at offset {self.position}")
        return result

class _SExpressionParser:
    def __init__(self, text: str):
        self.text = text
        self.position = 0

    def _space(self) -> None:
        while self.position < len(self.text) and self.text[self.position].isspace():
            self.position += 1

    def value(self) -> Any:
        self._space()
        if self.position >= len(self.text):
            raise ValueError("unexpected end of S-expression")
        if self.text[self.position] == "(":
            self.position += 1
            values: list[Any] = []
            while True:
                self._space()
                if self.position >= len(self.text):
                    raise ValueError("unterminated S-expression")
                if self.text[self.position] == ")":
                    self.position += 1
                    return values
                values.append(self.value())
        if self.text[self.position] == '"':
            value, consumed = json.JSONDecoder().raw_decode(self.text[self.position :])
            self.position += consumed
            return value
        start = self.position
        while self.position < len(self.text) and (
            not self.text[self.position].isspace()
            and self.text[self.position] not in "()"
        ):
            self.position += 1
        if start == self.position:
            raise ValueError(f"expected S-expression atom at offset {self.position}")
        return self.text[start : self.position]

    def parse(self) -> Any:
        result = self.value()
        self._space()
        if self.position != len(self.text):
            raise ValueError(f"trailing S-expression at offset {self.position}")
        return result


def _lean_name(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("expected Lean constructor name")
    return value.rsplit(".", 1)[-1]


def _evaluate_lean_data(value: Any, environment: dict[str, Any]) -> Any:
    if isinstance(value, str):
        if value in environment:
            return environment[value]
        if re.fullmatch(r"-?\d+", value):
            return int(value)
        return value
    if not isinstance(value, list) or not value:
        raise ValueError("invalid Lean data expression")
    constructor = _lean_name(value[0])
    if constructor == "let":
        if len(value) != 3 or not isinstance(value[1], list):
            raise ValueError("invalid Lean let expression")
        local = dict(environment)
        for binding in value[1]:
            if not isinstance(binding, list) or len(binding) != 2 or not isinstance(
                binding[0], str
            ):
                raise ValueError("invalid Lean let binding")
            local[binding[0]] = _evaluate_lean_data(binding[1], local)
        return _evaluate_lean_data(value[2], local)
    if constructor == "as":
        if len(value) >= 2 and _lean_name(value[1]) == "nil":
            return []
        raise ValueError("unsupported Lean type ascription")
    if constructor == "nil":
        return []
    if constructor == "cons":
        if len(value) != 3:
            raise ValueError("invalid Lean list constructor")
        tail = _evaluate_lean_data(value[2], environment)
        if not isinstance(tail, list):
            raise ValueError("Lean list tail is not a list")
        return [_evaluate_lean_data(value[1], environment), *tail]
    if constructor == "I":
        if len(value) != 2:
            raise ValueError("invalid Lean Data.I")
        return {
            "kind": "data",
            "variant": "integer",
            "value": int(_evaluate_lean_data(value[1], environment)),
        }
    if constructor == "mk" and "ByteString" in str(value[0]):
        if len(value) != 2 or not isinstance(value[1], str):
            raise ValueError("invalid Lean byte string")
        return value[1].encode("utf-8")
    if constructor == "B":
        if len(value) != 2:
            raise ValueError("invalid Lean Data.B")
        encoded = _evaluate_lean_data(value[1], environment)
        if not isinstance(encoded, bytes):
            raise ValueError("Lean Data.B payload is not bytes")
        return {"kind": "data", "variant": "bytes", "hex": encoded.hex()}
    if constructor == "Constr":
        if len(value) != 3:
            raise ValueError("invalid Lean Data.Constr")
        fields = _evaluate_lean_data(value[2], environment)
        if not isinstance(fields, list):
            raise ValueError("Lean constructor fields are not a list")
        return {
            "kind": "data",
            "variant": "constructor",
            "index": int(_evaluate_lean_data(value[1], environment)),
            "fields": fields,
        }
    if constructor == "List":
        if len(value) != 2:
            raise ValueError("invalid Lean Data.List")
        items = _evaluate_lean_data(value[1], environment)
        if not isinstance(items, list):
            raise ValueError("Lean Data.List payload is not a list")
        return {"kind": "data", "variant": "list", "items": items}
    if constructor == "mk" and "Prod" in str(value[0]):
        if len(value) != 3:
            raise ValueError("invalid Lean pair")
        return (
            _evaluate_lean_data(value[1], environment),
            _evaluate_lean_data(value[2], environment),
        )
    if constructor == "Map":
        if len(value) != 2:
            raise ValueError("invalid Lean Data.Map")
        entries = _evaluate_lean_data(value[1], environment)
        if not isinstance(entries, list) or not all(
            isinstance(entry, tuple) and len(entry) == 2 for entry in entries
        ):
            raise ValueError("Lean Data.Map payload is not a pair list")
        return {
            "kind": "data",
            "variant": "map",
            "entries": [{"key": key, "value": item} for key, item in entries],
        }
    raise ValueError(f"unsupported Lean data constructor: {value[0]}")


def _parse_lean_data(rendered: str) -> dict[str, Any]:
    value = _evaluate_lean_data(_SExpressionParser(rendered).parse(), {})
    if not isinstance(value, dict) or value.get("kind") != "data":
        raise ValueError("Lean witness is not Plutus Data")
    return value


def _normalize_lean_data(rendered: str) -> str:
    value = re.sub(
        r"[A-Za-z0-9_.]*Data\.(Constr|Map|List|I|B)\b",
        lambda match: match.group(1),
        rendered,
    )

    def byte_string(match: re.Match[str]) -> str:
        text = json.loads(match.group(1))
        return "#" + text.encode("utf-8").hex()

    return re.sub(
        r"\([A-Za-z0-9_.]*ByteString\.mk\s+(\"(?:\\.|[^\"\\])*\")\)",
        byte_string,
        value,
    )


def _parse_witness_value(rendered: str) -> dict[str, Any]:
    value = rendered.strip()
    if re.fullmatch(r"-?\d+", value):
        return {"kind": "integer", "value": int(value), "rendered": value}
    if value.lower() in {"true", "false"}:
        return {"kind": "boolean", "value": value.lower() == "true", "rendered": value}
    if value.startswith("#") and re.fullmatch(r"#[0-9a-fA-F]*", value):
        return {"kind": "bytes", "hex": value[1:].lower(), "rendered": value}
    try:
        parsed = _DataParser(_normalize_lean_data(value)).parse()
    except (ValueError, UnicodeError, json.JSONDecodeError):
        try:
            parsed = _parse_lean_data(value)
        except (ValueError, UnicodeError, json.JSONDecodeError):
            return {"kind": "lean_display", "rendered": value}
    return parsed | {"rendered": value}


def extract_witness(stdout: str, stderr: str) -> dict[str, Any] | None:
    text = f"{stdout}\n{stderr}"
    marker = text.find("Counterexample")
    if marker < 0:
        marker = text.find("Expected Falsified")
    if marker < 0:
        return None
    values: dict[str, Any] = {}
    current_name: str | None = None
    rendered_lines: list[str] = []

    def store_current() -> None:
        if current_name is not None:
            rendered = " ".join(rendered_lines)
            values[current_name] = _parse_witness_value(rendered)

    for line in text[marker:].splitlines()[1:]:
        match = re.match(r"\s*-\s+([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$", line)
        if match:
            store_current()
            current_name = match.group(1)
            rendered_lines = [match.group(2).strip()]
            continue
        if current_name is not None and line[:1].isspace() and line.strip():
            rendered_lines.append(line.strip())
            continue
        if current_name is not None:
            store_current()
            break
    if current_name is not None and current_name not in values:
        store_current()
    if not values:
        return None
    return {
        "witness_source": "legacy_human_parser",
        "values": values,
        "raw_available": all(
            value["kind"] != "lean_display" for value in values.values()
        ),
    }


def _encode_data(value: dict[str, Any]) -> str:
    variant = value.get("variant")
    if variant == "integer":
        return f"I {int(value['value'])}"
    if variant == "bytes":
        encoded = str(value["hex"]).lower()
        if not re.fullmatch(r"[0-9a-f]*", encoded):
            raise ValueError("invalid Data byte array")
        return f"B #{encoded}"
    if variant == "list":
        return "List [" + ", ".join(_encode_data(item) for item in value["items"]) + "]"
    if variant == "map":
        entries = ", ".join(
            f"({_encode_data(row['key'])}, {_encode_data(row['value'])})"
            for row in value["entries"]
        )
        return f"Map [{entries}]"
    if variant == "constructor":
        fields = ", ".join(_encode_data(item) for item in value["fields"])
        return f"Constr {int(value['index'])} [{fields}]"
    raise ValueError(f"unsupported Data variant: {variant}")


def encode_uplc_term(value: dict[str, Any]) -> str:
    kind = value.get("kind")
    if kind == "integer":
        return f"(con integer {int(value['value'])})"
    if kind == "boolean":
        return f"(con bool {'True' if value['value'] else 'False'})"
    if kind == "bytes":
        encoded = str(value["hex"]).lower()
        if not re.fullmatch(r"[0-9a-f]*", encoded):
            raise ValueError("invalid byte array")
        return f"(con bytestring #{encoded})"
    if kind == "data":
        return f"(con data ({_encode_data(value)}))"
    if kind == "list":
        item_type = str(value.get("item_type", "data"))
        items = ", ".join(encode_uplc_term(item) for item in value["items"])
        return f"(con (list {item_type}) [{items}])"
    if kind == "map":
        key_type = str(value.get("key_type", "data"))
        value_type = str(value.get("value_type", "data"))
        entries = ", ".join(
            f"({encode_uplc_term(row['key'])}, {encode_uplc_term(row['value'])})"
            for row in value["entries"]
        )
        return f"(con (map {key_type} {value_type}) [{entries}])"
    if kind == "constructor":
        return f"(con data ({_encode_data({'kind': 'data', 'variant': 'constructor', 'index': value['index'], 'fields': value['fields']})}))"
    raise ValueError(f"unsupported counterexample value kind: {kind}")


def _witness_expected(
    pair: ProgramPairRecord,
    input_model: InputModel,
    obligation: SemanticObligationRecord,
    theorem_hash: str,
) -> dict[str, Any]:
    return {
        "program_pair_id": pair.program_pair_id,
        "logical_obligation_id": obligation.logical_obligation_id,
        "theorem_statement_hash": theorem_hash,
        "semantic_model_id": obligation.semantic_model_id,
        "ordered_argument_list": list(input_model.argument_order),
        "argument_names": list(input_model.argument_order),
        "argument_types": [row["type"] for row in input_model.variables],
        "checker_implementation_id": CHECKER_IMPLEMENTATION_ID,
    }


def _legacy_witness_v2(
    legacy: dict[str, Any],
    pair: ProgramPairRecord,
    input_model: InputModel,
    obligation: SemanticObligationRecord,
    theorem_hash: str,
) -> dict[str, Any]:
    values = legacy.get("values")
    if not isinstance(values, dict):
        raise ValueError("legacy witness has no structured values")
    expected_names = list(input_model.argument_order)
    if sorted(values) != sorted(expected_names):
        raise ValueError("legacy witness argument names or arity do not match the model")
    structured_values = [values[name] for name in expected_names]
    serialized_terms = [encode_uplc_term(value) for value in structured_values]
    record = {
        "protocol_version": WITNESS_PROTOCOL,
        **_witness_expected(
            pair,
            input_model,
            obligation,
            theorem_hash,
        ),
        "structured_argument_values": structured_values,
        "serialized_uplc_argument_terms": serialized_terms,
        "domain_satisfaction_evidence": {
            "satisfied": True,
            "predicate": input_model.domain_expression,
            "method": "symbolic_counterexample_premise",
        },
        "witness_source": "legacy_human_parser",
    }
    record["witness_sha256"] = witness_hash(record)
    return validate_witness_record(
        record,
        _witness_expected(pair, input_model, obligation, theorem_hash),
    )


def _domain_witness_v2(
    pair: ProgramPairRecord,
    input_model: InputModel,
    obligation: SemanticObligationRecord,
    theorem_hash: str,
) -> dict[str, Any] | None:
    if input_model.domain_expression != "True":
        return None
    domain_witness = input_model.domain_witness
    if not isinstance(domain_witness, dict):
        return None
    arguments = domain_witness.get("arguments")
    if not isinstance(arguments, list):
        return None
    by_name = {
        row.get("name"): row.get("value")
        for row in arguments
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    }
    structured_values: list[dict[str, Any]] = []
    for variable in input_model.variables:
        name = variable["name"]
        if name not in by_name:
            return None
        raw = by_name[name]
        if variable["type"] == "Integer" and isinstance(raw, int):
            structured = {"kind": "integer", "value": raw}
        elif variable["type"] == "Data":
            if isinstance(raw, dict) and raw.get("kind") == "integer":
                structured = {
                    "kind": "data",
                    "variant": "integer",
                    "value": int(raw["value"]),
                }
            else:
                return None
        else:
            return None
        structured_values.append(structured)
    record = {
        "protocol_version": WITNESS_PROTOCOL,
        **_witness_expected(
            pair,
            input_model,
            obligation,
            theorem_hash,
        ),
        "structured_argument_values": structured_values,
        "serialized_uplc_argument_terms": [
            encode_uplc_term(value) for value in structured_values
        ],
        "domain_satisfaction_evidence": {
            "satisfied": True,
            "predicate": input_model.domain_expression,
            "method": "versioned_input_model_domain_witness",
        },
        "witness_source": "generated_domain_witness",
    }
    record["witness_sha256"] = witness_hash(record)
    return validate_witness_record(
        record,
        _witness_expected(pair, input_model, obligation, theorem_hash),
    )


def _lean_namespace(pair_id: str) -> str:
    return "EquivCheck_" + re.sub(r"[^A-Za-z0-9_]", "_", pair_id)


def _version_names(plutus_version: str) -> tuple[str, str]:
    normalized = plutus_version.lower().removeprefix("plutus").removeprefix("v")
    if normalized not in {"1", "2", "3"}:
        raise ValueError(f"unsupported Plutus version: {plutus_version}")
    return f"CardanoLedgerApi.V{normalized}", f"PlutusV{normalized}"


def _conversion_name(purpose: str) -> str:
    conversions = {
        "spending": "spendingInputs",
        "minting": "mintingInputs",
        "rewarding": "rewardingInputs",
        "certifying": "certifyingInputs",
        "voting": "votingInputs",
        "proposing": "proposingInputs",
    }
    if purpose not in conversions:
        raise ValueError(f"no purpose-specific conversion for {purpose}")
    return conversions[purpose]


def _obligation_binding(
    *,
    pair: ProgramPairRecord,
    obligation: SemanticObligationRecord,
    theorem_hash: str,
    checker_configuration_id: str,
) -> dict[str, Any]:
    return {
        "protocol_version": RESULT_PROTOCOL,
        "program_pair_id": pair.program_pair_id,
        "logical_obligation_id": obligation.logical_obligation_id,
        "semantic_model_id": obligation.semantic_model_id,
        "checker_configuration_id": checker_configuration_id,
        "checker_implementation_id": CHECKER_IMPLEMENTATION_ID,
        "old_script_sha256": pair.old_script.sha256,
        "new_script_sha256": pair.new_script.sha256,
        "verified_abi_id": pair.verified_abi_id,
        "obligation_kind": obligation.obligation_kind,
        "theorem_statement_hash": theorem_hash,
        "generated_source_schema_version": GENERATED_LEAN_SCHEMA_VERSION,
    }


def _lean_marker(
    *,
    status: str,
    pair: ProgramPairRecord,
    obligation: SemanticObligationRecord,
    theorem_hash: str,
    checker_configuration_id: str,
) -> str:
    payload = _stable_json(
        _obligation_binding(
            pair=pair,
            obligation=obligation,
            theorem_hash=theorem_hash,
            checker_configuration_id=checker_configuration_id,
        )
        | {"solver_status": status}
    )
    return f"#eval IO.println {json.dumps(RESULT_PREFIX + payload)}"


def _source_binding_declarations(
    obligation: SemanticObligationRecord,
) -> list[str]:
    return [
        f"def logicalObligationId : String := {json.dumps(obligation.logical_obligation_id)}",
        f"def generatedSourceSchemaVersion : String := {json.dumps(GENERATED_LEAN_SCHEMA_VERSION)}",
        "",
    ]


def _common_source(pair: ProgramPairRecord, old_path: str, new_path: str) -> list[str]:
    module, language = _version_names(pair.plutus_version)
    namespace = _lean_namespace(pair.program_pair_id)
    return [
        "import PlutusCore.UPLC",
        f"import {module}",
        "import Blaster",
        "",
        f"namespace {namespace}",
        f"open {module}",
        "open CardanoLedgerApi.IsData.Class (toTerm)",
        "open PlutusCore.Data (Data)",
        "open PlutusCore.Integer (Integer)",
        "open PlutusCore.UPLC.Term",
        "open PlutusCore.UPLC.CekMachine",
        "open PlutusCore.UPLC.PlutusScript",
        "",
        "set_option warn.sorry false",
        f'#import_uplc oldProgram {language} single_cbor_hex {json.dumps(old_path)}',
        f'#import_uplc newProgram {language} single_cbor_hex {json.dumps(new_path)}',
        "",
    ]


def _model_source(input_model: InputModel) -> tuple[list[str], str, str]:
    if not input_model.supported:
        raise ValueError(input_model.unsupported_reason or "unsupported input model")
    binders = " ".join(
        f"({row['name']} : {row['type']})" for row in input_model.variables
    )
    arguments = " ".join(row["name"] for row in input_model.variables)
    if input_model.kind == "pure_integer":
        conversion = [
            f"def modelInputs {binders} : List Term :=",
            "  [Term.Const $ Const.Integer input]",
        ]
    elif input_model.kind == "validator_raw":
        rendered = ", ".join(f"toTerm {row['name']}" for row in input_model.variables)
        conversion = [f"def modelInputs {binders} : List Term :=", f"  [{rendered}]"]
    elif input_model.kind == "validator_ledger":
        parameters = [row for row in input_model.variables if row["name"].startswith("parameter")]
        input_name = input_model.variables[-1]["name"]
        expression = f"{_conversion_name(input_model.purpose)} {input_name}"
        for parameter in reversed(parameters):
            expression = f"toTerm {parameter['name']} :: {expression}"
        conversion = [f"def modelInputs {binders} : List Term :=", f"  {expression}"]
    else:
        raise ValueError(f"unsupported input model kind: {input_model.kind}")
    return conversion, binders, arguments


def _raw_non_vacuity_source(input_model: InputModel, binders: str) -> list[str]:
    if input_model.domain_expression != "True":
        return []
    witnesses = []
    for row in input_model.variables:
        witnesses.append("0" if row["type"] == "Integer" else "Data.I 0")
    existential = " ∃ ".join([])
    del existential
    if not witnesses:
        return ["theorem domainNonVacuous : True := by trivial", ""]
    nested = f"∃ {binders}, True"
    constructor = "⟨" + ", ".join([*witnesses, "by trivial"]) + "⟩"
    return [f"theorem domainNonVacuous : {nested} := by", f"  exact {constructor}", ""]

def _witness_encoder_source(input_model: InputModel) -> list[str]:
    if input_model.kind == "pure_integer":
        return []
    return [
        "private def witnessHexDigit (n : UInt8) : Char :=",
        "  if n < 10 then Char.ofNat (n.toNat + '0'.toNat)",
        "  else Char.ofNat (n.toNat - 10 + 'a'.toNat)",
        "",
        "private def witnessBytesHex (bs : PlutusCore.ByteString.ByteString) : String :=",
        "  bs.data.toUTF8.foldl (fun out byte =>",
        "    out.push (witnessHexDigit (byte / 16)) |>.push (witnessHexDigit (byte % 16))) \"\"",
        "",
        "private partial def witnessData : Data → String",
        "  | .I i => s!\"(I {i})\"",
        "  | .B bs => s!\"(B #{witnessBytesHex bs})\"",
        "  | .List xs => \"(List [\" ++ String.intercalate \", \" (xs.map witnessData) ++ \"])\"",
        "  | .Map xs => \"(Map [\" ++ String.intercalate \", \"",
        "      (xs.map fun (k, v) => s!\"({witnessData k}, {witnessData v})\") ++ \"])\"",
        "  | .Constr i xs => s!\"(Constr {i} [\" ++",
        "      String.intercalate \", \" (xs.map witnessData) ++ \"])\"",
        "",
        "private instance : Repr Data where",
        "  reprPrec data _ := .text (witnessData data)",
        "",
    ]


def _source_parts(
    pair: ProgramPairRecord,
    input_model: InputModel,
    runtime_step_bound: int,
    random_seed: int,
    solver_timeout: int,
    old_path: str,
    new_path: str,
    checker_configuration_id: str,
) -> dict[str, Any]:
    namespace = _lean_namespace(pair.program_pair_id)
    common = _common_source(pair, old_path, new_path)
    conversion, binders, arguments = _model_source(input_model)
    if input_model.kind == "pure_integer":
        observation_defs = [
            "inductive ProgramObservation where",
            "  | returned : Integer → ProgramObservation",
            "  | evaluationFailure : ProgramObservation",
            "  | unexpectedResultType : ProgramObservation",
            "  | runtimeBoundExhausted : ProgramObservation",
            "deriving DecidableEq",
            "",
            "def observeProgram : State → ProgramObservation",
            "  | .Halt (.VCon (.Integer value)) => .returned value",
            "  | .Halt _ => .unexpectedResultType",
            "  | .Error => .evaluationFailure",
            "  | _ => .runtimeBoundExhausted",
        ]
        observation = (
            f"observeProgram (oldPrepared.prop {arguments}) = "
            f"observeProgram (newPrepared.prop {arguments})"
        )
    else:
        observation_defs = [
            "inductive ValidatorObservation where",
            "  | success : ValidatorObservation",
            "  | failure : ValidatorObservation",
            "  | runtimeBoundExhausted : ValidatorObservation",
            "deriving DecidableEq",
            "",
            "def observeValidator : State → ValidatorObservation",
            "  | .Halt _ => .success",
            "  | .Error => .failure",
            "  | _ => .runtimeBoundExhausted",
        ]
        observation = (
            f"observeValidator (oldPrepared.prop {arguments}) = "
            f"observeValidator (newPrepared.prop {arguments})"
        )
    preparation = [
        *common,
        *conversion,
        "",
        *observation_defs,
        "def completedWithinBound : State → Bool",
        "  | .Halt _ => true",
        "  | .Error => true",
        "  | _ => false",
        "",
        "",
        f"#prep_uplc oldPrepared oldProgram modelInputs {runtime_step_bound}",
        f"#prep_uplc newPrepared newProgram modelInputs {runtime_step_bound}",
        "",
        *_raw_non_vacuity_source(input_model, binders),
        *_witness_encoder_source(input_model),
    ]
    equivalence_kind = (
        "ledger_observational_equivalence"
        if input_model.profile.startswith("ledger-valid")
        else "observational_equivalence"
    )
    non_vacuity_kind = (
        "ledger_domain_non_vacuity"
        if input_model.profile.startswith("ledger-valid")
        else "domain_non_vacuity"
    )
    obligations = {
        kind: SemanticObligationRecord.create(
            pair, input_model, kind, runtime_step_bound
        )
        for kind in (
            non_vacuity_kind,
            "old_program_completion",
            "new_program_completion",
            equivalence_kind,
        )
    }
    theorem = f"∀ {binders}, {input_model.domain_expression} → ({observation})"
    theorem_hash = theorem_statement_hash(theorem)
    options = (
        f"(dump-smt-lib: 1) (gen-cex: 1) (random-seed: {random_seed}) "
        f"(timeout: {solver_timeout})"
    )
    import_source = "\n".join([*common, f"end {namespace}", ""])
    preparation_source = "\n".join([*preparation, f"end {namespace}", ""])
    optimization_source = "\n".join(
        [
            *preparation,
            f"#blaster (only-optimize: 1) (random-seed: {random_seed}) [{theorem}]",
            "",
            f"end {namespace}",
            "",
        ]
    )

    def expected_source(status: str, expected_code: int) -> str:
        obligation = obligations[equivalence_kind]
        return "\n".join(
            [
                *preparation,
                *_source_binding_declarations(obligation),
                f"#blaster {options} (solve-result: {expected_code}) [{theorem}]",
                _lean_marker(
                    status=status,
                    pair=pair,
                    obligation=obligation,
                    theorem_hash=theorem_hash,
                    checker_configuration_id=checker_configuration_id,
                ),
                "",
                f"end {namespace}",
                "",
            ]
        )

    completion: dict[str, dict[str, Any]] = {}
    for label in ("old", "new"):
        kind = f"{label}_program_completion"
        obligation = obligations[kind]
        completion_theorem = (
            f"∀ {binders}, {input_model.domain_expression} → "
            f"(completedWithinBound ({label}Prepared.prop {arguments}) = true)"
        )
        completion_hash = theorem_statement_hash(completion_theorem)

        def completion_source(status: str, expected_code: int) -> str:
            return "\n".join(
                [
                    *preparation,
                    *_source_binding_declarations(obligation),
                    f"#blaster {options} (solve-result: {expected_code}) [{completion_theorem}]",
                    _lean_marker(
                        status=status,
                        pair=pair,
                        obligation=obligation,
                        theorem_hash=completion_hash,
                        checker_configuration_id=checker_configuration_id,
                    ),
                    "",
                    f"end {namespace}",
                    "",
                ]
            )

        completion[label] = {
            "theorem": completion_theorem,
            "theorem_hash": completion_hash,
            "obligation": obligation,
            "binding": _obligation_binding(
                pair=pair,
                obligation=obligation,
                theorem_hash=completion_hash,
                checker_configuration_id=checker_configuration_id,
            ),
            "valid": completion_source("valid", 0),
            "falsified": completion_source("falsified", 1),
            "inconclusive": completion_source("inconclusive", 2),
        }

    non_vacuity_obligation = obligations[non_vacuity_kind]
    if input_model.domain_expression == "True":
        non_vacuity_statement = (
            f"∃ {binders}, True" if binders else "True"
        )
        non_vacuity_hash = theorem_statement_hash(non_vacuity_statement)
        non_vacuity_expected_status = "valid"
        non_vacuity_source = "\n".join(
            [
                *preparation,
                *_source_binding_declarations(non_vacuity_obligation),
                _lean_marker(
                    status="valid",
                    pair=pair,
                    obligation=non_vacuity_obligation,
                    theorem_hash=non_vacuity_hash,
                    checker_configuration_id=checker_configuration_id,
                ),
                "",
                f"end {namespace}",
                "",
            ]
        )
        non_vacuity_method = "lean_elaboration_of_concrete_witness"
    else:
        emptiness = f"∀ {binders}, ¬({input_model.domain_expression})"
        non_vacuity_hash = theorem_statement_hash(emptiness)
        non_vacuity_expected_status = "falsified"
        non_vacuity_source = "\n".join(
            [
                *preparation,
                *_source_binding_declarations(non_vacuity_obligation),
                f"#blaster {options} (solve-result: 1) [{emptiness}]",
                _lean_marker(
                    status="falsified",
                    pair=pair,
                    obligation=non_vacuity_obligation,
                    theorem_hash=non_vacuity_hash,
                    checker_configuration_id=checker_configuration_id,
                ),
                "",
                f"end {namespace}",
                "",
            ]
        )
        non_vacuity_method = "solver_falsification_of_domain_emptiness"
    return {
        "import": import_source,
        "preparation": preparation_source,
        "optimization": optimization_source,
        "valid": expected_source("valid", 0),
        "falsified": expected_source("falsified", 1),
        "inconclusive": expected_source("inconclusive", 2),
        "theorem": theorem,
        "theorem_hash": theorem_hash,
        "equivalence_kind": equivalence_kind,
        "equivalence_obligation": obligations[equivalence_kind],
        "equivalence_binding": _obligation_binding(
            pair=pair,
            obligation=obligations[equivalence_kind],
            theorem_hash=theorem_hash,
            checker_configuration_id=checker_configuration_id,
        ),
        "non_vacuity": non_vacuity_source,
        "non_vacuity_hash": non_vacuity_hash,
        "non_vacuity_kind": non_vacuity_kind,
        "non_vacuity_obligation": non_vacuity_obligation,
        "non_vacuity_binding": _obligation_binding(
            pair=pair,
            obligation=non_vacuity_obligation,
            theorem_hash=non_vacuity_hash,
            checker_configuration_id=checker_configuration_id,
        ),
        "non_vacuity_expected_status": non_vacuity_expected_status,
        "non_vacuity_method": non_vacuity_method,
        "completion": completion,
        "obligations": obligations,
        "options": {
            "random_seed": random_seed,
            "solver_timeout_seconds": solver_timeout,
            "counterexample_generation": True,
            "runtime_step_bound": runtime_step_bound,
        },
    }


def _solver_input(output: str) -> str | None:
    marker = output.find("Smt Query:")
    if marker >= 0:
        start = output.find("\n", marker)
        return output[start + 1 :] if start >= 0 else None
    start = output.find("(set-logic")
    if start < 0:
        return None
    end = max(output.rfind("(check-sat)"), output.rfind("(get-value"))
    if end < start:
        return output[start:]
    line_end = output.find("\n", end)
    return output[start:] if line_end < 0 else output[start : line_end + 1]


class RealBlasterBackend:
    def __init__(self, config: BlasterConfig):
        self.config = config
        self._environment: dict[str, Any] | None = None
        self._environment_error: str | None = None
        self._lean_environment: dict[str, str] | None = None

    def _ensure_environment(self, output_root: Path) -> dict[str, Any]:
        if self._environment is not None:
            return self._environment
        if self._environment_error is not None:
            raise RuntimeError(self._environment_error)
        root = self.config.backend_root
        try:
            if not root.is_dir():
                raise RuntimeError(f"CardanoLedgerApiBlaster checkout is missing: {root}")
            manifest = json.loads((root / "lake-manifest.json").read_text(encoding="utf-8"))
            locked = {row["name"]: row["rev"] for row in manifest.get("packages", [])}
            expected = {
                "Blaster": self.config.revisions["Lean-blaster"],
                "PlutusCore": self.config.revisions["PlutusCoreBlaster"],
                "CardanoLedgerApi": self.config.revisions["CardanoLedgerApiBlaster"],
            }
            for package_name, expected_revision in expected.items():
                if locked.get(package_name) != expected_revision:
                    raise RuntimeError(
                        f"{package_name} lock mismatch: expected {expected_revision}, got {locked.get(package_name)}"
                    )
            lean = run_process(["lake", "env", "lean", "--version"], root, 120.0)
            if lean.exit_code != 0 or f"version {self.config.lean_version}" not in lean.stdout:
                raise RuntimeError(
                    f"Lean version mismatch: expected {self.config.lean_version}, got {(lean.stdout or lean.stderr).strip()}"
                )
            z3 = run_process(
                [self.config.solver_executable, "--version"], root, 30.0
            )
            if z3.exit_code != 0 or f"Z3 version {self.config.z3_version}" not in z3.stdout:
                raise RuntimeError(
                    f"Z3 version mismatch: expected {self.config.z3_version}, got {(z3.stdout or z3.stderr).strip()}"
                )
            setup = run_process(
                ["lake", "build", "CardanoLedgerApi"],
                root,
                self.config.timeouts.lean_elaboration,
            )
            write_process_logs(
                setup,
                output_root / "logs" / "blaster-setup.stdout.log",
                output_root / "logs" / "blaster-setup.stderr.log",
            )
            if setup.timed_out or setup.exit_code != 0:
                raise RuntimeError("CardanoLedgerApiBlaster setup failed or timed out")
            lean_path = run_process(
                ["lake", "env", "printenv", "LEAN_PATH"], root, 30.0
            )
            executable_path = run_process(
                ["lake", "env", "printenv", "PATH"], root, 30.0
            )
            if lean_path.exit_code != 0 or executable_path.exit_code != 0:
                raise RuntimeError("failed to resolve the pinned Lake environment")
            self._lean_environment = {
                "LEAN_PATH": lean_path.stdout.strip(),
                "PATH": (
                    f"{self.config.solver_executable.parent}{os.pathsep}"
                    f"{executable_path.stdout.strip()}"
                ),
            }
            self._environment = {
                "revisions": dict(self.config.revisions),
                "lean_version": self.config.lean_version,
                "z3_version": self.config.z3_version,
                "solver": self.config.solver,
            }
            return self._environment
        except (KeyError, OSError, ValueError, RuntimeError) as error:
            self._environment_error = str(error)
            raise RuntimeError(self._environment_error) from error

    def _stable_inputs(self, pair: ProgramPairRecord, output_root: Path) -> tuple[str, str]:
        inputs = output_root / "semantic-inputs"
        inputs.mkdir(parents=True, exist_ok=True)
        rows = []
        for artifact in (pair.old_script, pair.new_script):
            relative = f"semantic-inputs/{artifact.sha256}.cbor"
            destination = output_root / relative
            if not destination.is_file():
                shutil.copy2(artifact.path, destination)
            rows.append(relative)
        return rows[0], rows[1]

    def _run_stage(
        self,
        pair: ProgramPairRecord,
        stage: str,
        source: str,
        timeout: float,
        output_root: Path,
        options: dict[str, Any],
    ) -> tuple[ProcessResult, dict[str, Any], Path, str]:
        source_path = output_root / "generated-lean" / f"{pair.program_pair_id}-{stage}.lean"
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(source, encoding="utf-8")
        source_hash = _sha256_text(source)
        result = run_process(
            ["lean", "-s", "131072", source_path.resolve()],
            output_root,
            timeout,
            environment={
                **(self._lean_environment or {}),
                "BLASTER_SOLVER": self.config.solver,
                "BLASTER_TIMEOUT": str(max(1, int(self.config.timeouts.z3))),
            },
        )
        stdout_path = output_root / "logs" / f"{pair.program_pair_id}-{stage}.stdout.log"
        stderr_path = output_root / "logs" / f"{pair.program_pair_id}-{stage}.stderr.log"
        write_process_logs(result, stdout_path, stderr_path)
        record = result.to_dict() | {
            "phase": stage,
            "stdout_path": stdout_path.relative_to(output_root).as_posix(),
            "stderr_path": stderr_path.relative_to(output_root).as_posix(),
            "generated_lean_path": source_path.relative_to(output_root).as_posix(),
            "generated_lean_sha256": source_hash,
            "timeout_seconds": timeout,
            "effective_options": options,
        }
        return result, record, source_path, source_hash
    def compare(
        self,
        pair: ProgramPairRecord,
        input_model: InputModel,
        output_root: Path,
    ) -> BlasterResult:
        if not input_model.supported:
            status = (
                "fallback_purpose_unsupported"
                if input_model.purpose == "fallback"
                and input_model.profile.startswith("ledger-valid")
                else "raw_model_unsupported"
                if input_model.profile.startswith("raw-uplc")
                else "ledger_model_unsupported"
            )
            return BlasterResult(
                status=status,
                command=None,
                exit_code=None,
                duration_seconds=0.0,
                error=input_model.unsupported_reason,
            )
        if (
            pair.verified_abi.get("status") != "verified"
            or not pair.verified_abi_id
        ):
            return BlasterResult(
                status="raw_model_unsupported",
                command=None,
                exit_code=None,
                duration_seconds=0.0,
                error="raw_model_not_bound_to_abi",
            )
        checker_id = self.config.checker_configuration()[
            "checker_configuration_id"
        ]
        try:
            self._ensure_environment(output_root)
            old_path, new_path = self._stable_inputs(pair, output_root)
            parts = _source_parts(
                pair,
                input_model,
                self.config.runtime_step_bound,
                self.config.random_seed,
                max(1, int(self.config.timeouts.z3)),
                old_path,
                new_path,
                checker_id,
            )
        except (RuntimeError, ValueError, OSError) as error:
            return BlasterResult(
                status="blaster_error",
                command=None,
                exit_code=None,
                duration_seconds=0.0,
                error=str(error),
            )

        phase_records: list[dict[str, Any]] = []
        proof_obligations: dict[str, Any] = {}
        for kind, obligation in parts["obligations"].items():
            theorem_hash = (
                parts["non_vacuity_hash"]
                if kind == parts["non_vacuity_kind"]
                else parts["completion"][kind.removesuffix("_program_completion")][
                    "theorem_hash"
                ]
                if kind in {"old_program_completion", "new_program_completion"}
                else parts["theorem_hash"]
            )
            proof_obligations[kind] = obligation.to_dict() | {
                "status": "pending",
                "theorem_statement_hash": theorem_hash,
                "checker_configuration_id": checker_id,
                "generated_source_schema_version": GENERATED_LEAN_SCHEMA_VERSION,
            }
        total_duration = 0.0
        profile_tag = re.sub(r"[^A-Za-z0-9_.-]+", "-", input_model.profile)

        for stage, source, timeout in (
            ("uplc-import", parts["import"], self.config.timeouts.uplc_import),
            (
                "uplc-preparation",
                parts["preparation"],
                self.config.timeouts.uplc_preparation,
            ),
        ):
            result, record, _source_path, source_hash = self._run_stage(
                pair,
                f"{profile_tag}-{stage}",
                source,
                timeout,
                output_root,
                parts["options"],
            )
            phase_records.append(record)
            total_duration += result.duration_seconds
            if result.timed_out or result.exit_code != 0:
                return BlasterResult(
                    status=(
                        "blaster_timeout"
                        if result.timed_out
                        else "blaster_inconclusive"
                        if stage == "uplc-preparation"
                        else "blaster_error"
                    ),
                    command=result.command,
                    exit_code=result.exit_code,
                    duration_seconds=round(total_duration, 6),
                    stdout_path=record["stdout_path"],
                    stderr_path=record["stderr_path"],
                    generated_lean_path=record["generated_lean_path"],
                    generated_lean_sha256=source_hash,
                    phase_results=phase_records,
                    proof_obligations=proof_obligations,
                    error=f"{stage} failed or timed out; no logical verdict",
                )

        non_vacuity_result, non_vacuity_record, non_vacuity_path, non_vacuity_hash = (
            self._run_stage(
                pair,
                f"{profile_tag}-{parts['non_vacuity_kind']}",
                parts["non_vacuity"],
                self.config.timeouts.lean_elaboration + self.config.timeouts.z3,
                output_root,
                parts["options"]
                | {"proof_obligation": parts["non_vacuity_kind"]},
            )
        )
        phase_records.append(non_vacuity_record)
        total_duration += non_vacuity_result.duration_seconds
        try:
            non_vacuity_marker = parse_result_protocol(
                non_vacuity_result.stdout,
                non_vacuity_result.stderr,
                exit_code=non_vacuity_result.exit_code,
                expected=parts["non_vacuity_binding"],
            )
        except ValueError as error:
            return BlasterResult(
                status="domain_non_vacuous_failed",
                command=non_vacuity_result.command,
                exit_code=non_vacuity_result.exit_code,
                duration_seconds=round(total_duration, 6),
                stdout_path=non_vacuity_record["stdout_path"],
                stderr_path=non_vacuity_record["stderr_path"],
                generated_lean_path=non_vacuity_record["generated_lean_path"],
                generated_lean_sha256=non_vacuity_hash,
                phase_results=phase_records,
                proof_obligations=proof_obligations,
                error=str(error),
            )
        if (
            non_vacuity_marker["solver_status"]
            != parts["non_vacuity_expected_status"]
        ):
            return BlasterResult(
                status="domain_non_vacuous_failed",
                command=non_vacuity_result.command,
                exit_code=non_vacuity_result.exit_code,
                duration_seconds=round(total_duration, 6),
                phase_results=phase_records,
                proof_obligations=proof_obligations,
                error="domain non-vacuity marker conflicts with the proof method",
            )
        non_vacuity_kind = parts["non_vacuity_kind"]
        proof_obligations[non_vacuity_kind] |= {
            "status": "proven",
            "solver_status": non_vacuity_marker["solver_status"],
            "method": parts["non_vacuity_method"],
            "generated_lean_path": non_vacuity_path.relative_to(
                output_root
            ).as_posix(),
            "generated_lean_sha256": non_vacuity_hash,
            "legacy_human_witness": extract_witness(
                non_vacuity_result.stdout, non_vacuity_result.stderr
            ),
        }

        completion_proven = True
        for label in ("old", "new"):
            kind = f"{label}_program_completion"
            completion_parts = parts["completion"][label]
            completion_final: tuple[
                ProcessResult, dict[str, Any], Path, str, dict[str, Any]
            ] | None = None
            for expected_status, stage in (
                ("valid", f"{kind}-valid"),
                ("falsified", f"{kind}-falsified"),
                ("inconclusive", f"{kind}-inconclusive"),
            ):
                result, record, source_path, source_hash = self._run_stage(
                    pair,
                    f"{profile_tag}-{stage}",
                    completion_parts[expected_status],
                    self.config.timeouts.lean_elaboration
                    + self.config.timeouts.z3,
                    output_root,
                    parts["options"]
                    | {
                        "expected_result": expected_status,
                        "proof_obligation": kind,
                    },
                )
                phase_records.append(record)
                total_duration += result.duration_seconds
                if result.timed_out:
                    return BlasterResult(
                        status="blaster_timeout",
                        command=result.command,
                        exit_code=result.exit_code,
                        duration_seconds=round(total_duration, 6),
                        stdout_path=record["stdout_path"],
                        stderr_path=record["stderr_path"],
                        generated_lean_path=record["generated_lean_path"],
                        generated_lean_sha256=source_hash,
                        phase_results=phase_records,
                        proof_obligations=proof_obligations,
                        error=f"{kind} timed out",
                    )
                if result.exit_code != 0:
                    continue
                try:
                    marker = parse_result_protocol(
                        result.stdout,
                        result.stderr,
                        exit_code=result.exit_code,
                        expected=completion_parts["binding"],
                    )
                except ValueError as error:
                    return BlasterResult(
                        status="blaster_error",
                        command=result.command,
                        exit_code=result.exit_code,
                        duration_seconds=round(total_duration, 6),
                        stdout_path=record["stdout_path"],
                        stderr_path=record["stderr_path"],
                        generated_lean_path=record["generated_lean_path"],
                        generated_lean_sha256=source_hash,
                        phase_results=phase_records,
                        proof_obligations=proof_obligations,
                        error=str(error),
                    )
                if marker["solver_status"] != expected_status:
                    return BlasterResult(
                        status="blaster_error",
                        command=result.command,
                        exit_code=result.exit_code,
                        duration_seconds=round(total_duration, 6),
                        phase_results=phase_records,
                        proof_obligations=proof_obligations,
                        error="completion marker conflicts with expected solver trial",
                    )
                completion_final = (
                    result,
                    record,
                    source_path,
                    source_hash,
                    marker,
                )
                break
            if completion_final is None:
                last = phase_records[-1]
                return BlasterResult(
                    status="blaster_error",
                    command=last["command"],
                    exit_code=last["exit_code"],
                    duration_seconds=round(total_duration, 6),
                    stdout_path=last["stdout_path"],
                    stderr_path=last["stderr_path"],
                    generated_lean_path=last["generated_lean_path"],
                    generated_lean_sha256=last["generated_lean_sha256"],
                    phase_results=phase_records,
                    proof_obligations=proof_obligations,
                    error=f"no {kind} solver trial produced a protocol marker",
                )
            completion_status = completion_final[4]["solver_status"]
            proof_obligations[kind] |= {
                "status": (
                    "proven" if completion_status == "valid" else completion_status
                ),
                "solver_status": completion_status,
                "generated_lean_path": completion_final[2]
                .relative_to(output_root)
                .as_posix(),
                "generated_lean_sha256": completion_final[3],
            }
            completion_proven = (
                completion_proven and completion_status == "valid"
            )

        final: tuple[
            ProcessResult, dict[str, Any], Path, str, dict[str, Any]
        ] | None = None
        for expected_status, stage in (
            ("valid", "equivalence-valid"),
            ("falsified", "equivalence-falsified"),
            ("inconclusive", "equivalence-inconclusive"),
        ):
            result, record, source_path, source_hash = self._run_stage(
                pair,
                f"{profile_tag}-{stage}",
                parts[expected_status],
                self.config.timeouts.lean_elaboration + self.config.timeouts.z3,
                output_root,
                parts["options"] | {"expected_result": expected_status},
            )
            phase_records.append(record)
            total_duration += result.duration_seconds
            if result.timed_out:
                return BlasterResult(
                    status="blaster_timeout",
                    command=result.command,
                    exit_code=result.exit_code,
                    duration_seconds=round(total_duration, 6),
                    stdout_path=record["stdout_path"],
                    stderr_path=record["stderr_path"],
                    generated_lean_path=record["generated_lean_path"],
                    generated_lean_sha256=source_hash,
                    phase_results=phase_records,
                    proof_obligations=proof_obligations,
                    error="equivalence solver trial timed out",
                )
            if result.exit_code != 0:
                continue
            try:
                marker = parse_result_protocol(
                    result.stdout,
                    result.stderr,
                    exit_code=result.exit_code,
                    expected=parts["equivalence_binding"],
                )
            except ValueError as error:
                return BlasterResult(
                    status="blaster_error",
                    command=result.command,
                    exit_code=result.exit_code,
                    duration_seconds=round(total_duration, 6),
                    stdout_path=record["stdout_path"],
                    stderr_path=record["stderr_path"],
                    generated_lean_path=record["generated_lean_path"],
                    generated_lean_sha256=source_hash,
                    phase_results=phase_records,
                    proof_obligations=proof_obligations,
                    error=str(error),
                )
            if marker["solver_status"] != expected_status:
                return BlasterResult(
                    status="blaster_error",
                    command=result.command,
                    exit_code=result.exit_code,
                    duration_seconds=round(total_duration, 6),
                    phase_results=phase_records,
                    proof_obligations=proof_obligations,
                    error="equivalence marker conflicts with expected solver trial",
                )
            final = result, record, source_path, source_hash, marker
            break
        if final is None:
            last = phase_records[-1]
            return BlasterResult(
                status="blaster_error",
                command=last["command"],
                exit_code=last["exit_code"],
                duration_seconds=round(total_duration, 6),
                stdout_path=last["stdout_path"],
                stderr_path=last["stderr_path"],
                generated_lean_path=last["generated_lean_path"],
                generated_lean_sha256=last["generated_lean_sha256"],
                phase_results=phase_records,
                proof_obligations=proof_obligations,
                error="no equivalence solver trial produced a valid protocol marker",
            )

        result, record, source_path, source_hash, marker = final
        combined = f"{result.stdout}\n{result.stderr}"
        solver_text = _solver_input(combined)
        solver_path: Path | None = None
        solver_hash: str | None = None
        if solver_text:
            solver_path = (
                output_root / "logs" / f"{pair.program_pair_id}.smt2"
            )
            solver_path.write_text(solver_text, encoding="utf-8")
            solver_hash = _sha256_text(solver_text)
        protocol_status = marker["solver_status"]
        equivalence_kind = parts["equivalence_kind"]
        proof_obligations[equivalence_kind] |= {
            "status": protocol_status,
            "solver_status": protocol_status,
            "generated_lean_path": source_path.relative_to(
                output_root
            ).as_posix(),
            "generated_lean_sha256": source_hash,
        }
        status = {
            "valid": (
                "blaster_valid" if completion_proven else "bounded_equivalent"
            ),
            "falsified": "blaster_falsified_unreplayed",
            "inconclusive": "blaster_inconclusive",
        }[protocol_status]
        witness: dict[str, Any] | None = None
        if protocol_status == "falsified":
            expected_witness = _witness_expected(
                pair,
                input_model,
                parts["equivalence_obligation"],
                parts["theorem_hash"],
            )
            try:
                witness = parse_witness_protocol(
                    result.stdout,
                    result.stderr,
                    expected=expected_witness,
                )
                if witness is None:
                    legacy = extract_witness(result.stdout, result.stderr)
                    if legacy is not None:
                        witness = _legacy_witness_v2(
                            legacy,
                            pair,
                            input_model,
                            parts["equivalence_obligation"],
                            parts["theorem_hash"],
                        )
                    else:
                        witness = _domain_witness_v2(
                            pair,
                            input_model,
                            parts["equivalence_obligation"],
                            parts["theorem_hash"],
                        )
                    if witness is None:
                        raise ValueError(
                            "falsified result has no machine, legacy, or model-domain witness"
                        )
                encoded = [
                    encode_uplc_term(value)
                    for value in witness["structured_argument_values"]
                ]
                if encoded != witness["serialized_uplc_argument_terms"]:
                    raise ValueError("witness serialization is lossy")
            except (KeyError, TypeError, ValueError) as error:
                return BlasterResult(
                    status="blaster_error",
                    command=result.command,
                    exit_code=result.exit_code,
                    duration_seconds=round(total_duration, 6),
                    stdout_path=record["stdout_path"],
                    stderr_path=record["stderr_path"],
                    generated_lean_path=source_path.relative_to(
                        output_root
                    ).as_posix(),
                    generated_lean_sha256=source_hash,
                    phase_results=phase_records,
                    proof_obligations=proof_obligations,
                    error=str(error),
                )
        error = (
            "equivalent only within the recorded CEK runtime step bound"
            if status == "bounded_equivalent"
            else "solver returned inconclusive"
            if status == "blaster_inconclusive"
            else None
        )
        return BlasterResult(
            status=status,
            command=result.command,
            exit_code=result.exit_code,
            duration_seconds=round(total_duration, 6),
            stdout_path=record["stdout_path"],
            stderr_path=record["stderr_path"],
            generated_lean_path=source_path.relative_to(output_root).as_posix(),
            generated_lean_sha256=source_hash,
            solver_input_path=(
                solver_path.relative_to(output_root).as_posix()
                if solver_path
                else None
            ),
            solver_input_sha256=solver_hash,
            witness=witness,
            phase_results=phase_records,
            proof_obligations=proof_obligations,
            error=error,
        )

    def _evaluate_script(
        self,
        pair: ProgramPairRecord,
        label: str,
        arguments: list[str],
        output_root: Path,
        evaluator: EvaluatorConfig,
    ) -> dict[str, Any]:
        artifact = pair.old_script if label == "old" else pair.new_script
        if evaluator.backend_kind == "aiken":
            command = [
                str(evaluator.executable),
                "uplc",
                "eval",
                "--cbor",
                str(artifact.path),
            ]
        elif evaluator.backend_kind == "uplc-cli":
            command = [
                str(evaluator.executable),
                "eval",
                "--cbor",
                str(artifact.path),
            ]
        else:
            return {
                "ok": False,
                "outcome": "cli_error",
                "error_class": "unsupported_evaluator_backend",
                "backend_kind": evaluator.backend_kind,
            }
        configured_limits = dict(evaluator.evaluation_limits)
        evaluator_enforced_limits: dict[str, Any] = {}
        flag_names = {
            "cpu": "--cpu-budget",
            "memory": "--memory-budget",
            "uplc_budget": "--budget",
            "execution_budget": "--budget",
        }
        for name in evaluator.supported_limit_flags:
            if name in configured_limits and name in flag_names:
                command.extend([flag_names[name], str(configured_limits[name])])
                evaluator_enforced_limits[name] = configured_limits[name]
        command.extend(arguments)
        wall_timeout = self.config.timeouts.counterexample_replay
        result = run_process(command, output_root, wall_timeout)
        evaluator_tag = re.sub(r"[^A-Za-z0-9_.-]+", "-", evaluator.name)
        stdout_path = (
            output_root
            / "counterexamples"
            / f"{pair.program_pair_id}-{evaluator_tag}-{label}.stdout.log"
        )
        stderr_path = (
            output_root
            / "counterexamples"
            / f"{pair.program_pair_id}-{evaluator_tag}-{label}.stderr.log"
        )
        write_process_logs(result, stdout_path, stderr_path)
        classification = classify_evaluator_output(result)
        resource_names = {
            "cpu",
            "memory",
            "uplc_budget",
            "execution_budget",
        }
        unenforced_limits = {
            name: value
            for name, value in configured_limits.items()
            if name in resource_names and name not in evaluator_enforced_limits
        }
        externally_enforced_limits = {
            "wall_timeout_seconds": wall_timeout,
            "process_group_termination_on_timeout": True,
        }
        effective_limits = {
            **evaluator_enforced_limits,
            **externally_enforced_limits,
        }
        return classification | {
            "evaluator": evaluator.identity(),
            "command": command,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "process_group_termination_succeeded": (
                result.process_group_termination_succeeded
            ),
            "duration_seconds": result.duration_seconds,
            "stdout_path": stdout_path.relative_to(output_root).as_posix(),
            "stderr_path": stderr_path.relative_to(output_root).as_posix(),
            "stdout_sha256": hashlib.sha256(
                result.stdout.encode("utf-8")
            ).hexdigest(),
            "stderr_sha256": hashlib.sha256(
                result.stderr.encode("utf-8")
            ).hexdigest(),
            "configured_limits": configured_limits
            | {"wall_timeout_seconds": wall_timeout},
            "effective_limits": effective_limits,
            "evaluator_enforced_limits": evaluator_enforced_limits,
            "externally_enforced_limits": externally_enforced_limits,
            "unenforced_limits": unenforced_limits,
            "trace": [],
        }

    def replay(
        self,
        pair: ProgramPairRecord,
        input_model: InputModel,
        witness: dict[str, Any],
        output_root: Path,
    ) -> dict[str, Any]:
        evaluator = self.config.evaluator
        if evaluator is None:
            return {
                "confirmed": False,
                "reason": "replay evaluator is not configured",
            }
        try:
            old_path, new_path = self._stable_inputs(pair, output_root)
            parts = _source_parts(
                pair,
                input_model,
                self.config.runtime_step_bound,
                self.config.random_seed,
                max(1, int(self.config.timeouts.z3)),
                old_path,
                new_path,
                self.config.checker_configuration()[
                    "checker_configuration_id"
                ],
            )
            expected = _witness_expected(
                pair,
                input_model,
                parts["equivalence_obligation"],
                parts["theorem_hash"],
            )
            validated = validate_witness_record(witness, expected)
            encoded = [
                encode_uplc_term(value)
                for value in validated["structured_argument_values"]
            ]
            if encoded != validated["serialized_uplc_argument_terms"]:
                raise ValueError("witness serialization is lossy")
        except (KeyError, TypeError, ValueError) as error:
            return {
                "confirmed": False,
                "reason": f"witness validation failed: {error}",
            }
        arguments_path = (
            output_root
            / "counterexamples"
            / f"{pair.program_pair_id}-arguments.json"
        )
        arguments_path.parent.mkdir(parents=True, exist_ok=True)
        arguments_record = {
            "protocol_version": "EQUIV_REPLAY_ARGUMENTS_V2",
            "program_pair_id": pair.program_pair_id,
            "logical_obligation_id": parts[
                "equivalence_obligation"
            ].logical_obligation_id,
            "semantic_model_id": parts[
                "equivalence_obligation"
            ].semantic_model_id,
            "theorem_statement_hash": parts["theorem_hash"],
            "argument_order": list(input_model.argument_order),
            "arguments": encoded,
        }
        arguments_path.write_text(
            json.dumps(arguments_record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        def observation(row: dict[str, Any]) -> Any:
            if input_model.kind.startswith("validator"):
                return (
                    "success"
                    if row.get("outcome") == "program_success"
                    else "failure"
                    if row.get("outcome") == "program_failure"
                    else None
                )
            return (
                {"kind": "returned", "value": row.get("result_value")}
                if row.get("outcome") == "program_success"
                else {"kind": "evaluation_failure"}
                if row.get("outcome") == "program_failure"
                else None
            )

        def evaluate_backend(configured: EvaluatorConfig) -> dict[str, Any]:
            old = self._evaluate_script(
                pair, "old", encoded, output_root, configured
            )
            new = self._evaluate_script(
                pair, "new", encoded, output_root, configured
            )
            old_observation = observation(old)
            new_observation = observation(new)
            confirmed = (
                old.get("ok") is True
                and new.get("ok") is True
                and old_observation is not None
                and new_observation is not None
                and old_observation != new_observation
            )
            return {
                "evaluator": configured.identity(),
                "confirmed": confirmed,
                "old": old,
                "new": new,
                "old_observation": old_observation,
                "new_observation": new_observation,
            }

        primary = evaluate_backend(evaluator)
        secondary = (
            evaluate_backend(self.config.secondary_evaluator)
            if self.config.secondary_evaluator is not None
            else None
        )
        cross_confirmed = bool(
            primary["confirmed"]
            and secondary is not None
            and secondary["confirmed"]
            and self.config.secondary_evaluator is not None
            and self.config.secondary_evaluator.distinct_uplc_implementation
            and secondary["old_observation"] == primary["old_observation"]
            and secondary["new_observation"] == primary["new_observation"]
        )
        replay_confidence = (
            "cross_evaluator_confirmed"
            if cross_confirmed
            else "single_evaluator_confirmed"
            if primary["confirmed"]
            else "not_confirmed"
        )
        replay = {
            "schema_version": 2,
            "confirmed": bool(primary["confirmed"]),
            "replay_confidence": replay_confidence,
            "program_pair_id": pair.program_pair_id,
            "logical_obligation_id": parts[
                "equivalence_obligation"
            ].logical_obligation_id,
            "semantic_model_id": parts[
                "equivalence_obligation"
            ].semantic_model_id,
            "theorem_statement_hash": parts["theorem_hash"],
            "witness_sha256": witness.get("witness_sha256"),
            "witness_source": witness.get("witness_source"),
            "legacy_witness_validation": (
                {
                    "serialization_validated": True,
                    "concrete_replay_validated": bool(primary["confirmed"]),
                }
                if witness.get("witness_source") == "legacy_human_parser"
                else None
            ),
            "reason": (
                None
                if primary["confirmed"]
                else "replay did not confirm distinct semantic observations"
            ),
            "replay_trust": {
                "separately_pinned": evaluator.separately_pinned,
                "separate_binary": None,
                "separate_from_symbolic_model": True,
                "distinct_uplc_implementation": (
                    evaluator.distinct_uplc_implementation
                ),
            },
            "arguments_path": arguments_path.relative_to(
                output_root
            ).as_posix(),
            "arguments_sha256": hashlib.sha256(
                arguments_path.read_bytes()
            ).hexdigest(),
            "primary_evaluator": primary,
            "secondary_evaluator": secondary,
        }
        counterexample_path = (
            output_root / "counterexamples" / f"{pair.program_pair_id}.json"
        )
        counterexample_path.write_text(
            json.dumps(replay, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        replay["artifact_path"] = counterexample_path.relative_to(
            output_root
        ).as_posix()
        return replay
