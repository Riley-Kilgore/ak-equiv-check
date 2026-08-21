from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PARSER_VERSION = "aiken-blueprint-parser/v1"
SUPPORTED_RELEASES = frozenset({"v1.1.21", "v1.1.22", "v1.1.23"})
_REQUIRED_TOP_LEVEL = frozenset({"preamble", "validators", "definitions"})
_ALLOWED_TOP_LEVEL = _REQUIRED_TOP_LEVEL | {"$schema"}
_RELEASE_VERSION = re.compile(r"^(v\d+\.\d+\.\d+)(?:[+-].*)?$")


@dataclass(frozen=True)
class BlueprintCompatibilityError(ValueError):
    state: str
    detail: str

    def __str__(self) -> str:
        return f"{self.state}: {self.detail}"


def _failure(state: str, detail: str) -> BlueprintCompatibilityError:
    return BlueprintCompatibilityError(state=state, detail=detail)


def _schema_record(value: dict[str, Any]) -> dict[str, Any]:
    preamble = value["preamble"]
    compiler = preamble["compiler"]
    reported_version = compiler["version"]
    match = _RELEASE_VERSION.fullmatch(reported_version)
    release = match.group(1) if match else None
    family = (
        f"aiken-blueprint-{release}"
        if release in SUPPORTED_RELEASES
        else "aiken-blueprint-development-v1"
    )
    validators = value["validators"]
    validator_fields = sorted({key for row in validators for key in row})
    return {
        "status": "blueprint_schema_supported",
        "schema_family": family,
        "compiler_name": compiler["name"],
        "compiler_version": reported_version,
        "release": release,
        "detected_required_fields": sorted(_REQUIRED_TOP_LEVEL),
        "validator_record_shape": validator_fields,
        "compiled_code_encoding": "lower_or_upper_hex_encoded_serialized_uplc_cbor",
        "parameter_representation": "optional validator.parameters[].{title,schema}; absent means []",
        "datum_representation": "optional validator.datum.{title,schema}",
        "redeemer_representation": "validator.redeemer.{title,schema}",
        "definitions_representation": "top_level_definitions_object_with_json_schema_refs",
        "parser_version": PARSER_VERSION,
        "validator_count": len(validators),
    }


def parse_blueprint(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    path = path.expanduser().resolve()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise _failure("blueprint_missing_required_field", f"cannot read JSON: {error}") from error
    except json.JSONDecodeError as error:
        raise _failure("blueprint_schema_unsupported", f"invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise _failure("blueprint_schema_unsupported", "blueprint root is not an object")
    missing_top = sorted(_REQUIRED_TOP_LEVEL - value.keys())
    if missing_top:
        raise _failure(
            "blueprint_missing_required_field",
            f"missing top-level field(s): {', '.join(missing_top)}",
        )
    unknown_top = sorted(value.keys() - _ALLOWED_TOP_LEVEL)
    if unknown_top:
        raise _failure(
            "blueprint_schema_unsupported",
            f"unknown top-level field(s): {', '.join(unknown_top)}",
        )
    preamble = value["preamble"]
    definitions = value["definitions"]
    validators = value["validators"]
    if not isinstance(preamble, dict) or not isinstance(definitions, dict) or not isinstance(
        validators, list
    ):
        raise _failure(
            "blueprint_missing_required_field",
            "preamble and definitions must be objects and validators must be an array",
        )
    compiler = preamble.get("compiler")
    if (
        not isinstance(compiler, dict)
        or compiler.get("name") != "Aiken"
        or not isinstance(compiler.get("version"), str)
        or not isinstance(preamble.get("plutusVersion"), str)
    ):
        raise _failure(
            "blueprint_missing_required_field",
            "preamble must identify Aiken compiler version and Plutus version",
        )
    titles: set[str] = set()
    for index, row in enumerate(validators):
        if not isinstance(row, dict):
            raise _failure(
                "blueprint_schema_unsupported", f"validator {index} is not an object"
            )
        required = {"title", "compiledCode", "redeemer"}
        missing = sorted(required - row.keys())
        if missing:
            raise _failure(
                "blueprint_missing_required_field",
                f"validator {index} is missing: {', '.join(missing)}",
            )
        title = row["title"]
        if not isinstance(title, str) or not title:
            raise _failure(
                "blueprint_missing_required_field", f"validator {index} has no title"
            )
        if title in titles:
            raise _failure(
                "blueprint_schema_ambiguous", f"duplicate validator title: {title}"
            )
        titles.add(title)
        compiled_code = row["compiledCode"]
        if not isinstance(compiled_code, str) or not compiled_code:
            raise _failure(
                "blueprint_compiled_code_invalid", f"validator {title} has no compiled code"
            )
        try:
            serialized = bytes.fromhex(compiled_code)
        except ValueError as error:
            raise _failure(
                "blueprint_compiled_code_invalid",
                f"validator {title} compiled code is not hexadecimal",
            ) from error
        if not serialized:
            raise _failure(
                "blueprint_compiled_code_invalid", f"validator {title} compiled code is empty"
            )
        parameters = row.get("parameters", [])
        redeemer = row["redeemer"]
        datum = row.get("datum")
        if not isinstance(parameters, list) or not all(
            isinstance(parameter, dict)
            and isinstance(parameter.get("title"), str)
            and isinstance(parameter.get("schema"), dict)
            for parameter in parameters
        ):
            raise _failure(
                "blueprint_schema_unsupported",
                f"validator {title} has unsupported parameter representation",
            )
        for field_name, field_value in (("redeemer", redeemer), ("datum", datum)):
            if field_value is None and field_name == "datum":
                continue
            if (
                not isinstance(field_value, dict)
                or field_value.get("title") is not None
                and not isinstance(field_value.get("title"), str)
                or not isinstance(field_value.get("schema"), dict)
            ):
                raise _failure(
                    "blueprint_schema_unsupported",
                    f"validator {title} has unsupported {field_name} representation",
                )
    return value, _schema_record(value)


def inspect_blueprint(path: Path) -> dict[str, Any]:
    try:
        _, record = parse_blueprint(path)
        return record
    except BlueprintCompatibilityError as error:
        return {
            "status": error.state,
            "detail": error.detail,
            "schema_family": None,
            "parser_version": PARSER_VERSION,
        }
