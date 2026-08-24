from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .blueprints import parse_blueprint
from .evidence import program_artifact_id, program_pair_id, verified_abi_id
from .models import (
    HandlerPairRecord,
    ProgramPairRecord,
    ScriptArtifact,
    ValidatorRecord,
)

PURPOSES = {
    "spend": "spending",
    "mint": "minting",
    "withdraw": "rewarding",
    "publish": "certifying",
    "vote": "voting",
    "propose": "proposing",
    "else": "fallback",
}


@dataclass(frozen=True)
class Validator:
    title: str
    module: str
    name: str
    purpose: str
    parameters: tuple[dict[str, Any], ...]
    signature: dict[str, Any]
    compiled_code: str
    script_sha256: str
    script_size: int

    @property
    def base_key(self) -> tuple[str, str, str, str]:
        return self.module, self.name, self.purpose, self.title


@dataclass(frozen=True)
class PairingResult:
    old_count: int
    new_count: int
    validator_records_old: tuple[ValidatorRecord, ...]
    validator_records_new: tuple[ValidatorRecord, ...]
    handler_pairs: tuple[HandlerPairRecord, ...]
    program_pairs: tuple[ProgramPairRecord, ...]
    compatibility_results: tuple[dict[str, Any], ...]


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _parse_title(title: str) -> tuple[str, str, str]:
    parts = title.rsplit(".", 2)
    if len(parts) == 3:
        module, name, raw_purpose = parts
    elif len(parts) == 2:
        module, name = parts
        raw_purpose = "else"
    else:
        module, name, raw_purpose = "", title, "else"
    return module, name, PURPOSES.get(raw_purpose, raw_purpose)


def _schema_field(validator: dict[str, Any], name: str) -> dict[str, Any] | None:
    value = validator.get(name)
    if not isinstance(value, dict):
        return None
    return {
        "title": value.get("title"),
        "schema": value.get("schema", {}),
    }


def discover_validators(blueprint_path: Path) -> tuple[Validator, ...]:
    blueprint, _compatibility = parse_blueprint(blueprint_path)
    rows = blueprint["validators"]
    discovered: list[Validator] = []
    seen_titles: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"blueprint validator {index} is not an object")
        title = row.get("title")
        compiled_code = row.get("compiledCode")
        if not isinstance(title, str) or not title:
            raise ValueError(f"blueprint validator {index} has no title")
        if title in seen_titles:
            raise ValueError(f"duplicate blueprint validator title: {title}")
        seen_titles.add(title)
        if not isinstance(compiled_code, str) or not compiled_code:
            raise ValueError(f"blueprint validator {title} has no compiledCode")
        try:
            serialized = bytes.fromhex(compiled_code)
        except ValueError as error:
            raise ValueError(f"blueprint validator {title} has invalid compiledCode hex") from error
        module, name, purpose = _parse_title(title)
        parameters_value = row.get("parameters", [])
        if not isinstance(parameters_value, list):
            raise ValueError(f"blueprint validator {title} parameters are not an array")
        parameters = tuple(
            {
                "title": parameter.get("title"),
                "schema": parameter.get("schema", {}),
            }
            for parameter in parameters_value
            if isinstance(parameter, dict)
        )
        if len(parameters) != len(parameters_value):
            raise ValueError(f"blueprint validator {title} contains an invalid parameter")
        signature = {
            "parameters": list(parameters),
            "datum": _schema_field(row, "datum"),
            "redeemer": _schema_field(row, "redeemer"),
        }
        discovered.append(
            Validator(
                title=title,
                module=module,
                name=name,
                purpose=purpose,
                parameters=parameters,
                signature=signature,
                compiled_code=compiled_code.lower(),
                script_sha256=hashlib.sha256(serialized).hexdigest(),
                script_size=len(serialized),
            )
        )
    return tuple(discovered)


def _safe_stem(value: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.")
    return stem[-96:] or "validator"


def _identity(
    validator: Validator,
    package_identity: str,
    _package_path: str,
) -> dict[str, Any]:
    return {
        "source_identity": package_identity,
        "module": validator.module,
        "validator_name": validator.name,
        "purpose": validator.purpose,
        "parameter_schemas": list(validator.parameters),
        "datum_schema": validator.signature["datum"],
        "redeemer_schema": validator.signature["redeemer"],
        "blueprint_abi": {
            "title": validator.title,
            "parameter_count": len(validator.parameters),
        },
    }

def _runtime_argument_names(
    *, parameter_count: int, runtime_count: int, purpose: str, plutus_version: str
) -> tuple[str, ...]:
    parameters = tuple(f"parameter{index}" for index in range(parameter_count))
    normalized = plutus_version.lower().removeprefix("plutus").removeprefix("v")
    if normalized == "3" and runtime_count == 1:
        return parameters + ("script_context_data",)
    if purpose == "spending" and runtime_count == 3:
        return parameters + ("datum_data", "redeemer_data", "script_context_data")
    if purpose in {"minting", "rewarding", "certifying"} and runtime_count == 2:
        return parameters + ("redeemer_data", "script_context_data")
    return parameters + tuple(
        f"runtime_argument{index}" for index in range(runtime_count)
    )


def _compiled_abi(
    validator: Validator,
    inspection: dict[str, Any] | None,
    plutus_version: str,
    *,
    parser_error: str | None = None,
) -> dict[str, Any]:
    parameter_count = len(validator.parameters)
    arity = inspection.get("top_level_callable_arity") if inspection else None
    verified = (
        parser_error is None
        and isinstance(arity, int)
        and arity >= parameter_count
    )
    runtime_count = arity - parameter_count if verified else None
    argument_order = (
        _runtime_argument_names(
            parameter_count=parameter_count,
            runtime_count=runtime_count,
            purpose=validator.purpose,
            plutus_version=plutus_version,
        )
        if runtime_count is not None
        else ()
    )
    status = (
        "parser_error"
        if parser_error is not None
        else "verified"
        if verified
        else "partially_decoded"
        if inspection is not None
        else "unresolved"
    )
    return {
        "status": status,
        "verified": verified,
        "top_level_callable_arity": arity,
        "applied_parameter_count": parameter_count,
        "remaining_runtime_argument_count": runtime_count,
        "argument_order": list(argument_order),
        "argument_value_representation": ["PlutusData"] * len(argument_order),
        "parameter_schemas": list(validator.parameters),
        "plutus_version": plutus_version,
        "source_handler_title": validator.title,
        "source_purpose": validator.purpose,
        "abi_derivation_method": (
            inspection.get("abi_derivation_method") if inspection else None
        ),
        "abi_verifier_revision": (
            inspection.get("abi_verifier_revision") if inspection else None
        ),
        "parser_error": parser_error,
    }


def _abi_comparison_identity(abi: dict[str, Any]) -> dict[str, Any]:
    return {
        key: abi[key]
        for key in (
            "top_level_callable_arity",
            "applied_parameter_count",
            "remaining_runtime_argument_count",
            "argument_order",
            "argument_value_representation",
            "parameter_schemas",
            "plutus_version",
        )
    }



def _compatibility(
    status: str,
    validator: Validator,
    package_identity: str,
    package_path: str,
    *,
    old_signature: dict[str, Any] | None = None,
    new_signature: dict[str, Any] | None = None,
    old_abi: dict[str, Any] | None = None,
    new_abi: dict[str, Any] | None = None,
) -> dict[str, Any]:
    identity = _identity(validator, package_identity, package_path)
    payload = {
        "status": status,
        "validator_identity": identity,
        "old_signature": old_signature,
        "new_signature": new_signature,
        "old_abi": old_abi,
        "new_abi": new_abi,
    }
    return {
        "pair_id": f"compat-{_safe_stem(validator.name)}-{stable_hash(payload)[:16]}",
        **payload,
    }


def pair_validators(
    old_blueprint: Path,
    new_blueprint: Path,
    bundle_root: Path,
    *,
    package_identity: str,
    package_path: str,
    plutus_version: str,
    covered_features_by_title: dict[str, set[str]] | None = None,
    old_abi_inspection: dict[str, Any] | None = None,
    new_abi_inspection: dict[str, Any] | None = None,
    old_abi_parser_error: str | None = None,
    new_abi_parser_error: str | None = None,
    repository: str | None = None,
    package: str | None = None,
    old_compiler_artifact_id: str = "unbound",
    new_compiler_artifact_id: str = "unbound",
) -> PairingResult:
    old_validators = discover_validators(old_blueprint)
    new_validators = discover_validators(new_blueprint)
    old_by_key = {validator.base_key: validator for validator in old_validators}
    new_by_key = {validator.base_key: validator for validator in new_validators}
    feature_map = covered_features_by_title or {}
    repository_name = repository or package_identity
    package_name = package or Path(package_path).name
    blueprint_hashes = {
        "old": hashlib.sha256(old_blueprint.read_bytes()).hexdigest(),
        "new": hashlib.sha256(new_blueprint.read_bytes()).hexdigest(),
    }
    old_inspections = {
        row["title"]: row
        for row in (old_abi_inspection or {}).get("validators", [])
        if isinstance(row, dict) and isinstance(row.get("title"), str)
    }
    new_inspections = {
        row["title"]: row
        for row in (new_abi_inspection or {}).get("validators", [])
        if isinstance(row, dict) and isinstance(row.get("title"), str)
    }

    def validator_record(label: str, validator: Validator) -> ValidatorRecord:
        reference = {
            "blueprint_sha256": blueprint_hashes[label],
            "handler_title": validator.title,
            "script_sha256": validator.script_sha256,
        }
        identity = {
            "repository": repository_name,
            "package": package_name,
            "module": validator.module,
            "validator": validator.name,
            "handler_title": validator.title,
            "purpose": validator.purpose,
            "parameter_schemas": list(validator.parameters),
            "datum_schema": validator.signature["datum"],
            "redeemer_schema": validator.signature["redeemer"],
            "blueprint_reference": reference,
        }
        return ValidatorRecord(
            validator_record_id=stable_hash(identity),
            repository=repository_name,
            package=package_name,
            module=validator.module,
            validator=validator.name,
            handler_title=validator.title,
            purpose=validator.purpose,
            parameter_schemas=validator.parameters,
            datum_schema=validator.signature["datum"],
            redeemer_schema=validator.signature["redeemer"],
            blueprint_reference=reference,
        )

    old_records = {
        validator.title: validator_record("old", validator)
        for validator in old_validators
    }
    new_records = {
        validator.title: validator_record("new", validator)
        for validator in new_validators
    }
    compatibility: list[dict[str, Any]] = []
    handler_pairs: list[HandlerPairRecord] = []
    program_accumulators: dict[str, dict[str, Any]] = {}

    for key in sorted(set(old_by_key) | set(new_by_key)):
        old = old_by_key.get(key)
        new = new_by_key.get(key)
        if old is None:
            assert new is not None
            compatibility.append(
                _compatibility(
                    "validator_missing_old", new, package_identity, package_path
                )
            )
            continue
        if new is None:
            compatibility.append(
                _compatibility(
                    "validator_missing_new", old, package_identity, package_path
                )
            )
            continue
        if canonical_json(old.signature) != canonical_json(new.signature):
            compatibility.append(
                _compatibility(
                    "validator_signature_changed",
                    new,
                    package_identity,
                    package_path,
                    old_signature=old.signature,
                    new_signature=new.signature,
                )
            )
            continue
        old_abi = _compiled_abi(
            old,
            old_inspections.get(old.title),
            plutus_version,
            parser_error=old_abi_parser_error,
        )
        new_abi = _compiled_abi(
            new,
            new_inspections.get(new.title),
            plutus_version,
            parser_error=new_abi_parser_error,
        )
        if old_abi["status"] == "parser_error" or new_abi["status"] == "parser_error":
            compatibility.append(
                _compatibility(
                    "raw_abi_parser_error",
                    new,
                    package_identity,
                    package_path,
                    old_abi=old_abi,
                    new_abi=new_abi,
                )
            )
            continue
        if old_abi["status"] != "verified":
            compatibility.append(
                _compatibility(
                    "old_raw_abi_unresolved",
                    new,
                    package_identity,
                    package_path,
                    old_abi=old_abi,
                    new_abi=new_abi,
                )
            )
            continue
        if new_abi["status"] != "verified":
            compatibility.append(
                _compatibility(
                    "new_raw_abi_unresolved",
                    new,
                    package_identity,
                    package_path,
                    old_abi=old_abi,
                    new_abi=new_abi,
                )
            )
            continue
        abi_equal = _abi_comparison_identity(old_abi) == _abi_comparison_identity(
            new_abi
        )
        if not abi_equal:
            compatibility.append(
                _compatibility(
                    "raw_abi_mismatch",
                    new,
                    package_identity,
                    package_path,
                    old_abi=old_abi,
                    new_abi=new_abi,
                )
            )
            continue
        abi_record = {"status": "verified", **_abi_comparison_identity(old_abi)}
        abi_identity = verified_abi_id(abi_record)
        old_serialized = bytes.fromhex(old.compiled_code)
        new_serialized = bytes.fromhex(new.compiled_code)
        old_artifact_id = program_artifact_id(
            old_serialized, plutus_version, "single_cbor_hex"
        )
        new_artifact_id = program_artifact_id(
            new_serialized, plutus_version, "single_cbor_hex"
        )
        pair_identity = program_pair_id(
            old_artifact_id, new_artifact_id, abi_identity
        )
        old_record = old_records[old.title]
        new_record = new_records[new.title]
        handler_identity = {
            "repository": repository_name,
            "package": package_name,
            "module": new.module,
            "validator": new.name,
            "handler_title": new.title,
            "purpose": new.purpose,
            "parameter_schemas": list(new.parameters),
            "datum_schema": new.signature["datum"],
            "redeemer_schema": new.signature["redeemer"],
            "old_blueprint_reference": old_record.blueprint_reference,
            "new_blueprint_reference": new_record.blueprint_reference,
        }
        handler_pair_id = stable_hash(handler_identity)
        features = tuple(sorted(feature_map.get(new.title, set())))
        handler_pairs.append(
            HandlerPairRecord(
                handler_pair_id=handler_pair_id,
                repository=repository_name,
                package=package_name,
                module=new.module,
                validator=new.name,
                handler_title=new.title,
                purpose=new.purpose,
                parameter_schemas=new.parameters,
                datum_schema=new.signature["datum"],
                redeemer_schema=new.signature["redeemer"],
                old_blueprint_reference=old_record.blueprint_reference,
                new_blueprint_reference=new_record.blueprint_reference,
                old_validator_record_id=old_record.validator_record_id,
                new_validator_record_id=new_record.validator_record_id,
                program_pair_id=pair_identity,
                feature_ids=features,
            )
        )
        accumulator = program_accumulators.setdefault(
            pair_identity,
            {
                "old": old,
                "new": new,
                "old_artifact_id": old_artifact_id,
                "new_artifact_id": new_artifact_id,
                "abi_id": abi_identity,
                "abi": abi_record,
                "handler_pair_ids": set(),
                "handler_references": [],
                "features": set(),
            },
        )
        accumulator["handler_pair_ids"].add(handler_pair_id)
        accumulator["handler_references"].append(
            {
                "handler_pair_id": handler_pair_id,
                "handler_title": new.title,
                "purpose": new.purpose,
                "repository": repository_name,
                "package": package_name,
            }
        )
        accumulator["features"].update(features)

    program_pairs: list[ProgramPairRecord] = []
    for pair_identity, accumulator in sorted(program_accumulators.items()):
        references = tuple(
            sorted(
                accumulator["handler_references"],
                key=lambda row: row["handler_pair_id"],
            )
        )
        scripts: dict[str, ScriptArtifact] = {}
        for label, compiler_artifact in (
            ("old", old_compiler_artifact_id),
            ("new", new_compiler_artifact_id),
        ):
            validator = accumulator[label]
            artifact_id = accumulator[f"{label}_artifact_id"]
            script_path = bundle_root / label / "scripts" / f"{artifact_id}.flat"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text(validator.compiled_code + "\n", encoding="ascii")
            scripts[label] = ScriptArtifact(
                path=script_path,
                relative_path=script_path.relative_to(bundle_root).as_posix(),
                sha256=validator.script_sha256,
                size=validator.script_size,
                plutus_version=plutus_version,
                serialization_format="single_cbor_hex",
                compiler_artifact_id=compiler_artifact,
                source_validator_references=tuple(
                    row["handler_pair_id"] for row in references
                ),
                program_artifact_id=artifact_id,
            )
        program_pairs.append(
            ProgramPairRecord(
                program_pair_id=pair_identity,
                old_script=scripts["old"],
                new_script=scripts["new"],
                verified_abi_id=accumulator["abi_id"],
                verified_abi=accumulator["abi"],
                plutus_version=plutus_version,
                handler_pair_ids=tuple(sorted(accumulator["handler_pair_ids"])),
                handler_references=references,
                covered_feature_ids=tuple(sorted(accumulator["features"])),
            )
        )

    return PairingResult(
        old_count=len(old_validators),
        new_count=len(new_validators),
        validator_records_old=tuple(
            sorted(old_records.values(), key=lambda row: row.validator_record_id)
        ),
        validator_records_new=tuple(
            sorted(new_records.values(), key=lambda row: row.validator_record_id)
        ),
        handler_pairs=tuple(
            sorted(handler_pairs, key=lambda row: row.handler_pair_id)
        ),
        program_pairs=tuple(program_pairs),
        compatibility_results=tuple(
            sorted(compatibility, key=lambda row: row["pair_id"])
        ),
    )
