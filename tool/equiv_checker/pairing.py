from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import ScriptArtifact, ScriptPair


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
    pairs: tuple[ScriptPair, ...]
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
    try:
        blueprint = json.loads(blueprint_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid Aiken blueprint {blueprint_path}: {error}") from error
    rows = blueprint.get("validators")
    if not isinstance(rows, list):
        raise ValueError(f"Aiken blueprint has no validators array: {blueprint_path}")
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


def _compatibility(
    status: str,
    validator: Validator,
    package_identity: str,
    package_path: str,
    *,
    old_signature: dict[str, Any] | None = None,
    new_signature: dict[str, Any] | None = None,
) -> dict[str, Any]:
    identity = _identity(validator, package_identity, package_path)
    payload = {
        "status": status,
        "validator_identity": identity,
        "old_signature": old_signature,
        "new_signature": new_signature,
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
) -> PairingResult:
    old_validators = discover_validators(old_blueprint)
    new_validators = discover_validators(new_blueprint)
    old_by_key = {validator.base_key: validator for validator in old_validators}
    new_by_key = {validator.base_key: validator for validator in new_validators}
    feature_map = covered_features_by_title or {}
    pairs: list[ScriptPair] = []
    compatibility: list[dict[str, Any]] = []

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

        identity = _identity(new, package_identity, package_path)
        pair_digest = stable_hash(identity)
        pair_id = f"{_safe_stem(new.name)}-{new.purpose}-{pair_digest[:16]}"
        script_name = f"{_safe_stem(new.name)}-{pair_digest[:16]}.flat"
        script_records: dict[str, ScriptArtifact] = {}
        for label, validator in (("old", old), ("new", new)):
            script_path = bundle_root / label / "scripts" / script_name
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text(validator.compiled_code + "\n", encoding="ascii")
            script_records[label] = ScriptArtifact(
                path=script_path,
                relative_path=script_path.relative_to(bundle_root).as_posix(),
                sha256=validator.script_sha256,
                size=validator.script_size,
            )
        pairs.append(
            ScriptPair(
                pair_id=pair_id,
                validator_identity=identity,
                old_script=script_records["old"],
                new_script=script_records["new"],
                purpose=new.purpose,
                parameters=new.parameters,
                covered_feature_ids=tuple(sorted(feature_map.get(new.title, set()))),
                plutus_version=plutus_version,
            )
        )

    return PairingResult(
        old_count=len(old_validators),
        new_count=len(new_validators),
        pairs=tuple(sorted(pairs, key=lambda pair: pair.pair_id)),
        compatibility_results=tuple(
            sorted(compatibility, key=lambda row: row["pair_id"])
        ),
    )
