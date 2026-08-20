from __future__ import annotations

import hashlib
import json
import re
import os
import shutil
from pathlib import Path
from typing import Any

from .models import BlasterConfig, BlasterResult, InputModel, ScriptPair
from .process import ProcessResult, run_process, write_process_logs


RESULT_PREFIX = "EQUIV_RESULT_V1:"
_PROTOCOL_STATUSES = frozenset({"valid", "falsified", "inconclusive"})


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def parse_result_protocol(
    stdout: str,
    stderr: str,
    *,
    exit_code: int | None,
    expected_pair_id: str,
    expected_theorem_hash: str,
) -> dict[str, Any]:
    markers = [
        line[len(RESULT_PREFIX) :]
        for line in f"{stdout}\n{stderr}".splitlines()
        if line.startswith(RESULT_PREFIX)
    ]
    if len(markers) != 1:
        raise ValueError(f"expected exactly one {RESULT_PREFIX} marker, found {len(markers)}")
    try:
        value = json.loads(markers[0])
    except json.JSONDecodeError as error:
        raise ValueError("invalid JSON in Blaster result marker") from error
    if not isinstance(value, dict):
        raise ValueError("Blaster result marker must contain an object")
    if value.get("status") not in _PROTOCOL_STATUSES:
        raise ValueError(f"unknown Blaster protocol status: {value.get('status')}")
    if value.get("pair_id") != expected_pair_id:
        raise ValueError("Blaster result marker has the wrong pair_id")
    if value.get("theorem_hash") != expected_theorem_hash:
        raise ValueError("Blaster result marker has the wrong theorem_hash")
    if exit_code != 0:
        raise ValueError("Blaster result marker conflicts with the process exit code")
    return value


def parse_blaster_output(
    stdout: str,
    stderr: str,
    *,
    timed_out: bool = False,
    exit_code: int | None = 0,
    expected_pair_id: str = "pair",
    expected_theorem_hash: str = "theorem",
) -> str:
    """Compatibility entry point backed only by the exact result protocol."""
    if timed_out:
        return "blaster_timeout"
    try:
        marker = parse_result_protocol(
            stdout,
            stderr,
            exit_code=exit_code,
            expected_pair_id=expected_pair_id,
            expected_theorem_hash=expected_theorem_hash,
        )
    except ValueError:
        return "blaster_error"
    return {
        "valid": "blaster_valid",
        "falsified": "blaster_falsified_unreplayed",
        "inconclusive": "blaster_inconclusive",
    }[marker["status"]]


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
        "protocol": "EQUIV_WITNESS_V1",
        "values": values,
        "raw_available": all(value["kind"] != "lean_display" for value in values.values()),
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


def _lean_marker(
    *, status: str, pair_id: str, theorem_hash: str, profile: str, kind: str = "equivalence"
) -> str:
    payload = _stable_json(
        {
            "kind": kind,
            "pair_id": pair_id,
            "profile": profile,
            "status": status,
            "theorem_hash": theorem_hash,
        }
    )
    return f"#eval IO.println {json.dumps(RESULT_PREFIX + payload)}"


def _common_source(pair: ScriptPair, old_path: str, new_path: str) -> list[str]:
    module, language = _version_names(pair.plutus_version)
    namespace = _lean_namespace(pair.pair_id)
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
    pair: ScriptPair,
    input_model: InputModel,
    runtime_step_bound: int,
    random_seed: int,
    solver_timeout: int,
    old_path: str,
    new_path: str,
) -> dict[str, Any]:
    namespace = _lean_namespace(pair.pair_id)
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
        "",
        f"#prep_uplc oldPrepared oldProgram modelInputs {runtime_step_bound}",
        f"#prep_uplc newPrepared newProgram modelInputs {runtime_step_bound}",
        "",
        *_raw_non_vacuity_source(input_model, binders),
        *_witness_encoder_source(input_model),
    ]
    theorem = f"∀ {binders}, {input_model.domain_expression} → ({observation})"
    theorem_hash = _sha256_text(
        _stable_json(
            {
                "theorem": theorem,
                "profile": input_model.to_dict(),
                "runtime_step_bound": runtime_step_bound,
            }
        )
    )
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
        return "\n".join(
            [
                *preparation,
                f"#blaster {options} (solve-result: {expected_code}) [{theorem}]",
                _lean_marker(
                    status=status,
                    pair_id=pair.pair_id,
                    theorem_hash=theorem_hash,
                    profile=input_model.profile,
                ),
                "",
                f"end {namespace}",
                "",
            ]
        )

    non_vacuity_source: str | None = None
    non_vacuity_hash: str | None = None
    if input_model.domain_expression != "True":
        emptiness = f"∀ {binders}, ¬({input_model.domain_expression})"
        non_vacuity_hash = _sha256_text(
            _stable_json({"non_vacuity": emptiness, "profile": input_model.profile})
        )
        non_vacuity_source = "\n".join(
            [
                *preparation,
                f"#blaster {options} (solve-result: 1) [{emptiness}]",
                _lean_marker(
                    status="falsified",
                    pair_id=pair.pair_id,
                    theorem_hash=non_vacuity_hash,
                    profile=input_model.profile,
                    kind="domain_non_vacuity",
                ),
                "",
                f"end {namespace}",
                "",
            ]
        )
    return {
        "import": import_source,
        "preparation": preparation_source,
        "optimization": optimization_source,
        "valid": expected_source("valid", 0),
        "falsified": expected_source("falsified", 1),
        "inconclusive": expected_source("inconclusive", 2),
        "theorem": theorem,
        "theorem_hash": theorem_hash,
        "non_vacuity": non_vacuity_source,
        "non_vacuity_hash": non_vacuity_hash,
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

    def _stable_inputs(self, pair: ScriptPair, output_root: Path) -> tuple[str, str]:
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
        pair: ScriptPair,
        stage: str,
        source: str,
        timeout: float,
        output_root: Path,
        options: dict[str, Any],
    ) -> tuple[ProcessResult, dict[str, Any], Path, str]:
        source_path = output_root / "generated-lean" / f"{pair.pair_id}-{stage}.lean"
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(source, encoding="utf-8")
        source_hash = _sha256_text(source)
        result = run_process(
            ["lean", source_path.resolve()],
            output_root,
            timeout,
            environment={
                **(self._lean_environment or {}),
                "BLASTER_SOLVER": self.config.solver,
                "BLASTER_TIMEOUT": str(max(1, int(self.config.timeouts.z3))),
            },
        )
        stdout_path = output_root / "logs" / f"{pair.pair_id}-{stage}.stdout.log"
        stderr_path = output_root / "logs" / f"{pair.pair_id}-{stage}.stderr.log"
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
        self, pair: ScriptPair, input_model: InputModel, output_root: Path
    ) -> BlasterResult:
        if not input_model.supported:
            status = (
                "fallback_purpose_unsupported"
                if pair.purpose == "fallback" and input_model.profile.startswith("ledger-valid")
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
        total_duration = 0.0
        profile_tag = re.sub(r"[^A-Za-z0-9_.-]+", "-", input_model.profile)
        basic_stages = (
            ("uplc-import", parts["import"], self.config.timeouts.uplc_import),
            ("uplc-preparation", parts["preparation"], self.config.timeouts.uplc_preparation),
        )
        for stage, source, timeout in basic_stages:
            result, record, _source_path, source_hash = self._run_stage(
                pair, f"{profile_tag}-{stage}", source, timeout, output_root, parts["options"]
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
                    error=f"{stage} timed out; no logical verdict",
                )
            if result.exit_code != 0:
                status = "blaster_inconclusive" if stage == "uplc-preparation" else "blaster_error"
                return BlasterResult(
                    status=status,
                    command=result.command,
                    exit_code=result.exit_code,
                    duration_seconds=round(total_duration, 6),
                    stdout_path=record["stdout_path"],
                    stderr_path=record["stderr_path"],
                    generated_lean_path=record["generated_lean_path"],
                    generated_lean_sha256=source_hash,
                    phase_results=phase_records,
                    error=f"{stage} failed; no logical verdict",
                )

        if parts["non_vacuity"] is not None:
            result, record, _source_path, source_hash = self._run_stage(
                pair,
                f"{profile_tag}-domain-non-vacuity",
                parts["non_vacuity"],
                self.config.timeouts.lean_elaboration + self.config.timeouts.z3,
                output_root,
                parts["options"],
            )
            phase_records.append(record)
            total_duration += result.duration_seconds
            try:
                marker = parse_result_protocol(
                    result.stdout,
                    result.stderr,
                    exit_code=result.exit_code,
                    expected_pair_id=pair.pair_id,
                    expected_theorem_hash=parts["non_vacuity_hash"],
                )
            except ValueError as error:
                return BlasterResult(
                    status="domain_non_vacuous_failed",
                    command=result.command,
                    exit_code=result.exit_code,
                    duration_seconds=round(total_duration, 6),
                    stdout_path=record["stdout_path"],
                    stderr_path=record["stderr_path"],
                    generated_lean_path=record["generated_lean_path"],
                    generated_lean_sha256=source_hash,
                    phase_results=phase_records,
                    error=str(error),
                )
            if marker["status"] != "falsified":
                return BlasterResult(
                    status="domain_non_vacuous_failed",
                    command=result.command,
                    exit_code=result.exit_code,
                    duration_seconds=round(total_duration, 6),
                    phase_results=phase_records,
                    error="ledger domain emptiness was not falsified",
                )
            record["domain_witness"] = extract_witness(result.stdout, result.stderr)

        final: tuple[ProcessResult, dict[str, Any], Path, str, dict[str, Any]] | None = None
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
                    error="solver trial timed out; no logical verdict",
                )
            if result.exit_code != 0:
                continue
            try:
                marker = parse_result_protocol(
                    result.stdout,
                    result.stderr,
                    exit_code=result.exit_code,
                    expected_pair_id=pair.pair_id,
                    expected_theorem_hash=parts["theorem_hash"],
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
                    error=str(error),
                )
            if marker["status"] != expected_status:
                return BlasterResult(
                    status="blaster_error",
                    command=result.command,
                    exit_code=result.exit_code,
                    duration_seconds=round(total_duration, 6),
                    phase_results=phase_records,
                    error="protocol marker conflicts with expected solver trial",
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
                error="no expected-result Blaster trial produced a valid protocol marker",
            )

        result, record, source_path, source_hash, marker = final
        combined = f"{result.stdout}\n{result.stderr}"
        solver_text = _solver_input(combined)
        solver_path: Path | None = None
        solver_hash: str | None = None
        if solver_text:
            solver_path = output_root / "logs" / f"{pair.pair_id}.smt2"
            solver_path.write_text(solver_text, encoding="utf-8")
            solver_hash = _sha256_text(solver_text)
        protocol_status = marker["status"]
        status = {
            "valid": "bounded_equivalent",
            "falsified": "blaster_falsified_unreplayed",
            "inconclusive": "blaster_inconclusive",
        }[protocol_status]
        witness = extract_witness(result.stdout, result.stderr) if protocol_status == "falsified" else None
        return BlasterResult(
            status=status,
            command=result.command,
            exit_code=result.exit_code,
            duration_seconds=round(total_duration, 6),
            stdout_path=record["stdout_path"],
            stderr_path=record["stderr_path"],
            generated_lean_path=source_path.relative_to(output_root).as_posix(),
            generated_lean_sha256=source_hash,
            solver_input_path=solver_path.relative_to(output_root).as_posix() if solver_path else None,
            solver_input_sha256=solver_hash,
            witness=witness,
            phase_results=phase_records,
            error=(
                "equivalent only within the recorded CEK runtime step bound"
                if status == "bounded_equivalent"
                else None
                if status == "blaster_falsified_unreplayed"
                else "solver returned inconclusive"
            ),
        )

    def _evaluate_script(
        self,
        pair: ScriptPair,
        label: str,
        arguments: list[str],
        output_root: Path,
    ) -> dict[str, Any]:
        evaluator = self.config.evaluator
        if evaluator is None:
            return {"ok": False, "error_class": "evaluator_not_configured"}
        artifact = pair.old_script if label == "old" else pair.new_script
        command = [
            str(evaluator.executable),
            "uplc",
            "eval",
            "--cbor",
            str(artifact.path),
            *arguments,
        ]
        result = run_process(command, output_root, self.config.timeouts.counterexample_replay)
        stdout_path = output_root / "counterexamples" / f"{pair.pair_id}-{label}.stdout.log"
        stderr_path = output_root / "counterexamples" / f"{pair.pair_id}-{label}.stderr.log"
        write_process_logs(result, stdout_path, stderr_path)
        parsed: dict[str, Any] | None = None
        if not result.timed_out and result.exit_code == 0:
            try:
                candidate = json.loads(result.stdout)
                parsed = candidate if isinstance(candidate, dict) else None
            except json.JSONDecodeError:
                parsed = None
        return {
            "ok": not result.timed_out and result.exit_code in {0, 1} and (result.exit_code != 0 or parsed is not None),
            "command": command,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "duration_seconds": result.duration_seconds,
            "stdout_path": stdout_path.relative_to(output_root).as_posix(),
            "stderr_path": stderr_path.relative_to(output_root).as_posix(),
            "stdout_sha256": hashlib.sha256(result.stdout.encode("utf-8")).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr.encode("utf-8")).hexdigest(),
            "result_value": parsed.get("result") if parsed else None,
            "cost": {"cpu": parsed.get("cpu"), "memory": parsed.get("mem")} if parsed else None,
            "trace": [],
            "error_class": (
                "timeout"
                if result.timed_out
                else None
                if result.exit_code == 0 and parsed is not None
                else "evaluation_failure"
                if result.exit_code == 1
                else "malformed_evaluator_output"
            ),
        }

    def replay(
        self,
        pair: ScriptPair,
        input_model: InputModel,
        witness: dict[str, Any],
        output_root: Path,
    ) -> dict[str, Any]:
        evaluator = self.config.evaluator
        values = witness.get("values")
        if evaluator is None:
            return {"confirmed": False, "reason": "independent evaluator is not configured"}
        if not isinstance(values, dict):
            return {"confirmed": False, "reason": "witness has no structured values"}
        missing = [name for name in input_model.argument_order if name not in values]
        if missing:
            return {"confirmed": False, "reason": f"witness is missing arguments: {', '.join(missing)}"}
        try:
            encoded = [encode_uplc_term(values[name]) for name in input_model.argument_order]
        except (KeyError, TypeError, ValueError) as error:
            return {"confirmed": False, "reason": f"witness encoding failed: {error}"}
        arguments_path = output_root / "counterexamples" / f"{pair.pair_id}-arguments.json"
        arguments_path.parent.mkdir(parents=True, exist_ok=True)
        arguments_record = {
            "protocol": "EQUIV_REPLAY_ARGUMENTS_V1",
            "pair_id": pair.pair_id,
            "profile": input_model.profile,
            "argument_order": list(input_model.argument_order),
            "arguments": encoded,
        }
        arguments_path.write_text(json.dumps(arguments_record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        old = self._evaluate_script(pair, "old", encoded, output_root)
        new = self._evaluate_script(pair, "new", encoded, output_root)
        if input_model.kind.startswith("validator"):
            old_observation = "success" if old.get("exit_code") == 0 else "failure" if old.get("exit_code") == 1 else None
            new_observation = "success" if new.get("exit_code") == 0 else "failure" if new.get("exit_code") == 1 else None
        else:
            old_observation = (
                {"kind": "returned", "value": old.get("result_value")}
                if old.get("exit_code") == 0
                else {"kind": "evaluation_failure"}
                if old.get("exit_code") == 1
                else None
            )
            new_observation = (
                {"kind": "returned", "value": new.get("result_value")}
                if new.get("exit_code") == 0
                else {"kind": "evaluation_failure"}
                if new.get("exit_code") == 1
                else None
            )
        confirmed = (
            old.get("ok") is True
            and new.get("ok") is True
            and old_observation is not None
            and new_observation is not None
            and old_observation != new_observation
        )
        replay = {
            "schema_version": 1,
            "confirmed": confirmed,
            "reason": None if confirmed else "independent replay did not confirm distinct observations",
            "evaluator": evaluator.identity(),
            "evaluation_limits": evaluator.evaluation_limits,
            "arguments_path": arguments_path.relative_to(output_root).as_posix(),
            "arguments_sha256": hashlib.sha256(arguments_path.read_bytes()).hexdigest(),
            "old": old,
            "new": new,
            "old_observation": old_observation,
            "new_observation": new_observation,
        }
        counterexample_path = output_root / "counterexamples" / f"{pair.pair_id}.json"
        counterexample_path.write_text(json.dumps(replay, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        replay["artifact_path"] = counterexample_path.relative_to(output_root).as_posix()
        return replay
