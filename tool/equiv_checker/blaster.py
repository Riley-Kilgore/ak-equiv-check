from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .models import BlasterConfig, BlasterResult, InputModel, ScriptPair
from .process import ProcessResult, run_process, write_process_logs


_INCONCLUSIVE_PATTERNS = (
    "undetermined",
    "insufficient fuel",
    "maximum steps",
    "preparation fuel",
    "recursion depth reached",
)
_UNSUPPORTED_PATTERNS = (
    "unsupported",
    "not implemented",
    "unknown builtin",
    "unknown constant",
    "cannot translate",
)


def parse_blaster_output(stdout: str, stderr: str, *, timed_out: bool = False) -> str:
    if timed_out:
        return "blaster_timeout"
    text = f"{stdout}\n{stderr}".lower()
    if "falsified" in text:
        return "blaster_falsified_unreplayed"
    if "undetermined" in text:
        return "blaster_inconclusive"
    if re.search(
        r"(?:✅|\b)\s*(?:expected\s+)?valid\b", f"{stdout}\n{stderr}", re.IGNORECASE
    ):
        return "blaster_valid"
    if any(pattern in text for pattern in _INCONCLUSIVE_PATTERNS):
        return "blaster_inconclusive"
    if any(pattern in text for pattern in _UNSUPPORTED_PATTERNS):
        return "blaster_unsupported"
    return "blaster_error"


def extract_witness(stdout: str, stderr: str) -> dict[str, Any] | None:
    text = f"{stdout}\n{stderr}"
    marker = text.lower().find("counterexample:")
    if marker < 0:
        return None
    values: dict[str, Any] = {}
    for line in text[marker:].splitlines()[1:]:
        match = re.search(r"-\s+([A-Za-z_][A-Za-z0-9_]*):\s*(.+?)\s*$", line)
        if not match:
            if values and line.strip() and "info:" not in line:
                break
            continue
        name, rendered = match.groups()
        if re.fullmatch(r"-?\d+", rendered):
            values[name] = {
                "kind": "integer",
                "value": int(rendered),
                "rendered": rendered,
            }
        elif rendered.lower() in {"true", "false"}:
            values[name] = {
                "kind": "boolean",
                "value": rendered.lower() == "true",
                "rendered": rendered,
            }
        else:
            values[name] = {"kind": "lean_display", "rendered": rendered}
    return {"values": values, "raw_available": bool(values)} if values else None


def _lean_string(path: Path) -> str:
    return json.dumps(str(path.resolve()))


def _lean_namespace(pair_id: str) -> str:
    return "EquivCheck_" + re.sub(r"[^A-Za-z0-9_]", "_", pair_id)


def _version_names(plutus_version: str) -> tuple[str, str]:
    normalized = plutus_version.lower().removeprefix("plutus").removeprefix("v")
    if normalized not in {"1", "2", "3"}:
        raise ValueError(f"unsupported Plutus version: {plutus_version}")
    return f"CardanoLedgerApi.V{normalized}", f"PlutusV{normalized}"


def _conversion_name(purpose: str) -> str:
    return {
        "spending": "spendingInputs",
        "minting": "mintingInputs",
        "rewarding": "rewardingInputs",
        "certifying": "certifyingInputs",
        "voting": "votingInputs",
        "proposing": "proposingInputs",
        "fallback": "spendingInputs",
    }[purpose]


def _source_parts(
    pair: ScriptPair,
    input_model: InputModel,
    fuel: int,
) -> tuple[str, str, str, str, str]:
    module, language = _version_names(pair.plutus_version)
    namespace = _lean_namespace(pair.pair_id)
    common = [
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
        "open PlutusCore.UPLC.Utils",
        "",
        "set_option warn.sorry false",
        f"#import_uplc oldProgram {language} single_cbor_hex {_lean_string(pair.old_script.path)}",
        f"#import_uplc newProgram {language} single_cbor_hex {_lean_string(pair.new_script.path)}",
        "",
    ]
    import_source = "\n".join([*common, f"end {namespace}", ""])

    if input_model.kind == "pure_integer":
        conversion = [
            "inductive IntegerObservation where",
            "  | returned : Integer → IntegerObservation",
            "  | evaluationError : IntegerObservation",
            "  | nonIntegerResult : IntegerObservation",
            "deriving DecidableEq",
            "",
            "def observeInteger : PlutusCore.UPLC.CekMachine.State → IntegerObservation",
            "  | .Halt (.VCon (.Integer value)) => .returned value",
            "  | .Error => .evaluationError",
            "  | _ => .nonIntegerResult",
            "",
            "def modelInputs (input : Integer) : List Term :=",
            "  [Term.Const $ Const.Integer input]",
        ]
        binders = "(input : Integer)"
        arguments = "input"
        observation = (
            "observeInteger (oldPrepared.prop input) = "
            "observeInteger (newPrepared.prop input)"
        )
    elif input_model.kind == "validator":
        parameters = [
            row for row in input_model.variables if row["name"].startswith("parameter")
        ]
        input_row = input_model.variables[-1]
        binder_parts = [f"({row['name']} : Data)" for row in parameters]
        binder_parts.append(f"({input_row['name']} : {input_row['type']})")
        binders = " ".join(binder_parts)
        arguments = " ".join(row["name"] for row in input_model.variables)
        base = f"{_conversion_name(pair.purpose)} {input_row['name']}"
        expression = base
        for parameter in reversed(parameters):
            expression = f"toTerm {parameter['name']} :: {expression}"
        conversion = [f"def modelInputs {binders} : List Term :=", f"  {expression}"]
        observation = (
            f"isSuccessful (oldPrepared.prop {arguments}) ↔ "
            f"isSuccessful (newPrepared.prop {arguments})"
        )
    else:
        raise ValueError(f"unsupported input model kind: {input_model.kind}")

    preparation = [
        *common,
        *conversion,
        "",
        "def runWithinFuel (state : State) : Nat → Option State",
        "  | 0 =>",
        "      match state with",
        "      | .Halt _ => some state",
        "      | .Error => some state",
        "      | _ => none",
        "  | steps + 1 =>",
        "      match state with",
        "      | .Halt _ => some state",
        "      | .Error => some state",
        "      | _ => runWithinFuel (step default state) steps",
        "",
        "def executeWithinFuel (program : PlutusScript) (parameters : List Term) (steps : Nat) : Option State :=",
        "  match program.script with",
        "  | .Program _ body => runWithinFuel (initialState (applyParams body parameters)) steps",
        f"#prep_uplc oldPrepared oldProgram modelInputs {fuel}",
        f"#prep_uplc newPrepared newProgram modelInputs {fuel}",
        "",
    ]
    prepare_source = "\n".join([*preparation, f"end {namespace}", ""])
    finality = (
        f"(executeWithinFuel oldProgram (modelInputs {arguments}) {fuel}).isSome ∧ "
        f"(executeWithinFuel newProgram (modelInputs {arguments}) {fuel}).isSome"
    )
    fuel_theorem = f"∀ {binders}, {input_model.domain_expression} → ({finality})"
    fuel_source = "\n".join(
        [
            *preparation,
            "-- Preparation must terminate for every modeled input.",
            f"#blaster (dump-smt-lib: 1) (gen-cex: 0) [{fuel_theorem}]",
            "",
            f"end {namespace}",
            "",
        ]
    )
    theorem = f"∀ {binders}, {input_model.domain_expression} → ({observation})"
    optimization_source = "\n".join(
        [
            *preparation,
            "-- Optimize the equivalence goal under its independent outer timeout.",
            f"#blaster (only-optimize: 1) [{theorem}]",
            "",
            f"end {namespace}",
            "",
        ]
    )
    compare_source = "\n".join(
        [
            *preparation,
            "-- Compiler-regression equivalence under the recorded input model.",
            f"#blaster (dump-smt-lib: 1) (gen-cex: 1) [{theorem}]",
            "",
            f"end {namespace}",
            "",
        ]
    )
    return (
        import_source,
        prepare_source,
        fuel_source,
        optimization_source,
        compare_source,
    )


def _write_stage_source(path: Path, source: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _solver_input(output: str) -> str | None:
    marker = output.find("Smt Query:")
    if marker >= 0:
        start = output.find("\n", marker)
        return output[start + 1 :] if start >= 0 else None
    start = output.find("(set-logic")
    if start < 0:
        return None
    end_markers = [output.rfind("(check-sat)"), output.rfind("(get-value")]
    end = max(end_markers)
    if end < start:
        return output[start:]
    line_end = output.find("\n", end)
    return output[start:] if line_end < 0 else output[start:line_end] + "\n"


class RealBlasterBackend:
    def __init__(self, config: BlasterConfig):
        self.config = config
        self._environment: dict[str, Any] | None = None
        self._environment_error: str | None = None
        self._setup_result: ProcessResult | None = None

    def _ensure_environment(self, output_root: Path) -> dict[str, Any]:
        if self._environment is not None:
            return self._environment
        if self._environment_error is not None:
            raise RuntimeError(self._environment_error)
        root = self.config.backend_root
        try:
            if not root.is_dir():
                raise RuntimeError(
                    f"CardanoLedgerApiBlaster checkout is missing: {root}"
                )
            manifest = json.loads(
                (root / "lake-manifest.json").read_text(encoding="utf-8")
            )
            locked = {row["name"]: row["rev"] for row in manifest.get("packages", [])}
            expected = {
                "Blaster": self.config.revisions["Lean-blaster"],
                "PlutusCore": self.config.revisions["PlutusCoreBlaster"],
                "CardanoLedgerApi": self.config.revisions["CardanoLedgerApiBlaster"],
            }
            for package_name, expected_revision in expected.items():
                actual_revision = locked.get(package_name)
                if actual_revision != expected_revision:
                    raise RuntimeError(
                        f"{package_name} lock mismatch: expected {expected_revision}, got {actual_revision}"
                    )
            lean = run_process(["lake", "env", "lean", "--version"], root, 120.0)
            if (
                lean.exit_code != 0
                or f"version {self.config.lean_version}" not in lean.stdout
            ):
                raise RuntimeError(
                    f"Lean version mismatch: expected {self.config.lean_version}, got {(lean.stdout or lean.stderr).strip()}"
                )
            z3 = run_process(["z3", "--version"], root, 30.0)
            if (
                z3.exit_code != 0
                or f"Z3 version {self.config.z3_version}" not in z3.stdout
            ):
                raise RuntimeError(
                    f"Z3 version mismatch: expected {self.config.z3_version}, got {(z3.stdout or z3.stderr).strip()}"
                )
            setup_timeout = self.config.timeouts.lean_elaboration
            setup = run_process(
                ["lake", "build", "CardanoLedgerApi"], root, setup_timeout
            )
            self._setup_result = setup
            write_process_logs(
                setup,
                output_root / "logs" / "blaster-setup.stdout.log",
                output_root / "logs" / "blaster-setup.stderr.log",
            )
            if setup.timed_out:
                raise RuntimeError("CardanoLedgerApiBlaster setup timed out")
            if setup.exit_code != 0:
                raise RuntimeError("CardanoLedgerApiBlaster setup failed")
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

    def _run_stage(
        self,
        pair: ScriptPair,
        stage: str,
        source: str,
        timeout: float,
        output_root: Path,
    ) -> tuple[ProcessResult, dict[str, Any], Path, str]:
        source_path = output_root / "generated-lean" / f"{pair.pair_id}-{stage}.lean"
        source_hash = _write_stage_source(source_path, source)
        result = run_process(
            ["lake", "env", "lean", source_path],
            self.config.backend_root,
            timeout,
            environment={
                "BLASTER_SOLVER": self.config.solver,
                "BLASTER_TIMEOUT": str(max(1, int(self.config.timeouts.z3))),
            },
        )
        stdout_path = output_root / "logs" / f"{pair.pair_id}-{stage}.stdout.log"
        stderr_path = output_root / "logs" / f"{pair.pair_id}-{stage}.stderr.log"
        write_process_logs(result, stdout_path, stderr_path)
        record = result.to_dict()
        record.update(
            {
                "phase": stage,
                "stdout_path": stdout_path.relative_to(output_root).as_posix(),
                "stderr_path": stderr_path.relative_to(output_root).as_posix(),
                "generated_lean_path": source_path.relative_to(output_root).as_posix(),
                "generated_lean_sha256": source_hash,
                "timeout_seconds": timeout,
            }
        )
        return result, record, source_path, source_hash

    def compare(
        self, pair: ScriptPair, input_model: InputModel, output_root: Path
    ) -> BlasterResult:
        try:
            self._ensure_environment(output_root)
        except RuntimeError as error:
            return BlasterResult(
                status="blaster_error",
                command=None,
                exit_code=None,
                duration_seconds=0.0,
                error=str(error),
            )
        (
            import_source,
            prepare_source,
            fuel_source,
            optimization_source,
            compare_source,
        ) = _source_parts(pair, input_model, self.config.fuel)
        phase_records: list[dict[str, Any]] = []
        total_duration = 0.0
        final_result: ProcessResult | None = None
        final_source: Path | None = None
        final_hash: str | None = None
        for stage, source, timeout in (
            ("uplc-import", import_source, self.config.timeouts.uplc_import),
            ("uplc-preparation", prepare_source, self.config.timeouts.uplc_preparation),
            (
                "fuel-check",
                fuel_source,
                self.config.timeouts.lean_elaboration
                + self.config.timeouts.blaster_optimization
                + self.config.timeouts.z3,
            ),
            (
                "blaster-optimization",
                optimization_source,
                self.config.timeouts.blaster_optimization,
            ),
            (
                "equivalence",
                compare_source,
                self.config.timeouts.lean_elaboration + self.config.timeouts.z3,
            ),
        ):
            result, record, source_path, source_hash = self._run_stage(
                pair, stage, source, timeout, output_root
            )
            phase_records.append(record)
            total_duration += result.duration_seconds
            final_result, final_source, final_hash = result, source_path, source_hash
            if stage == "fuel-check":
                fuel_status = parse_blaster_output(
                    result.stdout, result.stderr, timed_out=result.timed_out
                )
                if fuel_status != "blaster_valid" or result.exit_code != 0:
                    if fuel_status == "blaster_falsified_unreplayed":
                        fuel_status = "blaster_inconclusive"
                    return BlasterResult(
                        status=fuel_status,
                        command=result.command,
                        exit_code=result.exit_code,
                        duration_seconds=round(total_duration, 6),
                        stdout_path=record["stdout_path"],
                        stderr_path=record["stderr_path"],
                        generated_lean_path=record["generated_lean_path"],
                        generated_lean_sha256=source_hash,
                        phase_results=phase_records,
                        error="UPLC preparation fuel is insufficient under the modeled domain",
                    )
            if stage != "equivalence" and (result.timed_out or result.exit_code != 0):
                status = parse_blaster_output(
                    result.stdout, result.stderr, timed_out=result.timed_out
                )
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
                    error=f"{stage} failed",
                )
        assert (
            final_result is not None
            and final_source is not None
            and final_hash is not None
        )
        status = parse_blaster_output(
            final_result.stdout, final_result.stderr, timed_out=final_result.timed_out
        )
        if status == "blaster_valid" and final_result.exit_code != 0:
            status = "blaster_error"
        final_record = phase_records[-1]
        combined = f"{final_result.stdout}\n{final_result.stderr}"
        solver_text = _solver_input(combined)
        solver_path: Path | None = None
        solver_hash: str | None = None
        if solver_text:
            solver_path = output_root / "logs" / f"{pair.pair_id}.smt2"
            solver_path.write_text(solver_text, encoding="utf-8")
            solver_hash = hashlib.sha256(solver_text.encode("utf-8")).hexdigest()
        witness = extract_witness(final_result.stdout, final_result.stderr)
        return BlasterResult(
            status=status,
            command=final_result.command,
            exit_code=final_result.exit_code,
            duration_seconds=round(total_duration, 6),
            stdout_path=final_record["stdout_path"],
            stderr_path=final_record["stderr_path"],
            generated_lean_path=final_source.relative_to(output_root).as_posix(),
            generated_lean_sha256=final_hash,
            solver_input_path=(
                solver_path.relative_to(output_root).as_posix() if solver_path else None
            ),
            solver_input_sha256=solver_hash,
            witness=witness,
            phase_results=phase_records,
            error=None
            if status
            in {"blaster_valid", "blaster_falsified_unreplayed", "blaster_inconclusive"}
            else "Blaster execution failed",
        )

    def replay(
        self,
        pair: ScriptPair,
        input_model: InputModel,
        witness: dict[str, Any],
        output_root: Path,
    ) -> dict[str, Any]:
        if input_model.kind != "pure_integer":
            return {
                "confirmed": False,
                "reason": "witness conversion is unsupported for this validator input model",
            }
        input_value = witness.get("values", {}).get("input")
        if not isinstance(input_value, dict) or input_value.get("kind") != "integer":
            return {
                "confirmed": False,
                "reason": "Blaster did not return a concrete integer input",
            }
        value = int(input_value["value"])
        _, prepare_source, _, _, _ = _source_parts(pair, input_model, self.config.fuel)
        namespace = _lean_namespace(pair.pair_id)
        suffix = f"end {namespace}\n"
        if not prepare_source.endswith(suffix):
            raise RuntimeError("generated preparation source has an unexpected shape")
        replay_source = prepare_source[: -len(suffix)] + "\n".join(
            [
                f'#eval IO.println ("EQUIV_REPLAY_OLD:" ++ reprStr (oldPrepared.exec ({value} : Integer)))',
                f'#eval IO.println ("EQUIV_REPLAY_NEW:" ++ reprStr (newPrepared.exec ({value} : Integer)))',
                "",
                suffix,
            ]
        )
        result, record, source_path, source_hash = self._run_stage(
            pair,
            "counterexample-replay",
            replay_source,
            self.config.timeouts.counterexample_replay,
            output_root,
        )
        old_match = re.search(r"EQUIV_REPLAY_OLD:(.+)", result.stdout)
        new_match = re.search(r"EQUIV_REPLAY_NEW:(.+)", result.stdout)
        old_observation = old_match.group(1).strip() if old_match else None
        new_observation = new_match.group(1).strip() if new_match else None
        confirmed = (
            not result.timed_out
            and result.exit_code == 0
            and old_observation is not None
            and new_observation is not None
            and old_observation != new_observation
        )
        replay = {
            "confirmed": confirmed,
            "input": {"integer": value},
            "old_observation": old_observation,
            "new_observation": new_observation,
            "command": result.command,
            "exit_code": result.exit_code,
            "duration_seconds": result.duration_seconds,
            "timed_out": result.timed_out,
            "stdout_path": record["stdout_path"],
            "stderr_path": record["stderr_path"],
            "generated_lean_path": source_path.relative_to(output_root).as_posix(),
            "generated_lean_sha256": source_hash,
        }
        counterexample_path = output_root / "counterexamples" / f"{pair.pair_id}.json"
        counterexample_path.parent.mkdir(parents=True, exist_ok=True)
        counterexample_path.write_text(
            json.dumps(replay, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        replay["artifact_path"] = counterexample_path.relative_to(
            output_root
        ).as_posix()
        return replay
