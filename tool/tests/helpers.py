from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

from equiv_checker.models import BlasterConfig, BlasterResult, InputModel, ScriptPair, Timeouts


IDENTITY_HEX = "46010100200101"
ZERO_HEX = "46010100248001"


def write_package(root: Path, *, with_lock: bool = True) -> Path:
    package = root / "package"
    package.mkdir(parents=True)
    (package / "aiken.toml").write_text(
        'name = "test/package"\nversion = "0.0.0"\nplutus = "v3"\n',
        encoding="utf-8",
    )
    if with_lock:
        (package / "aiken.lock").write_text("[etags]\n", encoding="utf-8")
    (package / "validators").mkdir()
    (package / "validators" / "main.ak").write_text("validator fixture {}\n", encoding="utf-8")
    return package


def validator(
    title: str = "module.validator.mint",
    compiled_code: str = IDENTITY_HEX,
    *,
    parameters: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "title": title,
        "redeemer": {"title": "redeemer", "schema": {}},
        "compiledCode": compiled_code,
        "hash": "00" * 28,
    }
    if parameters is not None:
        row["parameters"] = parameters
    return row


def write_fake_compiler(
    path: Path,
    validators: list[dict[str, Any]],
    *,
    version: str = "aiken v9.9.9+same",
    build_exit_code: int = 0,
    sleep_seconds: float = 0.0,
) -> Path:
    payload = json.dumps({"preamble": {}, "validators": validators, "definitions": {}})
    source = f'''#!/usr/bin/env python3
# binary-label: {path.name}
import json
import pathlib
import sys
import time

VERSION = {version!r}
BLUEPRINT = json.loads({payload!r})
BUILD_EXIT = {build_exit_code}
SLEEP = {sleep_seconds}

if "--version" in sys.argv:
    print(VERSION)
    raise SystemExit(0)
if len(sys.argv) > 1 and sys.argv[1] == "build":
    if SLEEP:
        time.sleep(SLEEP)
    if BUILD_EXIT:
        print("fake build failed", file=sys.stderr)
        raise SystemExit(BUILD_EXIT)
    out = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else "plutus.json"
    pathlib.Path(out).write_text(json.dumps(BLUEPRINT))
    if "--uplc" in sys.argv:
        for row in BLUEPRINT["validators"]:
            artifact = pathlib.Path("artifacts") / (row["title"] + ".uplc")
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text("(program 1.1.0 (con unit ()))\\n")
    raise SystemExit(0)
print("unsupported fake compiler command", file=sys.stderr)
raise SystemExit(2)
'''
    path.write_text(source, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class FakeBackend:
    def __init__(
        self,
        config: BlasterConfig,
        status: str,
        *,
        witness: dict[str, Any] | None = None,
        replay_confirmed: bool = False,
    ):
        self.config = config
        self.status = status
        self.witness = witness
        self.replay_confirmed = replay_confirmed
        self.calls: list[str] = []

    def compare(self, pair: ScriptPair, input_model: InputModel, output_root: Path) -> BlasterResult:
        self.calls.append(pair.pair_id)
        return BlasterResult(
            status=self.status,
            command=["fake-blaster"],
            exit_code=0 if self.status == "blaster_valid" else 1,
            duration_seconds=0.01,
            witness=self.witness,
        )

    def replay(
        self,
        pair: ScriptPair,
        input_model: InputModel,
        witness: dict[str, Any],
        output_root: Path,
    ) -> dict[str, Any]:
        return {
            "confirmed": self.replay_confirmed,
            "input": witness,
            "old_observation": "Halt 1",
            "new_observation": "Halt 0" if self.replay_confirmed else None,
        }


def fast_config(root: Path) -> BlasterConfig:
    return BlasterConfig(
        backend_root=root,
        revisions={
            "Lean-blaster": "1" * 40,
            "PlutusCoreBlaster": "2" * 40,
            "CardanoLedgerApiBlaster": "3" * 40,
        },
        lean_version="4.24.0",
        z3_version="4.15.4",
        solver="z3",
        fuel=100,
        timeouts=Timeouts(
            aiken_build=2,
            uplc_extraction=2,
            uplc_import=2,
            uplc_preparation=2,
            lean_elaboration=2,
            blaster_optimization=2,
            z3=2,
            counterexample_replay=2,
        ),
    )
