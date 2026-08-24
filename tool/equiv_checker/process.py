from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence

_MINIMAL_ENVIRONMENT_KEYS = (
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
)


@dataclass(frozen=True)
class ProcessResult:
    command: list[str]
    cwd: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool
    process_group_termination_succeeded: bool | None = None
    def to_dict(self, *, include_output: bool = False) -> dict[str, object]:
        result = asdict(self)
        if not include_output:
            result.pop("stdout")
            result.pop("stderr")
        return result


def run_process(
    command: Sequence[str | Path],
    cwd: Path,
    timeout: float,
    *,
    environment: Mapping[str, str] | None = None,
    inherit_environment: bool = True,
) -> ProcessResult:
    argv = [str(part) for part in command]
    if inherit_environment:
        env = os.environ.copy()
    else:
        env = {
            key: os.environ[key]
            for key in _MINIMAL_ENVIRONMENT_KEYS
            if key in os.environ
        }
        env.setdefault("PATH", os.defpath)
        env.update(
            {
                "GCM_INTERACTIVE": "never",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
    env.update({"NO_COLOR": "1", "CLICOLOR": "0", "TERM": "dumb"})
    if environment:
        env.update(environment)
    popen_options: dict[str, object] = {}
    if os.name == "nt":
        popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_options["start_new_session"] = True
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **popen_options,
    )
    timed_out = False
    process_group_termination_succeeded: bool | None = None
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name == "nt":
            process.kill()
            process_group_termination_succeeded = True
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
                process_group_termination_succeeded = True
            except ProcessLookupError:
                process_group_termination_succeeded = True
            except OSError:
                process_group_termination_succeeded = False
        stdout, stderr = process.communicate()
    return ProcessResult(
        command=argv,
        cwd=str(cwd),
        exit_code=process.returncode,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=round(time.monotonic() - started, 6),
        timed_out=timed_out,
        process_group_termination_succeeded=process_group_termination_succeeded,
    )


def write_process_logs(result: ProcessResult, stdout_path: Path, stderr_path: Path) -> None:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path.write_text(result.stdout, encoding="utf-8")
    stderr_path.write_text(result.stderr, encoding="utf-8")
