from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import DEFAULT_WORK_ROOT, compiler_pair, load_blaster_config
from .runner import compare_sentinel


class GateFailure(RuntimeError):
    def __init__(self, report: dict[str, Any]):
        self.report = report
        super().__init__("gate failed: " + "; ".join(report.get("gaps", [])))


def _surface_audit_errors(surface_audit: dict[str, Any]) -> list[str]:
    errors = []
    if surface_audit.get("unmapped_surface_variants") != []:
        errors.append("compiler surface audit has unmapped variants")
    if surface_audit.get("unmapped_keywords_or_aliases") != []:
        errors.append("compiler surface audit has unmapped keywords or aliases")
    return errors


def gate(
    package: Path,
    work_root: Path = DEFAULT_WORK_ROOT,
) -> dict[str, Any]:
    report = compare_sentinel(
        package,
        compiler_pair(),
        work_root=work_root,
        strict=True,
        blaster_config=load_blaster_config(),
    )
    if not report["strict_pass"]:
        raise GateFailure(report)
    return report
