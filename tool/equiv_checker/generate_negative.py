from __future__ import annotations

import json
import shutil
import re
from pathlib import Path
from typing import Any

from .config import REPOSITORY_ROOT


SENTINEL = REPOSITORY_ROOT / "sentinel"
NEGATIVE_ROOT = SENTINEL / "negative" / "cases"


CASES: dict[str, dict[str, Any]] = {
    "NEG-TAG-OVERFLOW": {
        "source": """// @feature NEG-TAG-OVERFLOW
pub type OverflowTag {
  @tag(18446744073709551616)
  TooLarge
  Other
}
""",
        "old_diagnostic": "PosOverflow",
        "old_failure_kind": "compiler_panic",
        "diagnostic": "decorator tag",
    },
    "NEG-NONEXHAUSTIVE-WHEN": {
        "source": """// @feature NEG-NONEXHAUSTIVE-WHEN
pub fn non_exhaustive(value: Bool) -> Int {
  when value is {
    True -> 1
  }
}
""",
        "diagnostic": "non-exhaustive",
    },
    "NEG-TYPE-MISMATCH": {
        "source": """// @feature NEG-TYPE-MISMATCH
pub fn wrong_type() -> Int {
  False
}
""",
        "diagnostic": "struggled to unify",
    },
    "NEG-OPAQUE-CONSTRUCTOR": {
        "source": """use hidden

// @feature NEG-OPAQUE-CONSTRUCTOR
pub fn reveal() -> hidden.Secret {
  hidden.Secret(42)
}
""",
        "extra": {
            "lib/hidden.ak": """pub opaque type Secret {
  Secret(Int)
}
""",
        },
        "diagnostic": "opaque",
    },
    "NEG-INVALID-VALIDATOR-ARITY": {
        "source_dir": "validators",
        "source": """// @feature NEG-INVALID-VALIDATOR-ARITY
validator invalid_arity {
  spend(_datum, _redeemer) {
    True
  }
}
""",
        "diagnostic": "not enough arguments",
    },
    "NEG-STRING-PATTERN": {
        "source": """// @feature NEG-STRING-PATTERN
pub fn string_pattern(value: String) -> Bool {
  when value is {
    @\"forbidden\" -> True
    _ -> False
  }
}
""",
        "diagnostic": "pattern",
    },
    "NEG-CURVE-PATTERN": {
        "source": """// @feature NEG-CURVE-PATTERN
pub fn curve_pattern(value: Bls12_381<G1>) -> Bool {
  when value is {
    #<Bls12_381, G1>\"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb\" -> True
    _ -> False
  }
}
""",
        "diagnostic": "pattern",
    },
    "NEG-LIST-SPREAD-NO-SUBJECT": {
        "source": """// @feature NEG-LIST-SPREAD-NO-SUBJECT
pub fn missing_spread_subject() -> List<Int> {
  [1, 2, ..]
}
""",
        "diagnostic": "spread",
    },
    "NEG-TARGET-PLUTUS-V1": {
        "source": """// @feature NEG-TARGET-PLUTUS-V1
pub fn rejected_v1_target() -> Bool { True }
""",
        "plutus": "v1",
        "diagnostic": "only supports Plutus V3",
    },
    "NEG-TARGET-PLUTUS-V2": {
        "source": """// @feature NEG-TARGET-PLUTUS-V2
pub fn rejected_v2_target() -> Bool { True }
""",
        "plutus": "v2",
        "diagnostic": "only supports Plutus V3",
    },
    "NEG-INT-BINARY": {
        "source": """// @feature NEG-INT-BINARY
pub const unsupported_binary = 0b101010
""",
        "diagnostic": "discarded expression",
    },
    "NEG-INT-OCTAL": {
        "source": """// @feature NEG-INT-OCTAL
pub const unsupported_octal = 0o52
""",
        "diagnostic": "discarded expression",
    },
}


def _package_name(row_id: str) -> str:
    return "negative_" + row_id.removeprefix("NEG-").lower().replace("-", "_")


def generate_negative_cases(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    expected_ids = {row["id"] for row in rows}
    if expected_ids != set(CASES):
        raise ValueError(
            "negative case mismatch: "
            f"missing={sorted(expected_ids - set(CASES))}, "
            f"extra={sorted(set(CASES) - expected_ids)}"
        )

    entries: list[dict[str, Any]] = []
    for row in rows:
        row_id = row["id"]
        case = CASES[row_id]
        slug = row_id.lower().replace("-", "_")
        case_root = NEGATIVE_ROOT / slug
        if case_root.exists():
            shutil.rmtree(case_root)
        source_root = case_root / case.get("source_dir", "lib")
        source_root.mkdir(parents=True, exist_ok=True)
        manifest = "\n".join(
            [
                f'name = "equiv/{_package_name(row_id)}"',
                'version = "0.0.0"',
                'compiler = "v1.1.23"',
                f'plutus = "{case.get("plutus", "v3")}"',
                'license = "Apache-2.0"',
                'description = "Expected compile failure sentinel"',
                "",
            ]
        )
        (case_root / "aiken.toml").write_text(manifest, encoding="utf-8")
        fixture_path = source_root / "fixture.ak"
        fixture_path.write_text(case["source"], encoding="utf-8")
        for relative, content in case.get("extra", {}).items():
            destination = case_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8")
        expectation = {
            "feature_id": row_id,
            "diagnostic_pattern": case["diagnostic"],
            "diagnostic_patterns": {
                "old": case.get("old_diagnostic", case["diagnostic"]),
                "new": case["diagnostic"],
            },
            "failure_kinds": {
                "old": case.get("old_failure_kind", "diagnostic"),
                "new": "diagnostic",
            },
            "source_pattern": (
                "aiken.toml"
                if row_id.startswith("NEG-TARGET-")
                else "fixture.ak"
            ),
        }
        (case_root / "expected.json").write_text(
            json.dumps(expectation, indent=2) + "\n", encoding="utf-8"
        )
        relative_source = fixture_path.relative_to(SENTINEL).as_posix()
        lines = case["source"].splitlines()
        marker_line = next(
            index
            for index, line in enumerate(lines, 1)
            if re.search(rf"@feature\s+{re.escape(row_id)}(?:\s|$)", line)
        )
        entries.append(
            {
                "feature_id": row_id,
                "source_path": relative_source,
                "line_start": marker_line + 1,
                "line_end": min(marker_line + 3, len(lines)),
                "ast_evidence": {"node_kind": "ExpectedDiagnosticFixture"},
                "uplc_path": None,
                "validator_title": None,
                "branch_selector": None,
                "artifact_hashes": {"old": None, "new": None},
                "reachability_required": False,
                "negative_compile_case": True,
                "verification_status": "manifested_unverified",
            }
        )
    return entries
