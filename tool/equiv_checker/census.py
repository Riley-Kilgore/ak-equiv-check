from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .config import CONTRACT_PATH, SHIM_BINARY, SHIM_MANIFEST, load_json


MARKER = re.compile(
    r"//\s*@(feature|builtin)\s+([A-Z0-9-]+)(?:\s+selector=(-?\d+))?"
)
LOW_PRIORITY_KINDS = {
    "App",
    "Constructor",
    "Fn",
    "Tuple",
    "Pair",
    "Var",
    "Link",
    "Record",
    "Discarded",
    "Named",
}


@dataclass(frozen=True)
class AstNode:
    kind: str
    start: int
    end: int
    path: tuple[str, ...]


def ensure_shim() -> Path:
    inputs = [
        SHIM_MANIFEST,
        SHIM_MANIFEST.parent / "Cargo.lock",
        *sorted((SHIM_MANIFEST.parent / "src").rglob("*.rs")),
    ]
    rebuild = not SHIM_BINARY.exists() or any(
        path.exists() and path.stat().st_mtime_ns > SHIM_BINARY.stat().st_mtime_ns
        for path in inputs
    )
    if rebuild:
        completed = subprocess.run(
            ["cargo", "build", "--release", "--manifest-path", str(SHIM_MANIFEST)],
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode:
            raise RuntimeError(
                "failed to build aiken compiler shim\n"
                + completed.stdout
                + completed.stderr
            )
    return SHIM_BINARY


def typed_ast(package: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [str(ensure_shim()), "typed-ast", str(package)],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"typed AST extraction failed for {package}\n{completed.stdout}{completed.stderr}"
        )
    return json.loads(completed.stdout)


def _span(payload: dict[str, Any], code_size: int) -> tuple[int, int] | None:
    location = payload.get("location")
    if not isinstance(location, dict):
        return None
    start = location.get("start")
    end = payload.get("end_position", location.get("end"))
    if not isinstance(start, int) or not isinstance(end, int):
        return None
    if start < 0 or end < start or end > code_size:
        return None
    return start, end


def flatten_ast(ast: Any, code_size: int) -> list[AstNode]:
    nodes: list[AstNode] = []

    def walk(value: Any, path: tuple[str, ...], inherited_kind: str | None = None) -> None:
        if isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, (*path, str(index)), inherited_kind)
            return
        if not isinstance(value, dict):
            return

        kind = inherited_kind
        if len(value) == 1:
            key, child = next(iter(value.items()))
            if isinstance(child, dict) and (key[:1].isupper() or key == "Use"):
                kind = key
                path = (*path, key)

        span = _span(value, code_size)
        if span and kind:
            nodes.append(AstNode(kind, span[0], span[1], path))

        if "body" in value and "name" in value and isinstance(value.get("location"), dict):
            handler_span = _span(value, code_size)
            if handler_span:
                nodes.append(
                    AstNode(
                        f"ValidatorHandler:{value['name']}",
                        handler_span[0],
                        handler_span[1],
                        (*path, "handler"),
                    )
                )

        for key, child in value.items():
            walk(child, (*path, str(key)), kind)

    walk(ast, ())
    unique = {(node.kind, node.start, node.end, node.path): node for node in nodes}
    return sorted(unique.values(), key=lambda node: (node.start, node.end, node.kind))


def _line_number(code: str, offset: int) -> int:
    return code.count("\n", 0, offset) + 1


def _relative(path: Path, package: Path) -> str:
    try:
        return path.resolve().relative_to(package.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _best_node(nodes: list[AstNode], start: int, end: int, marker: bool) -> AstNode | None:
    if marker:
        candidates = [node for node in nodes if node.start >= end and node.start - end <= 800]
        return min(
            candidates,
            key=lambda node: (
                node.start,
                node.end - node.start,
                node.kind in LOW_PRIORITY_KINDS,
            ),
            default=None,
        )

    candidates = [node for node in nodes if node.start <= start and node.end >= end]
    return min(
        candidates,
        key=lambda node: (
            node.end - node.start,
            node.kind in LOW_PRIORITY_KINDS,
        ),
        default=None,
    )


def _node_accepts(row: dict[str, Any], node: AstNode) -> bool:
    category = row["category"]
    path = "/".join(node.path).lower()
    kind = node.kind
    if category in {"project_and_targets", "negative_compile_contract", "comments_and_docs"}:
        return False
    if category == "operators":
        return kind in {"BinOp", "UnOp"}
    if category == "patterns":
        return "pattern" in path or "clause" in path
    if category == "literals":
        return (
            kind in {"Int", "UInt", "ByteArray", "String", "List", "Tuple", "Pair", "Var", "CurvePoint"}
            and "annotation" not in path
            and "pattern" not in path
        )
    if category == "type_system_and_data_conversion":
        return "annotation" in path or kind in {"Call", "Assignment"}
    if category == "validators":
        return kind == "Validator" or kind.startswith("ValidatorHandler:")
    if category == "modules_definitions_imports":
        return kind in {
            "Use",
            "Function",
            "ModuleConstant",
            "DataType",
            "TypeAlias",
            "Test",
            "Benchmark",
            "Validator",
            "Call",
            "Var",
        }
    if category == "tests_benchmarks_and_tracing":
        return kind in {"Test", "Benchmark", "Trace", "Call", "Var"}
    if category == "functions_calls_and_bindings":
        return kind not in {"Use", "Validator", "ModuleConstant", "App", "Constructor"}
    if category == "control_flow_and_expressions":
        return kind not in {"Use", "Validator", "ModuleConstant", "App", "Constructor"}
    return True


def _record(
    row_id: str,
    path: Path,
    package: Path,
    code: str,
    node: AstNode | None,
    start: int,
    end: int,
    detector: str,
    marker: bool,
    selector: int | None = None,
    syntax_example: str | None = None,
) -> dict[str, Any]:
    span_start = node.start if node else start
    span_end = node.end if node else end
    result: dict[str, Any] = {
        "feature_id": row_id,
        "file": _relative(path, package),
        "line_start": _line_number(code, span_start),
        "line_end": _line_number(code, max(span_start, span_end - 1)),
        "byte_start": span_start,
        "byte_end": span_end,
        "ast_node_kind": node.kind if node else "source_text",
        "ast_path": list(node.path) if node else [],
        "detector_rule": detector,
        "marker_bound": marker,
    }
    if selector is not None:
        result["branch_selector"] = selector
    if syntax_example is not None:
        result["syntax_example"] = syntax_example
    return result


def _source_records(
    package: Path,
    ast_output: dict[str, Any],
    features: list[dict[str, Any]],
    builtins: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    feature_by_id = {row["id"]: row for row in features}
    builtin_by_id = {row["id"]: row for row in builtins}
    records: list[dict[str, Any]] = []

    for module in ast_output["modules"]:
        path = Path(module["path"])
        code = module["code"]
        nodes = flatten_ast(module["ast"], len(code))
        marked_ids: set[str] = set()

        for match in MARKER.finditer(code):
            marker_kind, row_id, raw_selector = match.groups()
            row = feature_by_id.get(row_id) if marker_kind == "feature" else builtin_by_id.get(row_id)
            if row is None:
                raise ValueError(f"unknown {marker_kind} marker {row_id} in {path}")
            evidence_start = match.start()
            evidence_end = match.end()
            node = _best_node(nodes, evidence_start, evidence_end, marker=True)
            if marker_kind == "builtin":
                call = re.search(
                    rf"\b{re.escape(row['aiken_name'])}\b",
                    code[match.end() : match.end() + 800],
                )
                if call is None:
                    raise ValueError(
                        f"builtin marker {row_id} has no following {row['aiken_name']} reference in {path}"
                    )
                evidence_start = match.end() + call.start()
                evidence_end = match.end() + call.end()
                node = _best_node(nodes, evidence_start, evidence_end, marker=False)
                if node is None or node.kind not in {"Call", "ModuleSelect"}:
                    raise ValueError(
                        f"builtin marker {row_id} is not bound to a typed builtin reference in {path}"
                    )
            records.append(
                _record(
                    row_id,
                    path,
                    package,
                    code,
                    node,
                    evidence_start,
                    evidence_end,
                    row.get("detector_hints", ["typed AST builtin call"])[0],
                    True,
                    int(raw_selector) if raw_selector is not None else None,
                )
            )
            marked_ids.add(row_id)

        for row in features:
            if row["id"] in marked_ids:
                continue
            for syntax in row.get("syntax_examples", []):
                if not syntax or "..." in syntax or "<" in syntax and ">" in syntax:
                    continue
                start = code.find(syntax)
                if start < 0:
                    continue
                end = start + len(syntax)
                node = _best_node(nodes, start, end, marker=False)
                if node is None or not _node_accepts(row, node):
                    continue
                records.append(
                    _record(
                        row["id"],
                        path,
                        package,
                        code,
                        node,
                        start,
                        end,
                        row["detector_hints"][0],
                        False,
                        syntax_example=syntax,
                    )
                )
                break

        for row in builtins:
            if row["id"] in marked_ids:
                continue
            call = re.search(rf"\b{re.escape(row['aiken_name'])}\s*\(", code)
            if call is None:
                continue
            node = _best_node(nodes, call.start(), call.end(), marker=False)
            if node is None or node.kind != "Call":
                continue
            records.append(
                _record(
                    row["id"],
                    path,
                    package,
                    code,
                    node,
                    call.start(),
                    call.end(),
                    "typed AST builtin call",
                    False,
                )
            )

        for row in features:
            if row["id"] in marked_ids or row.get("syntax_examples"):
                continue
            hint = row["detector_hints"][0]
            typed_name = re.fullmatch(
                r"typed (?:AST contains|use of) ([A-Za-z0-9_]+)(?:<.*>)?",
                hint,
            )
            if typed_name:
                name = typed_name.group(1)
                node = next(
                    (
                        candidate
                        for candidate in nodes
                        if candidate.kind in {"App", "Constructor"}
                        and code[candidate.start : candidate.end].find(name) >= 0
                    ),
                    None,
                )
                if node:
                    records.append(
                        _record(
                            row["id"],
                            path,
                            package,
                            code,
                            node,
                            node.start,
                            node.end,
                            hint,
                            False,
                        )
                    )

    return records


def _manifest_records(package: Path, features: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = {row["id"]: row for row in features}
    manifest_path = package / "aiken.toml"
    code = manifest_path.read_text(encoding="utf-8")
    records: list[dict[str, Any]] = []

    checks = {
        "TARGET-PLUTUS-V3": re.compile(r"(?m)^plutus\s*=\s*[\"']v3[\"']"),
        "PROJECT-TOML": re.compile(r"(?m)^name\s*="),
        "PROJECT-COMPILER-PIN": re.compile(r"(?m)^compiler\s*=\s*[\"']v[^\"']+[\"']"),
        "PROJECT-DEPENDENCY": re.compile(r"(?m)^\[\[dependencies\]\]"),
        "PROJECT-DEPENDENCY-GITHUB": re.compile(r"(?m)^source\s*=\s*[\"']github[\"']"),
        "PROJECT-CONFIG-SECTION": re.compile(r"(?m)^\[config(?:\.|\])"),
    }
    for row_id, pattern in checks.items():
        if row_id not in rows:
            continue
        match = pattern.search(code)
        if match:
            records.append(
                _record(
                    row_id,
                    manifest_path,
                    package,
                    code,
                    None,
                    match.start(),
                    match.end(),
                    rows[row_id]["detector_hints"][0],
                    False,
                )
            )

    lock_path = package / "aiken.lock"
    if "PROJECT-LOCK" in rows and lock_path.exists():
        lock_code = lock_path.read_text(encoding="utf-8")
        records.append(
            _record(
                "PROJECT-LOCK",
                lock_path,
                package,
                lock_code,
                None,
                0,
                min(len(lock_code), 1),
                rows["PROJECT-LOCK"]["detector_hints"][0],
                False,
            )
        )
    return records


def _negative_records(
    package: Path, features: Iterable[dict[str, Any]]
) -> list[dict[str, Any]]:
    rows = {
        row["id"]: row for row in features if row.get("negative_compile_case")
    }
    records: list[dict[str, Any]] = []
    negative_root = package / "negative" / "cases"
    if not negative_root.exists():
        return records
    for path in sorted(negative_root.glob("*/**/fixture.ak")):
        code = path.read_text(encoding="utf-8")
        for match in MARKER.finditer(code):
            marker_kind, row_id, _ = match.groups()
            if marker_kind != "feature" or row_id not in rows:
                continue
            records.append(
                _record(
                    row_id,
                    path,
                    package,
                    code,
                    None,
                    match.end(),
                    match.end(),
                    rows[row_id]["detector_hints"][0],
                    True,
                )
            )
    return records


def census(package: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    contract = load_json(CONTRACT_PATH)
    ast_output = typed_ast(package)
    records = _source_records(
        package,
        ast_output,
        contract["features"],
        contract["active_uplc_builtins"],
    )
    records.extend(_manifest_records(package, contract["features"]))
    records.extend(_negative_records(package, contract["features"]))
    records.sort(key=lambda record: (record["feature_id"], record["file"], record["line_start"]))
    return records, {
        "backend": ast_output["backend"],
        "compiler_revision": ast_output["compiler_revision"],
        "module_count": len(ast_output["modules"]),
    }
