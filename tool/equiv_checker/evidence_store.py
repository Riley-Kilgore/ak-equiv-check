from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

from .evidence import (
    WITNESS_FIELDS,
    candidate_witness_id,
    execution_attempt_id_from_record,
    obligation_attempt_id_from_record,
    obligation_result_id,
    replay_id,
    validate_witness_record,
)

STORE_SCHEMA_VERSION = "equiv-evidence-store/v1"


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _decode_json(value: bytes, label: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid evidence-store JSON: {label}") from error
    if not isinstance(decoded, dict):
        raise ValueError(f"evidence-store JSON is not an object: {label}")
    return decoded


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid evidence-store JSON: {path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"evidence-store JSON is not an object: {path}")
    return value
def _regular_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError(
                f"evidence-store entry contains a symlink: {relative}"
            )
        if path.is_file():
            files.append(path)
    return files


def _content_id(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} is not a SHA-256 content identity")
    return value




def _fsync_file(path: Path) -> None:
    with path.open("rb") as stream:
        os.fsync(stream.fileno())


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class EvidenceStore:
    """Content-addressed obligation evidence with verified, atomic publication."""

    def __init__(self, root: Path):
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "locks").mkdir(exist_ok=True)
        (self.root / "quarantine").mkdir(exist_ok=True)

    def entry_path(
        self, checker_configuration_id: str, logical_obligation_id: str
    ) -> Path:
        checker_id = _content_id(
            checker_configuration_id, "checker_configuration_id"
        )
        obligation_id = _content_id(
            logical_obligation_id, "logical_obligation_id"
        )
        return (
            self.root
            / checker_id[:2]
            / checker_id
            / obligation_id[:2]
            / obligation_id
        )

    def _lock_path(
        self, checker_configuration_id: str, logical_obligation_id: str
    ) -> Path:
        return (
            self.root
            / "locks"
            / f"{checker_configuration_id}-{logical_obligation_id}.lock"
        )

    @contextmanager
    def _lock(
        self,
        checker_configuration_id: str,
        logical_obligation_id: str,
        *,
        exclusive: bool,
    ) -> Iterator[None]:
        lock_path = self._lock_path(
            checker_configuration_id, logical_obligation_id
        )
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as stream:
            fcntl.flock(
                stream.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            )
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    @contextmanager
    def execution_claim(
        self,
        checker_configuration_id: str,
        logical_obligation_ids: list[str],
    ) -> Iterator[None]:
        checker_id = _content_id(
            checker_configuration_id, "checker_configuration_id"
        )
        obligation_ids = sorted(
            _content_id(value, "logical_obligation_id")
            for value in logical_obligation_ids
        )
        if not obligation_ids or len(obligation_ids) != len(
            set(obligation_ids)
        ):
            raise ValueError(
                "execution claim requires distinct logical obligations"
            )
        claim_id = _sha256_bytes(
            _canonical_bytes(
                {
                    "checker_configuration_id": checker_id,
                    "logical_obligation_ids": obligation_ids,
                }
            )
        )
        lock_path = (
            self.root
            / "locks"
            / "executions"
            / f"{checker_id}-{claim_id}.lock"
        )
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def _quarantine_locked(self, entry: Path) -> Path | None:
        if not entry.exists():
            return None
        quarantine = (
            self.root
            / "quarantine"
            / f"{entry.parent.parent.name}-{entry.name}-{uuid.uuid4().hex}"
        )
        quarantine.parent.mkdir(parents=True, exist_ok=True)
        os.replace(entry, quarantine)
        _fsync_directory(entry.parent)
        _fsync_directory(quarantine.parent)
        return quarantine

    def _verify_entry(
        self,
        entry: Path,
        expected: Mapping[str, Any],
        *,
        validate_path: bool = True,
    ) -> dict[str, Any]:
        if entry.is_symlink():
            raise ValueError("evidence-store entry is a symlink")
        required = {
            "result.json",
            "execution-attempt.json",
            "lineage.json",
            "checksums.json",
        }
        names = {path.name for path in _regular_files(entry)}
        missing = sorted(required - names)
        if missing:
            raise ValueError("partial cache entry; missing=" + ", ".join(missing))
        checksums = _read_json(entry / "checksums.json")
        if checksums.get("schema_version") != STORE_SCHEMA_VERSION:
            raise ValueError("unsupported evidence-store checksum schema")
        files = checksums.get("files")
        if not isinstance(files, dict) or not files:
            raise ValueError("invalid evidence-store checksum table")
        actual_files = {
            path.relative_to(entry).as_posix()
            for path in _regular_files(entry)
            if path.name != "checksums.json"
        }
        if set(files) != actual_files:
            raise ValueError("evidence-store file inventory mismatch")
        payload_by_name: dict[str, bytes] = {}
        for relative, checksum in files.items():
            if (
                not isinstance(checksum, str)
                or len(checksum) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in checksum
                )
            ):
                raise ValueError(
                    f"invalid evidence-store checksum: {relative}"
                )
            file_path = entry / relative
            if not file_path.is_file():
                raise ValueError(
                    f"evidence-store file is missing: {relative}"
                )
            value = file_path.read_bytes()
            if _sha256_bytes(value) != checksum:
                raise ValueError(
                    f"evidence-store checksum mismatch: {relative}"
                )
            payload_by_name[relative] = value

        result = _decode_json(payload_by_name["result.json"], "result.json")
        execution = _decode_json(
            payload_by_name["execution-attempt.json"],
            "execution-attempt.json",
        )
        lineage = _decode_json(
            payload_by_name["lineage.json"], "lineage.json"
        )
        boundaries = {
            "logical_obligation_id": result.get("logical_obligation_id"),
            "checker_configuration_id": result.get(
                "checker_configuration_id"
            ),
            "checker_implementation_id": result.get(
                "checker_implementation_id"
            ),
            "program_pair_id": result.get("program_pair_id"),
            "semantic_model_id": result.get("semantic_model_id"),
            "obligation_kind": result.get("obligation_kind"),
            "generated_source_schema_version": result.get(
                "generated_source_schema_version"
            ),
        }
        if set(expected) != set(boundaries):
            raise ValueError("incomplete evidence reuse boundary")
        for field, value in expected.items():
            if boundaries[field] != value:
                raise ValueError(
                    f"cached evidence boundary mismatch: {field}"
                )
        if validate_path and entry.name != result.get(
            "logical_obligation_id"
        ):
            raise ValueError("cached evidence logical path mismatch")
        if (
            validate_path
            and entry.parent.parent.name
            != result.get("checker_configuration_id")
        ):
            raise ValueError("cached evidence configuration path mismatch")
        if execution.get("execution_attempt_id") != result.get(
            "execution_attempt_id"
        ):
            raise ValueError("cached evidence has wrong execution parent")
        if (
            execution.get("checker_configuration_id")
            != result.get("checker_configuration_id")
            or execution.get("checker_implementation_id")
            != result.get("checker_implementation_id")
        ):
            raise ValueError(
                "cached execution has wrong checker configuration"
            )
        if execution_attempt_id_from_record(execution) != execution.get(
            "execution_attempt_id"
        ):
            raise ValueError("cached execution attempt identity mismatch")
        if obligation_attempt_id_from_record(result) != result.get(
            "obligation_attempt_id"
        ):
            raise ValueError("cached obligation attempt identity mismatch")
        if obligation_result_id(result) != result.get("evidence_result_id"):
            raise ValueError("cached obligation result identity mismatch")
        if result.get("status") == "pending":
            raise ValueError("pending evidence cannot enter the evidence store")
        if lineage.get("reuse_boundary") != boundaries:
            raise ValueError("cached evidence lineage boundary mismatch")
        for lineage_field, result_field in (
            ("evidence_result_id", "evidence_result_id"),
            ("execution_attempt_id", "execution_attempt_id"),
            ("obligation_attempt_id", "obligation_attempt_id"),
            ("witness_id", "witness_reference"),
            ("replay_id", "replay_reference"),
        ):
            if lineage.get(lineage_field) != result.get(result_field):
                raise ValueError(
                    f"cached evidence lineage mismatch: {lineage_field}"
                )

        generated_hash = result.get("generated_source_sha256")
        generated_source = payload_by_name.get("generated-source.lean")
        if generated_hash is not None:
            if generated_source is None:
                raise ValueError("cached generated source is missing")
            if _sha256_bytes(generated_source) != generated_hash:
                raise ValueError("cached generated source hash mismatch")
        elif generated_source is not None:
            raise ValueError("unreferenced cached generated source")

        witness = None
        witness_reference = result.get("witness_reference")
        witness_bytes = payload_by_name.get("witness.json")
        if witness_reference is not None:
            if witness_bytes is None:
                raise ValueError("cached witness is missing")
            witness = _decode_json(witness_bytes, "witness.json")
            if witness.get("witness_id") != witness_reference:
                raise ValueError("cached witness reference mismatch")
            if candidate_witness_id(witness) != witness_reference:
                raise ValueError("cached witness identity mismatch")
            if witness.get(
                "producing_logical_obligation_id"
            ) != result.get("logical_obligation_id"):
                raise ValueError("cached witness has wrong logical parent")
            if witness.get(
                "producing_obligation_attempt_id"
            ) != result.get("obligation_attempt_id"):
                raise ValueError(
                    "cached witness has wrong obligation attempt parent"
                )
            if witness.get(
                "producing_execution_attempt_id"
            ) != result.get("execution_attempt_id"):
                raise ValueError("cached witness has wrong execution parent")
            protocol_witness = {
                key: witness[key] for key in WITNESS_FIELDS if key in witness
            }
            validate_witness_record(
                protocol_witness,
                {
                    "program_pair_id": result["program_pair_id"],
                    "logical_obligation_id": result[
                        "logical_obligation_id"
                    ],
                    "semantic_model_id": result["semantic_model_id"],
                    "checker_implementation_id": result[
                        "checker_implementation_id"
                    ],
                },
            )
        elif witness_bytes is not None:
            raise ValueError("unreferenced cached witness")

        replay = None
        replay_reference = result.get("replay_reference")
        replay_bytes = payload_by_name.get("replay.json")
        if replay_reference is not None:
            if replay_bytes is None:
                raise ValueError("cached replay is missing")
            replay = _decode_json(replay_bytes, "replay.json")
            if replay.get("replay_id") != replay_reference:
                raise ValueError("cached replay reference mismatch")
            if replay_id(replay) != replay_reference:
                raise ValueError("cached replay identity mismatch")
            if replay.get("confirmed") is not True:
                raise ValueError("cached replay is not confirmed")
            for replay_field, result_field in (
                ("logical_obligation_id", "logical_obligation_id"),
                ("obligation_attempt_id", "obligation_attempt_id"),
                ("execution_attempt_id", "execution_attempt_id"),
                ("witness_id", "witness_reference"),
            ):
                if replay.get(replay_field) != result.get(result_field):
                    raise ValueError(
                        f"cached replay has wrong {replay_field} parent"
                    )
        elif replay_bytes is not None:
            raise ValueError("unreferenced cached replay")
        cached_logs = {
            relative.removeprefix("logs/"): value
            for relative, value in payload_by_name.items()
            if relative.startswith("logs/")
        }
        return {
            "result": result,
            "execution_attempt": execution,
            "witness": witness,
            "replay": replay,
            "lineage": lineage,
            "entry_path": str(entry),
            "generated_source": generated_source,
            "logs": cached_logs,
        }

    @staticmethod
    def _boundary_ids(
        expected: Mapping[str, Any],
    ) -> tuple[str, str]:
        checker_id = _content_id(
            expected.get("checker_configuration_id"),
            "checker_configuration_id",
        )
        obligation_id = _content_id(
            expected.get("logical_obligation_id"),
            "logical_obligation_id",
        )
        return checker_id, obligation_id

    def load(self, expected: Mapping[str, Any]) -> dict[str, Any] | None:
        checker_id, obligation_id = self._boundary_ids(expected)
        entry = self.entry_path(checker_id, obligation_id)
        with self._lock(checker_id, obligation_id, exclusive=False):
            if not entry.is_dir():
                return None
            try:
                return self._verify_entry(entry, expected)
            except (OSError, ValueError, KeyError, TypeError):
                pass
        with self._lock(checker_id, obligation_id, exclusive=True):
            if not entry.is_dir():
                return None
            try:
                return self._verify_entry(entry, expected)
            except (OSError, ValueError, KeyError, TypeError):
                self._quarantine_locked(entry)
                return None

    def verify(self, expected: Mapping[str, Any]) -> dict[str, Any]:
        checker_id, obligation_id = self._boundary_ids(expected)
        entry = self.entry_path(checker_id, obligation_id)
        with self._lock(checker_id, obligation_id, exclusive=False):
            if not entry.is_dir():
                raise ValueError(
                    f"evidence-store entry is missing: {obligation_id}"
                )
            try:
                return self._verify_entry(entry, expected)
            except (KeyError, TypeError) as error:
                raise ValueError(
                    "evidence-store entry has malformed records"
                ) from error

    def quarantine(self, expected: Mapping[str, Any]) -> Path | None:
        checker_id, obligation_id = self._boundary_ids(expected)
        entry = self.entry_path(checker_id, obligation_id)
        with self._lock(checker_id, obligation_id, exclusive=True):
            return self._quarantine_locked(entry)

    def put(
        self,
        *,
        result: Mapping[str, Any],
        execution_attempt: Mapping[str, Any],
        witness: Mapping[str, Any] | None = None,
        replay: Mapping[str, Any] | None = None,
        generated_source: bytes | None = None,
        logs: Mapping[str, bytes] | None = None,
    ) -> dict[str, Any]:
        checker_id, obligation_id = self._boundary_ids(result)
        expected = {
            "logical_obligation_id": obligation_id,
            "checker_configuration_id": checker_id,
            "checker_implementation_id": result[
                "checker_implementation_id"
            ],
            "program_pair_id": result["program_pair_id"],
            "semantic_model_id": result["semantic_model_id"],
            "obligation_kind": result["obligation_kind"],
            "generated_source_schema_version": result[
                "generated_source_schema_version"
            ],
        }
        entry = self.entry_path(checker_id, obligation_id)
        with self._lock(checker_id, obligation_id, exclusive=True):
            if entry.is_dir():
                try:
                    return self._verify_entry(entry, expected) | {
                        "cache_reused": True
                    }
                except (OSError, ValueError, KeyError, TypeError):
                    self._quarantine_locked(entry)
            entry.parent.mkdir(parents=True, exist_ok=True)
            staging = Path(
                tempfile.mkdtemp(
                    prefix=f".{obligation_id}.staging-",
                    dir=entry.parent,
                )
            )
            try:
                payloads: dict[str, bytes] = {
                    "result.json": _canonical_bytes(dict(result)),
                    "execution-attempt.json": _canonical_bytes(
                        dict(execution_attempt)
                    ),
                }
                if witness is not None:
                    payloads["witness.json"] = _canonical_bytes(
                        dict(witness)
                    )
                if replay is not None:
                    payloads["replay.json"] = _canonical_bytes(dict(replay))
                if generated_source is not None:
                    payloads["generated-source.lean"] = bytes(
                        generated_source
                    )
                for name, value in (logs or {}).items():
                    relative = (Path("logs") / Path(name).name).as_posix()
                    if relative in payloads:
                        raise ValueError(
                            f"duplicate evidence log name: {relative}"
                        )
                    payloads[relative] = bytes(value)
                lineage = {
                    "schema_version": STORE_SCHEMA_VERSION,
                    "reuse_boundary": dict(expected),
                    "evidence_result_id": result["evidence_result_id"],
                    "execution_attempt_id": result["execution_attempt_id"],
                    "obligation_attempt_id": result[
                        "obligation_attempt_id"
                    ],
                    "witness_id": result.get("witness_reference"),
                    "replay_id": result.get("replay_reference"),
                }
                payloads["lineage.json"] = _canonical_bytes(lineage)
                for relative, value in payloads.items():
                    destination = staging / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(value)
                    _fsync_file(destination)
                checksum_payload = {
                    "schema_version": STORE_SCHEMA_VERSION,
                    "files": {
                        relative: _sha256_bytes(value)
                        for relative, value in sorted(payloads.items())
                    },
                }
                checksum_path = staging / "checksums.json"
                checksum_path.write_bytes(
                    _canonical_bytes(checksum_payload)
                )
                _fsync_file(checksum_path)
                self._verify_entry(
                    staging, expected, validate_path=False
                )
                directories = {
                    path.parent
                    for path in _regular_files(staging)
                }
                for directory in sorted(
                    directories,
                    key=lambda path: len(path.parts),
                    reverse=True,
                ):
                    _fsync_directory(directory)
                os.replace(staging, entry)
                _fsync_directory(entry.parent)
                return self._verify_entry(entry, expected) | {
                    "cache_reused": False
                }
            except Exception:
                if entry.is_dir():
                    self._quarantine_locked(entry)
                if staging.exists():
                    shutil.rmtree(staging)
                raise
