from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

from equiv_checker.evidence import (
    GENERATED_LEAN_SCHEMA_VERSION,
    checker_configuration_id,
    checker_configuration_payload,
    execution_attempt_id_from_record,
    identity_hash,
    logical_obligation_id,
    obligation_attempt_id_from_record,
    obligation_result_id,
    program_artifact_id,
    program_pair_id,
    semantic_model_id,
    sha256_bytes,
    verified_abi_id,
)
from equiv_checker.evidence_store import EvidenceStore


def _canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _rewrite_checked_json(entry: Path, name: str, value: object) -> None:
    payload = _canonical_json_bytes(value)
    (entry / name).write_bytes(payload)
    checksums_path = entry / "checksums.json"
    checksums = json.loads(checksums_path.read_text(encoding="utf-8"))
    checksums["files"][name] = hashlib.sha256(payload).hexdigest()
    checksums_path.write_bytes(_canonical_json_bytes(checksums))


def _concurrent_put_worker(
    root: str,
    ready_queue: Any,
    start_event: Any,
    result_queue: Any,
    result: dict[str, Any],
    execution: dict[str, Any],
    generated_source: bytes,
    marker: str,
) -> None:
    try:
        worker_result = dict(result)
        worker_result["writer_marker"] = marker
        worker_execution = dict(execution)
        worker_execution["writer_marker"] = marker
        ready_queue.put(marker)
        if not start_event.wait(10):
            raise RuntimeError("concurrent evidence writer did not receive start signal")
        published = EvidenceStore(Path(root)).put(
            result=worker_result,
            execution_attempt=worker_execution,
            generated_source=generated_source,
            logs={"stdout.log": (marker + "\n").encode("utf-8")},
        )
        result_queue.put(
            {
                "worker_marker": marker,
                "cache_reused": published["cache_reused"],
                "result_marker": published["result"].get("writer_marker"),
                "execution_marker": published["execution_attempt"].get(
                    "writer_marker"
                ),
            }
        )
    except BaseException as error:
        result_queue.put(
            {
                "worker_marker": marker,
                "error": f"{type(error).__name__}: {error}",
            }
        )

def _claimed_execution_worker(
    root: str,
    ready_queue: Any,
    start_event: Any,
    result_queue: Any,
    result: dict[str, Any],
    execution: dict[str, Any],
    generated_source: bytes,
    expected: dict[str, Any],
) -> None:
    try:
        ready_queue.put(os.getpid())
        if not start_event.wait(10):
            raise RuntimeError(
                "claimed evidence worker did not receive start signal"
            )
        store = EvidenceStore(Path(root))
        with store.execution_claim(
            expected["checker_configuration_id"],
            [expected["logical_obligation_id"]],
        ):
            cached = store.load(expected)
            if cached is None:
                time.sleep(0.25)
                store.put(
                    result=result,
                    execution_attempt=execution,
                    generated_source=generated_source,
                )
                result_queue.put({"executed": True})
            else:
                result_queue.put({"executed": False})
    except BaseException as error:
        result_queue.put(
            {"error": f"{type(error).__name__}: {error}"}
        )


class EvidenceStoreTests(unittest.TestCase):
    def _records(
        self,
    ) -> tuple[
        dict[str, Any],
        dict[str, Any],
        bytes,
        dict[str, Any],
        dict[str, Any],
    ]:
        checker_implementation = identity_hash(
            "test_checker_implementation", {"revision": "fixture-v1"}
        )
        configuration_payload = checker_configuration_payload(
            lean_version="4.19.0",
            revisions={
                "Lean-blaster": "1" * 40,
                "PlutusCoreBlaster": "2" * 40,
                "CardanoLedgerApiBlaster": "3" * 40,
                "UPLC importer": "4" * 40,
                "UPLC preparer": "5" * 40,
            },
            z3_version="4.13.4",
            solver="z3",
            solver_binary_sha256="6" * 64,
            solver_configuration={"smt.random_seed": 17},
            checker_implementation_id_value=checker_implementation,
        )
        configuration_id = checker_configuration_id(configuration_payload)

        old_artifact = program_artifact_id(b"old program", "v3", "flat")
        new_artifact = program_artifact_id(b"new program", "v3", "flat")
        abi_id = verified_abi_id(
            {
                "status": "verified",
                "top_level_callable_arity": 1,
                "applied_parameter_count": 0,
                "remaining_runtime_argument_count": 1,
                "argument_order": ["datum"],
                "argument_value_representation": ["data"],
                "parameter_schemas": [],
                "plutus_version": "v3",
            }
        )
        pair_id = program_pair_id(old_artifact, new_artifact, abi_id)
        model = {
            "profile": "raw-uplc-v1",
            "version": "1",
            "purpose": "spend",
            "variables": [{"name": "datum", "type": "Data"}],
            "argument_order": ["datum"],
            "arity": 1,
            "domain_expression": "True",
            "domain_assumptions": [],
            "observation": "evaluate",
        }
        model_id = semantic_model_id(model, 100)
        obligation_kind = "observational_equivalence"
        obligation_id = logical_obligation_id(pair_id, model_id, obligation_kind)
        generated_source = b"theorem generatedEvidence : True := by trivial\n"
        generated_hash = sha256_bytes(generated_source)

        execution = {
            "checker_configuration_id": configuration_id,
            "checker_implementation_id": checker_implementation,
            "execution_plan": {
                "kind": "generated_lean_process",
                "program_pair_id": pair_id,
                "semantic_model_id": model_id,
                "planned_logical_obligation_ids": [obligation_id],
                "phase": "equivalence",
                "command": ["lake", "env", "lean", "Generated.lean"],
                "effective_options": {"timeout": 2.0},
            },
            "generated_source_sha256": generated_hash,
            "process_timeouts": {"lean": 3.0, "z3": 2.0},
            "random_seed": 17,
            "platform_identity": {
                "system": "linux",
                "machine": "x86_64",
                "python_implementation": "CPython",
                "python_version": "3.12.0",
            },
            "execution_sequence": 1,
            "command": ["lake", "env", "lean", "Generated.lean"],
            "exit_code": 0,
            "timed_out": False,
            "duration_seconds": 0.125,
            "stdout_path": "logs/stdout.log",
            "stderr_path": "logs/stderr.log",
        }
        execution["execution_attempt_id"] = execution_attempt_id_from_record(
            execution
        )
        result = {
            "logical_obligation_id": obligation_id,
            "execution_attempt_id": execution["execution_attempt_id"],
            "checker_configuration_id": configuration_id,
            "checker_implementation_id": checker_implementation,
            "program_pair_id": pair_id,
            "semantic_model_id": model_id,
            "obligation_kind": obligation_kind,
            "status": "proven",
            "generated_source_sha256": generated_hash,
            "solver_status": "valid",
            "witness_reference": None,
            "replay_reference": None,
            "relevant_solver_options": {
                "solver": "z3",
                "solver_timeout": 2.0,
            },
            "attempt_sequence": 1,
            "generated_source_schema_version": GENERATED_LEAN_SCHEMA_VERSION,
            "generated_source_path": "Generated.lean",
            "reused": False,
        }
        result["obligation_attempt_id"] = obligation_attempt_id_from_record(result)
        result["evidence_result_id"] = obligation_result_id(result)
        expected = {
            "logical_obligation_id": obligation_id,
            "checker_configuration_id": configuration_id,
            "checker_implementation_id": checker_implementation,
            "program_pair_id": pair_id,
            "semantic_model_id": model_id,
            "obligation_kind": obligation_kind,
            "generated_source_schema_version": GENERATED_LEAN_SCHEMA_VERSION,
        }
        return result, execution, generated_source, expected, configuration_payload

    def _put(
        self, root: Path
    ) -> tuple[EvidenceStore, dict[str, Any], dict[str, Any], bytes, dict[str, Any]]:
        result, execution, generated_source, expected, _ = self._records()
        store = EvidenceStore(root)
        stored = store.put(
            result=result,
            execution_attempt=execution,
            generated_source=generated_source,
            logs={
                "stdout.log": b"proof complete\n",
                "stderr.log": b"",
            },
        )
        self.assertFalse(stored["cache_reused"])
        return store, result, execution, generated_source, expected

    def _assert_quarantined(
        self, store: EvidenceStore, expected: dict[str, Any]
    ) -> None:
        entry = store.entry_path(
            expected["checker_configuration_id"], expected["logical_obligation_id"]
        )
        self.assertIsNone(store.load(expected))
        self.assertFalse(entry.exists())
        quarantined = [
            path for path in (store.root / "quarantine").iterdir() if path.is_dir()
        ]
        self.assertEqual(len(quarantined), 1)

    def test_put_load_and_exact_put_reuse_the_same_verified_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store, result, execution, generated_source, expected = self._put(root)

            loaded = store.load(expected)
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(loaded["result"], result)
            self.assertEqual(loaded["execution_attempt"], execution)
            self.assertEqual(
                loaded["generated_source"], generated_source
            )
            self.assertEqual(
                loaded["logs"]["stdout.log"], b"proof complete\n"
            )
            self.assertEqual(loaded["logs"]["stderr.log"], b"")

            reused = store.put(
                result=result,
                execution_attempt=execution,
                generated_source=generated_source,
                logs={"stdout.log": b"proof complete\n", "stderr.log": b""},
            )
            self.assertTrue(reused["cache_reused"])
            self.assertEqual(reused["result"], result)
            self.assertEqual(reused["entry_path"], loaded["entry_path"])
            self.assertEqual(store.verify(expected)["result"], result)

    def test_changed_reuse_boundaries_are_rejected_and_quarantined(self) -> None:
        result, _, _, expected, configuration_payload = self._records()
        alternative_pair = program_pair_id(
            program_artifact_id(b"other old", "v3", "flat"),
            program_artifact_id(b"other new", "v3", "flat"),
            identity_hash("test_abi", {"arity": 1}),
        )
        alternative_model = semantic_model_id(
            {
                "profile": "raw-uplc-v1",
                "version": "2",
                "purpose": "spend",
                "variables": [{"name": "datum", "type": "Data"}],
                "argument_order": ["datum"],
                "arity": 1,
                "domain_expression": "datum = datum",
                "domain_assumptions": [],
                "observation": "evaluate",
            },
            100,
        )
        changed_configuration_payload = dict(configuration_payload)
        changed_configuration_payload["solver_configuration"] = {
            "smt.random_seed": 99
        }
        alternative_checker = checker_configuration_id(
            changed_configuration_payload
        )
        cases = {
            "program_pair_id": alternative_pair,
            "semantic_model_id": alternative_model,
            "obligation_kind": "domain_non_vacuity",
            "checker_configuration_id": alternative_checker,
            "generated_source_schema_version": "equiv-generated-lean/v4",
        }

        for field, changed_value in cases.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                store, _, _, _, _ = self._put(Path(temporary))
                changed_expected = dict(expected)
                changed_expected[field] = changed_value
                if field == "checker_configuration_id":
                    original_entry = store.entry_path(
                        result["checker_configuration_id"],
                        result["logical_obligation_id"],
                    )
                    misplaced_entry = store.entry_path(
                        changed_expected["checker_configuration_id"],
                        changed_expected["logical_obligation_id"],
                    )
                    misplaced_entry.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(original_entry, misplaced_entry)
                with self.assertRaisesRegex(
                    ValueError, f"cached evidence boundary mismatch: {field}"
                ):
                    store.verify(changed_expected)
                self._assert_quarantined(store, changed_expected)

    def test_checksum_corruption_is_rejected_and_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, _, _, _, expected = self._put(Path(temporary))
            entry = store.entry_path(
                expected["checker_configuration_id"],
                expected["logical_obligation_id"],
            )
            with (entry / "result.json").open("ab") as stream:
                stream.write(b"corrupt")

            with self.assertRaisesRegex(
                ValueError, "evidence-store checksum mismatch: result.json"
            ):
                store.verify(expected)
            self._assert_quarantined(store, expected)

    def test_partial_entry_is_rejected_and_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, _, _, _, expected = self._put(Path(temporary))
            entry = store.entry_path(
                expected["checker_configuration_id"],
                expected["logical_obligation_id"],
            )
            (entry / "execution-attempt.json").unlink()

            with self.assertRaisesRegex(
                ValueError,
                "partial cache entry; missing=execution-attempt.json",
            ):
                store.verify(expected)
            self._assert_quarantined(store, expected)

    def test_entry_directory_symlink_is_rejected_and_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store, _, _, _, expected = self._put(root)
            entry = store.entry_path(
                expected["checker_configuration_id"],
                expected["logical_obligation_id"],
            )
            target = root / "detached-valid-entry"
            entry.rename(target)
            entry.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "entry is a symlink"):
                store.verify(expected)
            self._assert_quarantined(store, expected)

    def test_checksum_valid_malformed_record_is_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, result, _, _, expected = self._put(Path(temporary))
            entry = store.entry_path(
                expected["checker_configuration_id"],
                expected["logical_obligation_id"],
            )
            malformed = dict(result)
            malformed.pop("relevant_solver_options")
            _rewrite_checked_json(entry, "result.json", malformed)
            with self.assertRaisesRegex(
                ValueError, "malformed records"
            ):
                store.verify(expected)
            self._assert_quarantined(store, expected)

    def test_tampered_execution_identity_inputs_are_rejected_and_quarantined(
        self,
    ) -> None:
        cases = {
            "process timeout": lambda row: row["process_timeouts"].__setitem__(
                "z3", 9.0
            ),
            "random seed": lambda row: row.__setitem__("random_seed", 99),
            "platform": lambda row: row["platform_identity"].__setitem__(
                "machine", "arm64"
            ),
            "execution sequence": lambda row: row.__setitem__(
                "execution_sequence", 2
            ),
        }
        for label, tamper in cases.items():
            with self.subTest(field=label), tempfile.TemporaryDirectory() as temporary:
                store, _, execution, _, expected = self._put(Path(temporary))
                entry = store.entry_path(
                    expected["checker_configuration_id"],
                    expected["logical_obligation_id"],
                )
                changed_execution = json.loads(json.dumps(execution))
                tamper(changed_execution)
                self.assertNotEqual(
                    execution_attempt_id_from_record(changed_execution),
                    changed_execution["execution_attempt_id"],
                )
                _rewrite_checked_json(
                    entry, "execution-attempt.json", changed_execution
                )

                with self.assertRaisesRegex(
                    ValueError, "cached execution attempt identity mismatch"
                ):
                    store.verify(expected)
                self._assert_quarantined(store, expected)

    def test_tampered_obligation_attempt_is_rejected_even_with_resealed_result(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, result, _, _, expected = self._put(Path(temporary))
            entry = store.entry_path(
                expected["checker_configuration_id"],
                expected["logical_obligation_id"],
            )
            changed_result = json.loads(json.dumps(result))
            changed_result["relevant_solver_options"]["solver_timeout"] = 9.0
            self.assertNotEqual(
                obligation_attempt_id_from_record(changed_result),
                changed_result["obligation_attempt_id"],
            )
            changed_result["evidence_result_id"] = obligation_result_id(
                changed_result
            )
            _rewrite_checked_json(entry, "result.json", changed_result)

            with self.assertRaisesRegex(
                ValueError, "cached obligation attempt identity mismatch"
            ):
                store.verify(expected)
            self._assert_quarantined(store, expected)

    def test_concurrent_writers_publish_one_complete_valid_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, execution, generated_source, expected, _ = self._records()
            context = multiprocessing.get_context("spawn")
            ready_queue = context.Queue()
            start_event = context.Event()
            result_queue = context.Queue()
            processes = [
                context.Process(
                    target=_concurrent_put_worker,
                    args=(
                        str(root),
                        ready_queue,
                        start_event,
                        result_queue,
                        result,
                        execution,
                        generated_source,
                        marker,
                    ),
                )
                for marker in ("writer-a", "writer-b")
            ]
            for process in processes:
                process.start()
            try:
                ready_markers = {
                    ready_queue.get(timeout=10), ready_queue.get(timeout=10)
                }
            finally:
                start_event.set()
            self.assertEqual(ready_markers, {"writer-a", "writer-b"})

            for process in processes:
                process.join(15)
            stuck = [process for process in processes if process.is_alive()]
            for process in stuck:
                process.terminate()
                process.join(5)
            self.assertEqual(stuck, [])
            self.assertEqual([process.exitcode for process in processes], [0, 0])

            publications = [
                result_queue.get(timeout=5), result_queue.get(timeout=5)
            ]
            self.assertFalse([row for row in publications if "error" in row])
            self.assertEqual(
                {row["cache_reused"] for row in publications}, {False, True}
            )
            published_markers = {row["result_marker"] for row in publications}
            self.assertEqual(len(published_markers), 1)
            published_marker = published_markers.pop()
            self.assertIn(published_marker, {"writer-a", "writer-b"})
            self.assertEqual(
                {row["execution_marker"] for row in publications},
                {published_marker},
            )

            store = EvidenceStore(root)
            verified = store.verify(expected)
            self.assertEqual(
                verified["result"]["writer_marker"], published_marker
            )
            self.assertEqual(
                verified["execution_attempt"]["writer_marker"], published_marker
            )
            entry = Path(verified["entry_path"])
            self.assertEqual(
                (entry / "logs" / "stdout.log").read_text(encoding="utf-8"),
                published_marker + "\n",
            )
            self.assertEqual(
                list(entry.parent.glob(f".{result['logical_obligation_id']}.staging-*")),
                [],
            )

    def test_execution_claim_prevents_duplicate_live_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, execution, generated_source, expected, _ = self._records()
            context = multiprocessing.get_context("spawn")
            ready_queue = context.Queue()
            start_event = context.Event()
            result_queue = context.Queue()
            processes = [
                context.Process(
                    target=_claimed_execution_worker,
                    args=(
                        str(root),
                        ready_queue,
                        start_event,
                        result_queue,
                        result,
                        execution,
                        generated_source,
                        expected,
                    ),
                )
                for _ in range(2)
            ]
            for process in processes:
                process.start()
            try:
                ready_processes = {
                    ready_queue.get(timeout=10), ready_queue.get(timeout=10)
                }
            finally:
                start_event.set()
            self.assertEqual(len(ready_processes), 2)

            for process in processes:
                process.join(15)
            stuck = [process for process in processes if process.is_alive()]
            for process in stuck:
                process.terminate()
                process.join(5)
            self.assertEqual(stuck, [])
            self.assertEqual([process.exitcode for process in processes], [0, 0])

            outcomes = [
                result_queue.get(timeout=5), result_queue.get(timeout=5)
            ]
            self.assertFalse([row for row in outcomes if "error" in row])
            self.assertEqual(
                [row["executed"] for row in outcomes].count(True), 1
            )
            self.assertEqual(
                [row["executed"] for row in outcomes].count(False), 1
            )
            self.assertEqual(
                EvidenceStore(root).verify(expected)["result"], result
            )
