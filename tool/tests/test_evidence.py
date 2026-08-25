from __future__ import annotations

import copy
import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from equiv_checker.evidence import (
    GENERATED_LEAN_SCHEMA_VERSION,
    RESULT_PROTOCOL,
    attempt_id,
    checker_configuration_id,
    checker_configuration_payload,
    logical_obligation_id,
    program_artifact_id,
    program_pair_id,
    semantic_model_id,
    validate_result_marker,
)
from equiv_checker.models import ProgramPairRecord, ScriptArtifact
from equiv_checker.runner import (
    _cached_pair_matches,
    _pair_result,
    _planned_logical_obligation_ids,
    _planned_semantic_model_ids,
    _seal_evidence_row,
)
from equiv_checker.semantics import (
    pure_integer_input_model,
    raw_validator_input_model,
)
from helpers import fast_config


class EvidenceIdentityTests(unittest.TestCase):
    def test_different_scripts_cannot_share_obligation_or_attempt(self) -> None:
        abi_id = "a" * 64
        old_a = program_artifact_id(b"old-a", "v3", "single_cbor_hex")
        new_a = program_artifact_id(b"new-a", "v3", "single_cbor_hex")
        old_b = program_artifact_id(b"old-b", "v3", "single_cbor_hex")
        new_b = program_artifact_id(b"new-b", "v3", "single_cbor_hex")
        pair_a = program_pair_id(old_a, new_a, abi_id)
        pair_b = program_pair_id(old_b, new_b, abi_id)
        model = pure_integer_input_model()
        model_id = model.semantic_model_id(100)
        obligation_a = logical_obligation_id(
            pair_a, model_id, "observational_equivalence"
        )
        obligation_b = logical_obligation_id(
            pair_b, model_id, "observational_equivalence"
        )
        checker = "c" * 64
        attempt_a = attempt_id(
            logical_obligation_id_value=obligation_a,
            checker_configuration_id_value=checker,
            random_seed=1,
            solver_timeout=30,
            process_timeouts={"z3": 30},
            platform_identity_value={"system": "test"},
            attempt_sequence=1,
        )
        attempt_b = attempt_id(
            logical_obligation_id_value=obligation_b,
            checker_configuration_id_value=checker,
            random_seed=1,
            solver_timeout=30,
            process_timeouts={"z3": 30},
            platform_identity_value={"system": "test"},
            attempt_sequence=1,
        )
        self.assertNotEqual(pair_a, pair_b)
        self.assertNotEqual(obligation_a, obligation_b)
        self.assertNotEqual(attempt_a, attempt_b)

    def test_semantic_model_identity_binds_every_semantic_field(self) -> None:
        model = pure_integer_input_model().to_dict()
        baseline = semantic_model_id(model, 100)
        mutations = {
            "argument_order": ["renamed"],
            "domain_expression": "input >= 0",
            "domain_assumptions": ["Only non-negative integers."],
            "observation": "success_only",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(model)
                changed[field] = value
                self.assertNotEqual(baseline, semantic_model_id(changed, 100))
        changed_type = copy.deepcopy(model)
        changed_type["variables"][0]["type"] = "Data"
        self.assertNotEqual(baseline, semantic_model_id(changed_type, 100))
        self.assertNotEqual(baseline, semantic_model_id(model, 101))

    def test_checker_identity_binds_versions_and_revisions(self) -> None:
        arguments = {
            "lean_version": "4.24.0",
            "revisions": {
                "Lean-blaster": "1" * 40,
                "PlutusCoreBlaster": "2" * 40,
                "CardanoLedgerApiBlaster": "3" * 40,
            },
            "z3_version": "4.15.2",
            "solver": "z3",
            "solver_binary_sha256": "4" * 64,
            "solver_configuration": {"timeout_units": "seconds"},
        }
        baseline = checker_configuration_id(
            checker_configuration_payload(**arguments)
        )
        changes = (
            {"lean_version": "4.25.0"},
            {"z3_version": "4.16.0"},
            {
                "revisions": arguments["revisions"]
                | {"Lean-blaster": "9" * 40}
            },
            {
                "revisions": arguments["revisions"]
                | {"PlutusCoreBlaster": "8" * 40}
            },
        )
        for change in changes:
            with self.subTest(change=change):
                updated = arguments | change
                self.assertNotEqual(
                    baseline,
                    checker_configuration_id(
                        checker_configuration_payload(**updated)
                    ),
                )

    def test_attempt_identity_binds_seed_timeout_and_sequence(self) -> None:
        common = {
            "logical_obligation_id_value": "1" * 64,
            "checker_configuration_id_value": "2" * 64,
            "random_seed": 1,
            "solver_timeout": 30,
            "process_timeouts": {"z3": 30},
            "platform_identity_value": {"system": "test"},
            "attempt_sequence": 1,
        }
        baseline = attempt_id(**common)
        for change in (
            {"random_seed": 2},
            {"solver_timeout": 31},
            {"process_timeouts": {"z3": 31}},
            {"platform_identity_value": {"system": "other"}},
            {"attempt_sequence": 2},
        ):
            with self.subTest(change=change):
                self.assertNotEqual(baseline, attempt_id(**(common | change)))


class ResultProtocolTamperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.expected = {
            "program_pair_id": "1" * 64,
            "logical_obligation_id": "2" * 64,
            "semantic_model_id": "3" * 64,
            "checker_configuration_id": "4" * 64,
            "checker_implementation_id": "9" * 64,
            "old_script_sha256": "5" * 64,
            "new_script_sha256": "6" * 64,
            "verified_abi_id": "7" * 64,
            "obligation_kind": "observational_equivalence",
            "theorem_statement_hash": "8" * 64,
            "generated_source_schema_version": GENERATED_LEAN_SCHEMA_VERSION,
        }
        self.marker = {
            "protocol_version": RESULT_PROTOCOL,
            **self.expected,
            "solver_status": "valid",
        }

    def test_valid_marker_accepts_then_each_binding_tamper_rejects(self) -> None:
        self.assertEqual(
            validate_result_marker(self.marker, self.expected), self.marker
        )
        for field in self.expected:
            with self.subTest(field=field):
                tampered = self.marker | {field: "f" * 64}
                with self.assertRaises(ValueError):
                    validate_result_marker(tampered, self.expected)

    def test_protocol_schema_and_solver_tampering_reject(self) -> None:
        mutations = (
            self.marker | {"protocol_version": "EQUIV_RESULT_V1"},
            self.marker | {"solver_status": "unknown"},
            self.marker | {"unexpected": True},
            {
                key: value
                for key, value in self.marker.items()
                if key != "verified_abi_id"
            },
        )
        for marker in mutations:
            with self.subTest(marker=marker):
                with self.assertRaises(ValueError):
                    validate_result_marker(marker, self.expected)


class CachePoisoningTests(unittest.TestCase):
    def _pair(
        self,
        root: Path,
        *,
        old_hex: str = "46010100200101",
        new_hex: str = "46010100248001",
        abi_id: str = "a" * 64,
    ) -> ProgramPairRecord:
        artifacts = []
        root.mkdir(parents=True, exist_ok=True)
        for label, encoded in (("old", old_hex), ("new", new_hex)):
            path = root / f"{label}.flat"
            path.write_text(encoded + "\n", encoding="ascii")
            raw = bytes.fromhex(encoded)
            artifacts.append(
                ScriptArtifact(
                    path=path,
                    relative_path=f"{label}.flat",
                    sha256=hashlib.sha256(raw).hexdigest(),
                    size=len(raw),
                    plutus_version="v3",
                    serialization_format="single_cbor_hex",
                    compiler_artifact_id=label,
                )
            )
        return ProgramPairRecord(
            program_pair_id="b" * 64,
            old_script=artifacts[0],
            new_script=artifacts[1],
            verified_abi_id=abi_id,
            verified_abi={
                "status": "verified",
                "top_level_callable_arity": 1,
                "applied_parameter_count": 0,
                "remaining_runtime_argument_count": 1,
                "argument_order": ["script_context_data"],
                "argument_value_representation": ["PlutusData"],
                "parameter_schemas": [],
                "plutus_version": "v3",
            },
            plutus_version="v3",
            handler_pair_ids=("handler",),
            handler_references=(
                {"handler_pair_id": "handler", "purpose": "minting"},
            ),
        )

    def _cached_row(self, pair: ProgramPairRecord, config) -> dict:
        model = raw_validator_input_model(pair)
        row = _pair_result(
            pair,
            model,
            "equivalent_under_raw_model",
            None,
            source={},
            compilers={},
            config=config,
        )
        row["cache_binding"]["semantic_model_ids"] = (
            _planned_semantic_model_ids(pair, config)
        )
        row["cache_binding"]["logical_obligation_ids"] = (
            _planned_logical_obligation_ids(pair, config)
        )
        return _seal_evidence_row(row)

    def test_cache_reuse_rejects_script_abi_model_checker_and_schema_changes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pair = self._pair(root)
            config = fast_config(root)
            model = raw_validator_input_model(pair)
            row = self._cached_row(pair, config)
            self.assertTrue(
                _cached_pair_matches(row, pair, model, {}, {}, config)
            )
            changed_script = self._pair(
                root / "changed-script",
                old_hex="46010100248001",
            )
            changed_abi = replace(pair, verified_abi_id="c" * 64)
            changed_model = replace(
                model,
                domain_expression="False",
                domain_assumptions=("Empty domain.",),
            )
            changed_checker = replace(
                config,
                revisions=config.revisions | {"Lean-blaster": "9" * 40},
            )
            cases = (
                (changed_script, raw_validator_input_model(changed_script), config),
                (changed_abi, raw_validator_input_model(changed_abi), config),
                (pair, changed_model, config),
                (pair, model, changed_checker),
            )
            for changed_pair, changed_input, changed_config in cases:
                with self.subTest(
                    pair=changed_pair.verified_abi_id,
                    model=changed_input.domain_expression,
                ):
                    self.assertFalse(
                        _cached_pair_matches(
                            row,
                            changed_pair,
                            changed_input,
                            {},
                            {},
                            changed_config,
                        )
                    )
            schema_tamper = copy.deepcopy(row)
            schema_tamper["cache_binding"][
                "generated_source_schema_version"
            ] = "equiv-generated-lean/v999"
            _seal_evidence_row(schema_tamper)
            self.assertFalse(
                _cached_pair_matches(
                    schema_tamper, pair, model, {}, {}, config
                )
            )
            checksum_tamper = copy.deepcopy(row)
            checksum_tamper["status"] = "confirmed_non_equivalent"
            self.assertFalse(
                _cached_pair_matches(
                    checksum_tamper, pair, model, {}, {}, config
                )
            )


if __name__ == "__main__":
    unittest.main()
