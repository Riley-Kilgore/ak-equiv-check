from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from equiv_checker.pairing import discover_validators, pair_validators
from helpers import IDENTITY_HEX, validator


class ValidatorPairingTests(unittest.TestCase):
    def _blueprint(self, path: Path, validators: list[dict]) -> Path:
        path.write_text(json.dumps({"validators": validators}), encoding="utf-8")
        return path

    def test_pairing_is_stable_and_independent_of_array_position(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = validator("alpha.first.mint")
            second = validator("beta.second.spend")
            old = self._blueprint(root / "old.json", [first, second])
            new = self._blueprint(root / "new.json", [second, first])
            result = pair_validators(
                old,
                new,
                root / "bundle-a",
                package_identity="repo@commit:package",
                package_path="/package",
                plutus_version="v3",
            )
            repeated = pair_validators(
                old,
                new,
                root / "bundle-b",
                package_identity="repo@commit:package",
                package_path="/package",
                plutus_version="v3",
            )
            self.assertEqual(
                [pair.pair_id for pair in result.pairs],
                [pair.pair_id for pair in repeated.pairs],
            )
            self.assertEqual(len(result.pairs), 2)
            self.assertEqual(result.compatibility_results, ())

    def test_duplicate_features_share_one_script_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = validator()
            old = self._blueprint(root / "old.json", [row])
            new = self._blueprint(root / "new.json", [row])
            result = pair_validators(
                old,
                new,
                root / "bundle",
                package_identity="source",
                package_path="/package",
                plutus_version="v3",
                covered_features_by_title={row["title"]: {"FEATURE-A", "FEATURE-B", "FEATURE-A"}},
            )
            self.assertEqual(len(result.pairs), 1)
            self.assertEqual(
                result.pairs[0].covered_feature_ids,
                ("FEATURE-A", "FEATURE-B"),
            )

    def test_missing_and_changed_validators_are_compatibility_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unchanged = validator("module.unchanged.mint")
            old_only = validator("module.old_only.mint")
            new_only = validator("module.new_only.mint")
            old_changed = validator(
                "module.changed.mint",
                parameters=[{"title": "p", "schema": {"type": "integer"}}],
            )
            new_changed = validator(
                "module.changed.mint",
                parameters=[{"title": "p", "schema": {"type": "bytes"}}],
            )
            old = self._blueprint(root / "old.json", [unchanged, old_only, old_changed])
            new = self._blueprint(root / "new.json", [unchanged, new_only, new_changed])
            result = pair_validators(
                old,
                new,
                root / "bundle",
                package_identity="source",
                package_path="/package",
                plutus_version="v3",
            )
            self.assertEqual(len(result.pairs), 1)
            self.assertEqual(
                {row["status"] for row in result.compatibility_results},
                {
                    "validator_missing_old",
                    "validator_missing_new",
                    "validator_signature_changed",
                },
            )

    def test_script_hash_uses_canonical_serialized_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = validator(compiled_code=IDENTITY_HEX.upper())
            old = self._blueprint(root / "old.json", [row])
            new = self._blueprint(root / "new.json", [row])
            result = pair_validators(
                old,
                new,
                root / "bundle",
                package_identity="source",
                package_path="/package",
                plutus_version="v3",
            )
            expected = hashlib.sha256(bytes.fromhex(IDENTITY_HEX)).hexdigest()
            self.assertEqual(result.pairs[0].old_script.sha256, expected)
            self.assertEqual(result.pairs[0].new_script.sha256, expected)

    def test_named_handlers_and_else_keep_distinct_purposes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = [
                validator("module.multi.spend"),
                validator("module.multi.mint"),
                validator("module.multi.withdraw"),
                validator("module.multi.publish"),
                validator("module.multi.vote"),
                validator("module.multi.propose"),
                validator("module.multi.else"),
            ]
            blueprint = self._blueprint(root / "plutus.json", rows)
            discovered = discover_validators(blueprint)
            self.assertEqual(
                {row.purpose for row in discovered},
                {
                    "spending",
                    "minting",
                    "rewarding",
                    "certifying",
                    "voting",
                    "proposing",
                    "fallback",
                },
            )
            self.assertEqual(
                sum(row.purpose == "fallback" for row in discovered),
                1,
            )


if __name__ == "__main__":
    unittest.main()
