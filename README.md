# Aiken validator equivalence checker

`equiv-checker` compiles one locked Aiken package with labeled old and new compiler binaries, pairs validators by stable blueprint identity, compares canonical serialized script bytes, and sends only different script pairs to pinned Lean-blaster. It emits a JSON-schema-validated result bundle and an optional strict gate.

## Prerequisites and one-command smoke test

Install Python 3.11+, `uv`, `elan`/Lake, Aiken, and Z3 4.15.4. The checked-in Lake workspace pins Lean 4.24.0 and exact revisions of Lean-blaster, PlutusCoreBlaster, and CardanoLedgerApiBlaster. Then run:

```bash
make setup-smoke
```

This installs locked Python dependencies, builds the pinned Blaster backend, compares a parameterized Aiken package without sentinel metadata, proves a structurally different equivalent UPLC pair `blaster_valid`, falsifies a non-equivalent pair, and replays its integer witness through the PlutusCore CEK evaluator.

For the default Aiken pair, install v1.1.22 and v1.1.23 with `aikup`, or set `AIKEN_OLD` and `AIKEN_NEW` to binaries whose hashes match `corpus/compiler_pair.json`.

## Commands

Normal package comparison does not read or require `coverage/feature-manifest.json`:

```bash
cd tool
uv run equiv-checker compare ../path/to/package \
  --old-aiken ../bin/aiken-old \
  --new-aiken ../bin/aiken-new \
  --old-revision OLD_COMMIT \
  --new-revision NEW_COMMIT \
  --strict
```

The language-feature sentinel is a separate strict gate:

```bash
cd tool
uv run equiv-checker sentinel \
  --old-aiken ../bin/aiken-old \
  --new-aiken ../bin/aiken-new \
  --strict
```

Run one or more entries from a locked corpus manifest:

```bash
cd tool
uv run equiv-checker corpus run ../corpus/aiken_mandatory_corpus.json \
  --old-aiken ../bin/aiken-old \
  --new-aiken ../bin/aiken-new
```

Omit compiler flags to use the v1.1.22/v1.1.23 defaults in `corpus/compiler_pair.json`. Old and new are labels: distinct binaries remain distinct even when `--version` returns the same text. Omit `--strict` for best-effort reporting; `strict_pass` still records whether the strict gate would pass.

## Architecture and semantic contract

1. `runner.py` hashes compiler binaries, package source, dependency lock, checker configuration, and Blaster configuration to derive a stable run ID.
2. Old and new builds run concurrently in isolated copies. The original package and lock are hashed again after the run.
3. `pairing.py` reads both blueprints. Identity includes package identity/path, module, validator name, purpose, parameter count and schemas, datum/redeemer schemas, and blueprint title. Missing and changed validators are compatibility results.
4. Canonical `compiledCode` bytes are hashed and compared. Equal bytes return final status `identical`; no AST normalization can bypass Blaster.
5. `blaster.py` imports each different pair from single-CBOR hex, prepares both with the same modeled inputs and fuel, and uses a fuel-preserving CEK wrapper to prove that both preparations terminate within that fuel. Failure of this check is `blaster_inconclusive`.
6. A separately timed optimization stage precedes the explicit quantified theorem and the `Valid`, `Falsified`, or `Undetermined` verdict.
7. A replayable falsification is executed through the unoptimized PlutusCore CEK evaluator. Only an observed difference becomes `confirmed_non_equivalent`.
8. `runner.py` writes and validates the machine-readable bundle and applies the strict status allowlist.

For every pair, the formula is:

```text
forall modeled_input:
  domain(modeled_input) implies
  observe(old_program(modeled_input)) = observe(new_program(modeled_input))
```

Validator observation is successful versus unsuccessful CEK evaluation. Validator parameters, datum, redeemer, script context, and purpose inputs range over the broadest representable pinned model; the current default does not impose a ledger-validity predicate. The unrestricted domain is checked as non-vacuous from explicitly inhabited model types. Pure integer golden fixtures distinguish returned integers, evaluator errors, and non-integer values. CPU, memory, traces, diagnostics, and generated names are recorded separately and never affect the semantic verdict.

A `blaster_valid` result means equivalent under the pinned Blaster model and configured preparation fuel. It is not a reconstructed Lean proof.

## Result bundle

Each run is written under `work/runs/<run-id>/`:

```text
run.json
build-old.json
build-new.json
script-pairs.json
pair-results.json
feature-coverage.json
summary.json
summary.md
logs/
generated-lean/
counterexamples/
```

Strict mode passes only `identical`, `blaster_valid`, `expected_negative_diagnostic`, and `not_applicable`. Build failures, compatibility changes, unsupported behavior, inconclusive results, timeouts, errors, unreplayed falsifications, and confirmed differences fail.

Concrete replay currently converts integer witnesses used by the pure golden lane. Structured ledger-model witnesses that Blaster renders only as Lean display text remain `blaster_falsified_unreplayed`; strict mode rejects them rather than claiming a compiler bug.

## Reproducible demonstrations

```bash
cd tool
uv run python -m unittest \
  tests.test_real_blaster.RealBlasterGoldenTests.test_structurally_different_programs_are_blaster_valid -v
```

```bash
cd tool
uv run python -m unittest \
  tests.test_real_blaster.RealBlasterGoldenTests.test_falsification_is_replayed_by_the_actual_cek_evaluator -v
```

The first command must report `blaster_valid`. The second must extract an integer witness, replay different CEK results, and verify `confirmed_non_equivalent` is outside the strict passing set.
