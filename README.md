# Aiken validator equivalence checker

`equiv-checker` is a fail-closed Aiken v1.1.22 versus v1.1.23 compiler gate. It builds isolated copies of locked packages with both pinned compilers, discovers and pairs validators by stable blueprint identity, compares exact serialized UPLC bytes, sends only different pairs to pinned Lean-blaster, and independently replays validator counterexamples with Aiken's CEK evaluator.

## Pinned setup

Requirements: Python 3.11+, `uv`, and `elan`/Lake. Install the platform-specific Aiken v1.1.22, Aiken v1.1.23, and Z3 4.15.2 artifacts declared in the checked-in configurations:

```bash
python3 scripts/setup_toolchains.py
cd tool
uv sync --locked
cd blaster-backend
lake build CardanoLedgerApi
cd ../..
```

The setup script verifies archive and executable SHA-256 hashes and creates:

```text
bin/aiken-v1.1.22
bin/aiken-v1.1.23
work/toolchains/<pinned-z3>/bin/z3
```

`corpus/compiler_pair.json` records compiler releases, full revisions, archive hashes, binary hashes, and platform artifacts. `tool/blaster_config.json` pins Lean 4.24.0, Z3 4.15.2, the Blaster repositories, the independent evaluator, all stage timeouts, random seed, and the semantic runtime bound.

## Mandatory workflows

Plan all locked targets without compiling:

```bash
cd tool
uv run equiv-checker corpus plan ../corpus/aiken_mandatory_corpus.lock.json
```

Run the complete feature sentinel:

```bash
uv run equiv-checker sentinel \
  --old-aiken ../bin/aiken-v1.1.22 \
  --new-aiken ../bin/aiken-v1.1.23 \
  --feature-contract ../corpus/aiken_language_features_v1_1_23.json \
  --resume \
  --strict
```

Run all mandatory sources and all expanded package tasks:

```bash
uv run equiv-checker corpus run ../corpus/aiken_mandatory_corpus.lock.json \
  --old-aiken ../bin/aiken-v1.1.22 \
  --new-aiken ../bin/aiken-v1.1.23 \
  --jobs 8 \
  --resume
```

Normal package comparisons support `--resume` and `--force`. Corpus runs additionally support repeatable `--only SOURCE_OR_TARGET`, cached `--only-pair PAIR_ID`, and deterministic `--shard-index N --shard-count M`.

Capture a compact, relocatable baseline after both runs:

```bash
cd ..
cd tool
uv run python ../scripts/capture_baseline.py \
  --sentinel-run ../work/runs/<sentinel-run-id> \
  --corpus-run ../work/corpus-runs/<corpus-run-id>
```

## Semantic boundary

The primary formula is:

```text
forall raw_arguments:
  observe(old_program(raw_arguments)) =
  observe(new_program(raw_arguments))
```

Validator observation has three logical outcomes:

```text
success
failure
runtime-bound exhaustion
```

Runtime-bound exhaustion is never collapsed into validator failure. Pure-function fixtures additionally distinguish returned values, evaluation failure, and unexpected result types. CPU, memory, trace text, compiler diagnostics, generated names, and file paths are evidence only and never affect the logical verdict.

### `raw-uplc/v1`

This is the mandatory compiler-equivalence profile. Each validator parameter and each actual compiled script argument ranges over all Plutus `Data`, including values malformed for the source-level schema. Argument order and arity come from the compiled interface. Plutus V3 scripts receive their raw `ScriptContext` data argument; datum, redeemer, and purpose encodings are therefore included without assuming ledger validity. The generated Lean file defines a concrete `Data.I 0` tuple and elaborates its membership in the unrestricted domain.

### `ledger-valid/v1`

This secondary profile uses the pinned CardanoLedgerApiBlaster conversions. Plutus V1/V2 spending, minting, rewarding, and certifying use their `valid<Purpose>Context` predicates. Plutus V3 uses:

```text
validScriptContext ledger_input &&
is<Purpose>ScriptInfo ledger_input
```

Its non-vacuity stage asks Blaster for a concrete model of the purpose-specific predicate. Ledger-valid success cannot override a raw-model difference. An Aiken `else` handler is never treated as spending: V3 fallback is covered by the raw context encoding, while the single-purpose ledger profile is explicitly unsupported.

## Fuel and verdicts

`#import_uplc` fuel limits import elaboration. `#prep_uplc` fuel limits symbolic preparation. Lean elaboration, Blaster optimization, and Z3 each have separate wall-clock timeouts. Any exhaustion or tool failure is inconclusive.

The configured `semantic_runtime_step_bound` is different: the generated observation executes each modeled input for at most that many CEK transitions and exposes exhaustion as a distinct result. Therefore a solver-valid non-identical pair is `bounded_equivalent`, not unrestricted logical equivalence, and it does not pass strict mode. Exact serialized-byte equality remains the unconditional `identical` fast path.

Strict semantic passing statuses are:

```text
identical
equivalent_under_raw_model
expected_negative_diagnostic
not_applicable
```

Missing locks or evidence, bounded results, unsupported models or purposes, non-vacuity failures, preparation exhaustion, timeouts, solver errors, malformed witnesses, unreplayed falsifications, compatibility changes, and confirmed differences all fail closed.

## Counterexample protocol and replay

Lean emits exactly one versioned `EQUIV_RESULT_V1` JSON marker bound to the pair ID and theorem hash. The adapter rejects missing, duplicate, malformed, unknown, identity-mismatched, and exit-code-conflicting markers.

Structured witnesses cover integers, bytes, booleans, Plutus data constructors, lists, maps, validator parameters, and raw script-context data. A falsified validator is initially `blaster_falsified_unreplayed`. The pinned Aiken v1.1.23 `uplc eval --cbor` evaluator then executes the old and new serialized scripts with identical encoded arguments and limits. Only different independent observations produce `confirmed_non_equivalent`.

## Corpus execution

The executable lock uses full source commits and expands root, nested, and multi-package targets deterministically. Source-specific overlays, patches, and harnesses live under `corpus/adapters/<SOURCE_ID>/` and are applied only to isolated copies. Adapter, overlay, patch, harness, source, and dependency-lock hashes are recorded.

Corpus compiler subprocesses receive an allowlisted environment rather than the parent environment; account tokens, SSH agents, credential helpers, and arbitrary CI secrets are not inherited. Git configuration is disabled and interactive credential prompts are rejected. Aiken retains network access for public dependency materialization because the runner has no portable OS-level network namespace; corpus source files are treated as compiler input and are never executed as host commands.

Lanes are independent:

```text
compile
check
bench
config
docs
equivalence
negative-diagnostic
```

Compile-only, benchmark, configuration, and documentation targets do not require validators. Every task records old/new results, expected outcome, classification, logs, hashes, timeout, source immutability, and strict policy.

## Evidence and resume

Logical identities exclude absolute paths, host names, timestamps, temporary directories, and strict-mode policy. Completed comparison bundles are never deleted implicitly. `--resume` validates schemas and every individual pair result before reuse. `--force` preserves the previous bundle under `work/attempts/<run-id>/<sequence>/`.

Each comparison bundle contains:

```text
run.json
build-old.json
build-new.json
script-pairs.json
pair-results.json
pairs/<pair-id>/result.json
feature-coverage.json
summary.json
summary.md
logs/
generated-lean/
counterexamples/
```

Corpus runs store one `result.json` per stable task. Compact committed baseline metadata lives under `results/baselines/aiken-v1.1.22-v1.1.23/`; large logs, generated Lean, SMT files, and full bundles remain CI artifacts.

## Verification and CI

Run the complete Python and real-tool suite once:

```bash
cd tool
uv run python -m unittest discover -s tests -p 'test_*.py' -v
```

The real suite covers distinct Aiken compiler builds, exact-byte equality, non-identical bounded equivalence, size-dependent runtime work, validator-shaped structured falsification, independent CEK replay, and fail-closed classifications.

CI is split by cost and trust boundary. Pull requests run unit, schema, and fake-tool tests without downloading toolchains. The nightly scheduled job installs and hash-verifies both Aiken compilers and Z3, builds the pinned Lean dependencies, then runs each real smoke module once. Manual dispatch accepts `sentinel`, `first-wave`, or `full-corpus`; the full-corpus option runs the planner, strict sentinel, all mandatory tasks, baseline capture, and uploads the complete run bundles.
