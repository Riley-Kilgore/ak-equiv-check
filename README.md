# Aiken validator equivalence checker

`equiv-checker` is a fail-closed Aiken compiler gate. It builds isolated copies of locked packages with pinned or locally built compilers, discovers and pairs validators by stable blueprint identity, derives the callable ABI from decoded UPLC, compares exact serialized UPLC bytes, sends only different pairs to pinned Lean-blaster, and independently replays validator counterexamples with a separately pinned CEK evaluator.

Logical validator IDs use the normalized repository URL, package subpath, fixture content hash, dependency lock hash, and adapter hash. The enclosing Git commit remains provenance, but unrelated commits and checkout paths do not rename an unchanged validator pair.

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

`corpus/compiler_pair.json` records compiler releases, full revisions, archive hashes, binary hashes, and platform artifacts. `tool/blaster_config.json` pins Lean 4.24.0, Z3 4.15.2, the Blaster repositories, the separately pinned Aiken replay evaluator, all stage timeouts, random seed, and the semantic runtime bound.

## Released and local compiler artifacts

Compiler manifests are the preferred interface. A release build resolves an annotated tag to its full commit, uses a separate checkout and Cargo target directory, runs `cargo build --release --locked`, verifies `aiken --version`, and records source, lockfile, toolchain, binary, environment, and log hashes:

```bash
cd tool
uv run equiv-checker compiler build-release \
  --aiken-repository https://github.com/aiken-lang/aiken \
  --ref v1.1.23 \
  --label base \
  --output ../.ak-equiv/compilers/base
```

Use `--aiken-source /path/to/aiken` instead of `--aiken-repository` to resolve and build from an existing upstream clone. Cached artifacts are reused only when all build inputs and the compiler binary still match their manifest.

`corpus/compiler_release.lock.json` is the release trust root used by the candidate gate. It binds the canonical repository, annotated tag object, resolved commit and Git tree, source tree, `Cargo.lock`, reported Aiken version, required Rust version, build command, and each platform's target, binary, compiler artifact ID, and exact Rust toolchain. A missing release or platform record fails closed.

A clean local candidate:

```bash
uv run equiv-checker compiler build-local \
  --aiken-source /path/to/aiken-candidate \
  --label candidate \
  --output ../.ak-equiv/compilers/candidate
```

A dirty candidate requires explicit permission:

```bash
uv run equiv-checker compiler build-local \
  --aiken-source /path/to/aiken-candidate \
  --label candidate-dirty \
  --allow-dirty \
  --output ../.ak-equiv/compilers/candidate-dirty
```

Dirty manifests are marked non-reproducible from the commit alone. Their `reproducibility/` bundle contains the binary diff for tracked files, every untracked source file, source hashes, and build metadata. Compiler identity uses source and binary hashes, not only the reported version; two local binaries may legitimately report the same Aiken version.

The `local-candidate` profile requires a clean committed release or local artifact as its base and a `build-local` artifact as its candidate. Dirty candidate evidence is allowed; a dirty base is rejected so the reference point remains reproducible.

Compare a released base with a local candidate:

```bash
uv run equiv-checker compare ../fixtures/historical-codegen-equivalent \
  --old-compiler-manifest ../.ak-equiv/compilers/base/compiler.json \
  --new-compiler-manifest ../.ak-equiv/compilers/candidate/compiler.json \
  --strict

uv run equiv-checker profile run local-candidate \
  --old-compiler-manifest ../.ak-equiv/compilers/base/compiler.json \
  --new-compiler-manifest ../.ak-equiv/compilers/candidate/compiler.json \
  --resume --strict
```

Direct `--old-aiken` and `--new-aiken` paths remain supported for non-manifest comparisons.

## Historical release profiles

The immutable profile lock resolves Aiken v1.1.21, v1.1.22, and v1.1.23 to full commits and source trees:

```bash
uv run equiv-checker profile lock historical-equivalent-v1.1.21-v1.1.22
uv run equiv-checker profile lock historical-regression-v1.1.22-v1.1.23

uv run equiv-checker profile run historical-equivalent-v1.1.21-v1.1.22 --resume
uv run equiv-checker profile run historical-regression-v1.1.22-v1.1.23 --resume
```

`historical-equivalent` requires a compiler-generated script delta and strict `equivalent_under_raw_model`. `historical-regression` requires Blaster falsification, structured independent replay, `confirmed_non_equivalent`, and an underlying strict failure. The profile can pass because this expected history was observed, but `semantic_status` is never relabeled.

Coverage claims stay separate. The historical positive baseline demonstrates the real compiler-to-Blaster pipeline, but its shared v1.1.21-v1.1.22 feature contract is intentionally limited to the three source constructs in `fixtures/historical-codegen-equivalent/codegen-triggers.json`. All three are linked to non-identical compiler-generated scripts; no shared fixture feature is claimed only through a byte-identical script. The broader `corpus/aiken_language_features_v1_1_23.json` contract is current-sentinel coverage and is explicitly not applied as historical evidence for the older pair. A candidate-only feature must remain a compatibility difference until that contract is updated.

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

Gate a clean or dirty local compiler candidate through release provenance,
the complete sentinel, and every mandatory corpus task:

```bash
uv run equiv-checker candidate gate \
  --base-compiler-manifest ../.ak-equiv/compilers/base/compiler.json \
  --candidate-compiler-manifest ../.ak-equiv/compilers/candidate/compiler.json \
  --feature-contract ../corpus/aiken_language_features_v1_1_23.json \
  --corpus-lock ../corpus/aiken_mandatory_corpus.lock.json \
  --scope sentinel,mandatory \
  --resume \
  --policy strict
```

Dirty candidates still run semantic checks, but the release decision is
fail-closed and labels their evidence `development_only`.

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

The configured `semantic_runtime_step_bound` is different: the generated observation executes each modeled input for at most that many CEK transitions and exposes exhaustion as a distinct result. A solver-valid non-identical pair is promoted to `equivalent_under_raw_model` only when separate old-program and new-program theorems prove completion within that bound for every modeled input. Without both completion proofs it remains `bounded_equivalent` and cannot pass strict mode. Exact serialized-byte equality remains the unconditional `identical` fast path.

Strict semantic passing statuses are:

```text
identical
equivalent_under_raw_model
expected_negative_diagnostic
not_applicable
```

Missing locks or evidence, bounded results, unsupported models or purposes, non-vacuity failures, preparation exhaustion, timeouts, solver errors, malformed witnesses, unreplayed falsifications, compatibility changes, and confirmed differences all fail closed.

## Evidence identities

All evidence IDs are SHA-256 hashes of canonical JSON envelopes carrying
`identity_schema_version = equiv-evidence-identity/v2` and an identity kind.
The payloads are deliberately separate:

- A program artifact binds the serialized-script SHA-256, Plutus version, and
  serialization format. Its record also carries byte size, source-validator
  references, and compiler artifact ID.
- A program pair binds only the ordered old and new program-artifact IDs and
  the verified ABI ID. Paths, host data, timestamps, handler titles, and policy
  do not affect it.
- A semantic model binds its version and profile, variable types, argument
  order, arity, domain predicate and assumptions, observation, and semantic
  runtime bound. Ledger-valid models additionally bind the purpose-specific
  ledger predicate.
- A logical obligation binds the program-pair ID, semantic-model ID, and one
  explicit obligation kind.
- A checker configuration binds the generated-Lean schema, Lean and Z3
  versions, pinned Blaster/importer/preparer revisions, solver binary, and
  relevant solver configuration.
- An attempt binds the logical obligation and checker configuration to the
  random seed, solver and process timeouts, platform identity, and attempt
  sequence.

Strict and screening policies decide over evidence; they are not logical
obligation identities. Cache reuse requires the logical obligation, checker
configuration, program hashes, verified ABI, semantic model, and generated
source schema to match. Reuse records the original and new attempts plus the
validated artifact checksum.

## Result, witness, and replay protocols

Every solver verdict uses one strict-schema `EQUIV_RESULT_V2` JSON marker. It
binds the program pair, logical obligation, semantic model, checker
configuration, both script hashes, verified ABI, obligation kind, theorem
statement, generated-source schema, and solver status. Missing, duplicate,
malformed, unknown, mismatched, or exit-code-conflicting markers are rejected.

`EQUIV_WITNESS_V2` is the native machine-witness protocol. It binds the same
pair, obligation, theorem, and model to ordered names, types, structured
values, serialized UPLC terms, domain evidence, and a witness checksum.
Unsupported values, lossy serialization, wrong order or arity, domain
violations, duplicate markers, and conflicting witnesses are rejected. The
pinned upstream fallback is explicitly labeled
`witness_source = legacy_human_parser`; every fallback value is reserialized
and concretely replayed before it can confirm a difference.

Replay records configured, effective, evaluator-enforced, externally enforced,
and unenforced limits separately. The separately pinned Aiken evaluator is a
separate binary and separate from the symbolic model, but it is not a distinct
UPLC implementation; agreement is therefore `single_evaluator_confirmed`.
A configured distinct second backend can raise replay confidence to
`cross_evaluator_confirmed` without changing the semantic verdict.

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

## Evidence identity, reuse, and bundles

Program artifacts are identified by serialized bytes, Plutus version, and
serialization format. Program pairs add the ordered old/new artifact IDs and
verified ABI ID. Semantic models bind variable types, argument order, arity,
domain and assumptions, observation, semantic runtime bound, and any
purpose-specific ledger predicate. Logical obligations combine a program pair,
semantic model, and explicit obligation kind. Checker configurations bind the
Lean, Blaster, importer, preparer, ledger-model, and Z3 revisions and solver
configuration. Attempts additionally bind seed, process and solver timeouts,
platform, and attempt sequence. Policy is a decision over this evidence, not
part of its logical identity.

Absolute paths, host names, timestamps, temporary directories, handler titles,
and strict policy do not affect semantic identity. `--resume` accepts cached
evidence only when the obligation, checker, script hashes, ABI, model,
generated-source schema, generated Lean checksum, and sealed artifact checksum
all validate. `--force` preserves the previous bundle under
`work/attempts/<run-id>/<sequence>/`.

Comparison bundles contain separate validator, handler-pair, program-pair,
semantic-obligation, obligation-result, validator-link, and feature-link
records. Multiple blueprint handlers may link to one raw UPLC obligation;
purpose-specific ledger domains remain distinct.

Candidate gates emit:

```text
release-decision.json
release-decision.md
program-pairs.json
semantic-obligations.json
obligation-results.json
validator-links.json
feature-links.json
task-results.json
evidence-lineage.json
environment.json
checksums.json
```

Schema-version-2 historical baselines live under `results/baselines/`.
Validate their complete checksums, parent lineage, clean source provenance,
content identity, and public CI attestation with:

```bash
uv run equiv-checker baseline verify \
  ../results/baselines/historical-equivalent-v1.1.21-v1.1.22
```

Large compiler logs, generated Lean, SMT files, evaluator logs, binaries, and
complete run bundles remain CI artifacts.

## Verification and CI

Run the complete Python and real-tool suite once:

```bash
cd tool
uv run python -m unittest discover -s tests -p 'test_*.py' -v
```

The real suite covers released compiler builds, exact-byte equality,
non-identical strict equivalence with separate completion obligations,
validator-shaped structured falsification, concrete CEK replay, local clean
and dirty compiler provenance, and fail-closed classifications.

CI is split by cost and trust boundary. Pull requests run unit, schema,
identity, protocol-tamper, cache-poisoning, deduplication, report-invariant,
baseline-attestation, and fake-tool tests. Scheduled and main-branch jobs
separately run the released positive and negative profiles, a real changed-
output local v1.1.22 candidate against the v1.1.21 base, and a current
same-source local smoke. All actions are full-SHA pinned and evidence jobs
upload complete bundles.
