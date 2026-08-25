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

For an optimization branch, build both manifests from explicit source checkouts so
the evidence records the exact base and candidate trees:

```bash
uv run equiv-checker compiler build-local \
  --aiken-source /path/to/clean/aiken-v1.1.23 \
  --label base \
  --output ../.ak-equiv/compilers/base
uv run equiv-checker compiler build-local \
  --aiken-source /path/to/aiken-optimization-branch \
  --label candidate \
  --output ../.ak-equiv/compilers/candidate
```

Use `--allow-dirty` only for development evidence. Commit the candidate source
and rebuild before evaluating release publishability.

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

Gate a local compiler candidate through release provenance, the complete
sentinel, and every mandatory corpus task:

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

Screen the same policy-neutral evidence without recompiling or repeating solver
work by changing only `--policy screening`. The evidence run ID and the strict
and screening decision IDs remain unchanged; only the selected-decision ID
changes. Screening may accept `bounded_equivalent`, but preserves that semantic
state, cannot alter the strict decision, and is never publishable.

Verify the emitted bundle independently:

```bash
uv run equiv-checker candidate verify work/candidate-gates/<evidence-run-id>
```

Dirty or uncommitted candidates still complete semantic work, but their evidence
is labeled `development_only` and cannot be published. A publishable result
requires a strict pass, clean committed candidate source, verified source and
dependency inputs, a self-verified bundle, and a signed trusted-main CI archive.

Normal package comparisons support `--resume` and `--force`. Corpus runs
additionally support repeatable `--only SOURCE_OR_TARGET`, cached
`--only-pair PAIR_ID`, and deterministic
`--shard-index N --shard-count M`.

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
`identity_schema_version = equiv-evidence-identity/v3` and an identity kind.
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
- A checker implementation ID hashes the complete deterministic checker source
  tree: Python checker modules, JSON schemas, Rust shim sources and locks,
  checked-in Lean adapters and templates, Blaster toolchain metadata, and tool
  configuration and lock files. Generated data, caches, logs, work directories,
  and build outputs are excluded.
- A checker configuration binds that implementation ID, the generated-Lean,
  result, and witness protocol versions, Lean and Z3 versions, pinned
  Blaster/importer/preparer revisions, solver binary, and relevant solver
  configuration.
- An execution attempt represents one generated Lean process. It binds the
  complete execution plan, generated-source hash, checker configuration,
  process and solver timeouts, random seed, platform, and execution sequence.
- An obligation attempt binds exactly one logical obligation and checker
  configuration to its execution attempt, relevant solver options, and
  obligation attempt sequence. Several obligation attempts may share one
  execution attempt; one obligation attempt ID may never identify different
  logical obligations.

The evidence run ID binds compiler artifacts, all source and dependency inputs,
the feature contract, corpus lock, scope, checker implementation and
configuration, semantic models, and runtime bounds. Strict, screening, selected
policy, and CLI exit preference are excluded. Strict and screening decision IDs
separately bind the evidence run ID and their policy schema and configuration.

Global cache reuse requires the exact logical obligation, checker configuration
and implementation, generated-source schema, scripts, verified ABI, semantic
model, generated Lean checksum, and sealed artifact checksums. Each entry is
staged and atomically renamed under an exclusive per-obligation lock. Partial,
malformed, symlinked, or corrupt entries are quarantined before recomputation.

## Result, witness, and replay protocols

Every solver verdict uses one strict-schema `EQUIV_RESULT_V3` JSON marker. It
binds the checker implementation and configuration, program pair, exact logical
obligation, semantic model, both script hashes, verified ABI, obligation kind,
theorem statement, generated-source schema, and solver status. Missing,
duplicate, malformed, unknown, mismatched, or exit-code-conflicting markers are
rejected.

`EQUIV_WITNESS_V3` binds a witness to its producing logical obligation,
obligation attempt, and execution attempt, as well as the pair, theorem, model,
ordered names and types, structured values, serialized UPLC terms, domain
evidence, and witness checksum. Results that did not produce a witness carry a
null witness reference. The pinned upstream fallback remains explicitly labeled
`witness_source = legacy_human_parser`; normalized fallback output is not
described as a native witness and must be concretely replayed before it can
confirm a semantic difference.

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

Compile-only, benchmark, configuration, and documentation targets do not require validators. Every task records old/new results, expected outcome, final classification, logs, hashes, timeout, and source/dependency immutability. Release policy is derived later from those policy-neutral records.

## Evidence identity, reuse, and bundles

Candidate execution has five ordered phases: build and discovery for every
selected task, one global content-addressed obligation plan, exact cache lookup,
execution of each remaining unique obligation, then consumer linking and policy
decisions. Blaster is not invoked during discovery. Shared results link back to
every handler, feature, task, and source that consumes them.

Final bundles contain no pending obligations. Unsupported ledger profiles are
represented by explicit `ledger_model_unsupported` omission records. Optional
ledger omissions do not override or block complete raw equivalence; missing or
unsupported required raw evidence always blocks strict mode.

Candidate bundles contain:

```text
candidate-manifest.json
global-plan.json
global-program-pairs.json
global-semantic-obligations.json
program-artifacts.json
program-pairs.json
semantic-models.json
semantic-model-omissions.json
semantic-obligations.json
obligation-results.json
execution-attempts.json
witnesses.json
replays.json
validator-links.json
feature-links.json
task-results.json
source-results.json
evidence-lineage.json
pair-classifications.json
strict-decision.json
screening-decision.json
selected-decision.json
environment.json
feature-contract.json
corpus-lock.json
compiler-release-lock.json
ci-attestation.json
checksums.json
```

`candidate verify` recomputes input hashes, content identities, compiler and ABI
identities, semantic and attempt identities, witness and replay parentage,
cache-reuse lineage, all consumer links, classifications, decisions, checksums,
and count invariants. Archive verification additionally requires GitHub
Sigstore provenance from `.github/workflows/ci.yml` on `refs/heads/main`.

Schema-version-3 historical baselines are published under `results/baselines/`
only by the trusted `baseline-v3-publication` job after both real profiles
succeed. Until that publication commit lands, checked-in schema-version-2
baselines remain explicit legacy data and the read-only jobs skip, rather than
reinterpret, them. Version 3 validation covers complete checksums, attempt and
witness lineage, clean source provenance, content identity, and public CI
attestation:

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
baseline-attestation, and fake-tool tests. Main-branch pushes also run the real
changed-output candidate path. Scheduled, manual, and main-branch runs execute
the complete strict candidate gate across the sentinel and all mandatory tasks,
self-verify the bundle, sign the archive with GitHub artifact provenance, and
upload the gate, bundle, manifests, and release verification. Only the separate
baseline-publication job receives `contents: write`; all actions are full-SHA
pinned.
