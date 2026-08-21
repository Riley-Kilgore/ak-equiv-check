# Contributing

## Compiler comparison changes

Keep compiler provenance separate from semantic results. Never identify a compiler only by its reported version, and never commit compiler binaries or full generated evidence bundles.

Build a clean candidate from its source checkout:

```bash
cd tool
uv run equiv-checker compiler build-release \
  --aiken-source /path/to/upstream-aiken \
  --ref v1.1.23 \
  --label base \
  --output ../.ak-equiv/compilers/base
uv run equiv-checker compiler build-local \
  --aiken-source /path/to/aiken-candidate \
  --label candidate \
  --output ../.ak-equiv/compilers/candidate
uv run equiv-checker profile run local-candidate \
  --old-compiler-manifest ../.ak-equiv/compilers/base/compiler.json \
  --new-compiler-manifest ../.ak-equiv/compilers/candidate/compiler.json \
  --resume --strict
```

A dirty or untracked compiler source requires explicit permission:

```bash
uv run equiv-checker compiler build-local \
  --aiken-source /path/to/aiken-candidate \
  --label candidate-dirty \
  --allow-dirty \
  --output ../.ak-equiv/compilers/candidate-dirty
```

Retain the resulting `compiler.json`, build logs, and `reproducibility/` bundle in CI artifacts. A dirty build is not reproducible from its HEAD commit alone. The tracked binary diff, untracked source archive, complete source manifest, and hashes are required evidence.

## Historical profiles

When changing `corpus/compiler_profiles.json`, a historical fixture, semantic checker code, or `tool/blaster_config.json`:

1. Re-lock the affected profile and inspect the full release SHAs.
2. Build each release through `compiler build-release`; do not reuse a target directory across releases.
3. Run the profile with the real Blaster backend and independent evaluator.
4. Confirm the semantic status remains unchanged by the expectation layer.
5. Update only compact baseline JSON/NDJSON and checksums. Leave binaries, generated Lean, SMT files, and verbose logs to CI artifacts.

Commands:

```bash
uv run equiv-checker profile lock historical-equivalent-v1.1.21-v1.1.22
uv run equiv-checker profile run historical-equivalent-v1.1.21-v1.1.22 --force

uv run equiv-checker profile lock historical-regression-v1.1.22-v1.1.23
uv run equiv-checker profile run historical-regression-v1.1.22-v1.1.23 --force
```

The positive profile must observe different compiler-generated script hashes and finish as strict `equivalent_under_raw_model`. The regression profile must finish as semantic `confirmed_non_equivalent`, fail the underlying strict gate, and pass its profile expectation only after independent replay confirms distinct observations.

## Verification

Run focused tests while editing, then the complete suite once:

```bash
cd tool
uv run python -m unittest discover -s tests -p 'test_*.py' -v
```

Nightly CI rebuilds both historical pairs and performs a clean local compiler comparison. Its uploaded evidence is the reproducible source for large logs and generated proof artifacts.
