# Aiken codegen feature sentinel repository specification

**Language baseline:** Aiken `v1.1.23`  
**Contract:** 306 language/project rows and 87 active UPLC builtins.  

## Purpose

Create one small team-owned repository that keeps rare features stable and reachable. Public repositories can move, remove syntax, or place a feature behind dead code. The sentinel is the stable floor under the real-world corpus.

## Required layout

```text
aiken-codegen-equivalence-sentinel/
  aiken.toml
  aiken.lock
  lib/
    compile_only/
    checks/
    benchmarks/
  validators/
    features/
    builtins/
  env/
    default.ak
    preview.ak
  coverage/
    feature-manifest.json
    evidence-old.json
    evidence-new.json
```

## Version-pair rule

Generate the feature inventory from the newer compiler. A direct equivalence fixture must parse, type-check, and produce UPLC with both compilers. Record new-only or removed forms in a compatibility lane. Do not send a one-sided build to Lean-blaster.

## Reachability rule

Every direct-codegen fixture must be reachable from a validator handler. Use decoded validator inputs as arguments and a redeemer field as a deterministic branch selector. This prevents constant folding and dead-code removal from creating false coverage.

Each selected branch must affect the validator result. An unused helper does not count.

## Feature fixture rule

- Give each fixture a stable name based on its feature ID.
- Keep one primary feature in each fixture.
- Record the source path, line range, AST evidence, UPLC path, and artifact hash.
- Keep compile-only, check-only, benchmark, configuration, and docs fixtures outside the Blaster lane.
- Isolate intentional `todo`, `fail`, and negative diagnostic cases from positive validators.

## Builtin fixture rule

Create one reachable wrapper for each of the 87 active builtins. Group files by family, but give each builtin its own branch selector and evidence record.

| Family | Builtins |
|---|---:|
| bls12 381 | 17 |
| bytearray | 8 |
| bytearray bitwise | 11 |
| control and trace | 3 |
| conversion | 2 |
| cryptography and hashing | 9 |
| data | 13 |
| data constructors | 3 |
| integer | 10 |
| list | 5 |
| pair | 2 |
| string | 4 |

For each wrapper:

1. Decode at least one argument from a validator input.
2. Keep the builtin in the selected UPLC branch after optimization.
3. Store old and new UPLC paths and hashes.
4. Confirm the expected UPLC builtin name with a structural scan.
5. Run Lean-blaster on the old and new terms.

Use valid deterministic cryptographic inputs. Keep invalid-input behavior in separate branches.

## Project matrix

| Dimension | Required values |
|---|---|
| Plutus target | V3 only for the positive v1.1.23 baseline |
| Rejected targets | V1 and V2 as negative configuration tests |
| Trace level | silent, compact, verbose |
| Trace source | user-defined, compiler-generated, all |
| Conditional selection | default and named environment; default and named configuration |
| Configuration value | Int, Bool, UTF-8 ByteArray, hex ByteArray, homogeneous List, heterogeneous Tuple |
| Package layout | normal package and monorepo member selected by literal path and glob |
| Dependency mode | immutable pins and lockfile |

## Result states

- `equivalent`
- `non_equivalent`
- `blaster_unsupported`
- `blaster_inconclusive`
- `old_language_feature_unsupported`
- `old_compile_failed`
- `new_compile_failed`
- `feature_missing`
- `dead_code_only`
- `expected_negative_diagnostic`

Do not merge `non_equivalent` with build failures. A compile failure is not a semantic counterexample.

## CI release gate

Fail CI when a manifest row lacks evidence, an expected builtin is absent, a positive fixture fails to build, a required Blaster result is missing, or the compiler-surface audit finds a new unmapped form.
