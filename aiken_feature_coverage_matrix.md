# Aiken v1.1.23 feature-coverage matrix

**Baseline:** Aiken `v1.1.23`  
**Generated:** 2026-08-13  
**Contract:** 306 language, compiler, and project rows plus 87 active UPLC builtins.  

## Coverage decision

The 260-repository longlist gives broad real-world behavior. It does not prove complete feature coverage by itself. This matrix adds tagged compiler-surface mappings, mandatory public sources, and a required team-owned sentinel repository.

A feature counts only when the scanner records it and every required lane passes. A README statement, repository topic, or unused function does not count.

## Version-pair rule

Build the feature inventory from the newer compiler. Send a row to Lean-blaster only when both compilers accept the same source and both produce UPLC. Treat new-only syntax, removed syntax, and front-end failures as compatibility results, not semantic counterexamples. Keep one immutable manifest for each tested compiler pair.

## Current status

**Mapping complete; execution unverified.** Every audited surface variant and keyword maps to at least one contract row. The repositories have not yet passed the full old/new build and Blaster gate.

## Execution lanes

| Lane | Requirement |
|---|---|
| `compile` | Parse and type-check the same pinned source with both compiler variants. |
| `blaster` | Build reachable validator UPLC with both compiler variants and compare the pair with Lean-blaster. |
| `check` | Run unit, property, and validator tests with fixed options and seeds. |
| `bench` | Discover and run benchmark definitions with the same Sampler inputs. |
| `config` | Exercise target, environment, configuration, dependency, lockfile, and monorepo selection. |
| `docs` | Exercise source documentation generation. This lane does not enter Blaster. |

## Mandatory public repositories

| Order | Repository | Role | Lanes | Ref |
|---:|---|---|---|---|
| 1 | [aiken-lang/aiken](https://github.com/aiken-lang/aiken) | Authoritative grammar, AST, active builtin inventory, diagnostics, and acceptance packages. | `compile`, `check`, `blaster` | `v1.1.23` |
| 2 | [aiken-lang/stdlib](https://github.com/aiken-lang/stdlib) | Official library corpus for generics, custom data, collections, conversion, cryptography, and imports. | `compile`, `check`, `blaster-with-harness` | `v3.1.0` |
| 3 | [aiken-lang/fuzz](https://github.com/aiken-lang/fuzz) | Official Fuzzer and property-test corpus. | `compile`, `check` | `v2.2.0` |
| 4 | [aiken-lang/sample](https://github.com/aiken-lang/sample) | Official Sampler and benchmark corpus. | `compile`, `bench` | `9a7bca146277edaa413cf145ee4bb4063edb657d` |
| 5 | [ariady-putra-emurgo/aiken_primitive_types](https://github.com/ariady-putra-emurgo/aiken_primitive_types) | Focused valid primitive and prelude type examples. | `compile`, `check`, `blaster-with-harness` | `2a2427cbbc92ed8f8c443de260be9ae386771218` |
| 6 | [ariady-putra-emurgo/aiken_custom_types](https://github.com/ariady-putra-emurgo/aiken_custom_types) | Focused custom, opaque, generic, and recursive type examples. | `compile`, `check`, `blaster-with-harness` | `334c8eb589315802999f92bcc8ac303f45381d84` |
| 7 | [ariady-putra-emurgo/aiken_const_showcase](https://github.com/ariady-putra-emurgo/aiken_const_showcase) | Focused constants, comments, documentation, environment modules, and configuration values. | `compile`, `config`, `docs` | `03fb7c24ac8c5edb2d7f6282866d1a50748da0b4` |
| 8 | [ariady-putra-emurgo/aiken_fn_showcase](https://github.com/ariady-putra-emurgo/aiken_fn_showcase) | Focused functions, labels, calls, recursion, captures, pipelines, and backpassing. | `compile`, `check`, `blaster-with-harness` | `ae0827b32013ab21ae29bb1a55ccb51db7a53ace` |
| 9 | [ariady-putra-emurgo/aiken_control_answer](https://github.com/ariady-putra-emurgo/aiken_control_answer) | Completed control-flow and pattern-matching examples. | `compile`, `check`, `blaster-with-harness` | `c3142b9e3a1bd91cae94192fb21840110675e231` |
| 10 | [ariady-putra-emurgo/aiken_minting_answer](https://github.com/ariady-putra-emurgo/aiken_minting_answer) | Completed minting validators and redeemer checks. | `compile`, `check`, `blaster` | `de8f8806450316404b21e69a3c393dbd449d14e7` |
| 11 | [ariady-putra-emurgo/aiken_spending_validator](https://github.com/ariady-putra-emurgo/aiken_spending_validator) | Focused spend validators, parameters, datum/redeemer decoding, and CIP-68 examples. | `compile`, `check`, `blaster` | `36b12fbe2070c8d33e78981ed3cd090d9008f2a3` |
| 12 | [ariady-putra-emurgo/aiken_staking_validator](https://github.com/ariady-putra-emurgo/aiken_staking_validator) | Focused withdraw and publish handlers with an else fallback. | `compile`, `check`, `blaster` | `0c42c5f3814517479aa2fa95584337b27cd102cb` |
| 13 | [ariady-putra-emurgo/aiken_check_showcase](https://github.com/ariady-putra-emurgo/aiken_check_showcase) | Focused unit, property, validator, trace, and expected-failure tests. | `compile`, `check` | `f1658cb806f63ff9bca59d33c258cbd22b6f3efb` |

## Compiler-surface audit

- **160** tagged compiler and project surface variants mapped.
- **24** keywords or accepted aliases mapped.
- **87** active UPLC builtins mapped one-to-one.
- **0** unmapped audited variants.

| Surface | Variants |
|---|---:|
| `ModuleKind` | 4 |
| `Definition` | 8 |
| `DecoratorKind` | 2 |
| `Purpose` | 6 |
| `Annotation` | 6 |
| `BinOp` | 13 |
| `UnOp` | 2 |
| `LogicalOpChainKind` | 2 |
| `Pattern` | 9 |
| `Namespace` | 2 |
| `AssignmentKind` | 3 |
| `TraceKind` | 3 |
| `Tracing` | 3 |
| `TraceLevel` | 3 |
| `OnTestFailure` | 3 |
| `ArgBy` | 2 |
| `ArgName` | 2 |
| `FnStyle` | 3 |
| `TypedExpr` | 23 |
| `UntypedExpr` | 24 |
| `ByteArrayFormatPreference` | 4 |
| `Base` | 3 |
| `Bls12_381PointType` | 2 |
| `SimpleExpr` | 6 |
| `PlutusProjectTarget` | 3 |
| `PreludeType` | 19 |

## Summary

| Measure | Count |
|---|---:|
| Language and project rows | 306 |
| Negative compile rows | 12 |
| Active UPLC builtins | 87 |
| Total contract rows | 393 |
| Rows that require a sentinel fixture | 330 |

## Language and compiler rows

### Comments And Docs

| ID | Feature | Impact | Lanes | Public candidates | Sentinel | Status |
|---|---|---|---|---|---|---|
| `COMMENT-INLINE` | Inline source comment | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `COMMENT-DOC-DEFINITION` | Documentation comment on a definition | `compile_only` | `compile`, `docs` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | not required | `manifested_unverified` |
| `COMMENT-DOC-CONSTRUCTOR` | Documentation comment on a constructor | `compile_only` | `compile`, `docs` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | not required | `manifested_unverified` |
| `COMMENT-DOC-FIELD` | Documentation comment on a custom-type field | `compile_only` | `compile`, `docs` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | not required | `manifested_unverified` |
| `COMMENT-DOC-FN-ARG` | Documentation comment on a function argument | `compile_only` | `compile`, `docs` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | not required | `manifested_unverified` |
| `COMMENT-DOC-VALIDATOR-PARAM` | Documentation comment on a validator parameter | `compile_only` | `compile`, `docs` | `AIKEN_ACCEPTANCE`, `EDU_MINTING`, `EDU_SPENDING`, `EDU_STAKING` | not required | `manifested_unverified` |
| `COMMENT-DOC-HANDLER-ARG` | Documentation comment on a validator handler argument | `compile_only` | `compile`, `docs` | `AIKEN_ACCEPTANCE`, `EDU_MINTING`, `EDU_SPENDING`, `EDU_STAKING` | not required | `manifested_unverified` |
| `COMMENT-DOC-FALLBACK-ARG` | Documentation comment on an else-handler argument | `compile_only` | `compile`, `docs` | `AIKEN_ACCEPTANCE`, `EDU_MINTING`, `EDU_SPENDING`, `EDU_STAKING` | not required | `manifested_unverified` |
| `COMMENT-MODULE` | Module documentation comment | `compile_only` | `compile`, `docs` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | not required | `manifested_unverified` |
| `DOC-MODULE-HIDDEN` | Hidden module documentation tag | `docs_only` | `compile`, `docs` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | not required | `manifested_unverified` |
| `COMMENT-EXPECT` | Expect comment used as a runtime failure label | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `DOC-GENERATION` | HTML documentation generation | `docs_only` | `compile`, `docs` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | not required | `manifested_unverified` |

### Control Flow And Expressions

| ID | Feature | Impact | Lanes | Public candidates | Sentinel | Status |
|---|---|---|---|---|---|---|
| `BOOL-AND-BLOCK` | and keyword block | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONTROL` | required | `manifested_unverified` |
| `BOOL-OR-BLOCK` | or keyword block | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONTROL` | required | `manifested_unverified` |
| `IF-ELSE` | if/else expression | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONTROL` | required | `manifested_unverified` |
| `IF-ELSE-IF` | else-if chain | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONTROL` | required | `manifested_unverified` |
| `WHEN` | when/is pattern matching | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONTROL` | required | `manifested_unverified` |
| `IF-IS-PATTERN-TYPE` | if/is with an explicit pattern and type | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONTROL` | required | `manifested_unverified` |
| `IF-IS-TYPE` | if/is type-only shorthand | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONTROL` | required | `manifested_unverified` |
| `EXPR-GROUPING` | Parenthesized expression grouping | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `TRACE-BASIC` | Trace expression | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CHECK` | required | `manifested_unverified` |
| `TRACE-LABEL-STRING` | Trace label supplied as a String | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CHECK` | required | `manifested_unverified` |
| `TRACE-LABEL-BYTEARRAY` | Trace label supplied as a ByteArray | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `TRACE-LABEL-EXPRESSION` | Trace label supplied by an expression | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `TRACE-ARGS` | Trace with inspected values | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CHECK` | required | `manifested_unverified` |
| `TRACE-DEFAULT-CONT` | Trace with the default Void continuation | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `TRACE-QUESTION` | Postfix question-mark trace-if-false shorthand | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `FAIL-BARE` | fail without a reason | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `FAIL-REASON` | fail with a reason expression | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `TODO-BARE` | todo without a reason | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `TODO-REASON` | todo with a reason expression | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `ERROR-ALIAS` | Deprecated error alias for fail | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `ACCESS-RECORD` | Record field access | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |
| `ACCESS-TUPLE` | Tuple ordinal access | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `ACCESS-PAIR` | Pair ordinal access | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `RECORD-CONSTRUCT-NAMED` | Named-field record construction | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |
| `RECORD-CONSTRUCT-POSITIONAL` | Positional construction of a record constructor | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |
| `RECORD-FIELD-ORDER` | Named fields supplied in a different order | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |
| `RECORD-PUNNING` | Record field punning | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `RECORD-UPDATE` | Record update expression | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |

### Functions Calls And Bindings

| ID | Feature | Impact | Lanes | Public candidates | Sentinel | Status |
|---|---|---|---|---|---|---|
| `EXPR-VARIABLE` | Variable reference expression | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `FN-ANONYMOUS` | Anonymous function | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `FN-FIRST-CLASS` | Function stored or passed as a value | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `FN-HIGHER-ORDER` | Higher-order function | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS`, `AIKEN_STDLIB` | required | `manifested_unverified` |
| `FN-RECURSION` | Recursive named function | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `FN-ARG-NAMED` | Named function argument | `compile_only` | `compile` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | not required | `manifested_unverified` |
| `FN-ARG-DISCARD` | Discarded function argument | `compile_only` | `compile` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | not required | `manifested_unverified` |
| `FN-ARG-LABEL` | Labelled function argument | `compile_only` | `compile` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | not required | `manifested_unverified` |
| `FN-ARG-LABEL-OVERRIDE` | Argument label differs from the local name | `compile_only` | `compile` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | not required | `manifested_unverified` |
| `FN-ARG-LABELLED-DISCARD` | Labelled discarded function argument | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `FN-ARG-DESTRUCTURE` | Pattern destructuring in a function argument | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `FN-ARG-DESTRUCTURE-ANNOTATED` | Annotated destructuring function argument | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `FN-EMPTY-BODY-TODO` | Empty function body lowered to todo | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `CALL-POSITIONAL` | Positional function call | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `CALL-LABELLED` | Labelled function call | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `CALL-MIXED` | Mixed positional and labelled function call | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `CALL-PUNNING` | Call argument field punning | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `CAPTURE-FUNCTION` | Function-call capture with underscore | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `CAPTURE-CONSTRUCTOR` | Constructor-call capture with underscore | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `FN-ANON-BINOP` | Standalone binary operator used as a function | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `PIPE-BARE` | Pipeline into a bare function | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `PIPE-CALL-INSERT` | Pipeline value inserted into a call | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `PIPE-CAPTURE` | Pipeline with an explicit capture position | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `PIPE-RESULT-CALL` | Pipeline fallback that calls the produced function value | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `PIPE-ONE-LINE` | One-line pipeline | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `PIPE-MULTILINE` | Multiline pipeline | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `BLOCK-EXPRESSION` | Braced expression block | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `SEQUENCE-EXPRESSION` | Expression sequence with a final value | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `LET-VARIABLE` | Let binding | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `LET-MULTIPLE` | Multiple assignment patterns in one binding | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `LET-DESTRUCTURE` | Let pattern destructuring | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `LET-SHADOW` | Name shadowing | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `LET-BACKPASS` | Let backpassing assignment | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `EXPECT-PATTERN` | Expect pattern assertion | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `EXPECT-BOOLEAN` | Bare boolean expect assertion | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `EXPECT-BACKPASS` | Expect backpassing assignment | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |

### Literals

| ID | Feature | Impact | Lanes | Public candidates | Sentinel | Status |
|---|---|---|---|---|---|---|
| `LIT-BOOL-TRUE` | Bool literal True | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `LIT-BOOL-FALSE` | Bool literal False | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `LIT-INT-DECIMAL` | Decimal Int literal | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `LIT-INT-SEPARATOR` | Decimal Int literal with underscore separators | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `LIT-INT-HEX` | Hexadecimal Int literal | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `LIT-INT-NEGATIVE` | Negative Int through unary negation | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `LIT-BYTEARRAY-LIST-DECIMAL` | ByteArray list literal with decimal bytes | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `LIT-BYTEARRAY-LIST-HEX` | ByteArray list literal with hexadecimal bytes | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `LIT-BYTEARRAY-UTF8` | UTF-8 ByteArray literal | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `LIT-BYTEARRAY-HEX` | Hex-encoded ByteArray literal | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `LIT-BYTEARRAY-ESCAPE` | ByteArray escape sequences | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `LIT-BYTEARRAY-COMMENT` | Comment inside a ByteArray list literal | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `LIT-STRING` | String literal | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `LIT-STRING-MULTILINE` | Multiline String literal | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `LIT-STRING-UNICODE` | Unicode String literal | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `LIT-STRING-ESCAPE` | String escape sequences | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `LIT-LIST-EMPTY` | Empty List literal | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `LIT-LIST-ELEMENTS` | Non-empty List literal | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `LIT-LIST-SPREAD` | List spread or tail expression | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `LIT-TUPLE` | Tuple literal | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `LIT-PAIR` | Pair literal or Pair constructor | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `LIT-VOID` | Void constructor expression | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `LIT-CURVE-G1` | BLS12-381 G1 curve-point literal | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `LIT-CURVE-G2` | BLS12-381 G2 curve-point literal | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |

### Modules Definitions Imports

| ID | Feature | Impact | Lanes | Public candidates | Sentinel | Status |
|---|---|---|---|---|---|---|
| `MOD-LIB` | Library module | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `MOD-VALIDATOR` | Validator module | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_MINTING`, `EDU_SPENDING`, `EDU_STAKING` | required | `manifested_unverified` |
| `MOD-ENV` | Environment module | `project_only` | `compile`, `config` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | not required | `manifested_unverified` |
| `MOD-CONFIG` | Generated configuration module | `project_only` | `compile`, `config` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | not required | `manifested_unverified` |
| `DEF-FN-PRIVATE` | Private named function | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `DEF-FN-PUBLIC` | Public named function | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `DEF-CONST-PRIVATE` | Private module constant | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | required | `manifested_unverified` |
| `DEF-CONST-PUBLIC` | Public module constant | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | required | `manifested_unverified` |
| `DEF-TYPE-PRIVATE` | Private custom type | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |
| `DEF-TYPE-PUBLIC` | Public custom type | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |
| `DEF-TYPE-OPAQUE-PRIVATE` | Private opaque custom type | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |
| `DEF-TYPE-OPAQUE-PUBLIC` | Public opaque custom type | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |
| `DEF-TYPE-ALIAS-PRIVATE` | Private type alias | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `DEF-TYPE-ALIAS-PUBLIC` | Public type alias | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `DEF-TYPE-ALIAS-GENERIC` | Generic type alias parameters | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `DEF-TEST` | Test definition | `check_only` | `compile`, `check` | `AIKEN_ACCEPTANCE`, `EDU_CHECK`, `AIKEN_FUZZ` | not required | `manifested_unverified` |
| `DEF-BENCH` | Benchmark definition | `bench_only` | `compile`, `bench` | `AIKEN_ACCEPTANCE`, `AIKEN_SAMPLE` | not required | `manifested_unverified` |
| `DEF-VALIDATOR` | Validator definition | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_MINTING`, `EDU_SPENDING`, `EDU_STAKING` | required | `manifested_unverified` |
| `TYPE-CONSTRUCTOR-ZERO` | Zero-field custom constructor | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |
| `TYPE-CONSTRUCTOR-POSITIONAL` | Positional custom constructor fields | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |
| `TYPE-CONSTRUCTOR-RECORD` | Named record constructor fields | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |
| `TYPE-SHORTHAND-RECORD` | Single-constructor record shorthand | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |
| `TYPE-MULTI-CONSTRUCTOR` | Custom type with several constructors | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |
| `TYPE-RECURSIVE` | Recursive custom type | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |
| `TYPE-GENERIC` | Generic custom type parameters | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |
| `TYPE-OPAQUE-NEWTYPE` | Zero-cost opaque single-field newtype representation | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | required | `manifested_unverified` |
| `ENC-DEFAULT-TAG-ORDER` | Default constructor tags follow definition order | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `ENC-TAG-TYPE-DECIMAL` | @tag with a decimal value on a type | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `ENC-TAG-TYPE-HEX` | @tag with a hexadecimal value on a type | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `ENC-TAG-CONSTRUCTOR-DECIMAL` | @tag with a decimal value on a constructor | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `ENC-TAG-CONSTRUCTOR-HEX` | @tag with a hexadecimal value on a constructor | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `ENC-LIST` | @list encoding decorator | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `IMPORT-QUALIFIED` | Qualified module import | `compile_only` | `compile` | `AIKEN_ACCEPTANCE`, `AIKEN_STDLIB` | not required | `manifested_unverified` |
| `IMPORT-MODULE-ALIAS` | Module import alias | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `IMPORT-UNQUALIFIED` | Unqualified item import | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `IMPORT-ITEM-ALIAS` | Unqualified item alias | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `IMPORT-MERGED` | Merged repeated imports from the same module | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `IMPORT-PACKAGE` | Dependency package import | `project_only` | `compile`, `config` | `AIKEN_STDLIB`, `AIKEN_FUZZ`, `AIKEN_SAMPLE` | not required | `manifested_unverified` |
| `IMPORT-NESTED-PATH` | Nested module path | `compile_only` | `compile` | `AIKEN_ACCEPTANCE`, `AIKEN_STDLIB` | not required | `manifested_unverified` |
| `IMPORT-PRELUDE-IMPLICIT` | Implicit aiken prelude import | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `IMPORT-PRELUDE-EXPLICIT` | Explicit aiken prelude import | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `IMPORT-BUILTIN-MODULE` | Explicit aiken/builtin import | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `IMPORT-CONDITIONAL-ENV` | Conditional environment import | `project_only` | `compile`, `config` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | not required | `manifested_unverified` |
| `IMPORT-CONDITIONAL-CONFIG` | Conditional configuration import | `project_only` | `compile`, `config` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | not required | `manifested_unverified` |
| `IMPORT-EXPLICIT-ENV-MODULE` | Explicit import of another environment module | `project_only` | `compile`, `config` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | not required | `manifested_unverified` |
| `SELECT-MODULE` | Module-qualified value or function selection | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `AIKEN_STDLIB` | required | `manifested_unverified` |
| `SELECT-TYPE-NAMESPACE` | Type name used as a constructor namespace | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |

### Negative Compile Contract

| ID | Feature | Impact | Lanes | Public candidates | Sentinel | Status |
|---|---|---|---|---|---|---|
| `NEG-TAG-OVERFLOW` | @tag value overflow reports a diagnostic instead of a panic | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `NEG-NONEXHAUSTIVE-WHEN` | Non-exhaustive pattern matching reports an error | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `NEG-TYPE-MISMATCH` | Type mismatch reports an error | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `NEG-OPAQUE-CONSTRUCTOR` | External use of an opaque constructor reports an error | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `NEG-INVALID-VALIDATOR-ARITY` | Invalid validator handler arity reports an error | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `NEG-STRING-PATTERN` | String literals are rejected as patterns | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `NEG-CURVE-PATTERN` | Curve-point literals are rejected as patterns | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `NEG-LIST-SPREAD-NO-SUBJECT` | A list spread without a tail subject reports an error | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `NEG-TARGET-PLUTUS-V1` | The project manifest rejects Plutus V1 | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `NEG-TARGET-PLUTUS-V2` | The project manifest rejects Plutus V2 | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `NEG-INT-BINARY` | The v1.1.23 lexer rejects binary integer prefixes | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `NEG-INT-OCTAL` | The v1.1.23 lexer rejects octal integer prefixes | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |

### Operators

| ID | Feature | Impact | Lanes | Public candidates | Sentinel | Status |
|---|---|---|---|---|---|---|
| `OP-AND` | Boolean conjunction | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `OP-OR` | Boolean disjunction | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `OP-EQ` | Equality | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `OP-NEQ` | Inequality | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `OP-LT` | Integer less-than | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `OP-LTE` | Integer less-than-or-equal | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `OP-GTE` | Integer greater-than-or-equal | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `OP-GT` | Integer greater-than | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `OP-ADD` | Integer addition | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `OP-SUB` | Integer subtraction | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `OP-MUL` | Integer multiplication | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `OP-DIV` | Integer division | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `OP-MOD` | Integer modulo | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `OP-NOT` | Boolean negation | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `OP-NEGATE` | Integer unary negation | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `OP-EQ-SERIALIZABLE` | Equality on a serializable compound value | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `AIKEN_STDLIB` | required | `manifested_unverified` |
| `OP-NEQ-SERIALIZABLE` | Inequality on a serializable compound value | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `AIKEN_STDLIB` | required | `manifested_unverified` |

### Patterns

| ID | Feature | Impact | Lanes | Public candidates | Sentinel | Status |
|---|---|---|---|---|---|---|
| `PAT-INT-DECIMAL` | Decimal Int pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-INT-SEPARATOR` | Decimal Int pattern with separators | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-INT-HEX` | Hexadecimal Int pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-INT-NEGATIVE` | Negative Int pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-BYTEARRAY-LIST-DECIMAL` | ByteArray list-format pattern with decimal bytes | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-BYTEARRAY-LIST-HEX` | ByteArray list-format pattern with hexadecimal bytes | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-BYTEARRAY-UTF8` | UTF-8 ByteArray pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-BYTEARRAY-HEX` | Hex ByteArray pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-BOOL` | Bool constructor pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-VARIABLE` | Variable pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-DISCARD` | Wildcard discard pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-NAMED-DISCARD` | Named discard pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-AS` | as pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-LIST-EXACT` | Exact List pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-LIST-TAIL` | List tail pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-LIST-NAMED-TAIL` | Named List tail pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-PAIR` | Pair pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-TUPLE` | Tuple pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-CONSTRUCTOR-POSITIONAL` | Positional constructor pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-CONSTRUCTOR-RECORD` | Record constructor pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-CONSTRUCTOR-POSITIONAL-SPREAD` | Positional constructor pattern spread | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-RECORD-SPREAD` | Record constructor pattern spread | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-MODULE-QUALIFIED` | Module-qualified constructor pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-TYPE-QUALIFIED` | Type-qualified constructor pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-NESTED` | Nested pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-ALTERNATIVE` | Alternative patterns with vertical bar | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-FIELD-PUNNING` | Record-field punning in a pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-FIELD-RENAME` | Record-field rename in a pattern | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-ARG-DESTRUCTURE` | Pattern in a function argument | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-LET-DESTRUCTURE` | Pattern in let | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |
| `PAT-EXPECT-DESTRUCTURE` | Pattern in expect | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES`, `EDU_CONTROL` | required | `manifested_unverified` |

### Prelude Types

| ID | Feature | Impact | Lanes | Public candidates | Sentinel | Status |
|---|---|---|---|---|---|---|
| `TYPE-DATA` | Prelude type Data | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `TYPE-INT` | Prelude type Int | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `TYPE-BYTEARRAY` | Prelude type ByteArray | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `TYPE-BOOL` | Prelude type Bool | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `TYPE-G1` | Prelude type G1Element | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `TYPE-G2` | Prelude type G2Element | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `TYPE-MILLER` | Prelude type MillerLoopResult | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `TYPE-ORDERING` | Prelude type Ordering | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `TYPE-STRING` | Prelude type String | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `TYPE-VOID` | Prelude type Void | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `TYPE-LIST` | Prelude type List<a> | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `TYPE-PAIR` | Prelude type Pair<a, b> | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `TYPE-PAIRS` | Prelude type Pairs<a, b> | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `TYPE-OPTION` | Prelude type Option<a> | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `TYPE-NEVER` | Prelude type Never | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_PRIMITIVES` | required | `manifested_unverified` |
| `TYPE-SCRIPT-CONTEXT` | Prelude type ScriptContext | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |

### Project And Targets

| ID | Feature | Impact | Lanes | Public candidates | Sentinel | Status |
|---|---|---|---|---|---|---|
| `TARGET-PLUTUS-V3` | Plutus V3 project target | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE`, `AIKEN_STDLIB` | required | `manifested_unverified` |
| `PROJECT-TOML` | aiken.toml project manifest | `project_only` | `compile`, `config` | `AIKEN_ACCEPTANCE`, `AIKEN_STDLIB` | required | `manifested_unverified` |
| `PROJECT-COMPILER-PIN` | Compiler version constraint in aiken.toml | `project_only` | `compile`, `config` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `PROJECT-LOCK` | Locked dependencies through aiken.lock | `project_only` | `compile`, `config` | `AIKEN_STDLIB`, `AIKEN_FUZZ`, `AIKEN_SAMPLE` | required | `manifested_unverified` |
| `PROJECT-DEPENDENCY` | Package dependency resolution | `project_only` | `compile`, `config` | `AIKEN_STDLIB`, `AIKEN_FUZZ`, `AIKEN_SAMPLE` | required | `manifested_unverified` |
| `PROJECT-DEPENDENCY-GITHUB` | GitHub dependency source | `project_only` | `compile`, `config` | `AIKEN_STDLIB` | required | `manifested_unverified` |
| `PROJECT-DEPENDENCY-GITLAB` | GitLab dependency source declaration | `project_only` | `compile`, `config` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `PROJECT-DEPENDENCY-BITBUCKET` | Bitbucket dependency source declaration | `project_only` | `compile`, `config` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `PROJECT-MONOREPO` | Monorepo members property | `project_only` | `compile`, `config` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `PROJECT-MONOREPO-GLOB` | Glob expansion in monorepo members | `project_only` | `compile`, `config` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `PROJECT-ENV-DEFAULT` | Default environment module selection | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | required | `manifested_unverified` |
| `PROJECT-ENV-NAMED` | Named environment module selection | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | required | `manifested_unverified` |
| `PROJECT-CONFIG-DEFAULT` | Default configuration selection | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | required | `manifested_unverified` |
| `PROJECT-CONFIG-NAMED` | Named configuration selection | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | required | `manifested_unverified` |
| `PROJECT-CONDITIONAL-MODULE` | One conditional module API with several implementations | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | required | `manifested_unverified` |
| `PROJECT-BLUEPRINT` | Blueprint generation for validators | `project_only` | `compile`, `config` | `AIKEN_ACCEPTANCE`, `EDU_MINTING`, `EDU_SPENDING`, `EDU_STAKING` | required | `manifested_unverified` |
| `CONFIG-INT` | Injected Int configuration value | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | required | `manifested_unverified` |
| `CONFIG-BOOL` | Injected Bool configuration value | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | required | `manifested_unverified` |
| `CONFIG-BYTEARRAY-UTF8-STRING` | Injected UTF-8 ByteArray from a TOML string | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | required | `manifested_unverified` |
| `CONFIG-BYTEARRAY-UTF8-MAP` | Injected UTF-8 ByteArray from bytes/encoding fields | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | required | `manifested_unverified` |
| `CONFIG-BYTEARRAY-HEX-MAP` | Injected hex ByteArray from bytes/encoding fields | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | required | `manifested_unverified` |
| `CONFIG-LIST` | Injected homogeneous List configuration value | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | required | `manifested_unverified` |
| `CONFIG-TUPLE` | Injected heterogeneous Tuple configuration value | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | required | `manifested_unverified` |

### Tests Benchmarks And Tracing

| ID | Feature | Impact | Lanes | Public candidates | Sentinel | Status |
|---|---|---|---|---|---|---|
| `TEST-UNIT` | Unit test without a fuzzer | `check_only` | `compile`, `check` | `AIKEN_ACCEPTANCE`, `EDU_CHECK`, `AIKEN_FUZZ` | required | `manifested_unverified` |
| `TEST-PROPERTY-VIA` | Property-test argument introduced with via | `check_only` | `compile`, `check` | `AIKEN_ACCEPTANCE`, `EDU_CHECK`, `AIKEN_FUZZ` | required | `manifested_unverified` |
| `TEST-FUZZER-NAMED` | Named custom fuzzer | `check_only` | `compile`, `check` | `AIKEN_ACCEPTANCE`, `EDU_CHECK`, `AIKEN_FUZZ` | required | `manifested_unverified` |
| `TEST-FUZZER-COMPOSED` | Composed fuzzer | `check_only` | `compile`, `check` | `AIKEN_ACCEPTANCE`, `EDU_CHECK`, `AIKEN_FUZZ` | required | `manifested_unverified` |
| `TEST-MULTI-VIA` | Test with several via arguments | `check_only` | `compile`, `check` | `AIKEN_ACCEPTANCE`, `EDU_CHECK`, `AIKEN_FUZZ` | required | `manifested_unverified` |
| `TEST-VALIDATOR` | Validator behavior test | `check_only` | `compile`, `check` | `AIKEN_ACCEPTANCE`, `EDU_CHECK` | required | `manifested_unverified` |
| `TEST-FAIL` | test fail expected-failure mode | `check_only` | `compile`, `check` | `AIKEN_ACCEPTANCE`, `EDU_CHECK` | required | `manifested_unverified` |
| `TEST-FAIL-ONCE` | test fail once eventual-success mode | `check_only` | `compile`, `check` | `AIKEN_ACCEPTANCE`, `EDU_CHECK` | required | `manifested_unverified` |
| `TEST-TRACE` | Trace production inside a test | `check_only` | `compile`, `check` | `AIKEN_ACCEPTANCE`, `EDU_CHECK` | required | `manifested_unverified` |
| `BENCH-VIA` | Benchmark argument introduced with via | `bench_only` | `compile`, `bench` | `AIKEN_ACCEPTANCE`, `AIKEN_SAMPLE` | required | `manifested_unverified` |
| `BENCH-SAMPLER-NAMED` | Named custom Sampler | `bench_only` | `compile`, `bench` | `AIKEN_ACCEPTANCE`, `AIKEN_SAMPLE` | required | `manifested_unverified` |
| `BENCH-SAMPLER-COMPOSED` | Composed Sampler | `bench_only` | `compile`, `bench` | `AIKEN_ACCEPTANCE`, `AIKEN_SAMPLE` | required | `manifested_unverified` |
| `BENCH-MULTI-VIA` | Benchmark with several via arguments | `bench_only` | `compile`, `bench` | `AIKEN_ACCEPTANCE`, `AIKEN_SAMPLE` | required | `manifested_unverified` |
| `TRACE-LEVEL-SILENT` | Silent trace level | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `TRACE-LEVEL-COMPACT` | Compact trace level | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `TRACE-LEVEL-VERBOSE` | Verbose trace level | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `FRAMEWORK-PRNG` | PRNG support type | `check_only` | `compile`, `check` | `AIKEN_ACCEPTANCE`, `AIKEN_FUZZ` | required | `manifested_unverified` |
| `FRAMEWORK-FUZZER` | Fuzzer support type | `check_only` | `compile`, `check` | `AIKEN_ACCEPTANCE`, `AIKEN_FUZZ` | required | `manifested_unverified` |
| `FRAMEWORK-SAMPLER` | Sampler support type | `bench_only` | `compile`, `bench` | `AIKEN_ACCEPTANCE`, `AIKEN_SAMPLE` | required | `manifested_unverified` |
| `TRACE-SOURCE-USER` | User-defined trace source mode | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `TRACE-SOURCE-COMPILER` | Compiler-generated trace source mode | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `TRACE-SOURCE-ALL` | Combined user and compiler trace source mode | `project_only` | `compile`, `config`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |

### Type System And Data Conversion

| ID | Feature | Impact | Lanes | Public candidates | Sentinel | Status |
|---|---|---|---|---|---|---|
| `ANN-CONSTRUCTOR` | Constructor type annotation | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `ANN-MODULE-QUALIFIED` | Module-qualified constructor annotation | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `ANN-FUNCTION` | Function type annotation | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `ANN-VARIABLE` | Generic type-variable annotation | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `ANN-HOLE` | Anonymous type annotation hole | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `ANN-HOLE-NAMED` | Named type annotation hole | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `ANN-TUPLE` | Tuple type annotation | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `ANN-PAIR` | Pair type annotation | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `ANN-PAIR-QUALIFIED` | Qualified aiken.Pair type annotation | `compile_only` | `compile` | `AIKEN_ACCEPTANCE` | not required | `manifested_unverified` |
| `ANN-ARGUMENT` | Function argument annotation | `compile_only` | `compile` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | not required | `manifested_unverified` |
| `ANN-RETURN` | Function return annotation | `compile_only` | `compile` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | not required | `manifested_unverified` |
| `ANN-BINDING` | Let or expect binding annotation | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `ANN-CONSTANT` | Module constant annotation | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONSTANTS` | required | `manifested_unverified` |
| `TYPE-INFERENCE` | Local and return type inference | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `TYPE-GENERIC-FUNCTION` | Generic function instantiation | `indirect_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_FUNCTIONS` | required | `manifested_unverified` |
| `DATA-UPCAST-IMPLICIT` | Implicit serializable-value upcast to Data | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `AIKEN_STDLIB` | required | `manifested_unverified` |
| `DATA-UPCAST-AS-DATA` | Explicit as_data conversion | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `AIKEN_STDLIB` | required | `manifested_unverified` |
| `DATA-DOWNCAST-EXPECT` | Typed Data downcast through expect | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `AIKEN_STDLIB` | required | `manifested_unverified` |
| `DATA-DOWNCAST-IF-IS` | Typed Data downcast through if/is | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_CONTROL` | required | `manifested_unverified` |
| `OPAQUE-BOUNDARY` | Opaque constructor access boundary across modules | `compile_only` | `compile` | `AIKEN_ACCEPTANCE`, `EDU_CUSTOM_TYPES` | not required | `manifested_unverified` |
| `REGRESSION-EXPECT-UNUSED` | Typed expect validation retained when the binding is unused | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `REGRESSION-DECODER-IDENTITY` | Distinct Data decoder identities across modules and generic shapes | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |

### Validators

| ID | Feature | Impact | Lanes | Public candidates | Sentinel | Status |
|---|---|---|---|---|---|---|
| `VAL-SPEND` | Spend handler | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_SPENDING` | required | `manifested_unverified` |
| `VAL-MINT` | Mint handler | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_MINTING` | required | `manifested_unverified` |
| `VAL-WITHDRAW` | Withdraw handler | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_STAKING` | required | `manifested_unverified` |
| `VAL-PUBLISH` | Publish handler | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_STAKING` | required | `manifested_unverified` |
| `VAL-PROPOSE` | Propose handler | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `VAL-VOTE` | Vote handler | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `VAL-ELSE` | Validator else fallback | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_STAKING` | required | `manifested_unverified` |
| `VAL-PARAMETERIZED` | Parameterized validator | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_SPENDING` | required | `manifested_unverified` |
| `VAL-MULTI-HANDLER` | Validator with several purpose handlers | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_STAKING` | required | `manifested_unverified` |
| `VAL-MULTIPLE-DEFS` | Several validator definitions in one package | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_MINTING`, `EDU_SPENDING` | required | `manifested_unverified` |
| `VAL-SPEND-ARITY` | Four-argument spend handler boundary | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_SPENDING` | required | `manifested_unverified` |
| `VAL-OTHER-ARITY` | Three-argument non-spend handler boundary | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_MINTING`, `EDU_STAKING` | required | `manifested_unverified` |
| `VAL-DEFAULT-FALLBACK` | Compiler-generated default fallback when else is omitted | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |
| `VAL-DATUM-OPTION` | Optional datum boundary for spend | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_SPENDING` | required | `manifested_unverified` |
| `VAL-SCRIPT-CONTEXT` | Transaction or ScriptContext boundary decoding | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE`, `EDU_SPENDING`, `EDU_MINTING`, `EDU_STAKING` | required | `manifested_unverified` |
| `VAL-EMPTY-HANDLER-TODO` | Empty validator handler body lowered to todo | `direct_codegen` | `compile`, `blaster` | `AIKEN_ACCEPTANCE` | required | `manifested_unverified` |

## Active UPLC builtins

Each builtin needs a reachable wrapper with non-constant inputs. The selected UPLC branch must still contain the builtin after optimization.

### Bls12 381

| Opcode | Aiken name | UPLC name | Real-world candidates | Status |
|---:|---|---|---|---|
| 54 | `bls12_381_g1_add` | `bls12_381_G1_add` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |
| 55 | `bls12_381_g1_neg` | `bls12_381_G1_neg` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |
| 56 | `bls12_381_g1_scalar_mul` | `bls12_381_G1_scalarMul` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |
| 57 | `bls12_381_g1_equal` | `bls12_381_G1_equal` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |
| 58 | `bls12_381_g1_compress` | `bls12_381_G1_compress` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |
| 59 | `bls12_381_g1_uncompress` | `bls12_381_G1_uncompress` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |
| 60 | `bls12_381_g1_hash_to_group` | `bls12_381_G1_hashToGroup` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |
| 61 | `bls12_381_g2_add` | `bls12_381_G2_add` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |
| 62 | `bls12_381_g2_neg` | `bls12_381_G2_neg` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |
| 63 | `bls12_381_g2_scalar_mul` | `bls12_381_G2_scalarMul` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |
| 64 | `bls12_381_g2_equal` | `bls12_381_G2_equal` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |
| 65 | `bls12_381_g2_compress` | `bls12_381_G2_compress` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |
| 66 | `bls12_381_g2_uncompress` | `bls12_381_G2_uncompress` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |
| 67 | `bls12_381_g2_hash_to_group` | `bls12_381_G2_hashToGroup` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |
| 68 | `bls12_381_miller_loop` | `bls12_381_millerLoop` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |
| 69 | `bls12_381_mul_miller_loop_result` | `bls12_381_mulMlResult` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |
| 70 | `bls12_381_final_verify` | `bls12_381_finalVerify` | `cardano-foundation/bls`, `ilap/bls`, `blocksmithy/oakshield-aiken` | `manifested_unverified` |

### Bytearray

| Opcode | Aiken name | UPLC name | Real-world candidates | Status |
|---:|---|---|---|---|
| 10 | `append_bytearray` | `appendByteString` | sentinel and official tests | `manifested_unverified` |
| 11 | `cons_bytearray` | `consByteString` | sentinel and official tests | `manifested_unverified` |
| 12 | `slice_bytearray` | `sliceByteString` | sentinel and official tests | `manifested_unverified` |
| 13 | `length_of_bytearray` | `lengthOfByteString` | sentinel and official tests | `manifested_unverified` |
| 14 | `index_bytearray` | `indexByteString` | sentinel and official tests | `manifested_unverified` |
| 15 | `equals_bytearray` | `equalsByteString` | sentinel and official tests | `manifested_unverified` |
| 16 | `less_than_bytearray` | `lessThanByteString` | sentinel and official tests | `manifested_unverified` |
| 17 | `less_than_equals_bytearray` | `lessThanEqualsByteString` | sentinel and official tests | `manifested_unverified` |

### Bytearray Bitwise

| Opcode | Aiken name | UPLC name | Real-world candidates | Status |
|---:|---|---|---|---|
| 75 | `and_bytearray` | `andByteString` | `cardano-foundation/cip113-programmable-tokens` | `manifested_unverified` |
| 76 | `or_bytearray` | `orByteString` | `cardano-foundation/cip113-programmable-tokens` | `manifested_unverified` |
| 77 | `xor_bytearray` | `xorByteString` | `cardano-foundation/cip113-programmable-tokens` | `manifested_unverified` |
| 78 | `complement_bytearray` | `complementByteString` | `cardano-foundation/cip113-programmable-tokens` | `manifested_unverified` |
| 79 | `read_bit` | `readBit` | `cardano-foundation/cip113-programmable-tokens` | `manifested_unverified` |
| 80 | `write_bits` | `writeBits` | `cardano-foundation/cip113-programmable-tokens` | `manifested_unverified` |
| 81 | `replicate_byte` | `replicateByte` | `cardano-foundation/cip113-programmable-tokens` | `manifested_unverified` |
| 82 | `shift_bytearray` | `shiftByteString` | `cardano-foundation/cip113-programmable-tokens` | `manifested_unverified` |
| 83 | `rotate_bytearray` | `rotateByteString` | `cardano-foundation/cip113-programmable-tokens` | `manifested_unverified` |
| 84 | `count_set_bits` | `countSetBits` | `cardano-foundation/cip113-programmable-tokens` | `manifested_unverified` |
| 85 | `find_first_set_bit` | `findFirstSetBit` | `cardano-foundation/cip113-programmable-tokens` | `manifested_unverified` |

### Control And Trace

| Opcode | Aiken name | UPLC name | Real-world candidates | Status |
|---:|---|---|---|---|
| 26 | `if_then_else` | `ifThenElse` | sentinel and official tests | `manifested_unverified` |
| 27 | `choose_void` | `chooseUnit` | sentinel and official tests | `manifested_unverified` |
| 28 | `debug` | `trace` | sentinel and official tests | `manifested_unverified` |

### Conversion

| Opcode | Aiken name | UPLC name | Real-world candidates | Status |
|---:|---|---|---|---|
| 73 | `integer_to_bytearray` | `integerToByteString` | sentinel and official tests | `manifested_unverified` |
| 74 | `bytearray_to_integer` | `byteStringToInteger` | sentinel and official tests | `manifested_unverified` |

### Cryptography And Hashing

| Opcode | Aiken name | UPLC name | Real-world candidates | Status |
|---:|---|---|---|---|
| 18 | `sha2_256` | `sha2_256` | `lambdasistemi/cardano-keri`, `utxo-company/fortuna`, `cardano-foundation/bls` | `manifested_unverified` |
| 19 | `sha3_256` | `sha3_256` | `lambdasistemi/cardano-keri`, `utxo-company/fortuna`, `cardano-foundation/bls` | `manifested_unverified` |
| 20 | `blake2b_256` | `blake2b_256` | `lambdasistemi/cardano-keri`, `utxo-company/fortuna`, `cardano-foundation/bls` | `manifested_unverified` |
| 21 | `verify_ed25519_signature` | `verifySignature` | `lambdasistemi/cardano-keri`, `utxo-company/fortuna`, `cardano-foundation/bls` | `manifested_unverified` |
| 52 | `verify_ecdsa_secp256k1_signature` | `verifyEcdsaSecp256k1Signature` | `lambdasistemi/cardano-keri`, `utxo-company/fortuna`, `cardano-foundation/bls` | `manifested_unverified` |
| 53 | `verify_schnorr_secp256k1_signature` | `verifySchnorrSecp256k1Signature` | `lambdasistemi/cardano-keri`, `utxo-company/fortuna`, `cardano-foundation/bls` | `manifested_unverified` |
| 71 | `keccak_256` | `keccak_256` | `lambdasistemi/cardano-keri`, `utxo-company/fortuna`, `cardano-foundation/bls` | `manifested_unverified` |
| 72 | `blake2b_224` | `blake2b_224` | `lambdasistemi/cardano-keri`, `utxo-company/fortuna`, `cardano-foundation/bls` | `manifested_unverified` |
| 86 | `ripemd_160` | `ripemd_160` | `lambdasistemi/cardano-keri`, `utxo-company/fortuna`, `cardano-foundation/bls` | `manifested_unverified` |

### Data

| Opcode | Aiken name | UPLC name | Real-world candidates | Status |
|---:|---|---|---|---|
| 36 | `choose_data` | `chooseData` | sentinel and official tests | `manifested_unverified` |
| 37 | `constr_data` | `constrData` | sentinel and official tests | `manifested_unverified` |
| 38 | `map_data` | `mapData` | sentinel and official tests | `manifested_unverified` |
| 39 | `list_data` | `listData` | sentinel and official tests | `manifested_unverified` |
| 40 | `i_data` | `iData` | sentinel and official tests | `manifested_unverified` |
| 41 | `b_data` | `bData` | sentinel and official tests | `manifested_unverified` |
| 42 | `un_constr_data` | `unConstrData` | sentinel and official tests | `manifested_unverified` |
| 43 | `un_map_data` | `unMapData` | sentinel and official tests | `manifested_unverified` |
| 44 | `un_list_data` | `unListData` | sentinel and official tests | `manifested_unverified` |
| 45 | `un_i_data` | `unIData` | sentinel and official tests | `manifested_unverified` |
| 46 | `un_b_data` | `unBData` | sentinel and official tests | `manifested_unverified` |
| 47 | `equals_data` | `equalsData` | sentinel and official tests | `manifested_unverified` |
| 51 | `serialise_data` | `serialiseData` | sentinel and official tests | `manifested_unverified` |

### Data Constructors

| Opcode | Aiken name | UPLC name | Real-world candidates | Status |
|---:|---|---|---|---|
| 48 | `new_pair` | `mkPairData` | sentinel and official tests | `manifested_unverified` |
| 49 | `new_list` | `mkNilData` | sentinel and official tests | `manifested_unverified` |
| 50 | `new_pairs` | `mkNilPairData` | sentinel and official tests | `manifested_unverified` |

### Integer

| Opcode | Aiken name | UPLC name | Real-world candidates | Status |
|---:|---|---|---|---|
| 0 | `add_integer` | `addInteger` | sentinel and official tests | `manifested_unverified` |
| 1 | `subtract_integer` | `subtractInteger` | sentinel and official tests | `manifested_unverified` |
| 2 | `multiply_integer` | `multiplyInteger` | sentinel and official tests | `manifested_unverified` |
| 3 | `divide_integer` | `divideInteger` | sentinel and official tests | `manifested_unverified` |
| 4 | `quotient_integer` | `quotientInteger` | sentinel and official tests | `manifested_unverified` |
| 5 | `remainder_integer` | `remainderInteger` | sentinel and official tests | `manifested_unverified` |
| 6 | `mod_integer` | `modInteger` | sentinel and official tests | `manifested_unverified` |
| 7 | `equals_integer` | `equalsInteger` | sentinel and official tests | `manifested_unverified` |
| 8 | `less_than_integer` | `lessThanInteger` | sentinel and official tests | `manifested_unverified` |
| 9 | `less_than_equals_integer` | `lessThanEqualsInteger` | sentinel and official tests | `manifested_unverified` |

### List

| Opcode | Aiken name | UPLC name | Real-world candidates | Status |
|---:|---|---|---|---|
| 31 | `choose_list` | `chooseList` | sentinel and official tests | `manifested_unverified` |
| 32 | `cons_list` | `mkCons` | sentinel and official tests | `manifested_unverified` |
| 33 | `head_list` | `headList` | sentinel and official tests | `manifested_unverified` |
| 34 | `tail_list` | `tailList` | sentinel and official tests | `manifested_unverified` |
| 35 | `null_list` | `nullList` | sentinel and official tests | `manifested_unverified` |

### Pair

| Opcode | Aiken name | UPLC name | Real-world candidates | Status |
|---:|---|---|---|---|
| 29 | `fst_pair` | `fstPair` | sentinel and official tests | `manifested_unverified` |
| 30 | `snd_pair` | `sndPair` | sentinel and official tests | `manifested_unverified` |

### String

| Opcode | Aiken name | UPLC name | Real-world candidates | Status |
|---:|---|---|---|---|
| 22 | `append_string` | `appendString` | sentinel and official tests | `manifested_unverified` |
| 23 | `equals_string` | `equalsString` | sentinel and official tests | `manifested_unverified` |
| 24 | `encode_utf8` | `encodeUtf8` | sentinel and official tests | `manifested_unverified` |
| 25 | `decode_utf8` | `decodeUtf8` | sentinel and official tests | `manifested_unverified` |

## Baseline exclusions

| Item | Reason |
|---|---|
| Plutus V1 project target | The v1.1.23 project loader rejects it; keep it as a negative configuration test. |
| Plutus V2 project target | The v1.1.23 project loader rejects it; Aiken v1.1.23 accepts only Plutus V3 projects. |
| Binary and octal integer prefixes | The tagged v1.1.23 lexer Base enum contains only decimal and hexadecimal forms. |
| Legacy dot-prefixed operators | Legacy token variants remain in structures, but the tagged lexer does not emit them. |
| exp_mod_integer | The builtin enum entry is commented out. |
| case_list | The builtin enum entry is commented out. |
| case_data | The builtin enum entry is commented out. |
| Deliberately incomplete teaching activities | Intentional type errors or reachable todo terms are not positive equivalence cases. |

## Release gate

The feature gate passes only when:

1. Every required source is pinned to an immutable tag or commit.
2. The scanner emits at least one source record for every contract row.
3. Both compiler variants complete every required lane or return an allowed explicit state.
4. Every direct-codegen row produces old and new UPLC and reaches Lean-blaster.
5. Every builtin remains in the selected UPLC branch after optimization.
6. No row remains `manifested_unverified`, `missing`, or `dead_code_only`.
7. A fresh compiler-surface audit finds no unmapped variant or keyword.
