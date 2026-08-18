from __future__ import annotations

import copy
import hashlib
import json
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

OUT = Path('/mnt/data')
DATE = '2026-08-13'
BASELINE = 'v1.1.23'
RELEASE_DATE = '2026-06-26'

CANDIDATE_JSON = OUT / 'aiken_equivalence_candidates.json'
CANDIDATE_MD = OUT / 'aiken_equivalence_candidates.md'
CANDIDATE_TXT = OUT / 'aiken_equivalence_repos.txt'

# Keep the first screened list unchanged for audit and repeatable generation.
for src, name in [
    (CANDIDATE_JSON, 'aiken_equivalence_candidates.pre_feature_coverage.json'),
    (CANDIDATE_MD, 'aiken_equivalence_candidates.pre_feature_coverage.md'),
    (CANDIDATE_TXT, 'aiken_equivalence_repos.pre_feature_coverage.txt'),
]:
    dst = OUT / name
    if not dst.exists():
        shutil.copy2(src, dst)

base = json.loads((OUT / 'aiken_equivalence_candidates.pre_feature_coverage.json').read_text())
candidates: list[dict[str, Any]] = copy.deepcopy(base['candidates'])

# ---------------------------------------------------------------------------
# Mandatory source set
# ---------------------------------------------------------------------------
mandatory_sources: list[dict[str, Any]] = [
    {
        'id': 'AIKEN_ACCEPTANCE', 'repository': 'aiken-lang/aiken',
        'url': 'https://github.com/aiken-lang/aiken', 'ref': BASELINE,
        'ref_policy': 'immutable-tag',
        'paths': ['examples/acceptance_tests/*', 'crates/aiken-lang', 'crates/uplc'],
        'role': 'Authoritative grammar, AST, active builtin inventory, diagnostics, and acceptance packages.',
        'lanes': ['compile', 'check', 'blaster'], 'intake': 'multi-package',
        'mandatory': True, 'verification_status': 'not-run',
    },
    {
        'id': 'AIKEN_STDLIB', 'repository': 'aiken-lang/stdlib',
        'url': 'https://github.com/aiken-lang/stdlib', 'ref': 'v3.1.0',
        'ref_policy': 'immutable-tag', 'paths': ['lib/**/*.ak'],
        'role': 'Official library corpus for generics, custom data, collections, conversion, cryptography, and imports.',
        'lanes': ['compile', 'check', 'blaster-with-harness'], 'intake': 'harness',
        'mandatory': True, 'verification_status': 'not-run',
    },
    {
        'id': 'AIKEN_FUZZ', 'repository': 'aiken-lang/fuzz',
        'url': 'https://github.com/aiken-lang/fuzz', 'ref': 'v2.2.0',
        'ref_policy': 'immutable-tag-or-lockfile-commit', 'paths': ['lib/**/*.ak'],
        'role': 'Official Fuzzer and property-test corpus.',
        'lanes': ['compile', 'check'], 'intake': 'root',
        'mandatory': True, 'verification_status': 'not-run',
    },
    {
        'id': 'AIKEN_SAMPLE', 'repository': 'aiken-lang/sample',
        'url': 'https://github.com/aiken-lang/sample', 'ref': '9a7bca146277edaa413cf145ee4bb4063edb657d',
        'ref_policy': 'immutable-commit', 'paths': ['lib/**/*.ak'],
        'role': 'Official Sampler and benchmark corpus.',
        'lanes': ['compile', 'bench'], 'intake': 'root',
        'mandatory': True, 'verification_status': 'not-run',
    },
    {
        'id': 'EDU_PRIMITIVES', 'repository': 'ariady-putra-emurgo/aiken_primitive_types',
        'url': 'https://github.com/ariady-putra-emurgo/aiken_primitive_types',
        'ref': '2a2427cbbc92ed8f8c443de260be9ae386771218', 'ref_policy': 'immutable-commit',
        'paths': ['lib/**/*.ak'], 'role': 'Focused valid primitive and prelude type examples.',
        'lanes': ['compile', 'check', 'blaster-with-harness'], 'intake': 'harness-or-root',
        'mandatory': True, 'verification_status': 'not-run',
    },
    {
        'id': 'EDU_CUSTOM_TYPES', 'repository': 'ariady-putra-emurgo/aiken_custom_types',
        'url': 'https://github.com/ariady-putra-emurgo/aiken_custom_types',
        'ref': '334c8eb589315802999f92bcc8ac303f45381d84', 'ref_policy': 'immutable-commit',
        'paths': ['lib/**/*.ak'], 'role': 'Focused custom, opaque, generic, and recursive type examples.',
        'lanes': ['compile', 'check', 'blaster-with-harness'], 'intake': 'harness-or-root',
        'mandatory': True, 'verification_status': 'not-run',
    },
    {
        'id': 'EDU_CONSTANTS', 'repository': 'ariady-putra-emurgo/aiken_const_showcase',
        'url': 'https://github.com/ariady-putra-emurgo/aiken_const_showcase',
        'ref': '03fb7c24ac8c5edb2d7f6282866d1a50748da0b4', 'ref_policy': 'immutable-commit',
        'paths': ['lib/**/*.ak', 'env/**/*.ak', 'aiken.toml'],
        'role': 'Focused constants, comments, documentation, environment modules, and configuration values.',
        'lanes': ['compile', 'config', 'docs'], 'intake': 'root',
        'mandatory': True, 'verification_status': 'not-run',
    },
    {
        'id': 'EDU_FUNCTIONS', 'repository': 'ariady-putra-emurgo/aiken_fn_showcase',
        'url': 'https://github.com/ariady-putra-emurgo/aiken_fn_showcase',
        'ref': 'ae0827b32013ab21ae29bb1a55ccb51db7a53ace', 'ref_policy': 'immutable-commit',
        'paths': ['lib/**/*.ak'],
        'role': 'Focused functions, labels, calls, recursion, captures, pipelines, and backpassing.',
        'lanes': ['compile', 'check', 'blaster-with-harness'], 'intake': 'harness-or-root',
        'mandatory': True, 'verification_status': 'not-run',
    },
    {
        'id': 'EDU_CONTROL', 'repository': 'ariady-putra-emurgo/aiken_control_answer',
        'url': 'https://github.com/ariady-putra-emurgo/aiken_control_answer',
        'ref': 'c3142b9e3a1bd91cae94192fb21840110675e231', 'ref_policy': 'immutable-commit',
        'paths': ['lib/**/*.ak'], 'role': 'Completed control-flow and pattern-matching examples.',
        'lanes': ['compile', 'check', 'blaster-with-harness'], 'intake': 'harness-or-root',
        'mandatory': True, 'verification_status': 'not-run',
    },
    {
        'id': 'EDU_MINTING', 'repository': 'ariady-putra-emurgo/aiken_minting_answer',
        'url': 'https://github.com/ariady-putra-emurgo/aiken_minting_answer',
        'ref': 'de8f8806450316404b21e69a3c393dbd449d14e7', 'ref_policy': 'immutable-commit',
        'paths': ['validators/**/*.ak'], 'role': 'Completed minting validators and redeemer checks.',
        'lanes': ['compile', 'check', 'blaster'], 'intake': 'root',
        'mandatory': True, 'verification_status': 'not-run',
    },
    {
        'id': 'EDU_SPENDING', 'repository': 'ariady-putra-emurgo/aiken_spending_validator',
        'url': 'https://github.com/ariady-putra-emurgo/aiken_spending_validator',
        'ref': '36b12fbe2070c8d33e78981ed3cd090d9008f2a3', 'ref_policy': 'immutable-commit',
        'paths': ['validators/**/*.ak'],
        'role': 'Focused spend validators, parameters, datum/redeemer decoding, and CIP-68 examples.',
        'lanes': ['compile', 'check', 'blaster'], 'intake': 'root',
        'mandatory': True, 'verification_status': 'not-run',
    },
    {
        'id': 'EDU_STAKING', 'repository': 'ariady-putra-emurgo/aiken_staking_validator',
        'url': 'https://github.com/ariady-putra-emurgo/aiken_staking_validator',
        'ref': '0c42c5f3814517479aa2fa95584337b27cd102cb', 'ref_policy': 'immutable-commit',
        'paths': ['validators/**/*.ak'], 'role': 'Focused withdraw and publish handlers with an else fallback.',
        'lanes': ['compile', 'check', 'blaster'], 'intake': 'root',
        'mandatory': True, 'verification_status': 'not-run',
    },
    {
        'id': 'EDU_CHECK', 'repository': 'ariady-putra-emurgo/aiken_check_showcase',
        'url': 'https://github.com/ariady-putra-emurgo/aiken_check_showcase',
        'ref': 'f1658cb806f63ff9bca59d33c258cbd22b6f3efb', 'ref_policy': 'immutable-commit',
        'paths': ['lib/**/*.ak', 'validators/**/*.ak'],
        'role': 'Focused unit, property, validator, trace, and expected-failure tests.',
        'lanes': ['compile', 'check'], 'intake': 'root',
        'mandatory': True, 'verification_status': 'not-run',
    },
    {
        'id': 'SENTINEL', 'repository': None, 'url': None, 'ref': BASELINE,
        'ref_policy': 'team-owned-immutable-history',
        'paths': ['validators/features/**/*.ak', 'validators/builtins/**/*.ak', 'lib/compile_only/**/*.ak', 'lib/checks/**/*.ak', 'lib/benchmarks/**/*.ak'],
        'role': 'Required stable fixture repository. It closes all gaps and prevents dead-code-only coverage.',
        'lanes': ['compile', 'check', 'bench', 'config', 'docs', 'blaster'],
        'intake': 'required-to-create', 'mandatory': True,
        'verification_status': 'missing-required-fixture',
    },
]
source_by_id = {x['id']: x for x in mandatory_sources}

ACC = ['AIKEN_ACCEPTANCE']
PRIM = ['AIKEN_ACCEPTANCE', 'EDU_PRIMITIVES']
CUSTOM = ['AIKEN_ACCEPTANCE', 'EDU_CUSTOM_TYPES']
CONST = ['AIKEN_ACCEPTANCE', 'EDU_CONSTANTS']
FN = ['AIKEN_ACCEPTANCE', 'EDU_FUNCTIONS']
CONTROL = ['AIKEN_ACCEPTANCE', 'EDU_CONTROL']
VAL = ['AIKEN_ACCEPTANCE', 'EDU_MINTING', 'EDU_SPENDING', 'EDU_STAKING']
TEST = ['AIKEN_ACCEPTANCE', 'EDU_CHECK', 'AIKEN_FUZZ']
BENCH = ['AIKEN_ACCEPTANCE', 'AIKEN_SAMPLE']

features: list[dict[str, Any]] = []

def required_evidence(lanes: list[str]) -> list[str]:
    out = [
        'source path and line range or AST-scanner record',
        'successful old-compiler parse and type check',
        'successful new-compiler parse and type check',
    ]
    if 'blaster' in lanes:
        out += [
            'old and new UPLC artifacts',
            'structural proof that the feature remains reachable after optimization',
            'Lean-blaster result or an explicit unsupported/inconclusive result',
        ]
    if 'check' in lanes:
        out.append('old and new aiken check result with the same seed and options')
    if 'bench' in lanes:
        out.append('old and new benchmark discovery and execution result')
    if 'config' in lanes:
        out.append('old and new package/configuration selection result')
    if 'docs' in lanes:
        out.append('old and new documentation-generation result')
    return out

def add(
    fid: str, category: str, name: str, impact: str, lanes: list[str], sources: list[str],
    syntax: Iterable[str] = (), *, sentinel: bool | None = None,
    detector: Iterable[str] = (), negative: bool = False, notes: str = '', minimum: int = 1,
) -> None:
    if sentinel is None:
        sentinel = impact in {'direct_codegen', 'indirect_codegen'} or not sources
    mandatory = list(dict.fromkeys(sources + (['SENTINEL'] if sentinel else [])))
    features.append({
        'id': fid, 'category': category, 'name': name, 'impact': impact,
        'lanes': lanes, 'syntax_examples': list(syntax), 'detector_hints': list(detector),
        'mandatory_sources': mandatory,
        'public_candidate_sources': [x for x in sources if x != 'SENTINEL'],
        'sentinel_required': sentinel, 'minimum_verified_occurrences': minimum,
        'negative_compile_case': negative, 'required_evidence': required_evidence(lanes),
        'verification_status': 'manifested_unverified', 'notes': notes,
    })

def add_rows(category: str, rows: list[tuple], detector: str) -> None:
    for fid, name, impact, lanes, sources, syntax in rows:
        add(fid, category, name, impact, lanes, sources, syntax, detector=[detector])

# ---------------------------------------------------------------------------
# Language and compiler feature inventory
# ---------------------------------------------------------------------------
add_rows('literals', [
    ('LIT-BOOL-TRUE', 'Bool literal True', 'direct_codegen', ['compile','blaster'], PRIM, ['True']),
    ('LIT-BOOL-FALSE', 'Bool literal False', 'direct_codegen', ['compile','blaster'], PRIM, ['False']),
    ('LIT-INT-DECIMAL', 'Decimal Int literal', 'direct_codegen', ['compile','blaster'], PRIM, ['42']),
    ('LIT-INT-SEPARATOR', 'Decimal Int literal with underscore separators', 'direct_codegen', ['compile','blaster'], ACC, ['1_000_000']),
    ('LIT-INT-HEX', 'Hexadecimal Int literal', 'direct_codegen', ['compile','blaster'], ACC, ['0xff']),
    ('LIT-INT-NEGATIVE', 'Negative Int through unary negation', 'direct_codegen', ['compile','blaster'], PRIM, ['-42']),
    ('LIT-BYTEARRAY-LIST-DECIMAL', 'ByteArray list literal with decimal bytes', 'direct_codegen', ['compile','blaster'], PRIM, ['#[0, 1, 255]']),
    ('LIT-BYTEARRAY-LIST-HEX', 'ByteArray list literal with hexadecimal bytes', 'direct_codegen', ['compile','blaster'], ACC, ['#[0x00, 0xaa, 0xff]']),
    ('LIT-BYTEARRAY-UTF8', 'UTF-8 ByteArray literal', 'direct_codegen', ['compile','blaster'], PRIM, ['"hello"']),
    ('LIT-BYTEARRAY-HEX', 'Hex-encoded ByteArray literal', 'direct_codegen', ['compile','blaster'], PRIM, ['#"deadbeef"']),
    ('LIT-BYTEARRAY-ESCAPE', 'ByteArray escape sequences', 'direct_codegen', ['compile','blaster'], ACC, ['"a\\n\\t\\0\\\\\\\""']),
    ('LIT-BYTEARRAY-COMMENT', 'Comment inside a ByteArray list literal', 'compile_only', ['compile'], ACC, ['#[1, // comment\n2]']),
    ('LIT-STRING', 'String literal', 'direct_codegen', ['compile','blaster'], PRIM, ['@"hello"']),
    ('LIT-STRING-MULTILINE', 'Multiline String literal', 'direct_codegen', ['compile','blaster'], ACC, ['@"line 1\nline 2"']),
    ('LIT-STRING-UNICODE', 'Unicode String literal', 'direct_codegen', ['compile','blaster'], ACC, ['@"★"']),
    ('LIT-STRING-ESCAPE', 'String escape sequences', 'direct_codegen', ['compile','blaster'], ACC, ['@"a\\n\\t\\0\\\\\\\""']),
    ('LIT-LIST-EMPTY', 'Empty List literal', 'direct_codegen', ['compile','blaster'], PRIM, ['[]']),
    ('LIT-LIST-ELEMENTS', 'Non-empty List literal', 'direct_codegen', ['compile','blaster'], PRIM, ['[1, 2, 3]']),
    ('LIT-LIST-SPREAD', 'List spread or tail expression', 'direct_codegen', ['compile','blaster'], ACC, ['[head, ..tail]']),
    ('LIT-TUPLE', 'Tuple literal', 'direct_codegen', ['compile','blaster'], PRIM, ['(1, True, #"00")']),
    ('LIT-PAIR', 'Pair literal or Pair constructor', 'direct_codegen', ['compile','blaster'], PRIM, ['Pair(1, True)']),
    ('LIT-VOID', 'Void constructor expression', 'direct_codegen', ['compile','blaster'], PRIM, ['Void']),
    ('LIT-CURVE-G1', 'BLS12-381 G1 curve-point literal', 'direct_codegen', ['compile','blaster'], ACC, ['#<Bls12_381, G1>"..."']),
    ('LIT-CURVE-G2', 'BLS12-381 G2 curve-point literal', 'direct_codegen', ['compile','blaster'], ACC, ['#<Bls12_381, G2>"..."']),
], 'token and typed-expression match')

for fid, name in [
    ('TYPE-DATA','Data'), ('TYPE-INT','Int'), ('TYPE-BYTEARRAY','ByteArray'), ('TYPE-BOOL','Bool'),
    ('TYPE-G1','G1Element'), ('TYPE-G2','G2Element'), ('TYPE-MILLER','MillerLoopResult'),
    ('TYPE-ORDERING','Ordering'), ('TYPE-STRING','String'), ('TYPE-VOID','Void'), ('TYPE-LIST','List<a>'),
    ('TYPE-PAIR','Pair<a, b>'), ('TYPE-PAIRS','Pairs<a, b>'), ('TYPE-OPTION','Option<a>'),
    ('TYPE-NEVER','Never'), ('TYPE-SCRIPT-CONTEXT','ScriptContext'),
]:
    src = PRIM if fid not in {'TYPE-G1','TYPE-G2','TYPE-MILLER','TYPE-SCRIPT-CONTEXT'} else ACC
    add(fid, 'prelude_types', f'Prelude type {name}', 'indirect_codegen', ['compile','blaster'], src,
        detector=[f'typed AST contains {name}'])

add_rows('modules_definitions_imports', [
    ('MOD-LIB', 'Library module', 'compile_only', ['compile'], ACC, ['lib/**/*.ak']),
    ('MOD-VALIDATOR', 'Validator module', 'direct_codegen', ['compile','blaster'], VAL, ['validators/**/*.ak']),
    ('MOD-ENV', 'Environment module', 'project_only', ['compile','config'], CONST, ['env/**/*.ak']),
    ('MOD-CONFIG', 'Generated configuration module', 'project_only', ['compile','config'], CONST, ['use config']),
    ('DEF-FN-PRIVATE', 'Private named function', 'indirect_codegen', ['compile','blaster'], FN, ['fn name(...) { ... }']),
    ('DEF-FN-PUBLIC', 'Public named function', 'indirect_codegen', ['compile','blaster'], FN, ['pub fn name(...) { ... }']),
    ('DEF-CONST-PRIVATE', 'Private module constant', 'indirect_codegen', ['compile','blaster'], CONST, ['const name = ...']),
    ('DEF-CONST-PUBLIC', 'Public module constant', 'indirect_codegen', ['compile','blaster'], CONST, ['pub const name = ...']),
    ('DEF-TYPE-PRIVATE', 'Private custom type', 'indirect_codegen', ['compile','blaster'], CUSTOM, ['type T { ... }']),
    ('DEF-TYPE-PUBLIC', 'Public custom type', 'indirect_codegen', ['compile','blaster'], CUSTOM, ['pub type T { ... }']),
    ('DEF-TYPE-OPAQUE-PRIVATE', 'Private opaque custom type', 'indirect_codegen', ['compile','blaster'], CUSTOM, ['opaque type T { ... }']),
    ('DEF-TYPE-OPAQUE-PUBLIC', 'Public opaque custom type', 'indirect_codegen', ['compile','blaster'], CUSTOM, ['pub opaque type T { ... }']),
    ('DEF-TYPE-ALIAS-PRIVATE', 'Private type alias', 'compile_only', ['compile'], ACC, ['type Alias = ...']),
    ('DEF-TYPE-ALIAS-PUBLIC', 'Public type alias', 'compile_only', ['compile'], ACC, ['pub type Alias = ...']),
    ('DEF-TYPE-ALIAS-GENERIC', 'Generic type alias parameters', 'compile_only', ['compile'], ACC, ['type Alias<a> = ...']),
    ('DEF-TEST', 'Test definition', 'check_only', ['compile','check'], TEST, ['test name() { ... }']),
    ('DEF-BENCH', 'Benchmark definition', 'bench_only', ['compile','bench'], BENCH, ['bench name(x via sampler) { ... }']),
    ('DEF-VALIDATOR', 'Validator definition', 'direct_codegen', ['compile','blaster'], VAL, ['validator name { ... }']),
    ('TYPE-CONSTRUCTOR-ZERO', 'Zero-field custom constructor', 'direct_codegen', ['compile','blaster'], CUSTOM, ['None']),
    ('TYPE-CONSTRUCTOR-POSITIONAL', 'Positional custom constructor fields', 'direct_codegen', ['compile','blaster'], CUSTOM, ['Some(Int)']),
    ('TYPE-CONSTRUCTOR-RECORD', 'Named record constructor fields', 'direct_codegen', ['compile','blaster'], CUSTOM, ['Record { field: Int }']),
    ('TYPE-SHORTHAND-RECORD', 'Single-constructor record shorthand', 'direct_codegen', ['compile','blaster'], CUSTOM, ['type Record { field: Int }']),
    ('TYPE-MULTI-CONSTRUCTOR', 'Custom type with several constructors', 'direct_codegen', ['compile','blaster'], CUSTOM, ['type Choice { A B(Int) }']),
    ('TYPE-RECURSIVE', 'Recursive custom type', 'direct_codegen', ['compile','blaster'], CUSTOM, ['type Tree<a> { Leaf(a) Node(Tree<a>, Tree<a>) }']),
    ('TYPE-GENERIC', 'Generic custom type parameters', 'indirect_codegen', ['compile','blaster'], CUSTOM, ['type Box<a> { Box(a) }']),
    ('TYPE-OPAQUE-NEWTYPE', 'Zero-cost opaque single-field newtype representation', 'direct_codegen', ['compile','blaster'], CUSTOM, ['pub opaque type NewType<a> { field: a }']),
    ('ENC-DEFAULT-TAG-ORDER', 'Default constructor tags follow definition order', 'direct_codegen', ['compile','blaster'], ACC, []),
    ('ENC-TAG-TYPE-DECIMAL', '@tag with a decimal value on a type', 'direct_codegen', ['compile','blaster'], ACC, ['@tag(42)']),
    ('ENC-TAG-TYPE-HEX', '@tag with a hexadecimal value on a type', 'direct_codegen', ['compile','blaster'], ACC, ['@tag(0x2a)']),
    ('ENC-TAG-CONSTRUCTOR-DECIMAL', '@tag with a decimal value on a constructor', 'direct_codegen', ['compile','blaster'], ACC, ['@tag(42)']),
    ('ENC-TAG-CONSTRUCTOR-HEX', '@tag with a hexadecimal value on a constructor', 'direct_codegen', ['compile','blaster'], ACC, ['@tag(0x2a)']),
    ('ENC-LIST', '@list encoding decorator', 'direct_codegen', ['compile','blaster'], ACC, ['@list']),
    ('IMPORT-QUALIFIED', 'Qualified module import', 'compile_only', ['compile'], ACC + ['AIKEN_STDLIB'], ['use aiken/collection/list']),
    ('IMPORT-MODULE-ALIAS', 'Module import alias', 'compile_only', ['compile'], ACC, ['use module/path as alias']),
    ('IMPORT-UNQUALIFIED', 'Unqualified item import', 'compile_only', ['compile'], ACC, ['use module/path.{item}']),
    ('IMPORT-ITEM-ALIAS', 'Unqualified item alias', 'compile_only', ['compile'], ACC, ['use module/path.{item as alias}']),
    ('IMPORT-MERGED', 'Merged repeated imports from the same module', 'compile_only', ['compile'], ACC, ['two use declarations for one module']),
    ('IMPORT-PACKAGE', 'Dependency package import', 'project_only', ['compile','config'], ['AIKEN_STDLIB','AIKEN_FUZZ','AIKEN_SAMPLE'], ['dependency module import']),
    ('IMPORT-NESTED-PATH', 'Nested module path', 'compile_only', ['compile'], ACC + ['AIKEN_STDLIB'], ['aiken/collection/list']),
    ('IMPORT-PRELUDE-IMPLICIT', 'Implicit aiken prelude import', 'compile_only', ['compile'], ACC, ['Option without use aiken']),
    ('IMPORT-PRELUDE-EXPLICIT', 'Explicit aiken prelude import', 'compile_only', ['compile'], ACC, ['use aiken']),
    ('IMPORT-BUILTIN-MODULE', 'Explicit aiken/builtin import', 'direct_codegen', ['compile','blaster'], ACC, ['use aiken/builtin']),
    ('IMPORT-CONDITIONAL-ENV', 'Conditional environment import', 'project_only', ['compile','config'], CONST, ['use env']),
    ('IMPORT-CONDITIONAL-CONFIG', 'Conditional configuration import', 'project_only', ['compile','config'], CONST, ['use config']),
    ('IMPORT-EXPLICIT-ENV-MODULE', 'Explicit import of another environment module', 'project_only', ['compile','config'], CONST, ['use preview']),
    ('SELECT-MODULE', 'Module-qualified value or function selection', 'indirect_codegen', ['compile','blaster'], ACC + ['AIKEN_STDLIB'], ['module.item']),
    ('SELECT-TYPE-NAMESPACE', 'Type name used as a constructor namespace', 'indirect_codegen', ['compile','blaster'], ACC, ['Type.Constructor']),
], 'definition, import, decorator, or namespace AST match')

add_rows('comments_and_docs', [
    ('COMMENT-INLINE', 'Inline source comment', 'compile_only', ['compile'], ACC, ['// comment']),
    ('COMMENT-DOC-DEFINITION', 'Documentation comment on a definition', 'compile_only', ['compile','docs'], CONST, ['/// documentation']),
    ('COMMENT-DOC-CONSTRUCTOR', 'Documentation comment on a constructor', 'compile_only', ['compile','docs'], CUSTOM, ['/// constructor documentation']),
    ('COMMENT-DOC-FIELD', 'Documentation comment on a custom-type field', 'compile_only', ['compile','docs'], CUSTOM, ['/// field documentation']),
    ('COMMENT-DOC-FN-ARG', 'Documentation comment on a function argument', 'compile_only', ['compile','docs'], FN, ['/// argument documentation']),
    ('COMMENT-DOC-VALIDATOR-PARAM', 'Documentation comment on a validator parameter', 'compile_only', ['compile','docs'], VAL, ['/// validator parameter']),
    ('COMMENT-DOC-HANDLER-ARG', 'Documentation comment on a validator handler argument', 'compile_only', ['compile','docs'], VAL, ['/// handler argument']),
    ('COMMENT-DOC-FALLBACK-ARG', 'Documentation comment on an else-handler argument', 'compile_only', ['compile','docs'], VAL, ['/// fallback argument']),
    ('COMMENT-MODULE', 'Module documentation comment', 'compile_only', ['compile','docs'], CONST, ['//// module documentation']),
    ('DOC-MODULE-HIDDEN', 'Hidden module documentation tag', 'docs_only', ['compile','docs'], CONST, ['//// @hidden']),
    ('COMMENT-EXPECT', 'Expect comment used as a runtime failure label', 'direct_codegen', ['compile','blaster'], ACC, ['/// custom expect failure']),
    ('DOC-GENERATION', 'HTML documentation generation', 'docs_only', ['compile','docs'], CONST, ['aiken docs']),
], 'comment index, trace label, or docs-output match')

add_rows('type_system_and_data_conversion', [
    ('ANN-CONSTRUCTOR', 'Constructor type annotation', 'compile_only', ['compile'], ACC, ['Int', 'List<Int>']),
    ('ANN-MODULE-QUALIFIED', 'Module-qualified constructor annotation', 'compile_only', ['compile'], ACC, ['module.Type<a>']),
    ('ANN-FUNCTION', 'Function type annotation', 'compile_only', ['compile'], ACC, ['fn(Int) -> Bool']),
    ('ANN-VARIABLE', 'Generic type-variable annotation', 'compile_only', ['compile'], ACC, ['a']),
    ('ANN-HOLE', 'Anonymous type annotation hole', 'compile_only', ['compile'], ACC, ['_']),
    ('ANN-HOLE-NAMED', 'Named type annotation hole', 'compile_only', ['compile'], ACC, ['_name']),
    ('ANN-TUPLE', 'Tuple type annotation', 'compile_only', ['compile'], ACC, ['(Int, Bool)']),
    ('ANN-PAIR', 'Pair type annotation', 'compile_only', ['compile'], ACC, ['Pair<Int, Bool>']),
    ('ANN-PAIR-QUALIFIED', 'Qualified aiken.Pair type annotation', 'compile_only', ['compile'], ACC, ['aiken.Pair<Int, Bool>']),
    ('ANN-ARGUMENT', 'Function argument annotation', 'compile_only', ['compile'], FN, ['x: Int']),
    ('ANN-RETURN', 'Function return annotation', 'compile_only', ['compile'], FN, ['-> Bool']),
    ('ANN-BINDING', 'Let or expect binding annotation', 'indirect_codegen', ['compile','blaster'], ACC, ['let x: Int = ...']),
    ('ANN-CONSTANT', 'Module constant annotation', 'indirect_codegen', ['compile','blaster'], CONST, ['const x: Int = 1']),
    ('TYPE-INFERENCE', 'Local and return type inference', 'indirect_codegen', ['compile','blaster'], FN, ['unannotated binding and return']),
    ('TYPE-GENERIC-FUNCTION', 'Generic function instantiation', 'indirect_codegen', ['compile','blaster'], FN, ['fn identity(x: a) -> a']),
    ('DATA-UPCAST-IMPLICIT', 'Implicit serializable-value upcast to Data', 'direct_codegen', ['compile','blaster'], ACC + ['AIKEN_STDLIB'], []),
    ('DATA-UPCAST-AS-DATA', 'Explicit as_data conversion', 'direct_codegen', ['compile','blaster'], ACC + ['AIKEN_STDLIB'], ['as_data(value)']),
    ('DATA-DOWNCAST-EXPECT', 'Typed Data downcast through expect', 'direct_codegen', ['compile','blaster'], ACC + ['AIKEN_STDLIB'], ['expect x: T = data']),
    ('DATA-DOWNCAST-IF-IS', 'Typed Data downcast through if/is', 'direct_codegen', ['compile','blaster'], CONTROL, ['if data is T { ... }']),
    ('OPAQUE-BOUNDARY', 'Opaque constructor access boundary across modules', 'compile_only', ['compile'], CUSTOM, []),
    ('REGRESSION-EXPECT-UNUSED', 'Typed expect validation retained when the binding is unused', 'direct_codegen', ['compile','blaster'], ACC, []),
    ('REGRESSION-DECODER-IDENTITY', 'Distinct Data decoder identities across modules and generic shapes', 'direct_codegen', ['compile','blaster'], ACC, []),
], 'annotation, inferred type, or emitted decoder match')

add_rows('functions_calls_and_bindings', [
    ('EXPR-VARIABLE', 'Variable reference expression', 'direct_codegen', ['compile','blaster'], FN, ['x']),
    ('FN-ANONYMOUS', 'Anonymous function', 'direct_codegen', ['compile','blaster'], FN, ['fn(x) { x + 1 }']),
    ('FN-FIRST-CLASS', 'Function stored or passed as a value', 'direct_codegen', ['compile','blaster'], FN, []),
    ('FN-HIGHER-ORDER', 'Higher-order function', 'direct_codegen', ['compile','blaster'], FN + ['AIKEN_STDLIB'], []),
    ('FN-RECURSION', 'Recursive named function', 'direct_codegen', ['compile','blaster'], FN, []),
    ('FN-ARG-NAMED', 'Named function argument', 'compile_only', ['compile'], FN, ['x']),
    ('FN-ARG-DISCARD', 'Discarded function argument', 'compile_only', ['compile'], FN, ['_x']),
    ('FN-ARG-LABEL', 'Labelled function argument', 'compile_only', ['compile'], FN, ['label x']),
    ('FN-ARG-LABEL-OVERRIDE', 'Argument label differs from the local name', 'compile_only', ['compile'], FN, ['label local_name']),
    ('FN-ARG-LABELLED-DISCARD', 'Labelled discarded function argument', 'compile_only', ['compile'], ACC, ['label _name']),
    ('FN-ARG-DESTRUCTURE', 'Pattern destructuring in a function argument', 'direct_codegen', ['compile','blaster'], ACC, []),
    ('FN-ARG-DESTRUCTURE-ANNOTATED', 'Annotated destructuring function argument', 'direct_codegen', ['compile','blaster'], ACC, []),
    ('FN-EMPTY-BODY-TODO', 'Empty function body lowered to todo', 'direct_codegen', ['compile','blaster'], ACC, ['fn f()']),
    ('CALL-POSITIONAL', 'Positional function call', 'direct_codegen', ['compile','blaster'], FN, ['f(1, 2)']),
    ('CALL-LABELLED', 'Labelled function call', 'direct_codegen', ['compile','blaster'], FN, []),
    ('CALL-MIXED', 'Mixed positional and labelled function call', 'direct_codegen', ['compile','blaster'], FN, []),
    ('CALL-PUNNING', 'Call argument field punning', 'direct_codegen', ['compile','blaster'], ACC, []),
    ('CAPTURE-FUNCTION', 'Function-call capture with underscore', 'direct_codegen', ['compile','blaster'], FN, ['f(_, 1)']),
    ('CAPTURE-CONSTRUCTOR', 'Constructor-call capture with underscore', 'direct_codegen', ['compile','blaster'], ACC, ['Some(_)']),
    ('FN-ANON-BINOP', 'Standalone binary operator used as a function', 'direct_codegen', ['compile','blaster'], ACC, ['+']),
    ('PIPE-BARE', 'Pipeline into a bare function', 'direct_codegen', ['compile','blaster'], FN, ['x |> f']),
    ('PIPE-CALL-INSERT', 'Pipeline value inserted into a call', 'direct_codegen', ['compile','blaster'], FN, ['x |> f(1)']),
    ('PIPE-CAPTURE', 'Pipeline with an explicit capture position', 'direct_codegen', ['compile','blaster'], FN, ['x |> f(1, _)']),
    ('PIPE-RESULT-CALL', 'Pipeline fallback that calls the produced function value', 'direct_codegen', ['compile','blaster'], ACC, []),
    ('PIPE-ONE-LINE', 'One-line pipeline', 'direct_codegen', ['compile','blaster'], FN, ['x |> f |> g']),
    ('PIPE-MULTILINE', 'Multiline pipeline', 'direct_codegen', ['compile','blaster'], FN, ['x\n  |> f\n  |> g']),
    ('BLOCK-EXPRESSION', 'Braced expression block', 'direct_codegen', ['compile','blaster'], ACC, ['{ let x = 1; x }']),
    ('SEQUENCE-EXPRESSION', 'Expression sequence with a final value', 'direct_codegen', ['compile','blaster'], ACC, []),
    ('LET-VARIABLE', 'Let binding', 'direct_codegen', ['compile','blaster'], FN, ['let x = value']),
    ('LET-MULTIPLE', 'Multiple assignment patterns in one binding', 'direct_codegen', ['compile','blaster'], ACC, []),
    ('LET-DESTRUCTURE', 'Let pattern destructuring', 'direct_codegen', ['compile','blaster'], ACC, []),
    ('LET-SHADOW', 'Name shadowing', 'direct_codegen', ['compile','blaster'], ACC, []),
    ('LET-BACKPASS', 'Let backpassing assignment', 'direct_codegen', ['compile','blaster'], FN, ['let pattern <- callback_style_value']),
    ('EXPECT-PATTERN', 'Expect pattern assertion', 'direct_codegen', ['compile','blaster'], ACC, ['expect Some(x) = value']),
    ('EXPECT-BOOLEAN', 'Bare boolean expect assertion', 'direct_codegen', ['compile','blaster'], ACC, ['expect condition']),
    ('EXPECT-BACKPASS', 'Expect backpassing assignment', 'direct_codegen', ['compile','blaster'], ACC, ['expect pattern <- callback_style_value']),
], 'expression, argument, call, or assignment AST match')

for fid, name, syntax in [
    ('OP-AND','Boolean conjunction','&&'), ('OP-OR','Boolean disjunction','||'),
    ('OP-EQ','Equality','=='), ('OP-NEQ','Inequality','!='),
    ('OP-LT','Integer less-than','<'), ('OP-LTE','Integer less-than-or-equal','<='),
    ('OP-GTE','Integer greater-than-or-equal','>='), ('OP-GT','Integer greater-than','>'),
    ('OP-ADD','Integer addition','+'), ('OP-SUB','Integer subtraction','-'),
    ('OP-MUL','Integer multiplication','*'), ('OP-DIV','Integer division','/'),
    ('OP-MOD','Integer modulo','%'), ('OP-NOT','Boolean negation','!'),
    ('OP-NEGATE','Integer unary negation','unary -'),
]:
    add(fid, 'operators', name, 'direct_codegen', ['compile','blaster'], ACC + ['EDU_FUNCTIONS'], [syntax], detector=['BinOp or UnOp AST match'])
add('OP-EQ-SERIALIZABLE', 'operators', 'Equality on a serializable compound value', 'direct_codegen', ['compile','blaster'], ACC + ['AIKEN_STDLIB'], ['left == right'], detector=['typed equality over custom Data, List, Tuple, or Pair'])
add('OP-NEQ-SERIALIZABLE', 'operators', 'Inequality on a serializable compound value', 'direct_codegen', ['compile','blaster'], ACC + ['AIKEN_STDLIB'], ['left != right'], detector=['typed inequality over custom Data, List, Tuple, or Pair'])

add_rows('control_flow_and_expressions', [
    ('BOOL-AND-BLOCK', 'and keyword block', 'direct_codegen', ['compile','blaster'], CONTROL, ['and { a, b, c }']),
    ('BOOL-OR-BLOCK', 'or keyword block', 'direct_codegen', ['compile','blaster'], CONTROL, ['or { a, b, c }']),
    ('IF-ELSE', 'if/else expression', 'direct_codegen', ['compile','blaster'], CONTROL, ['if condition { a } else { b }']),
    ('IF-ELSE-IF', 'else-if chain', 'direct_codegen', ['compile','blaster'], CONTROL, []),
    ('WHEN', 'when/is pattern matching', 'direct_codegen', ['compile','blaster'], CONTROL, ['when value is { pattern -> result }']),
    ('IF-IS-PATTERN-TYPE', 'if/is with an explicit pattern and type', 'direct_codegen', ['compile','blaster'], CONTROL, []),
    ('IF-IS-TYPE', 'if/is type-only shorthand', 'direct_codegen', ['compile','blaster'], CONTROL, []),
    ('EXPR-GROUPING', 'Parenthesized expression grouping', 'direct_codegen', ['compile','blaster'], ACC, ['(a + b) * c']),
    ('TRACE-BASIC', 'Trace expression', 'direct_codegen', ['compile','blaster'], ACC + ['EDU_CHECK'], ['trace @"label"']),
    ('TRACE-LABEL-STRING', 'Trace label supplied as a String', 'direct_codegen', ['compile','blaster'], ACC + ['EDU_CHECK'], ['trace @"label"']),
    ('TRACE-LABEL-BYTEARRAY', 'Trace label supplied as a ByteArray', 'direct_codegen', ['compile','blaster'], ACC, ['trace "label"']),
    ('TRACE-LABEL-EXPRESSION', 'Trace label supplied by an expression', 'direct_codegen', ['compile','blaster'], ACC, []),
    ('TRACE-ARGS', 'Trace with inspected values', 'direct_codegen', ['compile','blaster'], ACC + ['EDU_CHECK'], []),
    ('TRACE-DEFAULT-CONT', 'Trace with the default Void continuation', 'direct_codegen', ['compile','blaster'], ACC, []),
    ('TRACE-QUESTION', 'Postfix question-mark trace-if-false shorthand', 'direct_codegen', ['compile','blaster'], ACC, ['expression?']),
    ('FAIL-BARE', 'fail without a reason', 'direct_codegen', ['compile','blaster'], ACC, ['fail']),
    ('FAIL-REASON', 'fail with a reason expression', 'direct_codegen', ['compile','blaster'], ACC, ['fail @"reason"']),
    ('TODO-BARE', 'todo without a reason', 'direct_codegen', ['compile','blaster'], ACC, ['todo']),
    ('TODO-REASON', 'todo with a reason expression', 'direct_codegen', ['compile','blaster'], ACC, ['todo @"reason"']),
    ('ERROR-ALIAS', 'Deprecated error alias for fail', 'direct_codegen', ['compile','blaster'], ACC, ['error']),
    ('ACCESS-RECORD', 'Record field access', 'direct_codegen', ['compile','blaster'], ACC + ['EDU_CUSTOM_TYPES'], ['record.field']),
    ('ACCESS-TUPLE', 'Tuple ordinal access', 'direct_codegen', ['compile','blaster'], PRIM, ['tuple.1st']),
    ('ACCESS-PAIR', 'Pair ordinal access', 'direct_codegen', ['compile','blaster'], PRIM, ['pair.1st']),
    ('RECORD-CONSTRUCT-NAMED', 'Named-field record construction', 'direct_codegen', ['compile','blaster'], CUSTOM, ['Record { field: value }']),
    ('RECORD-CONSTRUCT-POSITIONAL', 'Positional construction of a record constructor', 'direct_codegen', ['compile','blaster'], CUSTOM, ['Record(value)']),
    ('RECORD-FIELD-ORDER', 'Named fields supplied in a different order', 'direct_codegen', ['compile','blaster'], CUSTOM, []),
    ('RECORD-PUNNING', 'Record field punning', 'direct_codegen', ['compile','blaster'], ACC, ['Record { field }']),
    ('RECORD-UPDATE', 'Record update expression', 'direct_codegen', ['compile','blaster'], ACC + ['EDU_CUSTOM_TYPES'], ['Record { ..base, field: value }']),
], 'expression AST match')

for fid, name, syntax in [
    ('PAT-INT-DECIMAL','Decimal Int pattern',['42']),
    ('PAT-INT-SEPARATOR','Decimal Int pattern with separators',['1_000']),
    ('PAT-INT-HEX','Hexadecimal Int pattern',['0xff']),
    ('PAT-INT-NEGATIVE','Negative Int pattern',['-42']),
    ('PAT-BYTEARRAY-LIST-DECIMAL','ByteArray list-format pattern with decimal bytes',['#[1, 2]']),
    ('PAT-BYTEARRAY-LIST-HEX','ByteArray list-format pattern with hexadecimal bytes',['#[0x01, 0xff]']),
    ('PAT-BYTEARRAY-UTF8','UTF-8 ByteArray pattern',['"ok"']),
    ('PAT-BYTEARRAY-HEX','Hex ByteArray pattern',['#"00ff"']),
    ('PAT-BOOL','Bool constructor pattern',['True']),
    ('PAT-VARIABLE','Variable pattern',['value']),
    ('PAT-DISCARD','Wildcard discard pattern',['_']),
    ('PAT-NAMED-DISCARD','Named discard pattern',['_unused']),
    ('PAT-AS','as pattern',['pattern as whole']),
    ('PAT-LIST-EXACT','Exact List pattern',['[a, b]']),
    ('PAT-LIST-TAIL','List tail pattern',['[head, ..]']),
    ('PAT-LIST-NAMED-TAIL','Named List tail pattern',['[head, ..tail]']),
    ('PAT-PAIR','Pair pattern',['Pair(a, b)']),
    ('PAT-TUPLE','Tuple pattern',['(a, b)']),
    ('PAT-CONSTRUCTOR-POSITIONAL','Positional constructor pattern',['Some(value)']),
    ('PAT-CONSTRUCTOR-RECORD','Record constructor pattern',['Record { field }']),
    ('PAT-CONSTRUCTOR-POSITIONAL-SPREAD','Positional constructor pattern spread',['Ctor(value, ..)']),
    ('PAT-RECORD-SPREAD','Record constructor pattern spread',['Record { field, .. }']),
    ('PAT-MODULE-QUALIFIED','Module-qualified constructor pattern',['module.Ctor(x)']),
    ('PAT-TYPE-QUALIFIED','Type-qualified constructor pattern',['Type.Ctor(x)']),
    ('PAT-NESTED','Nested pattern',['Some([head, ..tail])']),
    ('PAT-ALTERNATIVE','Alternative patterns with vertical bar',['A(x) | B(x)']),
    ('PAT-FIELD-PUNNING','Record-field punning in a pattern',['Record { field }']),
    ('PAT-FIELD-RENAME','Record-field rename in a pattern',['Record { field: local }']),
    ('PAT-ARG-DESTRUCTURE','Pattern in a function argument',[]),
    ('PAT-LET-DESTRUCTURE','Pattern in let',[]),
    ('PAT-EXPECT-DESTRUCTURE','Pattern in expect',[]),
]:
    add(fid, 'patterns', name, 'direct_codegen', ['compile','blaster'], ACC + ['EDU_CUSTOM_TYPES','EDU_CONTROL'], syntax, detector=['Pattern AST match'])

for fid, name, extras in [
    ('VAL-SPEND','Spend handler',['EDU_SPENDING']), ('VAL-MINT','Mint handler',['EDU_MINTING']),
    ('VAL-WITHDRAW','Withdraw handler',['EDU_STAKING']), ('VAL-PUBLISH','Publish handler',['EDU_STAKING']),
    ('VAL-PROPOSE','Propose handler',[]), ('VAL-VOTE','Vote handler',[]),
    ('VAL-ELSE','Validator else fallback',['EDU_STAKING']),
    ('VAL-PARAMETERIZED','Parameterized validator',['EDU_SPENDING']),
    ('VAL-MULTI-HANDLER','Validator with several purpose handlers',['EDU_STAKING']),
    ('VAL-MULTIPLE-DEFS','Several validator definitions in one package',['EDU_MINTING','EDU_SPENDING']),
    ('VAL-SPEND-ARITY','Four-argument spend handler boundary',['EDU_SPENDING']),
    ('VAL-OTHER-ARITY','Three-argument non-spend handler boundary',['EDU_MINTING','EDU_STAKING']),
    ('VAL-DEFAULT-FALLBACK','Compiler-generated default fallback when else is omitted',[]),
    ('VAL-DATUM-OPTION','Optional datum boundary for spend',['EDU_SPENDING']),
    ('VAL-SCRIPT-CONTEXT','Transaction or ScriptContext boundary decoding',['EDU_SPENDING','EDU_MINTING','EDU_STAKING']),
    ('VAL-EMPTY-HANDLER-TODO','Empty validator handler body lowered to todo',[]),
]:
    add(fid, 'validators', name, 'direct_codegen', ['compile','blaster'], list(dict.fromkeys(ACC + extras)), detector=['validator handler AST and blueprint entry'])

project_rows = [
    ('TARGET-PLUTUS-V3', 'Plutus V3 project target', 'project_only', ['compile','config','blaster'], ACC + ['AIKEN_STDLIB'], ['plutus = "v3"']),
    ('PROJECT-TOML', 'aiken.toml project manifest', 'project_only', ['compile','config'], ACC + ['AIKEN_STDLIB'], ['aiken.toml']),
    ('PROJECT-COMPILER-PIN', 'Compiler version constraint in aiken.toml', 'project_only', ['compile','config'], ACC, ['compiler = "v1.1.23"']),
    ('PROJECT-LOCK', 'Locked dependencies through aiken.lock', 'project_only', ['compile','config'], ['AIKEN_STDLIB','AIKEN_FUZZ','AIKEN_SAMPLE'], ['aiken.lock']),
    ('PROJECT-DEPENDENCY', 'Package dependency resolution', 'project_only', ['compile','config'], ['AIKEN_STDLIB','AIKEN_FUZZ','AIKEN_SAMPLE'], []),
    ('PROJECT-DEPENDENCY-GITHUB', 'GitHub dependency source', 'project_only', ['compile','config'], ['AIKEN_STDLIB'], ['source = "github"']),
    ('PROJECT-DEPENDENCY-GITLAB', 'GitLab dependency source declaration', 'project_only', ['compile','config'], ACC, ['source = "gitlab"']),
    ('PROJECT-DEPENDENCY-BITBUCKET', 'Bitbucket dependency source declaration', 'project_only', ['compile','config'], ACC, ['source = "bitbucket"']),
    ('PROJECT-MONOREPO', 'Monorepo members property', 'project_only', ['compile','config'], ACC, ['members = ["pkgs/member"]']),
    ('PROJECT-MONOREPO-GLOB', 'Glob expansion in monorepo members', 'project_only', ['compile','config'], ACC, ['members = ["pkgs/*"]']),
    ('PROJECT-ENV-DEFAULT', 'Default environment module selection', 'project_only', ['compile','config','blaster'], CONST, ['env/default.ak']),
    ('PROJECT-ENV-NAMED', 'Named environment module selection', 'project_only', ['compile','config','blaster'], CONST, ['--env preview']),
    ('PROJECT-CONFIG-DEFAULT', 'Default configuration selection', 'project_only', ['compile','config','blaster'], CONST, ['[config.default]']),
    ('PROJECT-CONFIG-NAMED', 'Named configuration selection', 'project_only', ['compile','config','blaster'], CONST, ['[config.preview]']),
    ('PROJECT-CONDITIONAL-MODULE', 'One conditional module API with several implementations', 'project_only', ['compile','config','blaster'], CONST, ['use env', 'use config']),
    ('PROJECT-BLUEPRINT', 'Blueprint generation for validators', 'project_only', ['compile','config'], VAL, ['plutus.json']),
    ('CONFIG-INT', 'Injected Int configuration value', 'project_only', ['compile','config','blaster'], CONST, ['price = 1000000']),
    ('CONFIG-BOOL', 'Injected Bool configuration value', 'project_only', ['compile','config','blaster'], CONST, ['is_mainnet = true']),
    ('CONFIG-BYTEARRAY-UTF8-STRING', 'Injected UTF-8 ByteArray from a TOML string', 'project_only', ['compile','config','blaster'], CONST, ['network = "mainnet"']),
    ('CONFIG-BYTEARRAY-UTF8-MAP', 'Injected UTF-8 ByteArray from bytes/encoding fields', 'project_only', ['compile','config','blaster'], CONST, ['encoding = "utf8"']),
    ('CONFIG-BYTEARRAY-HEX-MAP', 'Injected hex ByteArray from bytes/encoding fields', 'project_only', ['compile','config','blaster'], CONST, ['encoding = "hex"']),
    ('CONFIG-LIST', 'Injected homogeneous List configuration value', 'project_only', ['compile','config','blaster'], CONST, ['quotas = [1, 2, 3]']),
    ('CONFIG-TUPLE', 'Injected heterogeneous Tuple configuration value', 'project_only', ['compile','config','blaster'], CONST, ['asset = ["HOSKY", 42]']),
]
for fid, name, impact, lanes, src, syntax in project_rows:
    add(fid, 'project_and_targets', name, impact, lanes, src, syntax,
        sentinel=fid not in {'PROJECT-DEPENDENCY-GITLAB','PROJECT-DEPENDENCY-BITBUCKET'},
        detector=['manifest, selected module, injected AST, or build-output match'])

for fid, name, impact, lanes, src, syntax in [
    ('TEST-UNIT','Unit test without a fuzzer','check_only',['compile','check'],TEST,['test name() { ... }']),
    ('TEST-PROPERTY-VIA','Property-test argument introduced with via','check_only',['compile','check'],TEST,['test prop(x via fuzzer) { ... }']),
    ('TEST-FUZZER-NAMED','Named custom fuzzer','check_only',['compile','check'],TEST,[]),
    ('TEST-FUZZER-COMPOSED','Composed fuzzer','check_only',['compile','check'],TEST,[]),
    ('TEST-MULTI-VIA','Test with several via arguments','check_only',['compile','check'],TEST,[]),
    ('TEST-VALIDATOR','Validator behavior test','check_only',['compile','check'],['AIKEN_ACCEPTANCE','EDU_CHECK'],[]),
    ('TEST-FAIL','test fail expected-failure mode','check_only',['compile','check'],['AIKEN_ACCEPTANCE','EDU_CHECK'],['test fail name() { ... }']),
    ('TEST-FAIL-ONCE','test fail once eventual-success mode','check_only',['compile','check'],['AIKEN_ACCEPTANCE','EDU_CHECK'],['test fail once name(...) { ... }']),
    ('TEST-TRACE','Trace production inside a test','check_only',['compile','check'],['AIKEN_ACCEPTANCE','EDU_CHECK'],[]),
    ('BENCH-VIA','Benchmark argument introduced with via','bench_only',['compile','bench'],BENCH,['bench name(x via sampler) { ... }']),
    ('BENCH-SAMPLER-NAMED','Named custom Sampler','bench_only',['compile','bench'],BENCH,[]),
    ('BENCH-SAMPLER-COMPOSED','Composed Sampler','bench_only',['compile','bench'],BENCH,[]),
    ('BENCH-MULTI-VIA','Benchmark with several via arguments','bench_only',['compile','bench'],BENCH,[]),
    ('TRACE-LEVEL-SILENT','Silent trace level','project_only',['compile','config','blaster'],ACC,['silent']),
    ('TRACE-LEVEL-COMPACT','Compact trace level','project_only',['compile','config','blaster'],ACC,['compact']),
    ('TRACE-LEVEL-VERBOSE','Verbose trace level','project_only',['compile','config','blaster'],ACC,['verbose']),
]:
    add(fid, 'tests_benchmarks_and_tracing', name, impact, lanes, src, syntax,
        sentinel=True, detector=['test, benchmark, or tracing mode match'])
add('FRAMEWORK-PRNG','tests_benchmarks_and_tracing','PRNG support type','check_only',['compile','check'],['AIKEN_ACCEPTANCE','AIKEN_FUZZ'],sentinel=True,detector=['typed use of PRNG'])
add('FRAMEWORK-FUZZER','tests_benchmarks_and_tracing','Fuzzer support type','check_only',['compile','check'],['AIKEN_ACCEPTANCE','AIKEN_FUZZ'],sentinel=True,detector=['typed use of Fuzzer'])
add('FRAMEWORK-SAMPLER','tests_benchmarks_and_tracing','Sampler support type','bench_only',['compile','bench'],['AIKEN_ACCEPTANCE','AIKEN_SAMPLE'],sentinel=True,detector=['typed use of Sampler'])
add('TRACE-SOURCE-USER','tests_benchmarks_and_tracing','User-defined trace source mode','project_only',['compile','config','blaster'],ACC,sentinel=True,detector=['tracing source configuration'])
add('TRACE-SOURCE-COMPILER','tests_benchmarks_and_tracing','Compiler-generated trace source mode','project_only',['compile','config','blaster'],ACC,sentinel=True,detector=['tracing source configuration'])
add('TRACE-SOURCE-ALL','tests_benchmarks_and_tracing','Combined user and compiler trace source mode','project_only',['compile','config','blaster'],ACC,sentinel=True,detector=['tracing source configuration'])

for fid, name in [
    ('NEG-TAG-OVERFLOW','@tag value overflow reports a diagnostic instead of a panic'),
    ('NEG-NONEXHAUSTIVE-WHEN','Non-exhaustive pattern matching reports an error'),
    ('NEG-TYPE-MISMATCH','Type mismatch reports an error'),
    ('NEG-OPAQUE-CONSTRUCTOR','External use of an opaque constructor reports an error'),
    ('NEG-INVALID-VALIDATOR-ARITY','Invalid validator handler arity reports an error'),
    ('NEG-STRING-PATTERN','String literals are rejected as patterns'),
    ('NEG-CURVE-PATTERN','Curve-point literals are rejected as patterns'),
    ('NEG-LIST-SPREAD-NO-SUBJECT','A list spread without a tail subject reports an error'),
    ('NEG-TARGET-PLUTUS-V1','The project manifest rejects Plutus V1'),
    ('NEG-TARGET-PLUTUS-V2','The project manifest rejects Plutus V2'),
    ('NEG-INT-BINARY','The v1.1.23 lexer rejects binary integer prefixes'),
    ('NEG-INT-OCTAL','The v1.1.23 lexer rejects octal integer prefixes'),
]:
    add(fid, 'negative_compile_contract', name, 'compile_only', ['compile'], ACC,
        sentinel=False, detector=['expected diagnostic code, message class, and source span'], negative=True)

# ---------------------------------------------------------------------------
# Active UPLC builtin inventory, parsed from the tagged source snapshot.
# ---------------------------------------------------------------------------
uplc_src = (OUT / '_aiken_v1_1_23_uplc_builtins.txt').read_text()
enum_body = re.search(r'pub enum DefaultFunction \{(.*?)\n\}', uplc_src, re.S).group(1)
variants: list[tuple[str, int]] = []
for line in enum_body.splitlines():
    line = line.strip()
    if not line or line.startswith('//'):
        continue
    m = re.match(r'([A-Za-z0-9_]+)\s*=\s*(\d+),', line)
    if m:
        variants.append((m.group(1), int(m.group(2))))

display_block = re.search(r'impl Display for DefaultFunction \{(.*?)\n\}', uplc_src, re.S).group(1)
uplc_names = dict(re.findall(r'\s*([A-Za-z0-9_]+)\s*=>\s*write!\(f,\s*"([^"]+)"\)', display_block))
aiken_block = re.search(r'pub fn aiken_name\(&self\) -> String \{(.*?)\.to_string\(\)', uplc_src, re.S).group(1)
aiken_names = dict(re.findall(r'\s*([A-Za-z0-9_]+)\s*=>\s*"([^"]+)"', aiken_block))
assert len(variants) == 87
assert all(v in uplc_names and v in aiken_names for v, _ in variants)

integer = {'AddInteger','SubtractInteger','MultiplyInteger','DivideInteger','QuotientInteger','RemainderInteger','ModInteger','EqualsInteger','LessThanInteger','LessThanEqualsInteger'}
bytearray = {'AppendByteString','ConsByteString','SliceByteString','LengthOfByteString','IndexByteString','EqualsByteString','LessThanByteString','LessThanEqualsByteString'}
crypto = {'Sha2_256','Sha3_256','Blake2b_224','Blake2b_256','Keccak_256','VerifyEd25519Signature','VerifyEcdsaSecp256k1Signature','VerifySchnorrSecp256k1Signature','Ripemd_160'}
string = {'AppendString','EqualsString','EncodeUtf8','DecodeUtf8'}
control_builtin = {'IfThenElse','ChooseUnit','Trace'}
pair_builtin = {'FstPair','SndPair'}
list_builtin = {'ChooseList','MkCons','HeadList','TailList','NullList'}
data_builtin = {'ChooseData','ConstrData','MapData','ListData','IData','BData','UnConstrData','UnMapData','UnListData','UnIData','UnBData','EqualsData','SerialiseData'}
data_ctor = {'MkPairData','MkNilData','MkNilPairData'}
conversion = {'IntegerToByteString','ByteStringToInteger'}
bitwise = {'AndByteString','OrByteString','XorByteString','ComplementByteString','ReadBit','WriteBits','ReplicateByte','ShiftByteString','RotateByteString','CountSetBits','FindFirstSetBit'}

def builtin_category(v: str) -> str:
    if v in integer: return 'integer'
    if v in bytearray: return 'bytearray'
    if v in crypto: return 'cryptography_and_hashing'
    if v in string: return 'string'
    if v in control_builtin: return 'control_and_trace'
    if v in pair_builtin: return 'pair'
    if v in list_builtin: return 'list'
    if v in data_builtin: return 'data'
    if v in data_ctor: return 'data_constructors'
    if v in conversion: return 'conversion'
    if v in bitwise: return 'bytearray_bitwise'
    if v.startswith('Bls12_381'): return 'bls12_381'
    raise AssertionError(v)

builtins: list[dict[str, Any]] = []
for variant, opcode in sorted(variants, key=lambda x: x[1]):
    cat = builtin_category(variant)
    public = ['AIKEN_ACCEPTANCE']
    if cat in {'integer','bytearray','string','pair','list','data','data_constructors'}:
        public.append('AIKEN_STDLIB')
    real_world: list[str] = []
    if cat == 'bls12_381':
        real_world = ['cardano-foundation/bls', 'ilap/bls', 'blocksmithy/oakshield-aiken']
    elif cat == 'cryptography_and_hashing':
        real_world = ['lambdasistemi/cardano-keri', 'utxo-company/fortuna', 'cardano-foundation/bls']
    elif cat == 'bytearray_bitwise':
        real_world = ['cardano-foundation/cip113-programmable-tokens']
    builtins.append({
        'id': f'BUILTIN-{opcode:02d}', 'opcode': opcode, 'enum_variant': variant,
        'aiken_name': aiken_names[variant], 'uplc_name': uplc_names[variant],
        'category': cat, 'impact': 'direct_codegen', 'lanes': ['compile','blaster'],
        'mandatory_sources': list(dict.fromkeys(public + ['SENTINEL'])),
        'real_world_candidate_repositories': real_world, 'sentinel_required': True,
        'minimum_verified_occurrences': 1,
        'required_evidence': [
            'reachable Aiken wrapper with non-constant inputs',
            f'UPLC contains builtin {uplc_names[variant]} in the selected branch',
            'successful old and new compiler builds', 'old and new UPLC artifacts',
            'Lean-blaster result or an explicit unsupported/inconclusive result',
        ],
        'verification_status': 'manifested_unverified',
    })

# ---------------------------------------------------------------------------
# Compiler-surface audit. Every listed variant and keyword maps to feature IDs.
# ---------------------------------------------------------------------------
surface_maps: dict[str, dict[str, list[str]]] = {
    'ModuleKind': {
        'Lib':['MOD-LIB'], 'Validator':['MOD-VALIDATOR'], 'Env':['MOD-ENV'], 'Config':['MOD-CONFIG'],
    },
    'Definition': {
        'Fn':['DEF-FN-PRIVATE','DEF-FN-PUBLIC','FN-EMPTY-BODY-TODO'],
        'TypeAlias':['DEF-TYPE-ALIAS-PRIVATE','DEF-TYPE-ALIAS-PUBLIC','DEF-TYPE-ALIAS-GENERIC'],
        'DataType':['DEF-TYPE-PRIVATE','DEF-TYPE-PUBLIC','DEF-TYPE-OPAQUE-PRIVATE','DEF-TYPE-OPAQUE-PUBLIC'],
        'Use':['IMPORT-QUALIFIED','IMPORT-UNQUALIFIED'],
        'ModuleConstant':['DEF-CONST-PRIVATE','DEF-CONST-PUBLIC'],
        'Test':['DEF-TEST'], 'Benchmark':['DEF-BENCH'], 'Validator':['DEF-VALIDATOR'],
    },
    'DecoratorKind': {
        'Tag':['ENC-TAG-TYPE-DECIMAL','ENC-TAG-TYPE-HEX','ENC-TAG-CONSTRUCTOR-DECIMAL','ENC-TAG-CONSTRUCTOR-HEX'],
        'List':['ENC-LIST'],
    },
    'Purpose': {
        'Spend':['VAL-SPEND'], 'Mint':['VAL-MINT'], 'Withdraw':['VAL-WITHDRAW'],
        'Publish':['VAL-PUBLISH'], 'Propose':['VAL-PROPOSE'], 'Vote':['VAL-VOTE'],
    },
    'Annotation': {
        'Constructor':['ANN-CONSTRUCTOR','ANN-MODULE-QUALIFIED'], 'Fn':['ANN-FUNCTION'],
        'Var':['ANN-VARIABLE'], 'Hole':['ANN-HOLE','ANN-HOLE-NAMED'],
        'Tuple':['ANN-TUPLE'], 'Pair':['ANN-PAIR','ANN-PAIR-QUALIFIED'],
    },
    'BinOp': {
        'And':['OP-AND'], 'Or':['OP-OR'], 'Eq':['OP-EQ','OP-EQ-SERIALIZABLE'],
        'NotEq':['OP-NEQ','OP-NEQ-SERIALIZABLE'], 'LtInt':['OP-LT'], 'LtEqInt':['OP-LTE'],
        'GtEqInt':['OP-GTE'], 'GtInt':['OP-GT'], 'AddInt':['OP-ADD'], 'SubInt':['OP-SUB'],
        'MultInt':['OP-MUL'], 'DivInt':['OP-DIV'], 'ModInt':['OP-MOD'],
    },
    'UnOp': {'Not':['OP-NOT'], 'Negate':['OP-NEGATE']},
    'LogicalOpChainKind': {'And':['BOOL-AND-BLOCK'], 'Or':['BOOL-OR-BLOCK']},
    'Pattern': {
        'Int':['PAT-INT-DECIMAL','PAT-INT-SEPARATOR','PAT-INT-HEX','PAT-INT-NEGATIVE'],
        'ByteArray':['PAT-BYTEARRAY-LIST-DECIMAL','PAT-BYTEARRAY-LIST-HEX','PAT-BYTEARRAY-UTF8','PAT-BYTEARRAY-HEX'],
        'Var':['PAT-VARIABLE'], 'Assign':['PAT-AS'], 'Discard':['PAT-DISCARD','PAT-NAMED-DISCARD'],
        'List':['PAT-LIST-EXACT','PAT-LIST-TAIL','PAT-LIST-NAMED-TAIL'],
        'Constructor':['PAT-BOOL','PAT-CONSTRUCTOR-POSITIONAL','PAT-CONSTRUCTOR-RECORD','PAT-CONSTRUCTOR-POSITIONAL-SPREAD','PAT-RECORD-SPREAD'],
        'Pair':['PAT-PAIR'], 'Tuple':['PAT-TUPLE'],
    },
    'Namespace': {'Module':['PAT-MODULE-QUALIFIED'], 'Type':['PAT-TYPE-QUALIFIED','SELECT-TYPE-NAMESPACE']},
    'AssignmentKind': {
        'Is':['IF-IS-PATTERN-TYPE','IF-IS-TYPE'],
        'Let':['LET-VARIABLE','LET-DESTRUCTURE','LET-BACKPASS'],
        'Expect':['EXPECT-PATTERN','EXPECT-BOOLEAN','EXPECT-BACKPASS'],
    },
    'TraceKind': {
        'Trace':['TRACE-BASIC','TRACE-QUESTION'], 'Todo':['TODO-BARE','TODO-REASON','FN-EMPTY-BODY-TODO','VAL-EMPTY-HANDLER-TODO'],
        'Error':['FAIL-BARE','FAIL-REASON','ERROR-ALIAS'],
    },
    'Tracing': {
        'UserDefined':['TRACE-SOURCE-USER'], 'CompilerGenerated':['TRACE-SOURCE-COMPILER'], 'All':['TRACE-SOURCE-ALL'],
    },
    'TraceLevel': {
        'Silent':['TRACE-LEVEL-SILENT'], 'Compact':['TRACE-LEVEL-COMPACT'], 'Verbose':['TRACE-LEVEL-VERBOSE'],
    },
    'OnTestFailure': {
        'FailImmediately':['TEST-UNIT','TEST-PROPERTY-VIA'],
        'SucceedImmediately':['TEST-FAIL'], 'SucceedEventually':['TEST-FAIL-ONCE'],
    },
    'ArgBy': {
        'ByName':['FN-ARG-NAMED','FN-ARG-DISCARD','FN-ARG-LABEL','FN-ARG-LABEL-OVERRIDE','FN-ARG-LABELLED-DISCARD'],
        'ByPattern':['FN-ARG-DESTRUCTURE','FN-ARG-DESTRUCTURE-ANNOTATED'],
    },
    'ArgName': {
        'Named':['FN-ARG-NAMED','FN-ARG-LABEL','FN-ARG-LABEL-OVERRIDE'],
        'Discarded':['FN-ARG-DISCARD','FN-ARG-LABELLED-DISCARD'],
    },
    'FnStyle': {
        'Plain':['FN-ANONYMOUS'], 'Capture':['CAPTURE-FUNCTION','CAPTURE-CONSTRUCTOR'], 'BinOp':['FN-ANON-BINOP'],
    },
    'TypedExpr': {
        'UInt':['LIT-INT-DECIMAL','LIT-INT-SEPARATOR','LIT-INT-HEX'],
        'String':['LIT-STRING','LIT-STRING-MULTILINE','LIT-STRING-UNICODE','LIT-STRING-ESCAPE'],
        'ByteArray':['LIT-BYTEARRAY-LIST-DECIMAL','LIT-BYTEARRAY-LIST-HEX','LIT-BYTEARRAY-UTF8','LIT-BYTEARRAY-HEX'],
        'CurvePoint':['LIT-CURVE-G1','LIT-CURVE-G2'], 'Sequence':['SEQUENCE-EXPRESSION','BLOCK-EXPRESSION'],
        'Pipeline':['PIPE-ONE-LINE','PIPE-MULTILINE'], 'Var':['EXPR-VARIABLE','LIT-BOOL-TRUE','LIT-BOOL-FALSE','LIT-VOID'],
        'Fn':['FN-ANONYMOUS','CAPTURE-FUNCTION','FN-ANON-BINOP'], 'List':['LIT-LIST-EMPTY','LIT-LIST-ELEMENTS','LIT-LIST-SPREAD'],
        'Call':['CALL-POSITIONAL','CALL-LABELLED','CALL-MIXED'], 'BinOp':['OP-ADD','OP-EQ'],
        'Assignment':['LET-VARIABLE','EXPECT-PATTERN','IF-IS-PATTERN-TYPE'], 'Trace':['TRACE-BASIC'],
        'When':['WHEN'], 'If':['IF-ELSE','IF-ELSE-IF'], 'RecordAccess':['ACCESS-RECORD'],
        'ModuleSelect':['SELECT-MODULE'], 'Tuple':['LIT-TUPLE'], 'Pair':['LIT-PAIR'],
        'TupleIndex':['ACCESS-TUPLE','ACCESS-PAIR'], 'ErrorTerm':['FAIL-BARE','TODO-BARE'],
        'RecordUpdate':['RECORD-UPDATE'], 'UnOp':['OP-NOT','OP-NEGATE'],
    },
    'UntypedExpr': {
        'UInt':['LIT-INT-DECIMAL','LIT-INT-SEPARATOR','LIT-INT-HEX'],
        'String':['LIT-STRING'], 'Sequence':['SEQUENCE-EXPRESSION','BLOCK-EXPRESSION'],
        'Var':['EXPR-VARIABLE','LIT-BOOL-TRUE','LIT-VOID'], 'Fn':['FN-ANONYMOUS','CAPTURE-FUNCTION','FN-ANON-BINOP'],
        'List':['LIT-LIST-EMPTY','LIT-LIST-ELEMENTS','LIT-LIST-SPREAD'], 'Call':['CALL-POSITIONAL','CALL-LABELLED'],
        'BinOp':['OP-ADD','OP-EQ'], 'ByteArray':['LIT-BYTEARRAY-LIST-DECIMAL','LIT-BYTEARRAY-UTF8','LIT-BYTEARRAY-HEX'],
        'CurvePoint':['LIT-CURVE-G1','LIT-CURVE-G2'], 'PipeLine':['PIPE-ONE-LINE','PIPE-MULTILINE'],
        'Assignment':['LET-VARIABLE','EXPECT-PATTERN','IF-IS-PATTERN-TYPE'], 'Trace':['TRACE-BASIC','TODO-BARE','FAIL-BARE'],
        'TraceIfFalse':['TRACE-QUESTION'], 'When':['WHEN'], 'If':['IF-ELSE'],
        'FieldAccess':['ACCESS-RECORD','ACCESS-TUPLE','ACCESS-PAIR'], 'Tuple':['LIT-TUPLE'], 'Pair':['LIT-PAIR'],
        'TupleIndex':['ACCESS-TUPLE','ACCESS-PAIR'], 'ErrorTerm':['FAIL-BARE','TODO-BARE'],
        'RecordUpdate':['RECORD-UPDATE'], 'UnOp':['OP-NOT','OP-NEGATE'],
        'LogicalOpChain':['BOOL-AND-BLOCK','BOOL-OR-BLOCK'],
    },
    'ByteArrayFormatPreference': {
        'HexadecimalString':['LIT-BYTEARRAY-HEX','PAT-BYTEARRAY-HEX','CONFIG-BYTEARRAY-HEX-MAP'],
        'ArrayOfBytes(Decimal)':['LIT-BYTEARRAY-LIST-DECIMAL','PAT-BYTEARRAY-LIST-DECIMAL'],
        'ArrayOfBytes(Hexadecimal)':['LIT-BYTEARRAY-LIST-HEX','PAT-BYTEARRAY-LIST-HEX'],
        'Utf8String':['LIT-BYTEARRAY-UTF8','PAT-BYTEARRAY-UTF8','CONFIG-BYTEARRAY-UTF8-STRING','CONFIG-BYTEARRAY-UTF8-MAP'],
    },
    'Base': {
        'Decimal(no_underscore)':['LIT-INT-DECIMAL','PAT-INT-DECIMAL'],
        'Decimal(numeric_underscore)':['LIT-INT-SEPARATOR','PAT-INT-SEPARATOR'],
        'Hexadecimal':['LIT-INT-HEX','PAT-INT-HEX'],
    },
    'Bls12_381PointType': {'G1':['LIT-CURVE-G1','TYPE-G1'], 'G2':['LIT-CURVE-G2','TYPE-G2']},
    'SimpleExpr': {
        'Int':['CONFIG-INT'], 'Bool':['CONFIG-BOOL'],
        'ByteArray(Utf8String)':['CONFIG-BYTEARRAY-UTF8-STRING','CONFIG-BYTEARRAY-UTF8-MAP'],
        'ByteArray(HexadecimalString)':['CONFIG-BYTEARRAY-HEX-MAP'],
        'List(uniform)':['CONFIG-LIST'], 'List(heterogeneous_to_tuple)':['CONFIG-TUPLE'],
    },
    'PlutusProjectTarget': {
        'V3(accepted)':['TARGET-PLUTUS-V3'], 'V1(rejected)':['NEG-TARGET-PLUTUS-V1'], 'V2(rejected)':['NEG-TARGET-PLUTUS-V2'],
    },
    'PreludeType': {
        'Data':['TYPE-DATA'], 'Int':['TYPE-INT'], 'ByteArray':['TYPE-BYTEARRAY'], 'Bool':['TYPE-BOOL'],
        'G1Element':['TYPE-G1'], 'G2Element':['TYPE-G2'], 'MillerLoopResult':['TYPE-MILLER'],
        'Ordering':['TYPE-ORDERING'], 'String':['TYPE-STRING'], 'Void':['TYPE-VOID'],
        'List':['TYPE-LIST'], 'Pair':['TYPE-PAIR'], 'Pairs':['TYPE-PAIRS'], 'Option':['TYPE-OPTION'],
        'Never':['TYPE-NEVER'], 'ScriptContext':['TYPE-SCRIPT-CONTEXT'],
        'PRNG':['FRAMEWORK-PRNG'], 'Fuzzer':['FRAMEWORK-FUZZER'], 'Sampler':['FRAMEWORK-SAMPLER'],
    },
}
keyword_map = {
    'as':['PAT-AS','IMPORT-MODULE-ALIAS','IMPORT-ITEM-ALIAS'], 'bench':['DEF-BENCH','BENCH-VIA'],
    'const':['DEF-CONST-PRIVATE','DEF-CONST-PUBLIC'], 'fn':['DEF-FN-PRIVATE','DEF-FN-PUBLIC','FN-ANONYMOUS'],
    'if':['IF-ELSE','IF-IS-PATTERN-TYPE','IF-IS-TYPE'], 'else':['IF-ELSE','VAL-ELSE'],
    'fail':['FAIL-BARE','FAIL-REASON','TEST-FAIL'], 'once':['TEST-FAIL-ONCE'],
    'expect':['EXPECT-PATTERN','EXPECT-BOOLEAN','EXPECT-BACKPASS'], 'is':['WHEN','IF-IS-PATTERN-TYPE','IF-IS-TYPE'],
    'let':['LET-VARIABLE','LET-DESTRUCTURE','LET-BACKPASS'], 'opaque':['DEF-TYPE-OPAQUE-PRIVATE','DEF-TYPE-OPAQUE-PUBLIC'],
    'pub':['DEF-FN-PUBLIC','DEF-CONST-PUBLIC','DEF-TYPE-PUBLIC','DEF-TYPE-ALIAS-PUBLIC','DEF-TYPE-OPAQUE-PUBLIC'],
    'use':['IMPORT-QUALIFIED','IMPORT-UNQUALIFIED'], 'test':['DEF-TEST','TEST-UNIT'],
    'todo':['TODO-BARE','TODO-REASON','FN-EMPTY-BODY-TODO'], 'type':['DEF-TYPE-PRIVATE','DEF-TYPE-ALIAS-PRIVATE'],
    'when':['WHEN'], 'trace':['TRACE-BASIC','TEST-TRACE'], 'validator':['DEF-VALIDATOR'],
    'via':['TEST-PROPERTY-VIA','BENCH-VIA'], 'and':['BOOL-AND-BLOCK'], 'or':['BOOL-OR-BLOCK'],
    'error':['ERROR-ALIAS'],
}

feature_ids = {f['id'] for f in features}
all_surface_ids = {fid for mapping in surface_maps.values() for ids in mapping.values() for fid in ids}
all_keyword_ids = {fid for ids in keyword_map.values() for fid in ids}
missing_surface_feature_ids = sorted((all_surface_ids | all_keyword_ids) - feature_ids)
assert not missing_surface_feature_ids, missing_surface_feature_ids
assert all(mapping and all(ids for ids in mapping.values()) for mapping in surface_maps.values())
assert all(keyword_map[k] for k in keyword_map)

compiler_surface_audit = {
    'generated_at': DATE, 'baseline': BASELINE,
    'status': 'mapping-complete-execution-unverified',
    'scope': {
        'tagged_ast_and_compiler_surfaces': list(surface_maps),
        'mapped_surface_variant_count': sum(len(x) for x in surface_maps.values()),
        'mapped_keyword_or_alias_count': len(keyword_map),
        'active_uplc_builtin_count': len(builtins),
    },
    'rule': 'A release is blocked when a tagged surface variant, keyword, accepted project form, prelude type, or active builtin has no feature row.',
    'surface_maps': surface_maps, 'keyword_map': keyword_map,
    'unmapped_surface_variants': [], 'unmapped_keywords_or_aliases': [],
    'positive_project_targets': ['V3'], 'rejected_project_targets': ['V1','V2'],
}

# ---------------------------------------------------------------------------
# Candidate catalog update
# ---------------------------------------------------------------------------
new_candidates = [
    ('aiken-lang/sample','P0','Official benchmark corpus','root','Official Sampler and benchmark corpus. Pin the selected commit.',['mandatory-feature-corpus','bench-lane'],True),
    ('ariady-putra-emurgo/aiken_primitive_types','P0','Language feature showcase','harness-or-root','Focused valid primitive and prelude type examples.',['mandatory-feature-corpus','requires-harness'],True),
    ('ariady-putra-emurgo/aiken_custom_types','P0','Language feature showcase','harness-or-root','Focused custom, opaque, generic, and recursive type examples.',['mandatory-feature-corpus','requires-harness'],True),
    ('ariady-putra-emurgo/aiken_const_showcase','P0','Language feature showcase','root','Focused constants, docs, environment modules, and configuration values.',['mandatory-feature-corpus','config-lane','docs-lane'],True),
    ('ariady-putra-emurgo/aiken_fn_showcase','P0','Language feature showcase','harness-or-root','Focused function, call, pipeline, capture, and backpassing examples.',['mandatory-feature-corpus','requires-harness'],True),
    ('ariady-putra-emurgo/aiken_control_answer','P0','Language feature showcase','harness-or-root','Completed control-flow and pattern-matching examples.',['mandatory-feature-corpus','requires-harness'],True),
    ('ariady-putra-emurgo/aiken_minting_answer','P0','Language feature showcase','root','Completed minting-validator examples.',['mandatory-feature-corpus'],True),
    ('ariady-putra-emurgo/aiken_spending_validator','P0','Language feature showcase','root','Focused spend validators and boundary decoding.',['mandatory-feature-corpus'],True),
    ('ariady-putra-emurgo/aiken_staking_validator','P0','Language feature showcase','root','Focused withdraw and publish handlers with fallback behavior.',['mandatory-feature-corpus'],True),
    ('ariady-putra-emurgo/aiken_check_showcase','P0','Language feature showcase','root','Focused unit, property, validator, trace, and expected-failure tests.',['mandatory-feature-corpus','check-lane'],True),
    ('ariady-putra-emurgo/aiken_control_flow','P1','Language feature showcase','harness-or-root','Supplemental control-flow activity. Scan for todo terms; use the completed answer repository for the mandatory lane.',['supplemental-feature-corpus','needs-todo-scan'],False),
    ('EmurgoFaculty/EA_BuildNOW_Aiken','P2','Corpus index / course metadata','special','Course index for focused examples. Do not compile it as one package.',['metadata-only','multi-package-index'],False),
]
for c in candidates:
    c.setdefault('feature_evidence_status','unscanned')
    c.setdefault('coverage_role','real-world-candidate')
    c.setdefault('declared_feature_families',[])
    c.setdefault('mandatory_corpus',False)

by_repo = {c['repository']: c for c in candidates}
for repo, priority, category, intake, note, flags, mandatory in new_candidates:
    if repo in by_repo:
        continue
    c = {
        'repository': repo, 'url': f'https://github.com/{repo}', 'priority': priority,
        'category': category, 'intake': intake, 'note': note,
        'aiken_file_count_2024': None, 'evidence': ['feature-coverage-2026'],
        'screen_status': 'repository-page-screened', 'flags': flags,
        'recommended_order': None, 'first_wave': mandatory,
        'feature_evidence_status': 'declared-coverage-build-unverified' if not 'metadata-only' in flags else 'metadata-only',
        'coverage_role': 'mandatory-feature-source' if mandatory else ('source-index' if 'metadata-only' in flags else 'supplemental-feature-source'),
        'declared_feature_families': [], 'mandatory_corpus': mandatory,
    }
    candidates.append(c)
    by_repo[repo] = c

official_updates = {
    'aiken-lang/aiken': ('Official compiler and conformance corpus','multi-package','official-language-conformance',['grammar','AST','acceptance tests','UPLC builtins','negative diagnostics']),
    'aiken-lang/stdlib': ('Official standard library corpus','harness','official-library-conformance',['generics','custom types','collections','Data','cryptography','imports']),
    'aiken-lang/fuzz': ('Official property-test corpus','root','official-test-conformance',['property tests','Fuzzer','via']),
}
for repo, (category, intake, role, families) in official_updates.items():
    c = by_repo[repo]
    c.update({'priority':'P0','category':category,'intake':intake,'mandatory_corpus':True,
              'feature_evidence_status':'declared-coverage-build-unverified','coverage_role':role,
              'declared_feature_families':families,'screen_status':'repository-page-screened'})
    c['flags'] = list(dict.fromkeys(c.get('flags',[]) + ['mandatory-feature-corpus','official-source']))
    c['evidence'] = list(dict.fromkeys(c.get('evidence',[]) + ['official-aiken-repository','feature-coverage-2026']))

family_declarations = {
    'aiken-lang/staking':['spend handler','withdraw/publish behavior'],
    'cardano-foundation/bls':['BLS12-381'], 'ilap/bls':['BLS12-381'],
    'blocksmithy/oakshield-aiken':['BLS12-381','Groth16','Merkle'],
    'cardano-foundation/cip113-programmable-tokens':['benchmarks','bitwise builtins','large test corpus'],
    'cardano-foundation/cardano-templates':['many validator purposes','multi-package'],
}
for repo, fam in family_declarations.items():
    if repo in by_repo:
        by_repo[repo]['declared_feature_families'] = list(dict.fromkeys(by_repo[repo].get('declared_feature_families',[]) + fam))

mandatory_order = [x['repository'] for x in mandatory_sources if x['repository']]
prior_first = [c['repository'] for c in sorted(base['candidates'], key=lambda x: x['recommended_order']) if c.get('first_wave') and c['repository'] not in mandatory_order]
supplemental = ['ariady-putra-emurgo/aiken_control_flow']
metadata = ['EmurgoFaculty/EA_BuildNOW_Aiken']
used = set(mandatory_order + prior_first + supplemental + metadata)
rest = [c['repository'] for c in sorted(candidates, key=lambda x: (x.get('recommended_order') is None, x.get('recommended_order') or 10**9, x['repository'].lower())) if c['repository'] not in used]
order = mandatory_order + prior_first + supplemental + rest + metadata
assert len(order) == len(candidates) == len(set(order))
for i, repo in enumerate(order, 1):
    by_repo[repo]['recommended_order'] = i
first_wave_repos = set(mandatory_order + prior_first)
for c in candidates:
    c['first_wave'] = c['repository'] in first_wave_repos
candidates = sorted(candidates, key=lambda x: x['recommended_order'])
urls = [c['url'] for c in candidates]
assert len(candidates) == len(set(urls)) == 260

priority_counts = Counter(c['priority'] for c in candidates)
status_counts = Counter(c['feature_evidence_status'] for c in candidates)
mandatory_public = [x for x in mandatory_sources if x['url']]

mandatory_corpus = {
    'generated_at': DATE,
    'baseline': {'aiken_release':BASELINE,'release_date':RELEASE_DATE,
                 'scope_rule':'Only forms accepted by the tagged lexer, parser, type checker, project loader, and active UPLC builtin enum are positive baseline features.'},
    'status': 'manifest-complete-build-verification-pending',
    'public_sources': mandatory_public, 'required_internal_source': source_by_id['SENTINEL'],
    'execution_order': mandatory_order,
    'supplemental_public_source': {'repository':'ariady-putra-emurgo/aiken_control_flow','url':'https://github.com/ariady-putra-emurgo/aiken_control_flow','reason':'Useful for scanning, but prefer the completed answer package for mandatory execution.'},
    'metadata_source': {'repository':'EmurgoFaculty/EA_BuildNOW_Aiken','url':'https://github.com/EmurgoFaculty/EA_BuildNOW_Aiken','reason':'Index only; not one compile target.'},
    'coverage_rule': 'Repository presence does not count. Static evidence and every required execution lane must pass.',
    'version_pair_rule': 'Use the newer compiler to define the inventory. Send only shared, two-sided UPLC builds to Lean-blaster. Record new-only and removed forms as compatibility results.',
}

impact_counts = Counter(f['impact'] for f in features)
category_counts = Counter(f['category'] for f in features)
builtin_category_counts = Counter(b['category'] for b in builtins)
manifest = {
    'generated_at': DATE,
    'baseline': {
        'aiken_release':BASELINE, 'release_date':RELEASE_DATE,
        'compiler_repository':'https://github.com/aiken-lang/aiken', 'compiler_ref':BASELINE,
        'acceptance_test_package_count':100, 'active_uplc_builtin_count':len(builtins),
        'source_of_truth':['v1.1.23 tagged AST and parser source','v1.1.23 project configuration loader','v1.1.23 active DefaultFunction enum','v1.1.23 acceptance-test packages'],
    },
    'coverage_contract': {
        'goal':'Exercise every mapped Aiken v1.1.23 language and compiler surface plus every active UPLC builtin.',
        'status':'mapping-complete-execution-unverified',
        'pass_condition':'Every positive row and builtin has verified evidence in all required lanes. Every negative row has the expected diagnostic under both compiler variants.',
        'repository_presence_is_not_coverage':True, 'reachable_code_required_for_blaster':True,
        'dead_code_does_not_count':True, 'sentinel_repository_required':True,
        'version_pair_rule':'The newer compiler defines the inventory. Only rows accepted by both compilers and emitted as UPLC by both compilers enter Lean-blaster.',
        'one_sided_build_is_not_equivalence_evidence':True,
    },
    'lanes': {
        'compile':'Parse and type-check the same pinned source with both compiler variants.',
        'blaster':'Build reachable validator UPLC with both compiler variants and compare the pair with Lean-blaster.',
        'check':'Run unit, property, and validator tests with fixed options and seeds.',
        'bench':'Discover and run benchmark definitions with the same Sampler inputs.',
        'config':'Exercise target, environment, configuration, dependency, lockfile, and monorepo selection.',
        'docs':'Exercise source documentation generation. This lane does not enter Blaster.',
    },
    'excluded_from_positive_v1_1_23_baseline': [
        {'item':'Plutus V1 project target','reason':'The v1.1.23 project loader rejects it; keep it as a negative configuration test.'},
        {'item':'Plutus V2 project target','reason':'The v1.1.23 project loader rejects it; Aiken v1.1.23 accepts only Plutus V3 projects.'},
        {'item':'Binary and octal integer prefixes','reason':'The tagged v1.1.23 lexer Base enum contains only decimal and hexadecimal forms.'},
        {'item':'Legacy dot-prefixed operators','reason':'Legacy token variants remain in structures, but the tagged lexer does not emit them.'},
        {'item':'exp_mod_integer','reason':'The builtin enum entry is commented out.'},
        {'item':'case_list','reason':'The builtin enum entry is commented out.'},
        {'item':'case_data','reason':'The builtin enum entry is commented out.'},
        {'item':'Deliberately incomplete teaching activities','reason':'Intentional type errors or reachable todo terms are not positive equivalence cases.'},
    ],
    'summary': {
        'language_and_project_feature_rows':len(features), 'active_builtin_rows':len(builtins),
        'total_contract_rows':len(features)+len(builtins),
        'negative_compile_rows':sum(f['negative_compile_case'] for f in features),
        'sentinel_required_rows':sum(f['sentinel_required'] for f in features)+len(builtins),
        'mapped_compiler_surface_variants':sum(len(x) for x in surface_maps.values()),
        'mapped_keywords_and_aliases':len(keyword_map),
        'impact_counts':dict(sorted(impact_counts.items())),
        'category_counts':dict(sorted(category_counts.items())),
        'builtin_category_counts':dict(sorted(builtin_category_counts.items())),
    },
    'mandatory_sources':mandatory_sources, 'compiler_surface_audit':compiler_surface_audit,
    'features':features, 'active_uplc_builtins':builtins,
}

updated = copy.deepcopy(base)
updated['generated_at'] = DATE
updated['objective'] = 'Versioned Aiken corpus for old-versus-new codegen comparison, Lean-blaster equivalence checking, and complete mapped Aiken v1.1.23 feature coverage.'
updated['scope'] = {
    'total_candidates':len(candidates), **{k:priority_counts.get(k,0) for k in ['P0','P1','P2']},
    'first_wave':len(first_wave_repos), 'mandatory_public_feature_sources':len(mandatory_public),
    'required_internal_feature_sources':1, 'feature_manifest_rows':len(features),
    'active_uplc_builtins':len(builtins), 'total_feature_contract_rows':len(features)+len(builtins),
    'mapped_compiler_surface_variants':sum(len(x) for x in surface_maps.values()),
    'mapped_keywords_and_aliases':len(keyword_map),
    'feature_evidence_status_counts':dict(sorted(status_counts.items())),
    'census_repositories_with_nonzero_aiken_files':base['scope'].get('census_repositories_with_nonzero_aiken_files'),
    'census_aiken_file_total':base['scope'].get('census_aiken_file_total'),
}
updated['screening_caveat'] = 'This is a versioned coverage contract, not a successful build report. Coverage remains unverified until source scanning, both compiler builds, UPLC extraction, and every required lane finish.'
updated['coverage_baseline'] = manifest['baseline']
updated['coverage_contract'] = manifest['coverage_contract']
updated['execution_lanes'] = manifest['lanes']
updated['mandatory_corpus'] = mandatory_corpus
updated['companion_files'] = {
    'feature_matrix_markdown':'aiken_feature_coverage_matrix.md',
    'feature_manifest_json':'aiken_language_features_v1_1_23.json',
    'compiler_surface_audit_json':'aiken_compiler_surface_audit.json',
    'mandatory_corpus_json':'aiken_mandatory_corpus.json',
    'mandatory_urls_txt':'aiken_mandatory_repos.txt',
    'sentinel_spec_markdown':'aiken_feature_sentinel_spec.md',
    'validation_json':'aiken_feature_coverage_validation.json',
}
extra_sources = [
    {'name':'Aiken v1.1.23 tagged compiler source','url':'https://github.com/aiken-lang/aiken/tree/v1.1.23','use':'Grammar, AST, project target, active builtins, and acceptance baseline.'},
    {'name':'Aiken stdlib','url':'https://github.com/aiken-lang/stdlib','use':'Official real-world library corpus.'},
    {'name':'Aiken fuzz','url':'https://github.com/aiken-lang/fuzz','use':'Official property-test corpus.'},
    {'name':'Aiken sample','url':'https://github.com/aiken-lang/sample','use':'Official benchmark corpus.'},
    {'name':'EMURGO BuildNOW Aiken index','url':'https://github.com/EmurgoFaculty/EA_BuildNOW_Aiken','use':'Focused feature showcases and completed examples.'},
]
existing = {x['url'] for x in updated.get('sources',[])}
updated.setdefault('sources',[]).extend(x for x in extra_sources if x['url'] not in existing)
updated['candidates'] = candidates

# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------
def esc(x: Any) -> str:
    return str(x).replace('|','\\|').replace('\n',' ').strip()

def link(c: dict[str, Any]) -> str:
    return f"[{c['repository']}]({c['url']})"

matrix = [
    '# Aiken v1.1.23 feature-coverage matrix','',
    f'**Baseline:** Aiken `{BASELINE}`  ', f'**Generated:** {DATE}  ',
    f'**Contract:** {len(features)} language, compiler, and project rows plus {len(builtins)} active UPLC builtins.  ','',
    '## Coverage decision','',
    f'The {len(candidates)}-repository longlist gives broad real-world behavior. It does not prove complete feature coverage by itself. This matrix adds tagged compiler-surface mappings, mandatory public sources, and a required team-owned sentinel repository.','',
    'A feature counts only when the scanner records it and every required lane passes. A README statement, repository topic, or unused function does not count.','',
    '## Version-pair rule','',
    'Build the feature inventory from the newer compiler. Send a row to Lean-blaster only when both compilers accept the same source and both produce UPLC. Treat new-only syntax, removed syntax, and front-end failures as compatibility results, not semantic counterexamples. Keep one immutable manifest for each tested compiler pair.','',
    '## Current status','',
    '**Mapping complete; execution unverified.** Every audited surface variant and keyword maps to at least one contract row. The repositories have not yet passed the full old/new build and Blaster gate.','',
    '## Execution lanes','', '| Lane | Requirement |','|---|---|',
]
for k,v in manifest['lanes'].items():
    matrix.append(f'| `{k}` | {esc(v)} |')
matrix += ['', '## Mandatory public repositories','', '| Order | Repository | Role | Lanes | Ref |','|---:|---|---|---|---|']
for i,src in enumerate(mandatory_public,1):
    matrix.append(f"| {i} | [{src['repository']}]({src['url']}) | {esc(src['role'])} | {', '.join(f'`{x}`' for x in src['lanes'])} | `{src['ref']}` |")
matrix += ['', '## Compiler-surface audit','',
           f'- **{sum(len(x) for x in surface_maps.values())}** tagged compiler and project surface variants mapped.',
           f'- **{len(keyword_map)}** keywords or accepted aliases mapped.',
           f'- **{len(builtins)}** active UPLC builtins mapped one-to-one.',
           '- **0** unmapped audited variants.', '',
           '| Surface | Variants |','|---|---:|']
for surface,mapping in surface_maps.items():
    matrix.append(f'| `{surface}` | {len(mapping)} |')
matrix += ['', '## Summary','', '| Measure | Count |','|---|---:|',
           f'| Language and project rows | {len(features)} |',
           f'| Negative compile rows | {sum(f["negative_compile_case"] for f in features)} |',
           f'| Active UPLC builtins | {len(builtins)} |',
           f'| Total contract rows | {len(features)+len(builtins)} |',
           f'| Rows that require a sentinel fixture | {manifest["summary"]["sentinel_required_rows"]} |',
           '', '## Language and compiler rows']
by_cat: dict[str,list[dict[str,Any]]] = defaultdict(list)
for f in features:
    by_cat[f['category']].append(f)
for cat in sorted(by_cat):
    matrix += ['', f'### {cat.replace("_"," ").title()}','',
               '| ID | Feature | Impact | Lanes | Public candidates | Sentinel | Status |','|---|---|---|---|---|---|---|']
    for f in by_cat[cat]:
        pubs = ', '.join(f'`{x}`' for x in f['public_candidate_sources']) or 'None'
        matrix.append(f"| `{f['id']}` | {esc(f['name'])} | `{f['impact']}` | {', '.join(f'`{x}`' for x in f['lanes'])} | {pubs} | {'required' if f['sentinel_required'] else 'not required'} | `{f['verification_status']}` |")
matrix += ['', '## Active UPLC builtins','',
           'Each builtin needs a reachable wrapper with non-constant inputs. The selected UPLC branch must still contain the builtin after optimization.','']
by_bcat: dict[str,list[dict[str,Any]]] = defaultdict(list)
for b in builtins:
    by_bcat[b['category']].append(b)
for cat in sorted(by_bcat):
    matrix += [f'### {cat.replace("_"," ").title()}','',
               '| Opcode | Aiken name | UPLC name | Real-world candidates | Status |','|---:|---|---|---|---|']
    for b in by_bcat[cat]:
        rw = ', '.join(f'`{x}`' for x in b['real_world_candidate_repositories']) or 'sentinel and official tests'
        matrix.append(f"| {b['opcode']} | `{b['aiken_name']}` | `{b['uplc_name']}` | {rw} | `{b['verification_status']}` |")
    matrix.append('')
matrix += ['## Baseline exclusions','', '| Item | Reason |','|---|---|']
for x in manifest['excluded_from_positive_v1_1_23_baseline']:
    matrix.append(f"| {esc(x['item'])} | {esc(x['reason'])} |")
matrix += ['', '## Release gate','',
           'The feature gate passes only when:','',
           '1. Every required source is pinned to an immutable tag or commit.',
           '2. The scanner emits at least one source record for every contract row.',
           '3. Both compiler variants complete every required lane or return an allowed explicit state.',
           '4. Every direct-codegen row produces old and new UPLC and reaches Lean-blaster.',
           '5. Every builtin remains in the selected UPLC branch after optimization.',
           '6. No row remains `manifested_unverified`, `missing`, or `dead_code_only`.',
           '7. A fresh compiler-surface audit finds no unmapped variant or keyword.']

sentinel = [
    '# Aiken codegen feature sentinel repository specification','',
    f'**Language baseline:** Aiken `{BASELINE}`  ',
    f'**Contract:** {len(features)} language/project rows and {len(builtins)} active UPLC builtins.  ','',
    '## Purpose','',
    'Create one small team-owned repository that keeps rare features stable and reachable. Public repositories can move, remove syntax, or place a feature behind dead code. The sentinel is the stable floor under the real-world corpus.','',
    '## Required layout','', '```text',
    'aiken-codegen-equivalence-sentinel/', '  aiken.toml', '  aiken.lock',
    '  lib/', '    compile_only/', '    checks/', '    benchmarks/',
    '  validators/', '    features/', '    builtins/', '  env/', '    default.ak', '    preview.ak',
    '  coverage/', '    feature-manifest.json', '    evidence-old.json', '    evidence-new.json', '```','',
    '## Version-pair rule','',
    'Generate the feature inventory from the newer compiler. A direct equivalence fixture must parse, type-check, and produce UPLC with both compilers. Record new-only or removed forms in a compatibility lane. Do not send a one-sided build to Lean-blaster.','',
    '## Reachability rule','',
    'Every direct-codegen fixture must be reachable from a validator handler. Use decoded validator inputs as arguments and a redeemer field as a deterministic branch selector. This prevents constant folding and dead-code removal from creating false coverage.','',
    'Each selected branch must affect the validator result. An unused helper does not count.','',
    '## Feature fixture rule','',
    '- Give each fixture a stable name based on its feature ID.',
    '- Keep one primary feature in each fixture.',
    '- Record the source path, line range, AST evidence, UPLC path, and artifact hash.',
    '- Keep compile-only, check-only, benchmark, configuration, and docs fixtures outside the Blaster lane.',
    '- Isolate intentional `todo`, `fail`, and negative diagnostic cases from positive validators.','',
    '## Builtin fixture rule','',
    f'Create one reachable wrapper for each of the {len(builtins)} active builtins. Group files by family, but give each builtin its own branch selector and evidence record.','',
    '| Family | Builtins |','|---|---:|']
for cat,count in sorted(builtin_category_counts.items()):
    sentinel.append(f'| {cat.replace("_"," ")} | {count} |')
sentinel += ['', 'For each wrapper:','',
             '1. Decode at least one argument from a validator input.',
             '2. Keep the builtin in the selected UPLC branch after optimization.',
             '3. Store old and new UPLC paths and hashes.',
             '4. Confirm the expected UPLC builtin name with a structural scan.',
             '5. Run Lean-blaster on the old and new terms.','',
             'Use valid deterministic cryptographic inputs. Keep invalid-input behavior in separate branches.','',
             '## Project matrix','', '| Dimension | Required values |','|---|---|',
             '| Plutus target | V3 only for the positive v1.1.23 baseline |',
             '| Rejected targets | V1 and V2 as negative configuration tests |',
             '| Trace level | silent, compact, verbose |',
             '| Trace source | user-defined, compiler-generated, all |',
             '| Conditional selection | default and named environment; default and named configuration |',
             '| Configuration value | Int, Bool, UTF-8 ByteArray, hex ByteArray, homogeneous List, heterogeneous Tuple |',
             '| Package layout | normal package and monorepo member selected by literal path and glob |',
             '| Dependency mode | immutable pins and lockfile |','',
             '## Result states','',
             '- `equivalent`', '- `non_equivalent`', '- `blaster_unsupported`', '- `blaster_inconclusive`',
             '- `old_language_feature_unsupported`', '- `old_compile_failed`', '- `new_compile_failed`',
             '- `feature_missing`', '- `dead_code_only`',
             '- `expected_negative_diagnostic`','',
             'Do not merge `non_equivalent` with build failures. A compile failure is not a semantic counterexample.','',
             '## CI release gate','',
             'Fail CI when a manifest row lacks evidence, an expected builtin is absent, a positive fixture fails to build, a required Blaster result is missing, or the compiler-surface audit finds a new unmapped form.']

catalog = [
    '# Aiken repositories for code-generation equivalence and feature coverage','',
    f'**Screen date:** {DATE}  ', f'**Language baseline:** Aiken `{BASELINE}`  ','',
    'This catalog supports old-versus-new Aiken codegen comparison and Lean-blaster equivalence checking.','',
    '## Result','',
    f'- **{len(candidates)}** unique public GitHub repositories.',
    f'- **{priority_counts["P0"]} P0**, **{priority_counts["P1"]} P1**, and **{priority_counts["P2"]} P2** candidates.',
    f'- **{len(first_wave_repos)}** repositories in the first wave.',
    f'- **{len(mandatory_public)}** mandatory public feature sources.',
    f'- **{len(features)}** language/project rows and **{len(builtins)}** active builtin rows.',
    f'- **{sum(len(x) for x in surface_maps.values())}** audited compiler/project variants and **{len(keyword_map)}** keywords or aliases mapped.','',
    '> **Status:** The mapping contract is complete, but build evidence is not. No repository counts for a feature until the scanner and all required lanes pass.','',
    '## Coverage model','',
    '1. Use official and focused repositories for known feature families.',
    '2. Use the longlist for complex interactions and historical compiler spans.',
    '3. Use the team-owned sentinel for every rare form and all active builtins.',
    '4. Reject a claim when the feature is unused, optimized away, or stated only in documentation.','',
    'See `aiken_feature_coverage_matrix.md`, `aiken_compiler_surface_audit.json`, and `aiken_feature_sentinel_spec.md`.','',
    '## Mandatory public feature corpus','', '| Order | Repository | Role | Intake |','|---:|---|---|---|']
for repo in mandatory_order:
    c = by_repo[repo]
    catalog.append(f"| {c['recommended_order']} | {link(c)} | {esc(c['coverage_role'])} | `{c['intake']}` |")
catalog += ['', '## Recommended first wave','', '| Order | Repository | Category | Intake | Feature role | Notes |','|---:|---|---|---|---|---|']
for c in candidates:
    if c['first_wave']:
        catalog.append(f"| {c['recommended_order']} | {link(c)} | {esc(c['category'])} | `{c['intake']}` | {esc(c['coverage_role'])} | {esc(c['note'])} |")
catalog += ['', '## Full catalog','']
for p in ['P0','P1','P2']:
    subset = [c for c in candidates if c['priority']==p]
    catalog += [f'### {p} — {len(subset)} repositories','',
                '| Order | Repository | Category | Intake | Feature evidence | Role | Flags | Notes |','|---:|---|---|---|---|---|---|---|']
    for c in subset:
        flags = ', '.join(f'`{x}`' for x in c.get('flags',[])) or '—'
        catalog.append(f"| {c['recommended_order']} | {link(c)} | {esc(c['category'])} | `{c['intake']}` | `{c['feature_evidence_status']}` | {esc(c['coverage_role'])} | {flags} | {esc(c['note'])} |")
    catalog.append('')
catalog += ['## Intake result classes','',
            'Keep these outcomes separate: discovery failure, dependency failure, old compile failure, new compile failure, UPLC generation failure, Blaster unsupported, Blaster inconclusive, equivalent, and non-equivalent.']

# ---------------------------------------------------------------------------
# Write and validate artifacts
# ---------------------------------------------------------------------------
files: dict[str, str] = {
    'aiken_equivalence_candidates.json': json.dumps(updated, indent=2, ensure_ascii=False) + '\n',
    'aiken_equivalence_candidates.md': '\n'.join(catalog) + '\n',
    'aiken_equivalence_repos.txt': '\n'.join(c['url'] for c in candidates) + '\n',
    'aiken_language_features_v1_1_23.json': json.dumps(manifest, indent=2, ensure_ascii=False) + '\n',
    'aiken_compiler_surface_audit.json': json.dumps(compiler_surface_audit, indent=2, ensure_ascii=False) + '\n',
    'aiken_feature_coverage_matrix.md': '\n'.join(matrix) + '\n',
    'aiken_feature_sentinel_spec.md': '\n'.join(sentinel) + '\n',
    'aiken_mandatory_corpus.json': json.dumps(mandatory_corpus, indent=2, ensure_ascii=False) + '\n',
    'aiken_mandatory_repos.txt': '\n'.join(x['url'] for x in mandatory_public) + '\n',
}
for name,text in files.items():
    (OUT/name).write_text(text)

checks = {
    'candidate_count':len(candidates), 'candidate_unique_urls':len(set(urls)),
    'candidate_orders_consecutive':all(c['recommended_order']==i for i,c in enumerate(candidates,1)),
    'first_wave_count':len(first_wave_repos), 'mandatory_public_source_count':len(mandatory_public),
    'immutable_public_source_ref_count':sum(
        1 for x in mandatory_public
        if x['ref'] not in {'main', 'master', 'resolve-main-to-immutable-commit'}
        and x['ref_policy'] in {'immutable-tag', 'immutable-tag-or-lockfile-commit', 'immutable-commit'}
    ),
    'unresolved_public_source_ref_count':sum(
        1 for x in mandatory_public
        if x['ref'] in {'main', 'master', 'resolve-main-to-immutable-commit'}
    ),
    'public_source_execution_statuses':sorted({x['verification_status'] for x in mandatory_public}),
    'required_internal_source_status':source_by_id['SENTINEL']['verification_status'],
    'non_builtin_feature_count':len(features), 'unique_non_builtin_feature_ids':len(feature_ids),
    'active_builtin_count':len(builtins), 'unique_builtin_names':len({b['aiken_name'] for b in builtins}),
    'contract_row_count':len(features)+len(builtins),
    'all_rows_have_sources':all(f['mandatory_sources'] for f in features) and all(b['mandatory_sources'] for b in builtins),
    'all_rows_have_evidence_rules':all(f['required_evidence'] for f in features) and all(b['required_evidence'] for b in builtins),
    'all_blaster_rows_require_uplc':all('old and new UPLC artifacts' in f['required_evidence'] for f in features if 'blaster' in f['lanes']),
    'surface_variant_count':sum(len(x) for x in surface_maps.values()),
    'unmapped_surface_variant_count':0, 'keyword_or_alias_count':len(keyword_map),
    'unmapped_keyword_or_alias_count':0, 'positive_project_targets':['V3'],
    'rejected_project_targets':['V1','V2'], 'excluded_inactive_builtins':['exp_mod_integer','case_list','case_data'],
}
ok = (
    checks['candidate_count']==260 and checks['candidate_unique_urls']==260 and checks['candidate_orders_consecutive']
    and checks['active_builtin_count']==87 and checks['unique_builtin_names']==87
    and checks['immutable_public_source_ref_count']==checks['mandatory_public_source_count']
    and checks['unresolved_public_source_ref_count']==0
    and checks['unique_non_builtin_feature_ids']==checks['non_builtin_feature_count']
    and checks['unmapped_surface_variant_count']==0 and checks['unmapped_keyword_or_alias_count']==0
    and checks['all_rows_have_sources'] and checks['all_rows_have_evidence_rules'] and checks['all_blaster_rows_require_uplc']
)
validation = {'generated_at':DATE,'ok':ok,'checks':checks,'sha256':{}}
for name in files:
    validation['sha256'][name] = hashlib.sha256((OUT/name).read_bytes()).hexdigest()
(OUT/'aiken_feature_coverage_validation.json').write_text(json.dumps(validation,indent=2)+'\n')
assert ok

print(json.dumps({
    'candidates':len(candidates), 'priority_counts':dict(priority_counts),
    'first_wave':len(first_wave_repos), 'mandatory_public':len(mandatory_public),
    'features':len(features), 'builtins':len(builtins), 'total_rows':len(features)+len(builtins),
    'surface_variants':sum(len(x) for x in surface_maps.values()), 'keywords_and_aliases':len(keyword_map),
    'sentinel_required_rows':manifest['summary']['sentinel_required_rows'],
    'validation_ok':ok, 'files':list(files)+['aiken_feature_coverage_validation.json'],
},indent=2))
