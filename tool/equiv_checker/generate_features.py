from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from .config import CONTRACT_PATH, REPOSITORY_ROOT, compiler_pair, load_json
from .generate_negative import generate_negative_cases

SENTINEL = REPOSITORY_ROOT / "sentinel"
FEATURE_DIR = SENTINEL / "validators" / "features"
MANIFEST_PATH = SENTINEL / "coverage" / "feature-manifest.json"


def constr(tag: int, *fields: str) -> str:
    return f"Constr {tag} [{', '.join(fields)}]"


def integer(value: int) -> str:
    return f"I {value}"


def bytestring(value: str) -> str:
    return f"B #{value}"


def data_list(*values: str) -> str:
    return f"List [{', '.join(values)}]"


def data_map(*pairs: tuple[str, str]) -> str:
    entries = ", ".join(f"({key}, {value})" for key, value in pairs)
    return f"Map [{entries}]"


def bool_data(value: bool) -> str:
    return constr(1 if value else 0)


def redeemer(selector: int, first: str, second: str = "I 0", third: str = "I 0") -> str:
    return f"(con data ({constr(0, integer(selector), constr(0, first, second, third))}))"


PATTERN_CASES: dict[str, tuple[str, str]] = {
    "PAT-INT-DECIMAL": ("expect value: Int = first\nwhen value is { 42 -> True\n  _ -> False }", integer(42)),
    "PAT-INT-SEPARATOR": ("expect value: Int = first\nwhen value is { 1_000 -> True\n  _ -> False }", integer(1000)),
    "PAT-INT-HEX": ("expect value: Int = first\nwhen value is { 0xff -> True\n  _ -> False }", integer(255)),
    "PAT-INT-NEGATIVE": ("expect value: Int = first\nwhen value is { -42 -> True\n  _ -> False }", integer(-42)),
    "PAT-BYTEARRAY-LIST-DECIMAL": ("expect value: ByteArray = first\nwhen value is { #[1, 2] -> True\n  _ -> False }", bytestring("0102")),
    "PAT-BYTEARRAY-LIST-HEX": ("expect value: ByteArray = first\nwhen value is { #[0x01, 0xff] -> True\n  _ -> False }", bytestring("01ff")),
    "PAT-BYTEARRAY-UTF8": ("expect value: ByteArray = first\nwhen value is { \"ok\" -> True\n  _ -> False }", bytestring("6f6b")),
    "PAT-BYTEARRAY-HEX": ("expect value: ByteArray = first\nwhen value is { #\"00ff\" -> True\n  _ -> False }", bytestring("00ff")),
    "PAT-BOOL": ("expect value: Bool = first\nwhen value is { True -> True\n  False -> False }", bool_data(True)),
    "PAT-VARIABLE": ("when first is { value -> value == first }", integer(7)),
    "PAT-DISCARD": ("when first is { _ -> True }", integer(7)),
    "PAT-NAMED-DISCARD": ("when first is { _unused -> True }", integer(7)),
    "PAT-AS": ("expect value: Int = first\nlet subject = Some(value)\nwhen subject is { Some(inner) as whole -> inner == value && whole == subject\n  None -> False }", integer(7)),
    "PAT-LIST-EXACT": ("expect values: List<Int> = first\nwhen values is { [a, b] -> a + b == 3\n  _ -> False }", data_list(integer(1), integer(2))),
    "PAT-LIST-TAIL": ("expect values: List<Int> = first\nwhen values is { [head, ..] -> head == 1\n  _ -> False }", data_list(integer(1), integer(2))),
    "PAT-LIST-NAMED-TAIL": ("expect values: List<Int> = first\nwhen values is { [head, ..tail] -> head == 1 && tail == [2]\n  _ -> False }", data_list(integer(1), integer(2))),
    "PAT-PAIR": ("expect pair: Pair<Int, Int> = first\nwhen pair is { Pair(a, b) -> a + b == 3 }", data_list(integer(1), integer(2))),
    "PAT-TUPLE": ("expect tuple: (Int, Int) = first\nwhen tuple is { (a, b) -> a + b == 3 }", data_list(integer(1), integer(2))),
    "PAT-CONSTRUCTOR-POSITIONAL": ("expect value: Int = first\nwhen Some(value) is { Some(inner) -> inner == value\n  None -> False }", integer(7)),
    "PAT-CONSTRUCTOR-RECORD": ("expect value: Int = first\nlet subject = PatternRecord { field: value, other: 1 }\nwhen subject is { PatternRecord { field, other: _ } -> field == value }", integer(7)),
    "PAT-CONSTRUCTOR-POSITIONAL-SPREAD": ("expect value: Int = first\nlet subject = PatternTriple(value, 2, 3)\nwhen subject is { PatternTriple(first_value, ..) -> first_value == value }", integer(7)),
    "PAT-RECORD-SPREAD": ("expect value: Int = first\nlet subject = PatternRecord { field: value, other: 1 }\nwhen subject is { PatternRecord { field, .. } -> field == value }", integer(7)),
    "PAT-MODULE-QUALIFIED": ("expect value: Int = first\nlet subject = pattern_support.Support(value)\nwhen subject is { pattern_support.Support(inner) -> inner == value }", integer(7)),
    "PAT-TYPE-QUALIFIED": ("expect value: Int = first\nlet subject = PatternA(value)\nwhen subject is { PatternA(inner) -> inner == value\n  PatternB(_) -> False }", integer(7)),
    "PAT-NESTED": ("expect values: List<Int> = first\nlet subject = Some(values)\nwhen subject is { Some([head, ..tail]) -> head == 1 && tail == [2]\n  _ -> False }", data_list(integer(1), integer(2))),
    "PAT-ALTERNATIVE": ("expect value: Int = first\nexpect pick_a: Bool = second\nlet subject = if pick_a { PatternA(value) } else { PatternB(value) }\nwhen subject is { PatternA(inner) | PatternB(inner) -> inner == value }", integer(7)),
    "PAT-FIELD-PUNNING": ("expect value: Int = first\nlet subject = PatternRecord { field: value, other: 1 }\nwhen subject is { PatternRecord { field, .. } -> field == value }", integer(7)),
    "PAT-FIELD-RENAME": ("expect value: Int = first\nlet subject = PatternRecord { field: value, other: 1 }\nwhen subject is { PatternRecord { field: local, .. } -> local == value }", integer(7)),
    "PAT-ARG-DESTRUCTURE": ("expect pair: (Int, Int) = first\nsum_pattern_pair(pair) == 3", data_list(integer(1), integer(2))),
    "PAT-LET-DESTRUCTURE": ("expect pair: (Int, Int) = first\nlet (a, b) = pair\na + b == 3", data_list(integer(1), integer(2))),
    "PAT-EXPECT-DESTRUCTURE": ("expect pair: (Int, Int) = first\nexpect (a, b) = pair\na + b == 3", data_list(integer(1), integer(2))),
}

CONTROL_CASES: dict[str, tuple[str, str, str, bool]] = {
    "BOOL-AND-BLOCK": ("expect a: Bool = first\nexpect b: Bool = second\nand { a, b, a == b }", bool_data(True), bool_data(True), False),
    "BOOL-OR-BLOCK": ("expect a: Bool = first\nexpect b: Bool = second\nor { a, b, a == b }", bool_data(False), bool_data(True), False),
    "IF-ELSE": ("expect condition: Bool = first\nif condition { True } else { False }", bool_data(True), integer(0), False),
    "IF-ELSE-IF": ("expect value: Int = first\nif value < 0 { False } else if value == 7 { True } else { False }", integer(7), integer(0), False),
    "WHEN": ("expect value: Int = first\nwhen value is { 7 -> True\n  _ -> False }", integer(7), integer(0), False),
    "IF-IS-PATTERN-TYPE": ("if first is value: Int { value == 7 } else { False }", integer(7), integer(0), False),
    "IF-IS-TYPE": ("if first is Int { first == 7 } else { False }", integer(7), integer(0), False),
    "EXPR-GROUPING": ("expect value: Int = first\n(value + 1) * 2 == 16", integer(7), integer(0), False),
    "TRACE-BASIC": ("expect value: Int = first\ntrace @\"control\"\nvalue == 7", integer(7), integer(0), False),
    "TRACE-LABEL-STRING": ("expect value: Int = first\ntrace @\"string label\"\nvalue == 7", integer(7), integer(0), False),
    "TRACE-LABEL-BYTEARRAY": ("expect value: Int = first\ntrace \"bytearray label\"\nvalue == 7", integer(7), integer(0), False),
    "TRACE-LABEL-EXPRESSION": ("expect value: Int = first\ntrace if value == 7 { @\"seven\" } else { @\"other\" }\nvalue == 7", integer(7), integer(0), False),
    "TRACE-ARGS": ("expect value: Int = first\ntrace @\"value\": value\nvalue == 7", integer(7), integer(0), False),
    "TRACE-DEFAULT-CONT": ("expect value: Int = first\nlet traced = fn() { trace @\"default continuation\" }\ntraced() == Void && value == 7", integer(7), integer(0), False),
    "TRACE-QUESTION": ("expect value: Bool = first\nvalue?", bool_data(True), integer(0), False),
    "FAIL-BARE": ("expect value: Int = first\nif value == 7 { fail } else { False }", integer(7), integer(0), True),
    "FAIL-REASON": ("expect value: Int = first\nif value == 7 { fail @\"sentinel failure\" } else { False }", integer(7), integer(0), True),
    "TODO-BARE": ("expect value: Int = first\nif value == 7 { todo } else { False }", integer(7), integer(0), True),
    "TODO-REASON": ("expect value: Int = first\nif value == 7 { todo @\"sentinel todo\" } else { False }", integer(7), integer(0), True),
    "ERROR-ALIAS": ("expect value: Int = first\nif value == 7 { error @\"sentinel error\" } else { False }", integer(7), integer(0), True),
    "ACCESS-RECORD": ("expect value: Int = first\nlet record = ControlRecord { field: value, other: 1 }\nrecord.field == value", integer(7), integer(0), False),
    "ACCESS-TUPLE": ("expect value: Int = first\nlet tuple = (value, True)\ntuple.1st == value", integer(7), integer(0), False),
    "ACCESS-PAIR": ("expect value: Int = first\nlet pair = Pair(value, True)\npair.1st == value", integer(7), integer(0), False),
    "RECORD-CONSTRUCT-NAMED": ("expect value: Int = first\nControlRecord { field: value, other: 1 }.field == value", integer(7), integer(0), False),
    "RECORD-CONSTRUCT-POSITIONAL": ("expect value: Int = first\nlet record = PositionalRecord(value, True)\nwhen record is { PositionalRecord(inner, _) -> inner == value }", integer(7), integer(0), False),
    "RECORD-FIELD-ORDER": ("expect value: Int = first\nlet record = ControlRecord { other: 1, field: value }\nrecord.field == value", integer(7), integer(0), False),
    "RECORD-PUNNING": ("expect field: Int = first\nlet record = ControlRecord { field, other: 1 }\nrecord.field == field", integer(7), integer(0), False),
    "RECORD-UPDATE": ("expect value: Int = first\nlet base = ControlRecord { field: 0, other: 1 }\nlet updated = ControlRecord { ..base, field: value }\nupdated.field == value", integer(7), integer(0), False),
}

FUNCTION_CASES: dict[str, tuple[str, str, bool]] = {
    "EXPR-VARIABLE": ("expect value: Int = first\nlet bound = value\nbound == value", integer(7), False),
    "FN-ANONYMOUS": ("expect value: Int = first\nlet add_one = fn(x) { x + 1 }\nadd_one(value) == 8", integer(7), False),
    "FN-FIRST-CLASS": ("expect value: Int = first\nlet function = add_one\nfunction(value) == 8", integer(7), False),
    "FN-HIGHER-ORDER": ("expect value: Int = first\napply_function(value, add_one) == 8", integer(7), False),
    "FN-RECURSION": ("expect value: Int = first\nfactorial(value) == 5040", integer(7), False),
    "FN-ARG-DESTRUCTURE": ("expect pair: (Int, Int) = first\nsum_function_pair(pair) == 3", data_list(integer(1), integer(2)), False),
    "FN-ARG-DESTRUCTURE-ANNOTATED": ("expect pair: Pair<Int, Int> = first\nsum_function_data_pair(pair) == 3", data_list(integer(1), integer(2)), False),
    "FN-EMPTY-BODY-TODO": ("expect value: Int = first\nif value == 7 { empty_body_todo() } else { False }", integer(7), True),
    "CALL-POSITIONAL": ("expect value: Int = first\nadd(value, 1) == 8", integer(7), False),
    "CALL-LABELLED": ("expect value: Int = first\nlabelled_add(right: 1, left: value) == 8", integer(7), False),
    "CALL-MIXED": ("expect value: Int = first\nlabelled_add(value, right: 1) == 8", integer(7), False),
    "CALL-PUNNING": ("expect left: Int = first\nlet right = 1\nlabelled_add(left: left, right: right) == 8", integer(7), False),
    "CAPTURE-FUNCTION": ("expect value: Int = first\nlet add_to_one = add(_, 1)\nadd_to_one(value) == 8", integer(7), False),
    "CAPTURE-CONSTRUCTOR": ("expect value: Int = first\nlet wrap = Some(_)\nwrap(value) == Some(value)", integer(7), False),
    "FN-ANON-BINOP": ("expect value: Int = first\napply_binary(value, +, 1) == 8", integer(7), False),
    "PIPE-BARE": ("expect value: Int = first\n(value |> add_one) == 8", integer(7), False),
    "PIPE-CALL-INSERT": ("expect value: Int = first\n(value |> add(1)) == 8", integer(7), False),
    "PIPE-CAPTURE": ("expect value: Int = first\n(value |> add(1, _)) == 8", integer(7), False),
    "PIPE-RESULT-CALL": ("expect value: Int = first\nlet result = value |> make_adder\nresult(1) == 8", integer(7), False),
    "PIPE-ONE-LINE": ("expect value: Int = first\n(value |> add_one |> add_one) == 9", integer(7), False),
    "PIPE-MULTILINE": ("expect value: Int = first\n(value\n  |> add_one\n  |> add_one) == 9", integer(7), False),
    "BLOCK-EXPRESSION": ("expect value: Int = first\nlet result = { let incremented = value + 1\n  incremented }\nresult == 8", integer(7), False),
    "SEQUENCE-EXPRESSION": ("expect value: Int = first\nlet result = { trace @\"sequence\"\n  value + 1 }\nresult == 8", integer(7), False),
    "LET-VARIABLE": ("expect value: Int = first\nlet result = value + 1\nresult == 8", integer(7), False),
    "LET-MULTIPLE": ("expect value: Int = first\nlet first_value = value\nlet second_value = first_value + 1\nsecond_value == 8", integer(7), False),
    "LET-DESTRUCTURE": ("expect pair: (Int, Int) = first\nlet (left, right) = pair\nleft + right == 3", data_list(integer(1), integer(2)), False),
    "LET-SHADOW": ("expect value: Int = first\nlet value = value + 1\nvalue == 8", integer(7), False),
    "LET-BACKPASS": ("expect value: Int = first\nlet inner <- with_int(value)\ninner == value", integer(7), False),
    "EXPECT-PATTERN": ("expect value: Int = first\nexpect Some(inner) = Some(value)\ninner == value", integer(7), False),
    "EXPECT-BOOLEAN": ("expect value: Int = first\nexpect value == 7\nTrue", integer(7), False),
    "EXPECT-BACKPASS": ("expect value: Int = first\nexpect 7 <- with_int(value)\nTrue", integer(7), False),
}

G1_LITERAL = '#<Bls12_381, G1>"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"'
G2_LITERAL = '#<Bls12_381, G2>"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"'
AIKEN_ESCAPED = r'a\n\t\0\\\"'

LITERAL_CASES: dict[str, tuple[str, str]] = {
    "LIT-BOOL-TRUE": ("expect value: Bool = first\nvalue == True", bool_data(True)),
    "LIT-BOOL-FALSE": ("expect value: Bool = first\nvalue == False", bool_data(False)),
    "LIT-INT-DECIMAL": ("expect value: Int = first\nvalue == 42", integer(42)),
    "LIT-INT-SEPARATOR": ("expect value: Int = first\nvalue == 1_000_000", integer(1_000_000)),
    "LIT-INT-HEX": ("expect value: Int = first\nvalue == 0xff", integer(255)),
    "LIT-INT-NEGATIVE": ("expect value: Int = first\nvalue == -42", integer(-42)),
    "LIT-BYTEARRAY-LIST-DECIMAL": ("expect value: ByteArray = first\nvalue == #[0, 1, 255]", bytestring("0001ff")),
    "LIT-BYTEARRAY-LIST-HEX": ("expect value: ByteArray = first\nvalue == #[0x00, 0xaa, 0xff]", bytestring("00aaff")),
    "LIT-BYTEARRAY-UTF8": ("expect value: ByteArray = first\nvalue == \"hello\"", bytestring("68656c6c6f")),
    "LIT-BYTEARRAY-HEX": ("expect value: ByteArray = first\nvalue == #\"deadbeef\"", bytestring("deadbeef")),
    "LIT-BYTEARRAY-ESCAPE": (f'expect value: ByteArray = first\nvalue == "{AIKEN_ESCAPED}"', bytestring("610a09005c22")),
    "LIT-STRING": ("expect value: ByteArray = first\nbuiltin.decode_utf8(value) == @\"hello\"", bytestring("68656c6c6f")),
    "LIT-STRING-MULTILINE": ("expect value: ByteArray = first\nbuiltin.decode_utf8(value) == @\"line 1\nline 2\"", bytestring("6c696e6520310a2020202020206c696e652032")),
    "LIT-STRING-UNICODE": ("expect value: ByteArray = first\nbuiltin.decode_utf8(value) == @\"★\"", bytestring("e29885")),
    "LIT-STRING-ESCAPE": (f'expect value: ByteArray = first\nbuiltin.decode_utf8(value) == @\"{AIKEN_ESCAPED}\"', bytestring("610a09005c22")),
    "LIT-LIST-EMPTY": ("expect values: List<Int> = first\nvalues == []", data_list()),
    "LIT-LIST-ELEMENTS": ("expect values: List<Int> = first\nvalues == [1, 2, 3]", data_list(integer(1), integer(2), integer(3))),
    "LIT-LIST-SPREAD": ("expect values: List<Int> = first\nexpect [head, ..tail] = values\n[head, ..tail] == values", data_list(integer(1), integer(2))),
    "LIT-TUPLE": ("expect value: (Int, Bool, ByteArray) = first\nvalue == (1, True, #\"00\")", data_list(integer(1), bool_data(True), bytestring("00"))),
    "LIT-PAIR": ("expect value: Pair<Int, Bool> = first\nvalue == Pair(1, True)", data_list(integer(1), bool_data(True))),
    "LIT-VOID": ("expect value: Void = first\nvalue == Void", constr(0)),
    "LIT-CURVE-G1": (f"expect value: Int = first\nlet point = {G1_LITERAL}\nbuiltin.bls12_381_g1_equal(point, point) && value == 7", integer(7)),
    "LIT-CURVE-G2": (f"expect value: Int = first\nlet point = {G2_LITERAL}\nbuiltin.bls12_381_g2_equal(point, point) && value == 7", integer(7)),
}

OPERATOR_CASES: dict[str, tuple[str, str, str]] = {
    "OP-AND": ("expect left: Bool = first\nexpect right: Bool = second\nleft && right", bool_data(True), bool_data(True)),
    "OP-OR": ("expect left: Bool = first\nexpect right: Bool = second\nleft || right", bool_data(False), bool_data(True)),
    "OP-EQ": ("expect left: Int = first\nexpect right: Int = second\nleft == right", integer(7), integer(7)),
    "OP-NEQ": ("expect left: Int = first\nexpect right: Int = second\nleft != right", integer(7), integer(8)),
    "OP-LT": ("expect left: Int = first\nexpect right: Int = second\nleft < right", integer(7), integer(8)),
    "OP-LTE": ("expect left: Int = first\nexpect right: Int = second\nleft <= right", integer(7), integer(7)),
    "OP-GTE": ("expect left: Int = first\nexpect right: Int = second\nleft >= right", integer(7), integer(7)),
    "OP-GT": ("expect left: Int = first\nexpect right: Int = second\nleft > right", integer(8), integer(7)),
    "OP-ADD": ("expect left: Int = first\nexpect right: Int = second\nleft + right == 15", integer(7), integer(8)),
    "OP-SUB": ("expect left: Int = first\nexpect right: Int = second\nleft - right == 1", integer(8), integer(7)),
    "OP-MUL": ("expect left: Int = first\nexpect right: Int = second\nleft * right == 56", integer(7), integer(8)),
    "OP-DIV": ("expect left: Int = first\nexpect right: Int = second\nleft / right == 7", integer(56), integer(8)),
    "OP-MOD": ("expect left: Int = first\nexpect right: Int = second\nleft % right == 1", integer(57), integer(8)),
    "OP-NOT": ("expect value: Bool = first\n!value", bool_data(False), integer(0)),
    "OP-NEGATE": ("expect value: Int = first\n-value == 7", integer(-7), integer(0)),
    "OP-EQ-SERIALIZABLE": ("expect value: Int = first\nlet left = Comparable { value }\nlet right = Comparable { value }\nleft == right", integer(7), integer(0)),
    "OP-NEQ-SERIALIZABLE": ("expect value: Int = first\nComparable { value } != Comparable { value: value + 1 }", integer(7), integer(0)),
}

PRELUDE_CASES: dict[str, tuple[str, str]] = {
    "TYPE-DATA": ("let value: Data = first\nvalue == first", integer(7)),
    "TYPE-INT": ("expect value: Int = first\nvalue == 7", integer(7)),
    "TYPE-BYTEARRAY": ("expect value: ByteArray = first\nvalue == #\"07\"", bytestring("07")),
    "TYPE-BOOL": ("expect value: Bool = first\nvalue == True", bool_data(True)),
    "TYPE-G1": (f"expect value: Int = first\nlet point: G1Element = {G1_LITERAL}\nbuiltin.bls12_381_g1_equal(point, point) && value == 7", integer(7)),
    "TYPE-G2": (f"expect value: Int = first\nlet point: G2Element = {G2_LITERAL}\nbuiltin.bls12_381_g2_equal(point, point) && value == 7", integer(7)),
    "TYPE-MILLER": (f"expect value: Int = first\nlet result: MillerLoopResult = builtin.bls12_381_miller_loop({G1_LITERAL}, {G2_LITERAL})\nbuiltin.bls12_381_final_verify(result, result) && value == 7", integer(7)),
    "TYPE-ORDERING": ("expect value: Int = first\nlet ordering: Ordering = if value < 7 { Less } else if value == 7 { Equal } else { Greater }\nordering == Equal", integer(7)),
    "TYPE-STRING": ("expect value: ByteArray = first\nlet decoded: String = builtin.decode_utf8(value)\ndecoded == @\"seven\"", bytestring("736576656e")),
    "TYPE-VOID": ("expect value: Void = first\nvalue == Void", constr(0)),
    "TYPE-LIST": ("expect value: List<Int> = first\nvalue == [7]", data_list(integer(7))),
    "TYPE-PAIR": ("expect value: Pair<Int, Bool> = first\nvalue == Pair(7, True)", data_list(integer(7), bool_data(True))),
    "TYPE-PAIRS": ("expect value: Pairs<Int, Bool> = first\nvalue == [Pair(7, True)]", data_map((integer(7), bool_data(True)))),
    "TYPE-OPTION": ("expect value: Int = first\nlet optional: Option<Int> = Some(value)\noptional == Some(7)", integer(7)),
    "TYPE-NEVER": ("expect value: Int = first\nlet never: Never = Never\nlet encoded: Data = never\nencoded == encoded && value == 7", integer(7)),
    "TYPE-SCRIPT-CONTEXT": ("expect value: Int = first\nlet _check: fn(ScriptContext) -> Bool = context_is_present\nvalue == 7", integer(7)),
}

CONVERSION_CASES: dict[str, tuple[str, str]] = {
    "ANN-BINDING": ("expect decoded: Int = first\nlet value: Int = decoded\nvalue == 7", integer(7)),
    "ANN-CONSTANT": ("expect value: Int = first\nvalue == annotated_constant", integer(7)),
    "TYPE-INFERENCE": ("expect value: Int = first\nlet inferred = value + 1\ninferred == 8", integer(7)),
    "TYPE-GENERIC-FUNCTION": ("expect value: Int = first\ngeneric_identity(value) == 7", integer(7)),
    "DATA-UPCAST-IMPLICIT": ("expect value: Int = first\nlet encoded: Data = value\nencoded == first", integer(7)),
    "DATA-UPCAST-AS-DATA": ("expect value: Int = first\nas_data(value) == first", integer(7)),
    "DATA-DOWNCAST-EXPECT": ("expect value: Int = first\nvalue == 7", integer(7)),
    "DATA-DOWNCAST-IF-IS": ("if first is value: Int { value == 7 } else { False }", integer(7)),
    "REGRESSION-EXPECT-UNUSED": ("expect _: Int = first\nfirst == first", integer(7)),
    "REGRESSION-DECODER-IDENTITY": ("expect value: Int = first\nlet encoded: Data = value\nexpect decoded: Int = encoded\ndecoded == value", integer(7)),
}

MODULE_CASES: dict[str, tuple[str, str, str]] = {
    "MOD-VALIDATOR": ("expect value: Int = first\nvalue == 7", integer(7), integer(0)),
    "DEF-FN-PRIVATE": ("expect value: Int = first\nprivate_increment(value) == 8", integer(7), integer(0)),
    "DEF-FN-PUBLIC": ("expect value: Int = first\npublic_increment(value) == 8", integer(7), integer(0)),
    "DEF-CONST-PRIVATE": ("expect value: Int = first\nvalue == private_constant", integer(7), integer(0)),
    "DEF-CONST-PUBLIC": ("expect value: Int = first\nvalue == public_constant", integer(7), integer(0)),
    "DEF-TYPE-PRIVATE": ("expect value: Int = first\nPrivateType(value) == PrivateType(7)", integer(7), integer(0)),
    "DEF-TYPE-PUBLIC": ("expect value: Int = first\nPublicType(value) == PublicType(7)", integer(7), integer(0)),
    "DEF-TYPE-OPAQUE-PRIVATE": ("expect value: Int = first\nPrivateOpaque(value) == PrivateOpaque(7)", integer(7), integer(0)),
    "DEF-TYPE-OPAQUE-PUBLIC": ("expect value: Int = first\nPublicOpaque(value) == PublicOpaque(7)", integer(7), integer(0)),
    "DEF-VALIDATOR": ("expect value: Int = first\nvalue == 7", integer(7), integer(0)),
    "TYPE-CONSTRUCTOR-ZERO": ("expect value: Int = first\nZero == Zero && value == 7", integer(7), integer(0)),
    "TYPE-CONSTRUCTOR-POSITIONAL": ("expect value: Int = first\nPositional(value) == Positional(7)", integer(7), integer(0)),
    "TYPE-CONSTRUCTOR-RECORD": ("expect value: Int = first\nConstructorRecord { value } == ConstructorRecord { value: 7 }", integer(7), integer(0)),
    "TYPE-SHORTHAND-RECORD": ("expect value: Int = first\nShorthandRecord { value } == ShorthandRecord { value: 7 }", integer(7), integer(0)),
    "TYPE-MULTI-CONSTRUCTOR": ("expect value: Int = first\nChoiceB(value) == ChoiceB(7)", integer(7), integer(0)),
    "TYPE-RECURSIVE": ("expect value: Int = first\nlet tree = Node(Leaf(value), Leaf(value))\nwhen tree is { Node(Leaf(left), Leaf(right)) -> left + right == 14\n  _ -> False }", integer(7), integer(0)),
    "TYPE-GENERIC": ("expect value: Int = first\nGenericBox(value) == GenericBox(7)", integer(7), integer(0)),
    "TYPE-OPAQUE-NEWTYPE": ("expect value: Int = first\nOpaqueNewtype { value } == OpaqueNewtype { value: 7 }", integer(7), integer(0)),
    "ENC-DEFAULT-TAG-ORDER": ("expect value: Int = first\nlet encoded: Data = DefaultSecond(value)\nbuiltin.equals_data(encoded, second)", integer(7), constr(1, integer(7))),
    "ENC-TAG-TYPE-DECIMAL": ("expect value: Int = first\nlet encoded: Data = DecimalTaggedType { value }\nbuiltin.equals_data(encoded, second)", integer(7), constr(42, integer(7))),
    "ENC-TAG-TYPE-HEX": ("expect value: Int = first\nlet encoded: Data = HexTaggedType { value }\nbuiltin.equals_data(encoded, second)", integer(7), constr(42, integer(7))),
    "ENC-TAG-CONSTRUCTOR-DECIMAL": ("expect value: Int = first\nlet encoded: Data = DecimalTagged(value)\nbuiltin.equals_data(encoded, second)", integer(7), constr(42, integer(7))),
    "ENC-TAG-CONSTRUCTOR-HEX": ("expect value: Int = first\nlet encoded: Data = HexTagged(value)\nbuiltin.equals_data(encoded, second)", integer(7), constr(42, integer(7))),
    "ENC-LIST": ("expect value: Int = first\nlet encoded: Data = ListEncoded { value }\nbuiltin.equals_data(encoded, second)", integer(7), data_list(integer(7))),
    "IMPORT-BUILTIN-MODULE": ("expect value: Int = first\nbuiltin.add_integer(value, 1) == 8", integer(7), integer(0)),
    "SELECT-MODULE": ("expect value: Int = first\ndefinition_support.increment(value) == 8", integer(7), integer(0)),
    "SELECT-TYPE-NAMESPACE": ("expect value: Int = first\nPublicType(value) == PublicType(7)", integer(7), integer(0)),
}


def _indent(body: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(prefix + line if line else line for line in body.splitlines())


def render_patterns(rows: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    lines = [
        "use cardano/assets.{PolicyId}",
        "use cardano/transaction.{Transaction}",
        "use sentinel/redeemer.{FeatureArgs, FeatureRedeemer}",
        "use sentinel/pattern_support",
        "",
        "pub type PatternRecord {",
        "  PatternRecord { field: Int, other: Int }",
        "}",
        "",
        "pub type PatternTriple {",
        "  PatternTriple(Int, Int, Int)",
        "}",
        "",
        "pub type PatternChoice {",
        "  PatternA(Int)",
        "  PatternB(Int)",
        "}",
        "",
        "fn sum_pattern_pair((left, right): (Int, Int)) -> Int {",
        "  left + right",
        "}",
        "",
        "pub fn evaluate_patterns(raw_redeemer: Data) -> Bool {",
        "  expect FeatureRedeemer { selector, args } = raw_redeemer",
        "  expect FeatureArgs { first, second, third: _ } = args",
        "",
        "  when selector is {",
    ]
    entries: list[dict[str, Any]] = []
    for selector, row in enumerate(rows):
        body, first = PATTERN_CASES[row["id"]]
        second = bool_data(True)
        lines.append(f"    // @feature {row['id']} selector={selector}")
        lines.append(f"    {selector} -> {{")
        lines.extend(_indent(body, 6).splitlines())
        lines.append("    }")
        entries.append(
            {
                "feature_id": row["id"],
                "source_path": "validators/features/patterns.ak",
                "line_start": 0,
                "line_end": 0,
                "ast_evidence": {"node_kind": "Pattern"},
                "uplc_path": "features/patterns.patterns.mint",
                "validator_title": "features/patterns.patterns.mint",
                "branch_selector": selector,
                "artifact_hashes": {"old": None, "new": None},
                "evaluation": {
                    "module": "features/patterns",
                    "name": "evaluate_patterns",
                    "selected_args": [redeemer(selector, first, second)],
                    "baseline_args": [redeemer(-1, first, second)],
                },
                "verification_status": "manifested_unverified",
            }
        )
    lines.extend(
        [
            "    _ -> False",
            "  }",
            "}",
            "",
            "validator patterns {",
            "  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {",
            "    evaluate_patterns(redeemer)",
            "  }",
            "}",
            "",
        ]
    )
    content = "\n".join(lines)
    content_lines = content.splitlines()
    for entry in entries:
        marker = f"@feature {entry['feature_id']} "
        marker_line = next(i for i, line in enumerate(content_lines, 1) if marker in line)
        entry["line_start"] = marker_line + 1
        entry["line_end"] = marker_line + 4
    return content, entries


def render_control(rows: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    lines = [
        "use cardano/assets.{PolicyId}",
        "use cardano/transaction.{Transaction}",
        "use sentinel/redeemer.{FeatureArgs, FeatureRedeemer}",
        "",
        "pub type ControlRecord {",
        "  ControlRecord { field: Int, other: Int }",
        "}",
        "",
        "pub type PositionalRecord {",
        "  PositionalRecord(Int, Bool)",
        "}",
        "",
        "pub fn evaluate_control(raw_redeemer: Data) -> Bool {",
        "  expect FeatureRedeemer { selector, args } = raw_redeemer",
        "  expect FeatureArgs { first, second, third: _ } = args",
        "",
        "  when selector is {",
    ]
    entries: list[dict[str, Any]] = []
    for selector, row in enumerate(rows):
        body, first, second, expects_failure = CONTROL_CASES[row["id"]]
        baseline_selector = -1 if expects_failure else -2
        lines.append(f"    // @feature {row['id']} selector={selector}")
        lines.append(f"    {selector} -> {{")
        lines.extend(_indent(body, 6).splitlines())
        lines.append("    }")
        entries.append(
            {
                "feature_id": row["id"],
                "source_path": "validators/features/control_flow_and_expressions.ak",
                "line_start": 0,
                "line_end": 0,
                "ast_evidence": {"node_kind": "Expression"},
                "uplc_path": "features/control_flow_and_expressions.control_flow_and_expressions.mint",
                "validator_title": "features/control_flow_and_expressions.control_flow_and_expressions.mint",
                "branch_selector": selector,
                "artifact_hashes": {"old": None, "new": None},
                "evaluation": {
                    "module": "features/control_flow_and_expressions",
                    "name": "evaluate_control",
                    "selected_args": [redeemer(selector, first, second)],
                    "baseline_args": [redeemer(baseline_selector, first, second)],
                    "allow_selected_failure": expects_failure,
                },
                "verification_status": "manifested_unverified",
            }
        )
    lines.extend(
        [
            "    -1 -> True",
            "    _ -> False",
            "  }",
            "}",
            "",
            "validator control_flow_and_expressions {",
            "  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {",
            "    evaluate_control(redeemer)",
            "  }",
            "}",
            "",
        ]
    )
    content = "\n".join(lines)
    content_lines = content.splitlines()
    for entry in entries:
        marker = f"@feature {entry['feature_id']} "
        marker_line = next(i for i, line in enumerate(content_lines, 1) if marker in line)
        entry["line_start"] = marker_line + 1
        entry["line_end"] = marker_line + 4
    return content, entries


def render_functions(rows: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    lines = [
        "use cardano/assets.{PolicyId}",
        "use cardano/transaction.{Transaction}",
        "use sentinel/redeemer.{FeatureArgs, FeatureRedeemer}",
        "",
        "fn add(left: Int, right: Int) -> Int { left + right }",
        "fn add_one(value: Int) -> Int { value + 1 }",
        "fn apply_function(value: Int, function: fn(Int) -> Int) -> Int { function(value) }",
        "fn apply_binary(left: Int, function: fn(Int, Int) -> Int, right: Int) -> Int { function(left, right) }",
        "fn factorial(value: Int) -> Int {",
        "  if value <= 1 { 1 } else { value * factorial(value - 1) }",
        "}",
        "fn sum_function_pair((left, right): (Int, Int)) -> Int { left + right }",
        "fn sum_function_data_pair(Pair(left, right): Pair<Int, Int>) -> Int { left + right }",
        "fn empty_body_todo() -> Bool {}",
        "fn labelled_add(left: Int, right: Int) -> Int { left + right }",
        "fn make_adder(left: Int) -> fn(Int) -> Int { fn(right) { left + right } }",
        "fn with_int(value: Int, then: fn(Int) -> Bool) -> Bool { then(value) }",
        "",
        "// @feature FN-ARG-NAMED",
        "fn named_argument(value: Int) -> Int { value }",
        "// @feature FN-ARG-DISCARD",
        "fn discarded_argument(_value: Int) -> Bool { True }",
        "// @feature FN-ARG-LABEL",
        "fn labelled_argument(label value: Int) -> Int { value }",
        "// @feature FN-ARG-LABEL-OVERRIDE",
        "fn overridden_label(external local_name: Int) -> Int { local_name }",
        "// @feature FN-ARG-LABELLED-DISCARD",
        "fn labelled_discard(ignored _value: Int) -> Bool { True }",
        "",
        "pub fn evaluate_functions(raw_redeemer: Data) -> Bool {",
        "  expect FeatureRedeemer { selector, args } = raw_redeemer",
        "  expect FeatureArgs { first, second: _, third: _ } = args",
        "",
        "  when selector is {",
    ]
    entries: list[dict[str, Any]] = []
    for selector, row in enumerate(rows):
        body, first, expects_failure = FUNCTION_CASES[row["id"]]
        baseline_selector = -1 if expects_failure else -2
        lines.append(f"    // @feature {row['id']} selector={selector}")
        lines.append(f"    {selector} -> {{")
        lines.extend(_indent(body, 6).splitlines())
        lines.append("    }")
        entries.append(
            {
                "feature_id": row["id"],
                "source_path": "validators/features/functions_calls_and_bindings.ak",
                "line_start": 0,
                "line_end": 0,
                "ast_evidence": {"node_kind": "Expression"},
                "uplc_path": "features/functions_calls_and_bindings.functions_calls_and_bindings.mint",
                "validator_title": "features/functions_calls_and_bindings.functions_calls_and_bindings.mint",
                "branch_selector": selector,
                "artifact_hashes": {"old": None, "new": None},
                "evaluation": {
                    "module": "features/functions_calls_and_bindings",
                    "name": "evaluate_functions",
                    "selected_args": [redeemer(selector, first)],
                    "baseline_args": [redeemer(baseline_selector, first)],
                    "allow_selected_failure": expects_failure,
                },
                "verification_status": "manifested_unverified",
            }
        )
    lines.extend(
        [
            "    -1 -> True",
            "    _ -> False",
            "  }",
            "}",
            "",
            "validator functions_calls_and_bindings {",
            "  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {",
            "    evaluate_functions(redeemer)",
            "  }",
            "}",
            "",
        ]
    )
    content = "\n".join(lines)
    content_lines = content.splitlines()
    for entry in entries:
        marker = f"@feature {entry['feature_id']} "
        marker_line = next(i for i, line in enumerate(content_lines, 1) if marker in line)
        entry["line_start"] = marker_line + 1
        entry["line_end"] = marker_line + 4
    return content, entries


def render_literals_operators_prelude(
    rows: list[dict[str, Any]],
) -> tuple[str, list[dict[str, Any]]]:
    lines = [
        "use aiken/builtin",
        "use cardano/assets.{PolicyId}",
        "use cardano/script_context.{ScriptContext}",
        "use cardano/transaction.{Transaction}",
        "use sentinel/redeemer.{FeatureArgs, FeatureRedeemer}",
        "",
        "pub type Comparable {",
        "  Comparable { value: Int }",
        "}",
        "",
        "pub const annotated_constant: Int = 7",
        "fn generic_identity(value: a) -> a { value }",
        "fn as_data(value: Data) -> Data { value }",
        "fn context_is_present(_context: ScriptContext) -> Bool { True }",
        "",
        "pub fn evaluate_literals_operators_prelude(raw_redeemer: Data) -> Bool {",
        "  expect FeatureRedeemer { selector, args } = raw_redeemer",
        "  expect FeatureArgs { first, second, third: _ } = args",
        "",
        "  when selector is {",
    ]
    entries: list[dict[str, Any]] = []
    for selector, row in enumerate(rows):
        row_id = row["id"]
        if row_id in LITERAL_CASES:
            body, first = LITERAL_CASES[row_id]
            second = integer(0)
        elif row_id in OPERATOR_CASES:
            body, first, second = OPERATOR_CASES[row_id]
        elif row_id in PRELUDE_CASES:
            body, first = PRELUDE_CASES[row_id]
            second = integer(0)
        else:
            body, first = CONVERSION_CASES[row_id]
            second = integer(0)
        lines.append(f"    // @feature {row_id} selector={selector}")
        lines.append(f"    {selector} -> {{")
        lines.extend(_indent(body, 6).splitlines())
        lines.append("    }")
        entries.append(
            {
                "feature_id": row_id,
                "source_path": "validators/features/literals_operators_prelude.ak",
                "line_start": 0,
                "line_end": 0,
                "ast_evidence": {"node_kind": "Expression"},
                "uplc_path": "features/literals_operators_prelude.literals_operators_prelude.mint",
                "validator_title": "features/literals_operators_prelude.literals_operators_prelude.mint",
                "branch_selector": selector,
                "artifact_hashes": {"old": None, "new": None},
                "evaluation": {
                    "module": "features/literals_operators_prelude",
                    "name": "evaluate_literals_operators_prelude",
                    "selected_args": [redeemer(selector, first, second)],
                    "baseline_args": [redeemer(-1, first, second)],
                },
                "verification_status": "manifested_unverified",
            }
        )
    lines.extend(
        [
            "    _ -> False",
            "  }",
            "}",
            "",
            "validator literals_operators_prelude {",
            "  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {",
            "    evaluate_literals_operators_prelude(redeemer)",
            "  }",
            "}",
            "",
        ]
    )
    content = "\n".join(lines)
    content_lines = content.splitlines()
    for entry in entries:
        marker = f"@feature {entry['feature_id']} "
        marker_line = next(i for i, line in enumerate(content_lines, 1) if marker in line)
        entry["line_start"] = marker_line + 1
        entry["line_end"] = marker_line + 4
    return content, entries


def render_modules(rows: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    lines = [
        "// @feature IMPORT-BUILTIN-MODULE",
        "use aiken/builtin",
        "use cardano/assets.{PolicyId}",
        "use cardano/transaction.{Transaction}",
        "// @feature SELECT-MODULE",
        "use sentinel/definition_support",
        "use sentinel/redeemer.{FeatureArgs, FeatureRedeemer}",
        "",
        "// @feature DEF-FN-PRIVATE",
        "fn private_increment(value: Int) -> Int { value + 1 }",
        "// @feature DEF-FN-PUBLIC",
        "pub fn public_increment(value: Int) -> Int { value + 1 }",
        "// @feature DEF-CONST-PRIVATE",
        "const private_constant = 7",
        "// @feature DEF-CONST-PUBLIC",
        "pub const public_constant = 7",
        "",
        "// @feature DEF-TYPE-PRIVATE",
        "type PrivateType { PrivateType(Int) }",
        "// @feature DEF-TYPE-PUBLIC",
        "// @feature SELECT-TYPE-NAMESPACE",
        "pub type PublicType { PublicType(Int) }",
        "// @feature DEF-TYPE-OPAQUE-PRIVATE",
        "opaque type PrivateOpaque { PrivateOpaque(Int) }",
        "// @feature DEF-TYPE-OPAQUE-PUBLIC",
        "pub opaque type PublicOpaque { PublicOpaque(Int) }",
        "",
        "// @feature TYPE-CONSTRUCTOR-ZERO",
        "pub type ZeroConstructor { Zero }",
        "// @feature TYPE-CONSTRUCTOR-POSITIONAL",
        "pub type PositionalConstructor { Positional(Int) }",
        "// @feature TYPE-CONSTRUCTOR-RECORD",
        "pub type ConstructorRecordType { ConstructorRecord { value: Int } }",
        "// @feature TYPE-SHORTHAND-RECORD",
        "pub type ShorthandRecord { value: Int }",
        "// @feature TYPE-MULTI-CONSTRUCTOR",
        "pub type MultiChoice { ChoiceA ChoiceB(Int) }",
        "// @feature TYPE-RECURSIVE",
        "pub type Tree<a> { Leaf(a) Node(Tree<a>, Tree<a>) }",
        "// @feature TYPE-GENERIC",
        "pub type GenericBox<a> { GenericBox(a) }",
        "// @feature TYPE-OPAQUE-NEWTYPE",
        "pub opaque type OpaqueNewtype<a> { value: a }",
        "",
        "// @feature ENC-DEFAULT-TAG-ORDER",
        "pub type DefaultTags { DefaultFirst(Int) DefaultSecond(Int) }",
        "// @feature ENC-TAG-TYPE-DECIMAL",
        "@tag(42)",
        "pub type DecimalTaggedType { value: Int }",
        "// @feature ENC-TAG-TYPE-HEX",
        "@tag(0x2a)",
        "pub type HexTaggedType { value: Int }",
        "pub type DecimalTaggedConstructors {",
        "  // @feature ENC-TAG-CONSTRUCTOR-DECIMAL",
        "  @tag(42)",
        "  DecimalTagged(Int)",
        "}",
        "pub type HexTaggedConstructors {",
        "  // @feature ENC-TAG-CONSTRUCTOR-HEX",
        "  @tag(0x2a)",
        "  HexTagged(Int)",
        "}",
        "// @feature ENC-LIST",
        "@list",
        "pub type ListEncoded { value: Int }",
        "",
        "pub fn evaluate_modules(raw_redeemer: Data) -> Bool {",
        "  expect FeatureRedeemer { selector, args } = raw_redeemer",
        "  expect FeatureArgs { first, second, third: _ } = args",
        "",
        "  when selector is {",
    ]
    entries: list[dict[str, Any]] = []
    for selector, row in enumerate(rows):
        body, first, second = MODULE_CASES[row["id"]]
        lines.append(f"    // branch {row['id']} selector={selector}")
        lines.append(f"    {selector} -> {{")
        lines.extend(_indent(body, 6).splitlines())
        lines.append("    }")
        entries.append(
            {
                "feature_id": row["id"],
                "source_path": "validators/features/modules_definitions_imports.ak",
                "line_start": 0,
                "line_end": 0,
                "ast_evidence": {"node_kind": "Definition"},
                "uplc_path": "features/modules_definitions_imports.modules_definitions_imports.mint",
                "validator_title": "features/modules_definitions_imports.modules_definitions_imports.mint",
                "branch_selector": selector,
                "artifact_hashes": {"old": None, "new": None},
                "evaluation": {
                    "module": "features/modules_definitions_imports",
                    "name": "evaluate_modules",
                    "selected_args": [redeemer(selector, first, second)],
                    "baseline_args": [redeemer(-1, first, second)],
                },
                "verification_status": "manifested_unverified",
            }
        )
    lines.extend(
        [
            "    _ -> False",
            "  }",
            "}",
            "",
            "// @feature DEF-VALIDATOR",
            "validator definition_feature {",
            "  mint(_redeemer: Data, _policy_id: PolicyId, _self: Transaction) { True }",
            "}",
            "",
            "// @feature MOD-VALIDATOR",
            "validator modules_definitions_imports {",
            "  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {",
            "    evaluate_modules(redeemer)",
            "  }",
            "}",
            "",
        ]
    )
    content = "\n".join(lines)
    content_lines = content.splitlines()
    for entry in entries:
        marker = f"@feature {entry['feature_id']}"
        marker_line = next(i for i, line in enumerate(content_lines, 1) if marker in line)
        entry["line_start"] = marker_line + 1
        entry["line_end"] = marker_line + 2
    return content, entries


def render_validators(rows: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    titles = {
        "VAL-SPEND": "features/validators.val_spend.spend",
        "VAL-MINT": "features/validators.val_mint.mint",
        "VAL-WITHDRAW": "features/validators.val_withdraw.withdraw",
        "VAL-PUBLISH": "features/validators.val_publish.publish",
        "VAL-PROPOSE": "features/validators.val_propose.propose",
        "VAL-VOTE": "features/validators.val_vote.vote",
        "VAL-ELSE": "features/validators.val_else.else",
        "VAL-PARAMETERIZED": "features/validators.val_parameterized.mint",
        "VAL-MULTI-HANDLER": "features/validators.val_multi_handler.mint",
        "VAL-MULTIPLE-DEFS": "features/validators.val_multiple_defs.mint",
        "VAL-SPEND-ARITY": "features/validators.val_spend_arity.spend",
        "VAL-OTHER-ARITY": "features/validators.val_other_arity.mint",
        "VAL-DEFAULT-FALLBACK": "features/validators.val_default_fallback.else",
        "VAL-DATUM-OPTION": "features/validators.val_datum_option.spend",
        "VAL-SCRIPT-CONTEXT": "features/validators.val_script_context.else",
        "VAL-EMPTY-HANDLER-TODO": "features/validators.val_empty_handler.mint",
    }
    lines = [
        "use cardano/address.{Credential}",
        "use cardano/assets.{PolicyId}",
        "use cardano/certificate.{Certificate}",
        "use cardano/governance.{ProposalProcedure, Voter}",
        "use cardano/script_context.{ScriptContext}",
        "use cardano/transaction.{OutputReference, Transaction}",
        "use sentinel/redeemer.{FeatureArgs, FeatureRedeemer}",
        "",
        "pub fn evaluate_validators(raw_redeemer: Data) -> Bool {",
        "  expect FeatureRedeemer { selector, args } = raw_redeemer",
        "  expect FeatureArgs { first, second: _, third: _ } = args",
        "",
        "  when selector is {",
    ]
    entries: list[dict[str, Any]] = []
    for selector, row in enumerate(rows):
        lines.extend(
            [
                f"    // branch {row['id']} selector={selector}",
                f"    {selector} -> {{",
                "      expect value: Int = first",
                "      value == 7",
                "    }",
            ]
        )
        title = titles[row["id"]]
        entries.append(
            {
                "feature_id": row["id"],
                "source_path": "validators/features/validators.ak",
                "line_start": 0,
                "line_end": 0,
                "ast_evidence": {"node_kind": "ValidatorHandler"},
                "uplc_path": title,
                "validator_title": title,
                "branch_selector": selector,
                "artifact_hashes": {"old": None, "new": None},
                "evaluation": {
                    "module": "features/validators",
                    "name": "evaluate_validators",
                    "selected_args": [redeemer(selector, integer(7))],
                    "baseline_args": [redeemer(-1, integer(7))],
                },
                "verification_status": "manifested_unverified",
            }
        )
    lines.extend(
        [
            "    _ -> False",
            "  }",
            "}",
            "",
            "// @feature VAL-SPEND",
            "validator val_spend {",
            "  spend(_datum: Option<Data>, redeemer: Data, _utxo: OutputReference, _self: Transaction) {",
            "    evaluate_validators(redeemer)",
            "  }",
            "}",
            "",
            "// @feature VAL-MINT",
            "validator val_mint {",
            "  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {",
            "    evaluate_validators(redeemer)",
            "  }",
            "}",
            "",
            "// @feature VAL-WITHDRAW",
            "validator val_withdraw {",
            "  withdraw(redeemer: Data, _account: Credential, _self: Transaction) {",
            "    evaluate_validators(redeemer)",
            "  }",
            "}",
            "",
            "// @feature VAL-PUBLISH",
            "validator val_publish {",
            "  publish(redeemer: Data, _certificate: Certificate, _self: Transaction) {",
            "    evaluate_validators(redeemer)",
            "  }",
            "}",
            "",
            "// @feature VAL-PROPOSE",
            "validator val_propose {",
            "  propose(redeemer: Data, _proposal: ProposalProcedure, _self: Transaction) {",
            "    evaluate_validators(redeemer)",
            "  }",
            "}",
            "",
            "// @feature VAL-VOTE",
            "validator val_vote {",
            "  vote(redeemer: Data, _voter: Voter, _self: Transaction) {",
            "    evaluate_validators(redeemer)",
            "  }",
            "}",
            "",
            "// @feature VAL-ELSE",
            "validator val_else {",
            "  else(_ctx: ScriptContext) { True }",
            "}",
            "",
            "// @feature VAL-PARAMETERIZED",
            "validator val_parameterized(parameter: Int) {",
            "  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {",
            "    parameter == parameter && evaluate_validators(redeemer)",
            "  }",
            "}",
            "",
            "// @feature VAL-MULTI-HANDLER",
            "validator val_multi_handler {",
            "  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) { evaluate_validators(redeemer) }",
            "  spend(_datum: Option<Data>, redeemer: Data, _utxo: OutputReference, _self: Transaction) { evaluate_validators(redeemer) }",
            "  else(_ctx: ScriptContext) { False }",
            "}",
            "",
            "// @feature VAL-MULTIPLE-DEFS",
            "validator val_multiple_defs {",
            "  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) { evaluate_validators(redeemer) }",
            "}",
            "",
            "// @feature VAL-SPEND-ARITY",
            "validator val_spend_arity {",
            "  spend(_datum: Option<Data>, redeemer: Data, _utxo: OutputReference, _self: Transaction) { evaluate_validators(redeemer) }",
            "}",
            "",
            "// @feature VAL-OTHER-ARITY",
            "validator val_other_arity {",
            "  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) { evaluate_validators(redeemer) }",
            "}",
            "",
            "validator val_default_fallback {",
            "  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) { evaluate_validators(redeemer) }",
            "  // @feature VAL-DEFAULT-FALLBACK",
            "  else(_ctx: ScriptContext) { True }",
            "}",
            "",
            "validator val_datum_option {",
            "  // @feature VAL-DATUM-OPTION",
            "  spend(_datum: Option<Data>, redeemer: Data, _utxo: OutputReference, _self: Transaction) { evaluate_validators(redeemer) }",
            "}",
            "",
            "validator val_script_context {",
            "  // @feature VAL-SCRIPT-CONTEXT",
            "  else(_ctx: ScriptContext) { True }",
            "}",
            "",
            "validator val_empty_handler {",
            "  // @feature VAL-EMPTY-HANDLER-TODO",
            "  mint(_redeemer: Data, _policy_id: PolicyId, _self: Transaction) {}",
            "}",
            "",
        ]
    )
    content = "\n".join(lines)
    content_lines = content.splitlines()
    for entry in entries:
        marker = f"@feature {entry['feature_id']}"
        marker_line = next(i for i, line in enumerate(content_lines, 1) if marker in line)
        entry["line_start"] = marker_line + 1
        entry["line_end"] = marker_line + 2
    return content, entries


def render_project_tests_docs(
    project_rows: list[dict[str, Any]],
    test_rows: list[dict[str, Any]],
    comment_rows: list[dict[str, Any]],
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    runtime_rows = [
        row
        for row in [*project_rows, *test_rows, *comment_rows]
        if "blaster" in row["lanes"]
    ]
    runtime_cases = {
        "TARGET-PLUTUS-V3": "value == 7",
        "PROJECT-ENV-DEFAULT": (
            "(env.environment_name == @\"default\" || "
            "env.environment_name == @\"preview\") && value == 7"
        ),
        "PROJECT-ENV-NAMED": (
            "(env.environment_name == @\"default\" || "
            "env.environment_name == @\"preview\") && env.network_id >= 0 && value == 7"
        ),
        "PROJECT-CONFIG-DEFAULT": "config.price > 0 && value == 7",
        "PROJECT-CONFIG-NAMED": "config.price > 0 && value == 7",
        "PROJECT-CONDITIONAL-MODULE": (
            "env.network_id >= 0 && config.price > 0 && value == 7"
        ),
        "CONFIG-INT": "config.price > 0 && value == 7",
        "CONFIG-BOOL": "(config.is_mainnet || !config.is_mainnet) && value == 7",
        "CONFIG-BYTEARRAY-UTF8-STRING": (
            "(config.network == \"mainnet\" || config.network == \"preview\") "
            "&& value == 7"
        ),
        "CONFIG-BYTEARRAY-UTF8-MAP": (
            "config.network_utf8 == \"preview\" && value == 7"
        ),
        "CONFIG-BYTEARRAY-HEX-MAP": (
            "config.policy_hex == #\"deadbeef\" && value == 7"
        ),
        "CONFIG-LIST": "config.quotas != [] && value == 7",
        "CONFIG-TUPLE": (
            "let (asset_name, quantity) = config.asset\n"
            "asset_name == \"HOSKY\" && quantity == 42 && value == 7"
        ),
        "TRACE-LEVEL-SILENT": "trace @\"silent profile\"\nvalue == 7",
        "TRACE-LEVEL-COMPACT": "trace @\"compact profile\"\nvalue == 7",
        "TRACE-LEVEL-VERBOSE": "trace @\"verbose profile\": value\nvalue == 7",
        "TRACE-SOURCE-USER": "trace @\"user-defined source\"\nvalue == 7",
        "TRACE-SOURCE-COMPILER": (
            "expect decoded: Int = first\n"
            "decoded == value"
        ),
        "TRACE-SOURCE-ALL": (
            "trace @\"combined source\"\n"
            "expect decoded: Int = first\n"
            "decoded == value"
        ),
        "COMMENT-EXPECT": (
            "/// custom expect failure\n"
            "expect decoded: Int = first\n"
            "decoded == value"
        ),
    }
    missing_runtime = [
        row["id"] for row in runtime_rows if row["id"] not in runtime_cases
    ]
    if missing_runtime:
        raise ValueError(f"missing project runtime cases: {missing_runtime}")

    project_lines = [
        "use config",
        "use env",
        "use sentinel/redeemer.{FeatureArgs, FeatureRedeemer}",
        "",
        "pub fn evaluate_project(raw_redeemer: Data) -> Bool {",
        "  expect FeatureRedeemer { selector, args } = raw_redeemer",
        "  expect FeatureArgs { first, second: _, third: _ } = args",
        "  expect value: Int = first",
        "",
        "  when selector is {",
    ]
    entries: list[dict[str, Any]] = []
    runtime_by_id = {row["id"]: row for row in runtime_rows}
    for selector, row in enumerate(runtime_rows):
        project_lines.append(f"    // @feature {row['id']} selector={selector}")
        project_lines.append(f"    {selector} -> {{")
        project_lines.extend(_indent(runtime_cases[row["id"]], 6).splitlines())
        project_lines.append("    }")
        entries.append(
            {
                "feature_id": row["id"],
                "source_path": "lib/project_features.ak",
                "line_start": 0,
                "line_end": 0,
                "ast_evidence": {"node_kind": "Expression"},
                "uplc_path": "features/project_and_targets.project_and_targets.mint",
                "validator_title": "features/project_and_targets.project_and_targets.mint",
                "branch_selector": selector,
                "artifact_hashes": {"old": None, "new": None},
                "evaluation": {
                    "module": "project_features",
                    "name": "evaluate_project",
                    "selected_args": [redeemer(selector, integer(7))],
                    "baseline_args": [redeemer(-1, integer(7))],
                },
                "verification_status": "manifested_unverified",
            }
        )
    project_lines.extend(["    _ -> False", "  }", "}", ""])

    non_runtime_project = [
        row for row in project_rows if row["id"] not in runtime_by_id
    ]
    project_lines.extend(
        [
            "pub fn project_contract_surface() -> Bool {",
            "  let value = 7",
        ]
    )
    for row in non_runtime_project:
        project_lines.append(f"  // @feature {row['id']}")
        project_lines.append("  expect value == 7")
    project_lines.extend(["  True", "}", ""])

    validator_content = "\n".join(
        [
            "use cardano/assets.{PolicyId}",
            "use cardano/transaction.{Transaction}",
            "use project_features",
            "",
            "validator project_and_targets {",
            "  mint(",
            "    raw_redeemer: Data,",
            "    _policy_id: PolicyId,",
            "    _self: Transaction,",
            "  ) {",
            "    project_features.evaluate_project(raw_redeemer)",
            "  }",
            "}",
            "",
        ]
    )

    test_lines = [
        "use sentinel/redeemer.{FeatureArgs, FeatureRedeemer}",
        "use project_features",
        "",
        "fn constant_fuzzer(value: a) -> Fuzzer<a> {",
        "  fn(prng) { Some((prng, value)) }",
        "}",
        "",
        "// @feature FRAMEWORK-PRNG",
        "fn preserve_prng(prng: PRNG) -> PRNG { prng }",
        "",
        "// @feature FRAMEWORK-FUZZER",
        "fn framework_fuzzer() -> Fuzzer<Int> { constant_fuzzer(7) }",
        "",
        "// @feature TEST-FUZZER-NAMED",
        "fn named_fuzzer() -> Fuzzer<Int> { constant_fuzzer(7) }",
        "",
        "// @feature TEST-FUZZER-COMPOSED",
        "fn composed_fuzzer() -> Fuzzer<Int> {",
        "  fn(prng) {",
        "    when named_fuzzer()(prng) is {",
        "      Some((next_prng, value)) -> Some((preserve_prng(next_prng), value + 1))",
        "      None -> None",
        "    }",
        "  }",
        "}",
        "",
        "fn pair_fuzzer() -> Fuzzer<(Int, Int)> {",
        "  fn(prng) { Some((prng, (7, 8))) }",
        "}",
        "",
        "// @feature FRAMEWORK-SAMPLER",
        "// @feature BENCH-SAMPLER-NAMED",
        "fn named_sampler() -> Sampler<Int> {",
        "  fn(size) { constant_fuzzer(size) }",
        "}",
        "",
        "// @feature BENCH-SAMPLER-COMPOSED",
        "fn composed_sampler() -> Sampler<(Int, Int)> {",
        "  fn(_size) { pair_fuzzer() }",
        "}",
        "",
        "// @feature TEST-UNIT",
        "test unit_feature() { True }",
        "",
        "// @feature TEST-PROPERTY-VIA",
        "test property_via(value via constant_fuzzer(7)) { value == 7 }",
        "",
        "// @feature TEST-MULTI-VIA",
        "test multiple_via_values((left, right) via pair_fuzzer()) {",
        "  left + right == 15",
        "}",
        "",
        "// @feature TEST-VALIDATOR",
        "test validator_behavior() {",
        "  let raw: Data = FeatureRedeemer {",
        "    selector: -1,",
        "    args: FeatureArgs { first: 7, second: 0, third: 0 },",
        "  }",
        "  project_features.evaluate_project(raw) == False",
        "}",
        "",
        "// @feature TEST-FAIL",
        "test expected_failure() fail { False }",
        "",
        "// @feature TEST-FAIL-ONCE",
        "test expected_failure_once(value via constant_fuzzer(7)) fail once {",
        "  value != 7",
        "}",
        "",
        "// @feature TEST-TRACE",
        "test trace_production(value via constant_fuzzer(7)) {",
        "  trace @\"sentinel test trace\": value",
        "  value == 7",
        "}",
        "",
        "// @feature BENCH-VIA",
        "bench benchmark_via(value via named_sampler()) { value >= 0 }",
        "",
        "// @feature BENCH-MULTI-VIA",
        "bench benchmark_multiple_values((left, right) via composed_sampler()) {",
        "  left + right == 15",
        "}",
        "",
    ]

    all_rows = [*project_rows, *test_rows, *comment_rows]
    source_by_id = {
        row["id"]: (
            "lib/feature_tests.ak"
            if row["category"] == "tests_benchmarks_and_tracing"
            and "blaster" not in row["lanes"]
            else "lib/project_features.ak"
        )
        for row in all_rows
    }
    for row in all_rows:
        if row["id"] in runtime_by_id:
            continue
        entries.append(
            {
                "feature_id": row["id"],
                "source_path": source_by_id[row["id"]],
                "line_start": 0,
                "line_end": 0,
                "ast_evidence": {"node_kind": "Definition"},
                "uplc_path": None,
                "validator_title": None,
                "branch_selector": None,
                "artifact_hashes": {"old": None, "new": None},
                "reachability_required": False,
                "verification_status": "manifested_unverified",
            }
        )

    contents = {
        "lib/project_features.ak": "\n".join(project_lines),
        "lib/feature_tests.ak": "\n".join(test_lines),
        "validators/features/project_and_targets.ak": validator_content,
    }
    content_lines = {
        path: content.splitlines() for path, content in contents.items()
    }
    for entry in entries:
        lines = content_lines[entry["source_path"]]
        marker = f"@feature {entry['feature_id']}"
        marker_line = next(
            index for index, line in enumerate(lines, 1) if marker in line
        )
        entry["line_start"] = marker_line + 1
        entry["line_end"] = marker_line + 3
    return contents, entries


def format_positive_sources(manifest: dict[str, Any]) -> None:
    new_compiler = compiler_pair()[1]
    completed = subprocess.run(
        [
            str(new_compiler.executable),
            "fmt",
            str(SENTINEL / "lib"),
            str(SENTINEL / "validators"),
            str(SENTINEL / "env"),
        ],
        cwd=REPOSITORY_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            "failed to format generated feature fixtures\n"
            + completed.stdout
            + completed.stderr
        )
    for key, marker_kind in (("features", "feature"), ("builtins", "builtin")):
        for entry in manifest.get(key, []):
            source_path = entry.get("source_path")
            if not source_path or source_path.startswith("negative/"):
                continue
            source = SENTINEL / source_path
            if source.suffix != ".ak" or not source.exists():
                continue
            lines = source.read_text(encoding="utf-8").splitlines()
            marker = re.compile(
                rf"@{re.escape(marker_kind)}\s+{re.escape(entry['feature_id'])}(?:\s|$)"
            )
            marker_line = next(
                (
                    index
                    for index, line in enumerate(lines, 1)
                    if marker.search(line)
                ),
                None,
            )
            if marker_line is not None:
                entry["line_start"] = marker_line + 1
                entry["line_end"] = min(marker_line + 4, len(lines))


def generate_features() -> dict[str, int]:
    contract = load_json(CONTRACT_PATH)
    pattern_rows = [
        row for row in contract["features"] if row["category"] == "patterns"
    ]
    control_rows = [
        row
        for row in contract["features"]
        if row["category"] == "control_flow_and_expressions"
    ]
    function_rows = [
        row
        for row in contract["features"]
        if row["category"] == "functions_calls_and_bindings"
        and row["sentinel_required"]
    ]
    combined_categories = {
        "literals",
        "operators",
        "prelude_types",
        "type_system_and_data_conversion",
    }
    combined_rows = [
        row
        for row in contract["features"]
        if row["category"] in combined_categories and row["sentinel_required"]
    ]
    module_rows = [
        row
        for row in contract["features"]
        if row["category"] == "modules_definitions_imports"
        and row["sentinel_required"]
    ]
    validator_rows = [
        row
        for row in contract["features"]
        if row["category"] == "validators" and row["sentinel_required"]
    ]
    project_rows = [
        row
        for row in contract["features"]
        if row["category"] == "project_and_targets" and row["sentinel_required"]
    ]
    test_rows = [
        row
        for row in contract["features"]
        if row["category"] == "tests_benchmarks_and_tracing"
        and row["sentinel_required"]
    ]
    comment_rows = [
        row
        for row in contract["features"]
        if row["category"] == "comments_and_docs" and row["sentinel_required"]
    ]
    negative_rows = [
        row
        for row in contract["features"]
        if row["negative_compile_case"]
    ]
    missing_patterns = [
        row["id"] for row in pattern_rows if row["id"] not in PATTERN_CASES
    ]
    missing_control = [
        row["id"] for row in control_rows if row["id"] not in CONTROL_CASES
    ]
    missing_functions = [
        row["id"] for row in function_rows if row["id"] not in FUNCTION_CASES
    ]
    combined_cases = (
        LITERAL_CASES | OPERATOR_CASES | PRELUDE_CASES | CONVERSION_CASES
    )
    missing_combined = [
        row["id"] for row in combined_rows if row["id"] not in combined_cases
    ]
    missing_modules = [
        row["id"] for row in module_rows if row["id"] not in MODULE_CASES
    ]
    if (
        missing_patterns
        or missing_control
        or missing_functions
        or missing_combined
        or missing_modules
    ):
        raise ValueError(
            "missing feature cases: "
            f"patterns={missing_patterns}, control={missing_control}, "
            f"functions={missing_functions}, combined={missing_combined}, "
            f"modules={missing_modules}"
        )

    FEATURE_DIR.mkdir(parents=True, exist_ok=True)
    pattern_content, pattern_entries = render_patterns(pattern_rows)
    control_content, control_entries = render_control(control_rows)
    (FEATURE_DIR / "patterns.ak").write_text(pattern_content, encoding="utf-8")
    (FEATURE_DIR / "control_flow_and_expressions.ak").write_text(
        control_content, encoding="utf-8"
    )
    function_content, function_entries = render_functions(function_rows)
    (FEATURE_DIR / "functions_calls_and_bindings.ak").write_text(
        function_content, encoding="utf-8"
    )
    combined_content, combined_entries = render_literals_operators_prelude(
        combined_rows
    )
    (FEATURE_DIR / "literals_operators_prelude.ak").write_text(
        combined_content, encoding="utf-8"
    )
    module_content, module_entries = render_modules(module_rows)
    (FEATURE_DIR / "modules_definitions_imports.ak").write_text(
        module_content, encoding="utf-8"
    )
    validator_content, validator_entries = render_validators(validator_rows)
    (FEATURE_DIR / "validators.ak").write_text(
        validator_content, encoding="utf-8"
    )
    project_contents, project_entries = render_project_tests_docs(
        project_rows, test_rows, comment_rows
    )
    for relative_path, content in project_contents.items():
        destination = SENTINEL / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    support = "pub type Support {\n  Support(Int)\n}\n"
    (SENTINEL / "lib" / "sentinel" / "pattern_support.ak").write_text(
        support, encoding="utf-8"
    )
    definition_support = "pub fn increment(value: Int) -> Int { value + 1 }\n"
    (SENTINEL / "lib" / "sentinel" / "definition_support.ak").write_text(
        definition_support, encoding="utf-8"
    )

    negative_entries = generate_negative_cases(negative_rows)
    generated_paths = {
        "validators/features/patterns.ak",
        "validators/features/control_flow_and_expressions.ak",
        "validators/features/functions_calls_and_bindings.ak",
        "validators/features/literals_operators_prelude.ak",
        "validators/features/modules_definitions_imports.ak",
        "validators/features/validators.ak",
        "lib/project_features.ak",
        "lib/feature_tests.ak",
        "validators/features/project_and_targets.ak",
    }
    manifest = load_json(MANIFEST_PATH)
    retained = [
        entry
        for entry in manifest.get("features", [])
        if entry.get("source_path") not in generated_paths
        and not entry.get("source_path", "").startswith("negative/cases/")
    ]
    entries = (
        pattern_entries
        + control_entries
        + function_entries
        + combined_entries
        + module_entries
        + validator_entries
        + project_entries
        + negative_entries
    )
    manifest["features"] = retained + entries
    format_positive_sources(manifest)
    MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return {"features": len(entries), "categories": 13}
