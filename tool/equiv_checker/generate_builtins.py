from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import CONTRACT_PATH, REPOSITORY_ROOT, load_json


SENTINEL = REPOSITORY_ROOT / "sentinel"
BUILTIN_DIR = SENTINEL / "validators" / "builtins"
MANIFEST_PATH = SENTINEL / "coverage" / "feature-manifest.json"


def integer(value: int) -> str:
    return f"I {value}"


def bytestring(value: str) -> str:
    return f"B #{value}"


def constr(index: int, *fields: str) -> str:
    return f"Constr {index} [{', '.join(fields)}]"


def data_list(*items: str) -> str:
    return f"List [{', '.join(items)}]"


def bool_data(value: bool) -> str:
    return constr(1 if value else 0)


def void_data() -> str:
    return constr(0)


def redeemer(selector: int, first: str, second: str, third: str) -> str:
    value = constr(0, integer(selector), constr(0, first, second, third))
    return f"(con data ({value}))"


G1_COMPRESSED = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
G2_COMPRESSED = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
ED25519_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
ED25519_SIGNATURE = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
ECDSA_KEY = "02c66e7d8966b5c555af5805989da9fbf8db95e15631ce358c3a1710c962679063"
ECDSA_MESSAGE = "aadf7de782034fbe3d3db2cb13c0cd91bf41cb08fac7bd61d54453cf6e82b450"
ECDSA_SIGNATURE = "dc4dc264a9fef17a3f253449cf8c397ab6f16fb3d63d86940b5586823dfd02ae3b461bb4336b5ecbaefd6627aa922efc048fec0c881c10c4c9428fca69c132a2"
SCHNORR_KEY = "b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390"
SCHNORR_MESSAGE = "e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614"
SCHNORR_SIGNATURE = "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8"


# Each entry is (Aiken branch body, first Data field, second Data field, third Data field).
CASES: dict[str, tuple[str, str, str, str]] = {
    "add_integer": ("expect left: Int = first\nexpect right: Int = second\nbuiltin.add_integer(left, right) == 10", integer(7), integer(3), integer(0)),
    "subtract_integer": ("expect left: Int = first\nexpect right: Int = second\nbuiltin.subtract_integer(left, right) == 4", integer(7), integer(3), integer(0)),
    "multiply_integer": ("expect left: Int = first\nexpect right: Int = second\nbuiltin.multiply_integer(left, right) == 21", integer(7), integer(3), integer(0)),
    "divide_integer": ("expect left: Int = first\nexpect right: Int = second\nbuiltin.divide_integer(left, right) == 2", integer(7), integer(3), integer(0)),
    "quotient_integer": ("expect left: Int = first\nexpect right: Int = second\nbuiltin.quotient_integer(left, right) == 2", integer(7), integer(3), integer(0)),
    "remainder_integer": ("expect left: Int = first\nexpect right: Int = second\nbuiltin.remainder_integer(left, right) == 1", integer(7), integer(3), integer(0)),
    "mod_integer": ("expect left: Int = first\nexpect right: Int = second\nbuiltin.mod_integer(left, right) == 1", integer(7), integer(3), integer(0)),
    "equals_integer": ("expect left: Int = first\nexpect right: Int = second\nbuiltin.equals_integer(left, right)", integer(7), integer(7), integer(0)),
    "less_than_integer": ("expect left: Int = first\nexpect right: Int = second\nbuiltin.less_than_integer(left, right)", integer(3), integer(7), integer(0)),
    "less_than_equals_integer": ("expect left: Int = first\nexpect right: Int = second\nbuiltin.less_than_equals_integer(left, right)", integer(7), integer(7), integer(0)),
    "append_bytearray": ("expect left: ByteArray = first\nexpect right: ByteArray = second\nexpect expected: ByteArray = third\nbuiltin.append_bytearray(left, right) == expected", bytestring("01"), bytestring("02"), bytestring("0102")),
    "cons_bytearray": ("expect byte: Int = first\nexpect tail: ByteArray = second\nexpect expected: ByteArray = third\nbuiltin.cons_bytearray(byte, tail) == expected", integer(1), bytestring("02"), bytestring("0102")),
    "slice_bytearray": ("expect value: ByteArray = first\nexpect start: Int = second\nexpect length: Int = third\nbuiltin.length_of_bytearray(builtin.slice_bytearray(start, length, value)) == length", bytestring("00010203"), integer(1), integer(2)),
    "length_of_bytearray": ("expect value: ByteArray = first\nbuiltin.length_of_bytearray(value) == 2", bytestring("0001"), integer(0), integer(0)),
    "index_bytearray": ("expect value: ByteArray = first\nexpect index: Int = second\nbuiltin.index_bytearray(value, index) == 1", bytestring("0001"), integer(1), integer(0)),
    "equals_bytearray": ("expect left: ByteArray = first\nexpect right: ByteArray = second\nbuiltin.equals_bytearray(left, right)", bytestring("01"), bytestring("01"), integer(0)),
    "less_than_bytearray": ("expect left: ByteArray = first\nexpect right: ByteArray = second\nbuiltin.less_than_bytearray(left, right)", bytestring("01"), bytestring("02"), integer(0)),
    "less_than_equals_bytearray": ("expect left: ByteArray = first\nexpect right: ByteArray = second\nbuiltin.less_than_equals_bytearray(left, right)", bytestring("01"), bytestring("01"), integer(0)),
    "sha2_256": ("expect value: ByteArray = first\nexpect expected: ByteArray = second\nbuiltin.sha2_256(value) == expected", bytestring(""), bytestring("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), integer(0)),
    "sha3_256": ("expect value: ByteArray = first\nexpect expected: ByteArray = second\nbuiltin.sha3_256(value) == expected", bytestring(""), bytestring("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"), integer(0)),
    "blake2b_256": ("expect value: ByteArray = first\nexpect expected: ByteArray = second\nbuiltin.blake2b_256(value) == expected", bytestring(""), bytestring("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"), integer(0)),
    "verify_ed25519_signature": ("expect key: ByteArray = first\nexpect message: ByteArray = second\nexpect signature: ByteArray = third\nbuiltin.verify_ed25519_signature(key, message, signature)", bytestring(ED25519_KEY), bytestring(""), bytestring(ED25519_SIGNATURE)),
    "append_string": ("expect left_bytes: ByteArray = first\nexpect right_bytes: ByteArray = second\nexpect expected: ByteArray = third\nlet left = builtin.decode_utf8(left_bytes)\nlet right = builtin.decode_utf8(right_bytes)\nbuiltin.encode_utf8(builtin.append_string(left, right)) == expected", bytestring("61"), bytestring("62"), bytestring("6162")),
    "equals_string": ("expect left_bytes: ByteArray = first\nexpect right_bytes: ByteArray = second\nlet left = builtin.decode_utf8(left_bytes)\nlet right = builtin.decode_utf8(right_bytes)\nbuiltin.equals_string(left, right)", bytestring("61"), bytestring("61"), integer(0)),
    "encode_utf8": ("expect value: ByteArray = first\nlet decoded = builtin.decode_utf8(value)\nbuiltin.encode_utf8(decoded) == value", bytestring("73656e74696e656c"), integer(0), integer(0)),
    "decode_utf8": ("expect value: ByteArray = first\nbuiltin.encode_utf8(builtin.decode_utf8(value)) == value", bytestring("73656e74696e656c"), integer(0), integer(0)),
    "if_then_else": ("expect condition: Bool = first\nexpect when_true: Bool = second\nexpect when_false: Bool = third\nbuiltin.if_then_else(condition, when_true, when_false)", bool_data(True), bool_data(True), bool_data(False)),
    "choose_void": ("expect unit: Void = first\nexpect value: Bool = second\nlet choose = builtin.choose_void\nchoose(unit, value)", void_data(), bool_data(True), integer(0)),
    "debug": ("expect value: Bool = first\nbuiltin.debug(@\"sentinel\", value)", bool_data(True), integer(0), integer(0)),
    "fst_pair": ("expect value: Pair<Int, Int> = first\nbuiltin.fst_pair(value) == 1", data_list(integer(1), integer(2)), integer(0), integer(0)),
    "snd_pair": ("expect value: Pair<Int, Int> = first\nbuiltin.snd_pair(value) == 2", data_list(integer(1), integer(2)), integer(0), integer(0)),
    "choose_list": ("expect values: List<Int> = first\nbuiltin.choose_list(values, False, True)", data_list(integer(1)), integer(0), integer(0)),
    "cons_list": ("expect value: Int = first\nexpect values: List<Int> = second\nbuiltin.head_list(builtin.cons_list(value, values)) == value", integer(1), data_list(integer(2)), integer(0)),
    "head_list": ("expect values: List<Int> = first\nbuiltin.head_list(values) == 1", data_list(integer(1)), integer(0), integer(0)),
    "tail_list": ("expect values: List<Int> = first\nbuiltin.null_list(builtin.tail_list(values))", data_list(integer(1)), integer(0), integer(0)),
    "null_list": ("expect values: List<Int> = first\nbuiltin.null_list(values)", data_list(), integer(0), integer(0)),
    "choose_data": ("builtin.choose_data(first, True, False, False, False, False)", constr(0), integer(0), integer(0)),
    "constr_data": ("expect tag: Int = first\nexpect fields: List<Data> = second\nbuiltin.equals_data(builtin.constr_data(tag, fields), third)", integer(0), data_list(integer(1)), constr(0, integer(1))),
    "map_data": ("expect entries: Pairs<Data, Data> = first\nbuiltin.equals_data(builtin.map_data(entries), second)", "Map [(I 1, I 2)]", "Map [(I 1, I 2)]", integer(0)),
    "list_data": ("expect items: List<Data> = first\nbuiltin.equals_data(builtin.list_data(items), second)", data_list(integer(1)), data_list(integer(1)), integer(0)),
    "i_data": ("expect value: Int = first\nbuiltin.equals_data(builtin.i_data(value), second)", integer(1), integer(1), integer(0)),
    "b_data": ("expect value: ByteArray = first\nlet encode = builtin.b_data\nlet changed = builtin.append_bytearray(value, #\"00\")\nbuiltin.equals_data(encode(changed), second)", bytestring("01"), bytestring("0100"), integer(0)),
    "un_constr_data": ("let pair = builtin.un_constr_data(first)\nbuiltin.fst_pair(pair) == 0", constr(0, integer(1)), integer(0), integer(0)),
    "un_map_data": ("builtin.null_list(builtin.un_map_data(first))", "Map []", integer(0), integer(0)),
    "un_list_data": ("builtin.null_list(builtin.un_list_data(first))", data_list(), integer(0), integer(0)),
    "un_i_data": ("builtin.un_i_data(first) == 1", integer(1), integer(0), integer(0)),
    "un_b_data": ("builtin.un_b_data(first) == #\"01\"", bytestring("01"), integer(0), integer(0)),
    "equals_data": ("builtin.equals_data(first, second)", integer(1), integer(1), integer(0)),
    "new_pair": ("builtin.equals_data(builtin.fst_pair(builtin.new_pair(first, second)), first)", integer(1), integer(2), integer(0)),
    "new_list": ("expect guard: Bool = first\nguard && builtin.null_list(builtin.new_list())", bool_data(True), integer(0), integer(0)),
    "new_pairs": ("expect guard: Bool = first\nguard && builtin.null_list(builtin.new_pairs())", bool_data(True), integer(0), integer(0)),
    "serialise_data": ("builtin.length_of_bytearray(builtin.serialise_data(first)) > 0", constr(0), integer(0), integer(0)),
    "verify_ecdsa_secp256k1_signature": ("expect key: ByteArray = first\nexpect message: ByteArray = second\nexpect signature: ByteArray = third\nbuiltin.verify_ecdsa_secp256k1_signature(key, message, signature)", bytestring(ECDSA_KEY), bytestring(ECDSA_MESSAGE), bytestring(ECDSA_SIGNATURE)),
    "verify_schnorr_secp256k1_signature": ("expect key: ByteArray = first\nexpect message: ByteArray = second\nexpect signature: ByteArray = third\nbuiltin.verify_schnorr_secp256k1_signature(key, message, signature)", bytestring(SCHNORR_KEY), bytestring(SCHNORR_MESSAGE), bytestring(SCHNORR_SIGNATURE)),
    "keccak_256": ("expect value: ByteArray = first\nexpect expected: ByteArray = second\nbuiltin.keccak_256(value) == expected", bytestring(""), bytestring("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), integer(0)),
    "blake2b_224": ("expect value: ByteArray = first\nexpect expected: ByteArray = second\nbuiltin.blake2b_224(value) == expected", bytestring(""), bytestring("836cc68931c2e4e3e838602eca1902591d216837bafddfe6f0c8cb07"), integer(0)),
    "integer_to_bytearray": ("expect value: Int = first\nlet encoded = builtin.integer_to_bytearray(True, 2, value)\nbuiltin.length_of_bytearray(encoded) == 2", integer(258), integer(0), integer(0)),
    "bytearray_to_integer": ("expect value: ByteArray = first\nbuiltin.bytearray_to_integer(True, value) == 258", bytestring("0102"), integer(0), integer(0)),
    "and_bytearray": ("expect left: ByteArray = first\nexpect right: ByteArray = second\nexpect expected: ByteArray = third\nbuiltin.and_bytearray(False, left, right) == expected", bytestring("0f"), bytestring("f0"), bytestring("00")),
    "or_bytearray": ("expect left: ByteArray = first\nexpect right: ByteArray = second\nexpect expected: ByteArray = third\nbuiltin.or_bytearray(False, left, right) == expected", bytestring("0f"), bytestring("f0"), bytestring("ff")),
    "xor_bytearray": ("expect left: ByteArray = first\nexpect right: ByteArray = second\nexpect expected: ByteArray = third\nbuiltin.xor_bytearray(False, left, right) == expected", bytestring("0f"), bytestring("f0"), bytestring("ff")),
    "complement_bytearray": ("expect value: ByteArray = first\nbuiltin.complement_bytearray(value) == #\"f0\"", bytestring("0f"), integer(0), integer(0)),
    "read_bit": ("expect value: ByteArray = first\nexpect index: Int = second\nbuiltin.read_bit(value, index)", bytestring("80"), integer(7), integer(0)),
    "write_bits": ("expect value: ByteArray = first\nexpect indexes: List<Int> = second\nbuiltin.write_bits(value, indexes, True) == #\"80\"", bytestring("00"), data_list(integer(7)), integer(0)),
    "replicate_byte": ("expect count: Int = first\nexpect byte: Int = second\nbuiltin.replicate_byte(count, byte) == #\"ffff\"", integer(2), integer(255), integer(0)),
    "shift_bytearray": ("expect value: ByteArray = first\nexpect amount: Int = second\nbuiltin.shift_bytearray(value, amount) == #\"02\"", bytestring("01"), integer(1), integer(0)),
    "rotate_bytearray": ("expect value: ByteArray = first\nexpect amount: Int = second\nbuiltin.rotate_bytearray(value, amount) == #\"02\"", bytestring("01"), integer(1), integer(0)),
    "count_set_bits": ("expect value: ByteArray = first\nbuiltin.count_set_bits(value) == 4", bytestring("0f"), integer(0), integer(0)),
    "find_first_set_bit": ("expect value: ByteArray = first\nbuiltin.find_first_set_bit(value) >= 0", bytestring("01"), integer(0), integer(0)),
    "ripemd_160": ("expect value: ByteArray = first\nexpect expected: ByteArray = second\nbuiltin.ripemd_160(value) == expected", bytestring(""), bytestring("9c1185a5c5e9fc54612808977ee8f548b2258d31"), integer(0)),
}


def _bls_case(name: str) -> tuple[str, str, str, str]:
    point_setup = "expect scalar: Int = first"
    message_setup = "expect message: ByteArray = first"
    cases = {
        "bls12_381_g1_add": f"{point_setup}\nlet point = builtin.bls12_381_g1_scalar_mul(scalar, generator_g1)\nbuiltin.length_of_bytearray(builtin.bls12_381_g1_compress(builtin.bls12_381_g1_add(point, generator_g1))) == 48",
        "bls12_381_g1_neg": f"{point_setup}\nlet point = builtin.bls12_381_g1_scalar_mul(scalar, generator_g1)\nbuiltin.length_of_bytearray(builtin.bls12_381_g1_compress(builtin.bls12_381_g1_neg(point))) == 48",
        "bls12_381_g1_scalar_mul": f"{point_setup}\nbuiltin.length_of_bytearray(builtin.bls12_381_g1_compress(builtin.bls12_381_g1_scalar_mul(scalar, generator_g1))) == 48",
        "bls12_381_g1_equal": f"{point_setup}\nlet point = builtin.bls12_381_g1_scalar_mul(scalar, generator_g1)\nbuiltin.bls12_381_g1_equal(point, point)",
        "bls12_381_g1_compress": f"{point_setup}\nlet point = builtin.bls12_381_g1_scalar_mul(scalar, generator_g1)\nbuiltin.length_of_bytearray(builtin.bls12_381_g1_compress(point)) == 48",
        "bls12_381_g1_uncompress": "expect compressed: ByteArray = first\nbuiltin.bls12_381_g1_equal(builtin.bls12_381_g1_uncompress(compressed), generator_g1)",
        "bls12_381_g1_hash_to_group": f"{message_setup}\nlet point = builtin.bls12_381_g1_hash_to_group(message, g1_dst)\nbuiltin.length_of_bytearray(builtin.bls12_381_g1_compress(point)) == 48",
        "bls12_381_g2_add": f"{point_setup}\nlet point = builtin.bls12_381_g2_scalar_mul(scalar, generator_g2)\nbuiltin.length_of_bytearray(builtin.bls12_381_g2_compress(builtin.bls12_381_g2_add(point, generator_g2))) == 96",
        "bls12_381_g2_neg": f"{point_setup}\nlet point = builtin.bls12_381_g2_scalar_mul(scalar, generator_g2)\nbuiltin.length_of_bytearray(builtin.bls12_381_g2_compress(builtin.bls12_381_g2_neg(point))) == 96",
        "bls12_381_g2_scalar_mul": f"{point_setup}\nbuiltin.length_of_bytearray(builtin.bls12_381_g2_compress(builtin.bls12_381_g2_scalar_mul(scalar, generator_g2))) == 96",
        "bls12_381_g2_equal": f"{point_setup}\nlet point = builtin.bls12_381_g2_scalar_mul(scalar, generator_g2)\nbuiltin.bls12_381_g2_equal(point, point)",
        "bls12_381_g2_compress": f"{point_setup}\nlet point = builtin.bls12_381_g2_scalar_mul(scalar, generator_g2)\nbuiltin.length_of_bytearray(builtin.bls12_381_g2_compress(point)) == 96",
        "bls12_381_g2_uncompress": "expect compressed: ByteArray = first\nbuiltin.bls12_381_g2_equal(builtin.bls12_381_g2_uncompress(compressed), generator_g2)",
        "bls12_381_g2_hash_to_group": f"{message_setup}\nlet point = builtin.bls12_381_g2_hash_to_group(message, g2_dst)\nbuiltin.length_of_bytearray(builtin.bls12_381_g2_compress(point)) == 96",
        "bls12_381_miller_loop": f"{point_setup}\nlet g1 = builtin.bls12_381_g1_scalar_mul(scalar, generator_g1)\nlet g2 = builtin.bls12_381_g2_scalar_mul(scalar, generator_g2)\nlet result = builtin.bls12_381_miller_loop(g1, g2)\nbuiltin.bls12_381_final_verify(result, result)",
        "bls12_381_mul_miller_loop_result": f"{point_setup}\nlet g1 = builtin.bls12_381_g1_scalar_mul(scalar, generator_g1)\nlet g2 = builtin.bls12_381_g2_scalar_mul(scalar, generator_g2)\nlet result = builtin.bls12_381_miller_loop(g1, g2)\nlet product = builtin.bls12_381_mul_miller_loop_result(result, result)\nbuiltin.bls12_381_final_verify(product, product)",
        "bls12_381_final_verify": f"{point_setup}\nlet g1 = builtin.bls12_381_g1_scalar_mul(scalar, generator_g1)\nlet g2 = builtin.bls12_381_g2_scalar_mul(scalar, generator_g2)\nlet result = builtin.bls12_381_miller_loop(g1, g2)\nbuiltin.bls12_381_final_verify(result, result)",
    }
    first = bytestring(G1_COMPRESSED) if name == "bls12_381_g1_uncompress" else bytestring(G2_COMPRESSED) if name == "bls12_381_g2_uncompress" else bytestring("73656e74696e656c") if "hash_to_group" in name else integer(2)
    return cases[name], first, integer(0), integer(0)


for bls_name in (
    "bls12_381_g1_add", "bls12_381_g1_neg", "bls12_381_g1_scalar_mul",
    "bls12_381_g1_equal", "bls12_381_g1_compress", "bls12_381_g1_uncompress",
    "bls12_381_g1_hash_to_group", "bls12_381_g2_add", "bls12_381_g2_neg",
    "bls12_381_g2_scalar_mul", "bls12_381_g2_equal", "bls12_381_g2_compress",
    "bls12_381_g2_uncompress", "bls12_381_g2_hash_to_group", "bls12_381_miller_loop",
    "bls12_381_mul_miller_loop_result", "bls12_381_final_verify",
):
    CASES[bls_name] = _bls_case(bls_name)


VECTOR_COMMENTS = {
    "bls12_381": [
        "// G1/G2 generator vectors: Aiken v1.1.23 acceptance_tests/113/validators/foo.ak.",
        "// Hash-to-curve DSTs follow RFC 9380 section 8.8 suites.",
    ],
    "cryptography_and_hashing": [
        "// Empty-message digest vectors: NIST FIPS 180-4/202, RFC 7693, Keccak submission, and ISO/IEC 10118-3 RIPEMD-160.",
        "// Ed25519 vector: RFC 8032 section 7.1 test 1 (also Aiken UPLC conformance verifyEd25519Signature1).",
        "// ECDSA and Schnorr vectors: Aiken v1.1.23 acceptance_tests/051/lib/tests.ak.",
    ],
}


BLS_CONSTANTS = f'''pub const generator_g1: G1Element =
  #<Bls12_381, G1>"{G1_COMPRESSED}"

pub const generator_g2: G2Element =
  #<Bls12_381, G2>"{G2_COMPRESSED}"

pub const g1_dst = "BLS12381G1_XMD:SHA-256_SSWU_RO_SENTINEL_"
pub const g2_dst = "BLS12381G2_XMD:SHA-256_SSWU_RO_SENTINEL_"
'''


def _indent(body: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(prefix + line for line in body.splitlines())


def render_family(category: str, rows: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    function_name = f"evaluate_{category}"
    family_bodies = "\n".join(CASES[row["aiken_name"]][0] for row in rows)
    second_binding = "second" if "second" in family_bodies else "second: _second"
    third_binding = "third" if "third" in family_bodies else "third: _third"
    lines = [
        "use aiken/builtin",
        "use cardano/assets.{PolicyId}",
        "use cardano/transaction.{Transaction}",
        "use sentinel/redeemer.{BuiltinArgs, BuiltinRedeemer}",
        "",
    ]
    lines.extend(VECTOR_COMMENTS.get(category, []))
    if category in VECTOR_COMMENTS:
        lines.append("")
    if category == "bls12_381":
        lines.extend(BLS_CONSTANTS.rstrip().splitlines())
        lines.append("")
    lines.extend(
        [
            f"pub fn {function_name}(raw_redeemer: Data) -> Bool {{",
            "  expect BuiltinRedeemer { selector, args } = raw_redeemer",
            f"  expect BuiltinArgs {{ first, {second_binding}, {third_binding} }} = args",
            "",
            "  when selector is {",
        ]
    )
    entries = []
    for selector, row in enumerate(rows):
        body, first, second, third = CASES[row["aiken_name"]]
        baseline_selector = -1 if row["aiken_name"] == "choose_void" else -2
        lines.append(f"    // @builtin {row['id']} selector={selector}")
        lines.append(f"    {selector} -> {{")
        lines.extend(_indent(body, 6).splitlines())
        lines.append("    }")
        entries.append(
            {
                "feature_id": row["id"],
                "source_path": f"validators/builtins/{category}.ak",
                "line_start": 0,
                "line_end": 0,
                "ast_evidence": {
                    "node_kind": (
                        "ModuleSelect"
                        if row["aiken_name"] in {"choose_void", "b_data"}
                        else "Call"
                    ),
                    "aiken_name": row["aiken_name"],
                },
                "uplc_path": f"builtins/{category}.{category}.mint",
                "validator_title": f"builtins/{category}.{category}.mint",
                "branch_selector": selector,
                "uplc_name": row["uplc_name"],
                "artifact_hashes": {"old": None, "new": None},
                "evaluation": {
                    "module": f"builtins/{category}",
                    "name": function_name,
                    "selected_args": [redeemer(selector, first, second, third)],
                    "baseline_args": [redeemer(baseline_selector, first, second, third)],
                    "allow_selected_failure": row["aiken_name"] == "choose_void",
                },
                "verification_status": "manifested_unverified",
            }
        )
    if category == "control_and_trace":
        lines.append("    -1 -> True")
    lines.extend(
        [
            "    _ -> False",
            "  }",
            "}",
            "",
            f"validator {category} {{",
            "  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {",
            f"    {function_name}(redeemer)",
            "  }",
            "}",
            "",
        ]
    )
    content = "\n".join(lines)
    content_lines = content.splitlines()
    for entry in entries:
        marker = f"@builtin {entry['feature_id']} "
        marker_line = next(i for i, line in enumerate(content_lines, 1) if marker in line)
        entry["line_start"] = marker_line + 1
        entry["line_end"] = marker_line + 4
    return content, entries


def generate() -> dict[str, Any]:
    contract = load_json(CONTRACT_PATH)
    rows = contract["active_uplc_builtins"]
    missing = sorted({row["aiken_name"] for row in rows} - CASES.keys())
    extra = sorted(CASES.keys() - {row["aiken_name"] for row in rows})
    if missing or extra:
        raise ValueError(f"builtin case mapping mismatch; missing={missing}, extra={extra}")

    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["category"], []).append(row)

    BUILTIN_DIR.mkdir(parents=True, exist_ok=True)
    keep = BUILTIN_DIR / ".gitkeep"
    if keep.exists():
        keep.unlink()
    entries = []
    for category, family_rows in sorted(grouped.items()):
        content, family_entries = render_family(category, family_rows)
        (BUILTIN_DIR / f"{category}.ak").write_text(content, encoding="utf-8")
        entries.extend(family_entries)

    manifest = load_json(MANIFEST_PATH)
    manifest["builtins"] = entries
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return {"families": len(grouped), "builtins": len(entries)}


if __name__ == "__main__":
    print(json.dumps(generate(), indent=2))
