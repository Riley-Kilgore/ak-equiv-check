use aiken/builtin
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use sentinel/redeemer.{BuiltinArgs, BuiltinRedeemer}

// Empty-message digest vectors: NIST FIPS 180-4/202, RFC 7693, Keccak submission, and ISO/IEC 10118-3 RIPEMD-160.
// Ed25519 vector: RFC 8032 section 7.1 test 1 (also Aiken UPLC conformance verifyEd25519Signature1).
// ECDSA and Schnorr vectors: Aiken v1.1.23 acceptance_tests/051/lib/tests.ak.

pub fn evaluate_cryptography_and_hashing(raw_redeemer: Data) -> Bool {
  expect BuiltinRedeemer { selector, args } = raw_redeemer
  expect BuiltinArgs { first, second, third } = args

  when selector is {
    // @builtin BUILTIN-18 selector=0
    0 -> {
      expect value: ByteArray = first
      expect expected: ByteArray = second
      builtin.sha2_256(value) == expected
    }
    // @builtin BUILTIN-19 selector=1
    1 -> {
      expect value: ByteArray = first
      expect expected: ByteArray = second
      builtin.sha3_256(value) == expected
    }
    // @builtin BUILTIN-20 selector=2
    2 -> {
      expect value: ByteArray = first
      expect expected: ByteArray = second
      builtin.blake2b_256(value) == expected
    }
    // @builtin BUILTIN-21 selector=3
    3 -> {
      expect key: ByteArray = first
      expect message: ByteArray = second
      expect signature: ByteArray = third
      builtin.verify_ed25519_signature(key, message, signature)
    }
    // @builtin BUILTIN-52 selector=4
    4 -> {
      expect key: ByteArray = first
      expect message: ByteArray = second
      expect signature: ByteArray = third
      builtin.verify_ecdsa_secp256k1_signature(key, message, signature)
    }
    // @builtin BUILTIN-53 selector=5
    5 -> {
      expect key: ByteArray = first
      expect message: ByteArray = second
      expect signature: ByteArray = third
      builtin.verify_schnorr_secp256k1_signature(key, message, signature)
    }
    // @builtin BUILTIN-71 selector=6
    6 -> {
      expect value: ByteArray = first
      expect expected: ByteArray = second
      builtin.keccak_256(value) == expected
    }
    // @builtin BUILTIN-72 selector=7
    7 -> {
      expect value: ByteArray = first
      expect expected: ByteArray = second
      builtin.blake2b_224(value) == expected
    }
    // @builtin BUILTIN-86 selector=8
    8 -> {
      expect value: ByteArray = first
      expect expected: ByteArray = second
      builtin.ripemd_160(value) == expected
    }
    _ -> False
  }
}

validator cryptography_and_hashing {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_cryptography_and_hashing(redeemer)
  }

  else(_) {
    fail
  }
}
