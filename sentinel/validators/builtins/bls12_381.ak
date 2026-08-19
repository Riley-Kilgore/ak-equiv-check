use aiken/builtin
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use sentinel/redeemer.{BuiltinArgs, BuiltinRedeemer}

// G1/G2 generator vectors: Aiken v1.1.23 acceptance_tests/113/validators/foo.ak.
// Hash-to-curve DSTs follow RFC 9380 section 8.8 suites.

pub const generator_g1: G1Element =
  #<Bls12_381, G1>"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"

pub const generator_g2: G2Element =
  #<Bls12_381, G2>"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"

pub const g1_dst = "BLS12381G1_XMD:SHA-256_SSWU_RO_SENTINEL_"

pub const g2_dst = "BLS12381G2_XMD:SHA-256_SSWU_RO_SENTINEL_"

pub fn evaluate_bls12_381(raw_redeemer: Data) -> Bool {
  expect BuiltinRedeemer { selector, args } = raw_redeemer
  expect BuiltinArgs { first, second: _second, third: _third } = args

  when selector is {
    // @builtin BUILTIN-54 selector=0
    0 -> {
      expect scalar: Int = first
      let point = builtin.bls12_381_g1_scalar_mul(scalar, generator_g1)
      builtin.length_of_bytearray(
        builtin.bls12_381_g1_compress(
          builtin.bls12_381_g1_add(point, generator_g1),
        ),
      ) == 48
    }
    // @builtin BUILTIN-55 selector=1
    1 -> {
      expect scalar: Int = first
      let point = builtin.bls12_381_g1_scalar_mul(scalar, generator_g1)
      builtin.length_of_bytearray(
        builtin.bls12_381_g1_compress(builtin.bls12_381_g1_neg(point)),
      ) == 48
    }
    // @builtin BUILTIN-56 selector=2
    2 -> {
      expect scalar: Int = first
      builtin.length_of_bytearray(
        builtin.bls12_381_g1_compress(
          builtin.bls12_381_g1_scalar_mul(scalar, generator_g1),
        ),
      ) == 48
    }
    // @builtin BUILTIN-57 selector=3
    3 -> {
      expect scalar: Int = first
      let point = builtin.bls12_381_g1_scalar_mul(scalar, generator_g1)
      builtin.bls12_381_g1_equal(point, point)
    }
    // @builtin BUILTIN-58 selector=4
    4 -> {
      expect scalar: Int = first
      let point = builtin.bls12_381_g1_scalar_mul(scalar, generator_g1)
      builtin.length_of_bytearray(builtin.bls12_381_g1_compress(point)) == 48
    }
    // @builtin BUILTIN-59 selector=5
    5 -> {
      expect compressed: ByteArray = first
      builtin.bls12_381_g1_equal(
        builtin.bls12_381_g1_uncompress(compressed),
        generator_g1,
      )
    }
    // @builtin BUILTIN-60 selector=6
    6 -> {
      expect message: ByteArray = first
      let point = builtin.bls12_381_g1_hash_to_group(message, g1_dst)
      builtin.length_of_bytearray(builtin.bls12_381_g1_compress(point)) == 48
    }
    // @builtin BUILTIN-61 selector=7
    7 -> {
      expect scalar: Int = first
      let point = builtin.bls12_381_g2_scalar_mul(scalar, generator_g2)
      builtin.length_of_bytearray(
        builtin.bls12_381_g2_compress(
          builtin.bls12_381_g2_add(point, generator_g2),
        ),
      ) == 96
    }
    // @builtin BUILTIN-62 selector=8
    8 -> {
      expect scalar: Int = first
      let point = builtin.bls12_381_g2_scalar_mul(scalar, generator_g2)
      builtin.length_of_bytearray(
        builtin.bls12_381_g2_compress(builtin.bls12_381_g2_neg(point)),
      ) == 96
    }
    // @builtin BUILTIN-63 selector=9
    9 -> {
      expect scalar: Int = first
      builtin.length_of_bytearray(
        builtin.bls12_381_g2_compress(
          builtin.bls12_381_g2_scalar_mul(scalar, generator_g2),
        ),
      ) == 96
    }
    // @builtin BUILTIN-64 selector=10
    10 -> {
      expect scalar: Int = first
      let point = builtin.bls12_381_g2_scalar_mul(scalar, generator_g2)
      builtin.bls12_381_g2_equal(point, point)
    }
    // @builtin BUILTIN-65 selector=11
    11 -> {
      expect scalar: Int = first
      let point = builtin.bls12_381_g2_scalar_mul(scalar, generator_g2)
      builtin.length_of_bytearray(builtin.bls12_381_g2_compress(point)) == 96
    }
    // @builtin BUILTIN-66 selector=12
    12 -> {
      expect compressed: ByteArray = first
      builtin.bls12_381_g2_equal(
        builtin.bls12_381_g2_uncompress(compressed),
        generator_g2,
      )
    }
    // @builtin BUILTIN-67 selector=13
    13 -> {
      expect message: ByteArray = first
      let point = builtin.bls12_381_g2_hash_to_group(message, g2_dst)
      builtin.length_of_bytearray(builtin.bls12_381_g2_compress(point)) == 96
    }
    // @builtin BUILTIN-68 selector=14
    14 -> {
      expect scalar: Int = first
      let g1 = builtin.bls12_381_g1_scalar_mul(scalar, generator_g1)
      let g2 = builtin.bls12_381_g2_scalar_mul(scalar, generator_g2)
      let result = builtin.bls12_381_miller_loop(g1, g2)
      builtin.bls12_381_final_verify(result, result)
    }
    // @builtin BUILTIN-69 selector=15
    15 -> {
      expect scalar: Int = first
      let g1 = builtin.bls12_381_g1_scalar_mul(scalar, generator_g1)
      let g2 = builtin.bls12_381_g2_scalar_mul(scalar, generator_g2)
      let result = builtin.bls12_381_miller_loop(g1, g2)
      let product = builtin.bls12_381_mul_miller_loop_result(result, result)
      builtin.bls12_381_final_verify(product, product)
    }
    // @builtin BUILTIN-70 selector=16
    16 -> {
      expect scalar: Int = first
      let g1 = builtin.bls12_381_g1_scalar_mul(scalar, generator_g1)
      let g2 = builtin.bls12_381_g2_scalar_mul(scalar, generator_g2)
      let result = builtin.bls12_381_miller_loop(g1, g2)
      builtin.bls12_381_final_verify(result, result)
    }
    _ -> False
  }
}

validator bls12_381 {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_bls12_381(redeemer)
  }

  else(_) {
    fail
  }
}
