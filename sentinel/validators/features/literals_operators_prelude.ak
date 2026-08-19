use aiken/builtin
use cardano/assets.{PolicyId}
use cardano/script_context.{ScriptContext}
use cardano/transaction.{Transaction}
use sentinel/redeemer.{FeatureArgs, FeatureRedeemer}

pub type Comparable {
  Comparable { value: Int }
}

pub const annotated_constant: Int = 7

fn generic_identity(value: a) -> a {
  value
}

fn as_data(value: Data) -> Data {
  value
}

fn context_is_present(_context: ScriptContext) -> Bool {
  True
}

pub fn evaluate_literals_operators_prelude(raw_redeemer: Data) -> Bool {
  expect FeatureRedeemer { selector, args } = raw_redeemer
  expect FeatureArgs { first, second, third: _ } = args

  when selector is {
    // @feature LIT-BOOL-TRUE selector=0
    0 -> {
      expect value: Bool = first
      value == True
    }
    // @feature LIT-BOOL-FALSE selector=1
    1 -> {
      expect value: Bool = first
      value == False
    }
    // @feature LIT-INT-DECIMAL selector=2
    2 -> {
      expect value: Int = first
      value == 42
    }
    // @feature LIT-INT-SEPARATOR selector=3
    3 -> {
      expect value: Int = first
      value == 1_000_000
    }
    // @feature LIT-INT-HEX selector=4
    4 -> {
      expect value: Int = first
      value == 0xff
    }
    // @feature LIT-INT-NEGATIVE selector=5
    5 -> {
      expect value: Int = first
      value == -42
    }
    // @feature LIT-BYTEARRAY-LIST-DECIMAL selector=6
    6 -> {
      expect value: ByteArray = first
      value == #[0, 1, 255]
    }
    // @feature LIT-BYTEARRAY-LIST-HEX selector=7
    7 -> {
      expect value: ByteArray = first
      value == #[0x00, 0xaa, 0xff]
    }
    // @feature LIT-BYTEARRAY-UTF8 selector=8
    8 -> {
      expect value: ByteArray = first
      value == "hello"
    }
    // @feature LIT-BYTEARRAY-HEX selector=9
    9 -> {
      expect value: ByteArray = first
      value == #"deadbeef"
    }
    // @feature LIT-BYTEARRAY-ESCAPE selector=10
    10 -> {
      expect value: ByteArray = first
      value == "a\n\t\0\\\""
    }
    // @feature LIT-STRING selector=11
    11 -> {
      expect value: ByteArray = first
      builtin.decode_utf8(value) == @"hello"
    }
    // @feature LIT-STRING-MULTILINE selector=12
    12 -> {
      expect value: ByteArray = first
      builtin.decode_utf8(value) == @"line 1\n      line 2"
    }
    // @feature LIT-STRING-UNICODE selector=13
    13 -> {
      expect value: ByteArray = first
      builtin.decode_utf8(value) == @"★"
    }
    // @feature LIT-STRING-ESCAPE selector=14
    14 -> {
      expect value: ByteArray = first
      builtin.decode_utf8(value) == @"a\n\t\0\\\""
    }
    // @feature LIT-LIST-EMPTY selector=15
    15 -> {
      expect values: List<Int> = first
      values == []
    }
    // @feature LIT-LIST-ELEMENTS selector=16
    16 -> {
      expect values: List<Int> = first
      values == [1, 2, 3]
    }
    // @feature LIT-LIST-SPREAD selector=17
    17 -> {
      expect values: List<Int> = first
      expect [head, ..tail] = values
      [head, ..tail] == values
    }
    // @feature LIT-TUPLE selector=18
    18 -> {
      expect value: (Int, Bool, ByteArray) = first
      value == (1, True, #"00")
    }
    // @feature LIT-PAIR selector=19
    19 -> {
      expect value: Pair<Int, Bool> = first
      value == Pair(1, True)
    }
    // @feature LIT-VOID selector=20
    20 -> {
      expect value: Void = first
      value == Void
    }
    // @feature LIT-CURVE-G1 selector=21
    21 -> {
      expect value: Int = first
      let point = #<Bls12_381, G1>"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
      builtin.bls12_381_g1_equal(point, point) && value == 7
    }
    // @feature LIT-CURVE-G2 selector=22
    22 -> {
      expect value: Int = first
      let point = #<Bls12_381, G2>"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
      builtin.bls12_381_g2_equal(point, point) && value == 7
    }
    // @feature TYPE-DATA selector=23
    23 -> {
      let value: Data = first
      value == first
    }
    // @feature TYPE-INT selector=24
    24 -> {
      expect value: Int = first
      value == 7
    }
    // @feature TYPE-BYTEARRAY selector=25
    25 -> {
      expect value: ByteArray = first
      value == #"07"
    }
    // @feature TYPE-BOOL selector=26
    26 -> {
      expect value: Bool = first
      value == True
    }
    // @feature TYPE-G1 selector=27
    27 -> {
      expect value: Int = first
      let point: G1Element = #<Bls12_381, G1>"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
      builtin.bls12_381_g1_equal(point, point) && value == 7
    }
    // @feature TYPE-G2 selector=28
    28 -> {
      expect value: Int = first
      let point: G2Element = #<Bls12_381, G2>"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
      builtin.bls12_381_g2_equal(point, point) && value == 7
    }
    // @feature TYPE-MILLER selector=29
    29 -> {
      expect value: Int = first
      let result: MillerLoopResult = builtin.bls12_381_miller_loop(
        #<Bls12_381, G1>"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        #<Bls12_381, G2>"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
      )
      builtin.bls12_381_final_verify(result, result) && value == 7
    }
    // @feature TYPE-ORDERING selector=30
    30 -> {
      expect value: Int = first
      let ordering: Ordering = if value < 7 {
        Less
      } else if value == 7 {
        Equal
      } else {
        Greater
      }
      ordering == Equal
    }
    // @feature TYPE-STRING selector=31
    31 -> {
      expect value: ByteArray = first
      let decoded: String = builtin.decode_utf8(value)
      decoded == @"seven"
    }
    // @feature TYPE-VOID selector=32
    32 -> {
      expect value: Void = first
      value == Void
    }
    // @feature TYPE-LIST selector=33
    33 -> {
      expect value: List<Int> = first
      value == [7]
    }
    // @feature TYPE-PAIR selector=34
    34 -> {
      expect value: Pair<Int, Bool> = first
      value == Pair(7, True)
    }
    // @feature TYPE-PAIRS selector=35
    35 -> {
      expect value: Pairs<Int, Bool> = first
      value == [Pair(7, True)]
    }
    // @feature TYPE-OPTION selector=36
    36 -> {
      expect value: Int = first
      let optional: Option<Int> = Some(value)
      optional == Some(7)
    }
    // @feature TYPE-NEVER selector=37
    37 -> {
      expect value: Int = first
      let never: Never = Never
      let encoded: Data = never
      encoded == encoded && value == 7
    }
    // @feature TYPE-SCRIPT-CONTEXT selector=38
    38 -> {
      expect value: Int = first
      let _check: fn(ScriptContext) -> Bool = context_is_present
      value == 7
    }
    // @feature ANN-BINDING selector=39
    39 -> {
      expect decoded: Int = first
      let value: Int = decoded
      value == 7
    }
    // @feature ANN-CONSTANT selector=40
    40 -> {
      expect value: Int = first
      value == annotated_constant
    }
    // @feature TYPE-INFERENCE selector=41
    41 -> {
      expect value: Int = first
      let inferred = value + 1
      inferred == 8
    }
    // @feature TYPE-GENERIC-FUNCTION selector=42
    42 -> {
      expect value: Int = first
      generic_identity(value) == 7
    }
    // @feature DATA-UPCAST-IMPLICIT selector=43
    43 -> {
      expect value: Int = first
      let encoded: Data = value
      encoded == first
    }
    // @feature DATA-UPCAST-AS-DATA selector=44
    44 -> {
      expect value: Int = first
      as_data(value) == first
    }
    // @feature DATA-DOWNCAST-EXPECT selector=45
    45 -> {
      expect value: Int = first
      value == 7
    }
    // @feature DATA-DOWNCAST-IF-IS selector=46
    46 ->
      if first is value: Int {
        value == 7
      } else {
        False
      }
    // @feature REGRESSION-EXPECT-UNUSED selector=47
    47 -> {
      expect _: Int = first
      first == first
    }
    // @feature REGRESSION-DECODER-IDENTITY selector=48
    48 -> {
      expect value: Int = first
      let encoded: Data = value
      expect decoded: Int = encoded
      decoded == value
    }
    // @feature OP-AND selector=49
    49 -> {
      expect left: Bool = first
      expect right: Bool = second
      left && right
    }
    // @feature OP-OR selector=50
    50 -> {
      expect left: Bool = first
      expect right: Bool = second
      left || right
    }
    // @feature OP-EQ selector=51
    51 -> {
      expect left: Int = first
      expect right: Int = second
      left == right
    }
    // @feature OP-NEQ selector=52
    52 -> {
      expect left: Int = first
      expect right: Int = second
      left != right
    }
    // @feature OP-LT selector=53
    53 -> {
      expect left: Int = first
      expect right: Int = second
      left < right
    }
    // @feature OP-LTE selector=54
    54 -> {
      expect left: Int = first
      expect right: Int = second
      left <= right
    }
    // @feature OP-GTE selector=55
    55 -> {
      expect left: Int = first
      expect right: Int = second
      left >= right
    }
    // @feature OP-GT selector=56
    56 -> {
      expect left: Int = first
      expect right: Int = second
      left > right
    }
    // @feature OP-ADD selector=57
    57 -> {
      expect left: Int = first
      expect right: Int = second
      left + right == 15
    }
    // @feature OP-SUB selector=58
    58 -> {
      expect left: Int = first
      expect right: Int = second
      left - right == 1
    }
    // @feature OP-MUL selector=59
    59 -> {
      expect left: Int = first
      expect right: Int = second
      left * right == 56
    }
    // @feature OP-DIV selector=60
    60 -> {
      expect left: Int = first
      expect right: Int = second
      left / right == 7
    }
    // @feature OP-MOD selector=61
    61 -> {
      expect left: Int = first
      expect right: Int = second
      left % right == 1
    }
    // @feature OP-NOT selector=62
    62 -> {
      expect value: Bool = first
      !value
    }
    // @feature OP-NEGATE selector=63
    63 -> {
      expect value: Int = first
      -value == 7
    }
    // @feature OP-EQ-SERIALIZABLE selector=64
    64 -> {
      expect value: Int = first
      let left = Comparable { value }
      let right = Comparable { value }
      left == right
    }
    // @feature OP-NEQ-SERIALIZABLE selector=65
    65 -> {
      expect value: Int = first
      Comparable { value } != Comparable { value: value + 1 }
    }
    _ -> False
  }
}

validator literals_operators_prelude {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_literals_operators_prelude(redeemer)
  }

  else(_) {
    fail
  }
}
