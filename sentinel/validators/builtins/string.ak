use aiken/builtin
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use sentinel/redeemer.{BuiltinArgs, BuiltinRedeemer}

pub fn evaluate_string(raw_redeemer: Data) -> Bool {
  expect BuiltinRedeemer { selector, args } = raw_redeemer
  expect BuiltinArgs { first, second, third } = args

  when selector is {
    // @builtin BUILTIN-22 selector=0
    0 -> {
      expect left_bytes: ByteArray = first
      expect right_bytes: ByteArray = second
      expect expected: ByteArray = third
      let left = builtin.decode_utf8(left_bytes)
      let right = builtin.decode_utf8(right_bytes)
      builtin.encode_utf8(builtin.append_string(left, right)) == expected
    }
    // @builtin BUILTIN-23 selector=1
    1 -> {
      expect left_bytes: ByteArray = first
      expect right_bytes: ByteArray = second
      let left = builtin.decode_utf8(left_bytes)
      let right = builtin.decode_utf8(right_bytes)
      builtin.equals_string(left, right)
    }
    // @builtin BUILTIN-24 selector=2
    2 -> {
      expect value: ByteArray = first
      let decoded = builtin.decode_utf8(value)
      builtin.encode_utf8(decoded) == value
    }
    // @builtin BUILTIN-25 selector=3
    3 -> {
      expect value: ByteArray = first
      builtin.encode_utf8(builtin.decode_utf8(value)) == value
    }
    _ -> False
  }
}

validator string {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_string(redeemer)
  }

  else(_) {
    fail
  }
}
