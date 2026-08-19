use aiken/builtin
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use sentinel/redeemer.{BuiltinArgs, BuiltinRedeemer}

pub fn evaluate_conversion(raw_redeemer: Data) -> Bool {
  expect BuiltinRedeemer { selector, args } = raw_redeemer
  expect BuiltinArgs { first, second: _second, third: _third } = args

  when selector is {
    // @builtin BUILTIN-73 selector=0
    0 -> {
      expect value: Int = first
      let encoded = builtin.integer_to_bytearray(True, 2, value)
      builtin.length_of_bytearray(encoded) == 2
    }
    // @builtin BUILTIN-74 selector=1
    1 -> {
      expect value: ByteArray = first
      builtin.bytearray_to_integer(True, value) == 258
    }
    _ -> False
  }
}

validator conversion {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_conversion(redeemer)
  }

  else(_) {
    fail
  }
}
