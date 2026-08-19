use aiken/builtin
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use sentinel/redeemer.{BuiltinArgs, BuiltinRedeemer}

pub fn evaluate_bytearray(raw_redeemer: Data) -> Bool {
  expect BuiltinRedeemer { selector, args } = raw_redeemer
  expect BuiltinArgs { first, second, third } = args

  when selector is {
    // @builtin BUILTIN-10 selector=0
    0 -> {
      expect left: ByteArray = first
      expect right: ByteArray = second
      expect expected: ByteArray = third
      builtin.append_bytearray(left, right) == expected
    }
    // @builtin BUILTIN-11 selector=1
    1 -> {
      expect byte: Int = first
      expect tail: ByteArray = second
      expect expected: ByteArray = third
      builtin.cons_bytearray(byte, tail) == expected
    }
    // @builtin BUILTIN-12 selector=2
    2 -> {
      expect value: ByteArray = first
      expect start: Int = second
      expect length: Int = third
      builtin.length_of_bytearray(builtin.slice_bytearray(start, length, value)) == length
    }
    // @builtin BUILTIN-13 selector=3
    3 -> {
      expect value: ByteArray = first
      builtin.length_of_bytearray(value) == 2
    }
    // @builtin BUILTIN-14 selector=4
    4 -> {
      expect value: ByteArray = first
      expect index: Int = second
      builtin.index_bytearray(value, index) == 1
    }
    // @builtin BUILTIN-15 selector=5
    5 -> {
      expect left: ByteArray = first
      expect right: ByteArray = second
      builtin.equals_bytearray(left, right)
    }
    // @builtin BUILTIN-16 selector=6
    6 -> {
      expect left: ByteArray = first
      expect right: ByteArray = second
      builtin.less_than_bytearray(left, right)
    }
    // @builtin BUILTIN-17 selector=7
    7 -> {
      expect left: ByteArray = first
      expect right: ByteArray = second
      builtin.less_than_equals_bytearray(left, right)
    }
    _ -> False
  }
}

validator bytearray {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_bytearray(redeemer)
  }

  else(_) {
    fail
  }
}
