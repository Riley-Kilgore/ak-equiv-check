use aiken/builtin
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use sentinel/redeemer.{BuiltinArgs, BuiltinRedeemer}

pub fn evaluate_bytearray_bitwise(raw_redeemer: Data) -> Bool {
  expect BuiltinRedeemer { selector, args } = raw_redeemer
  expect BuiltinArgs { first, second, third } = args

  when selector is {
    // @builtin BUILTIN-75 selector=0
    0 -> {
      expect left: ByteArray = first
      expect right: ByteArray = second
      expect expected: ByteArray = third
      builtin.and_bytearray(False, left, right) == expected
    }
    // @builtin BUILTIN-76 selector=1
    1 -> {
      expect left: ByteArray = first
      expect right: ByteArray = second
      expect expected: ByteArray = third
      builtin.or_bytearray(False, left, right) == expected
    }
    // @builtin BUILTIN-77 selector=2
    2 -> {
      expect left: ByteArray = first
      expect right: ByteArray = second
      expect expected: ByteArray = third
      builtin.xor_bytearray(False, left, right) == expected
    }
    // @builtin BUILTIN-78 selector=3
    3 -> {
      expect value: ByteArray = first
      builtin.complement_bytearray(value) == #"f0"
    }
    // @builtin BUILTIN-79 selector=4
    4 -> {
      expect value: ByteArray = first
      expect index: Int = second
      builtin.read_bit(value, index)
    }
    // @builtin BUILTIN-80 selector=5
    5 -> {
      expect value: ByteArray = first
      expect indexes: List<Int> = second
      builtin.write_bits(value, indexes, True) == #"80"
    }
    // @builtin BUILTIN-81 selector=6
    6 -> {
      expect count: Int = first
      expect byte: Int = second
      builtin.replicate_byte(count, byte) == #"ffff"
    }
    // @builtin BUILTIN-82 selector=7
    7 -> {
      expect value: ByteArray = first
      expect amount: Int = second
      builtin.shift_bytearray(value, amount) == #"02"
    }
    // @builtin BUILTIN-83 selector=8
    8 -> {
      expect value: ByteArray = first
      expect amount: Int = second
      builtin.rotate_bytearray(value, amount) == #"02"
    }
    // @builtin BUILTIN-84 selector=9
    9 -> {
      expect value: ByteArray = first
      builtin.count_set_bits(value) == 4
    }
    // @builtin BUILTIN-85 selector=10
    10 -> {
      expect value: ByteArray = first
      builtin.find_first_set_bit(value) >= 0
    }
    _ -> False
  }
}

validator bytearray_bitwise {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_bytearray_bitwise(redeemer)
  }

  else(_) {
    fail
  }
}
