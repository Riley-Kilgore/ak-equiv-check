use aiken/builtin
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use sentinel/redeemer.{BuiltinArgs, BuiltinRedeemer}

pub fn evaluate_integer(raw_redeemer: Data) -> Bool {
  expect BuiltinRedeemer { selector, args } = raw_redeemer
  expect BuiltinArgs { first, second, third: _third } = args

  when selector is {
    // @builtin BUILTIN-00 selector=0
    0 -> {
      expect left: Int = first
      expect right: Int = second
      builtin.add_integer(left, right) == 10
    }
    // @builtin BUILTIN-01 selector=1
    1 -> {
      expect left: Int = first
      expect right: Int = second
      builtin.subtract_integer(left, right) == 4
    }
    // @builtin BUILTIN-02 selector=2
    2 -> {
      expect left: Int = first
      expect right: Int = second
      builtin.multiply_integer(left, right) == 21
    }
    // @builtin BUILTIN-03 selector=3
    3 -> {
      expect left: Int = first
      expect right: Int = second
      builtin.divide_integer(left, right) == 2
    }
    // @builtin BUILTIN-04 selector=4
    4 -> {
      expect left: Int = first
      expect right: Int = second
      builtin.quotient_integer(left, right) == 2
    }
    // @builtin BUILTIN-05 selector=5
    5 -> {
      expect left: Int = first
      expect right: Int = second
      builtin.remainder_integer(left, right) == 1
    }
    // @builtin BUILTIN-06 selector=6
    6 -> {
      expect left: Int = first
      expect right: Int = second
      builtin.mod_integer(left, right) == 1
    }
    // @builtin BUILTIN-07 selector=7
    7 -> {
      expect left: Int = first
      expect right: Int = second
      builtin.equals_integer(left, right)
    }
    // @builtin BUILTIN-08 selector=8
    8 -> {
      expect left: Int = first
      expect right: Int = second
      builtin.less_than_integer(left, right)
    }
    // @builtin BUILTIN-09 selector=9
    9 -> {
      expect left: Int = first
      expect right: Int = second
      builtin.less_than_equals_integer(left, right)
    }
    _ -> False
  }
}

validator integer {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_integer(redeemer)
  }

  else(_) {
    fail
  }
}
