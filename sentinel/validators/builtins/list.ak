use aiken/builtin
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use sentinel/redeemer.{BuiltinArgs, BuiltinRedeemer}

pub fn evaluate_list(raw_redeemer: Data) -> Bool {
  expect BuiltinRedeemer { selector, args } = raw_redeemer
  expect BuiltinArgs { first, second, third: _third } = args

  when selector is {
    // @builtin BUILTIN-31 selector=0
    0 -> {
      expect values: List<Int> = first
      builtin.choose_list(values, False, True)
    }
    // @builtin BUILTIN-32 selector=1
    1 -> {
      expect value: Int = first
      expect values: List<Int> = second
      builtin.head_list(builtin.cons_list(value, values)) == value
    }
    // @builtin BUILTIN-33 selector=2
    2 -> {
      expect values: List<Int> = first
      builtin.head_list(values) == 1
    }
    // @builtin BUILTIN-34 selector=3
    3 -> {
      expect values: List<Int> = first
      builtin.null_list(builtin.tail_list(values))
    }
    // @builtin BUILTIN-35 selector=4
    4 -> {
      expect values: List<Int> = first
      builtin.null_list(values)
    }
    _ -> False
  }
}

validator list {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_list(redeemer)
  }

  else(_) {
    fail
  }
}
