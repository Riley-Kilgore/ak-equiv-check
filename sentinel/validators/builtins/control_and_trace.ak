use aiken/builtin
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use sentinel/redeemer.{BuiltinArgs, BuiltinRedeemer}

pub fn evaluate_control_and_trace(raw_redeemer: Data) -> Bool {
  expect BuiltinRedeemer { selector, args } = raw_redeemer
  expect BuiltinArgs { first, second, third } = args

  when selector is {
    // @builtin BUILTIN-26 selector=0
    0 -> {
      expect condition: Bool = first
      expect when_true: Bool = second
      expect when_false: Bool = third
      builtin.if_then_else(condition, when_true, when_false)
    }
    // @builtin BUILTIN-27 selector=1
    1 -> {
      expect unit: Void = first
      expect value: Bool = second
      let choose = builtin.choose_void
      choose(unit, value)
    }
    // @builtin BUILTIN-28 selector=2
    2 -> {
      expect value: Bool = first
      builtin.debug(@"sentinel", value)
    }
    -1 -> True
    _ -> False
  }
}

validator control_and_trace {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_control_and_trace(redeemer)
  }

  else(_) {
    fail
  }
}
