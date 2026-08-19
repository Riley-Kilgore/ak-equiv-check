use aiken/builtin
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use sentinel/redeemer.{BuiltinArgs, BuiltinRedeemer}

pub fn evaluate_pair(raw_redeemer: Data) -> Bool {
  expect BuiltinRedeemer { selector, args } = raw_redeemer
  expect BuiltinArgs { first, second: _second, third: _third } = args

  when selector is {
    // @builtin BUILTIN-29 selector=0
    0 -> {
      expect value: Pair<Int, Int> = first
      builtin.fst_pair(value) == 1
    }
    // @builtin BUILTIN-30 selector=1
    1 -> {
      expect value: Pair<Int, Int> = first
      builtin.snd_pair(value) == 2
    }
    _ -> False
  }
}

validator pair {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_pair(redeemer)
  }

  else(_) {
    fail
  }
}
