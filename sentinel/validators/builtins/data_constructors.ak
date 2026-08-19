use aiken/builtin
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use sentinel/redeemer.{BuiltinArgs, BuiltinRedeemer}

pub fn evaluate_data_constructors(raw_redeemer: Data) -> Bool {
  expect BuiltinRedeemer { selector, args } = raw_redeemer
  expect BuiltinArgs { first, second, third: _third } = args

  when selector is {
    // @builtin BUILTIN-48 selector=0
    0 ->
      builtin.equals_data(
        builtin.fst_pair(builtin.new_pair(first, second)),
        first,
      )
    // @builtin BUILTIN-49 selector=1
    1 -> {
      expect guard: Bool = first
      guard && builtin.null_list(builtin.new_list())
    }
    // @builtin BUILTIN-50 selector=2
    2 -> {
      expect guard: Bool = first
      guard && builtin.null_list(builtin.new_pairs())
    }
    _ -> False
  }
}

validator data_constructors {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_data_constructors(redeemer)
  }

  else(_) {
    fail
  }
}
