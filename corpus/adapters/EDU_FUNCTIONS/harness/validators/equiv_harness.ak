use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use modules/functions

validator functions_equiv_harness {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    expect value: Int = redeemer
    functions.add(value, 1) == value + 1
  }

  else(_) {
    fail
  }
}
