use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use advanced

validator control_equiv_harness {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    advanced.is_valid_(redeemer)
  }

  else(_) {
    fail
  }
}
