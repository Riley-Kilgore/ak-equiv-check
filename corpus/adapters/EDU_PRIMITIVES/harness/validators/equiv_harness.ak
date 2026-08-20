use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use modules/primitives

validator primitives_equiv_harness {
  mint(_redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    primitives.integer()
  }

  else(_) {
    fail
  }
}
