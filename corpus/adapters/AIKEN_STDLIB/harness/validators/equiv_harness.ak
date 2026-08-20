use aiken/collection/list
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}

validator stdlib_equiv_harness {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    list.length([redeemer]) == 1
  }

  else(_) {
    fail
  }
}
