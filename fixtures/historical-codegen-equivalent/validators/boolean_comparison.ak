use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}

validator boolean_comparison(input: Int) {
  mint(_redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    (input > 7) == True
  }

  else(_) {
    fail
  }
}
