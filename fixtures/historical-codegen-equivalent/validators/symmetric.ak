use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}

validator symmetric(input: Int) {
  mint(_redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    7 * input == 49
  }

  else(_) {
    fail
  }
}
