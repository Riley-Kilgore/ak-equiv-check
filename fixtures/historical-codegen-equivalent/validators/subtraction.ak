use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}

validator subtraction(input: Int) {
  mint(_redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    input - 7 == 11
  }

  else(_) {
    fail
  }
}
