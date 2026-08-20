use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}

validator parameterized(parameter: Int) {
  mint(_redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    parameter == parameter
  }

  else(_) {
    fail
  }
}
