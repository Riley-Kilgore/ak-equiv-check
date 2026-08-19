use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use project_features

validator project_and_targets {
  mint(raw_redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    project_features.evaluate_project(raw_redeemer)
  }

  else(_) {
    fail
  }
}
