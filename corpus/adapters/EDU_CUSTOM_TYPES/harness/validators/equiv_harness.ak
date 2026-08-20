use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use custom_types.{Single}

validator custom_types_equiv_harness {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    expect value: Int = redeemer
    let transparent = Single("SINGLE", value)
    transparent == Single("SINGLE", value)
  }

  else(_) {
    fail
  }
}
