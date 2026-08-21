use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}

type Small {
  Small(Int)
}

validator typed_expect(raw: Data) {
  mint(_redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    expect decoded: List<Small> = raw
    True
  }

  else(_) {
    fail
  }
}
