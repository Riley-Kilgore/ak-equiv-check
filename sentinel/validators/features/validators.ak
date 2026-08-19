use cardano/address.{Credential}
use cardano/assets.{PolicyId}
use cardano/certificate.{Certificate}
use cardano/governance.{ProposalProcedure, Voter}
use cardano/script_context.{ScriptContext}
use cardano/transaction.{OutputReference, Transaction}
use sentinel/redeemer.{FeatureArgs, FeatureRedeemer}

pub fn evaluate_validators(raw_redeemer: Data) -> Bool {
  expect FeatureRedeemer { selector, args } = raw_redeemer
  expect FeatureArgs { first, second: _, third: _ } = args

  when selector is {
    // branch VAL-SPEND selector=0
    0 -> {
      expect value: Int = first
      value == 7
    }
    // branch VAL-MINT selector=1
    1 -> {
      expect value: Int = first
      value == 7
    }
    // branch VAL-WITHDRAW selector=2
    2 -> {
      expect value: Int = first
      value == 7
    }
    // branch VAL-PUBLISH selector=3
    3 -> {
      expect value: Int = first
      value == 7
    }
    // branch VAL-PROPOSE selector=4
    4 -> {
      expect value: Int = first
      value == 7
    }
    // branch VAL-VOTE selector=5
    5 -> {
      expect value: Int = first
      value == 7
    }
    // branch VAL-ELSE selector=6
    6 -> {
      expect value: Int = first
      value == 7
    }
    // branch VAL-PARAMETERIZED selector=7
    7 -> {
      expect value: Int = first
      value == 7
    }
    // branch VAL-MULTI-HANDLER selector=8
    8 -> {
      expect value: Int = first
      value == 7
    }
    // branch VAL-MULTIPLE-DEFS selector=9
    9 -> {
      expect value: Int = first
      value == 7
    }
    // branch VAL-SPEND-ARITY selector=10
    10 -> {
      expect value: Int = first
      value == 7
    }
    // branch VAL-OTHER-ARITY selector=11
    11 -> {
      expect value: Int = first
      value == 7
    }
    // branch VAL-DEFAULT-FALLBACK selector=12
    12 -> {
      expect value: Int = first
      value == 7
    }
    // branch VAL-DATUM-OPTION selector=13
    13 -> {
      expect value: Int = first
      value == 7
    }
    // branch VAL-SCRIPT-CONTEXT selector=14
    14 -> {
      expect value: Int = first
      value == 7
    }
    // branch VAL-EMPTY-HANDLER-TODO selector=15
    15 -> {
      expect value: Int = first
      value == 7
    }
    _ -> False
  }
}

// @feature VAL-SPEND
validator val_spend {
  spend(
    _datum: Option<Data>,
    redeemer: Data,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    evaluate_validators(redeemer)
  }

  else(_) {
    fail
  }
}

// @feature VAL-MINT
validator val_mint {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_validators(redeemer)
  }

  else(_) {
    fail
  }
}

// @feature VAL-WITHDRAW
validator val_withdraw {
  withdraw(redeemer: Data, _account: Credential, _self: Transaction) {
    evaluate_validators(redeemer)
  }

  else(_) {
    fail
  }
}

// @feature VAL-PUBLISH
validator val_publish {
  publish(redeemer: Data, _certificate: Certificate, _self: Transaction) {
    evaluate_validators(redeemer)
  }

  else(_) {
    fail
  }
}

// @feature VAL-PROPOSE
validator val_propose {
  propose(redeemer: Data, _proposal: ProposalProcedure, _self: Transaction) {
    evaluate_validators(redeemer)
  }

  else(_) {
    fail
  }
}

// @feature VAL-VOTE
validator val_vote {
  vote(redeemer: Data, _voter: Voter, _self: Transaction) {
    evaluate_validators(redeemer)
  }

  else(_) {
    fail
  }
}

// @feature VAL-ELSE
validator val_else {
  else(_ctx: ScriptContext) {
    True
  }
}

// @feature VAL-PARAMETERIZED
validator val_parameterized(parameter: Int) {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    parameter == parameter && evaluate_validators(redeemer)
  }

  else(_) {
    fail
  }
}

// @feature VAL-MULTI-HANDLER
validator val_multi_handler {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_validators(redeemer)
  }

  spend(
    _datum: Option<Data>,
    redeemer: Data,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    evaluate_validators(redeemer)
  }

  else(_ctx: ScriptContext) {
    False
  }
}

// @feature VAL-MULTIPLE-DEFS
validator val_multiple_defs {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_validators(redeemer)
  }

  else(_) {
    fail
  }
}

// @feature VAL-SPEND-ARITY
validator val_spend_arity {
  spend(
    _datum: Option<Data>,
    redeemer: Data,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    evaluate_validators(redeemer)
  }

  else(_) {
    fail
  }
}

// @feature VAL-OTHER-ARITY
validator val_other_arity {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_validators(redeemer)
  }

  else(_) {
    fail
  }
}

validator val_default_fallback {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_validators(redeemer)
  }

  // @feature VAL-DEFAULT-FALLBACK
  else(_ctx: ScriptContext) {
    True
  }
}

validator val_datum_option {
  // @feature VAL-DATUM-OPTION
  spend(
    _datum: Option<Data>,
    redeemer: Data,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    evaluate_validators(redeemer)
  }

  else(_) {
    fail
  }
}

validator val_script_context {
  // @feature VAL-SCRIPT-CONTEXT
  else(_ctx: ScriptContext) {
    True
  }
}

validator val_empty_handler {
  // @feature VAL-EMPTY-HANDLER-TODO
  mint(_redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    todo
  }

  else(_) {
    fail
  }
}
