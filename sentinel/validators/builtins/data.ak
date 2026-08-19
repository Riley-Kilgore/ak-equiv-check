use aiken/builtin
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use sentinel/redeemer.{BuiltinArgs, BuiltinRedeemer}

pub fn evaluate_data(raw_redeemer: Data) -> Bool {
  expect BuiltinRedeemer { selector, args } = raw_redeemer
  expect BuiltinArgs { first, second, third } = args

  when selector is {
    // @builtin BUILTIN-36 selector=0
    0 -> builtin.choose_data(first, True, False, False, False, False)
    // @builtin BUILTIN-37 selector=1
    1 -> {
      expect tag: Int = first
      expect fields: List<Data> = second
      builtin.equals_data(builtin.constr_data(tag, fields), third)
    }
    // @builtin BUILTIN-38 selector=2
    2 -> {
      expect entries: Pairs<Data, Data> = first
      builtin.equals_data(builtin.map_data(entries), second)
    }
    // @builtin BUILTIN-39 selector=3
    3 -> {
      expect items: List<Data> = first
      builtin.equals_data(builtin.list_data(items), second)
    }
    // @builtin BUILTIN-40 selector=4
    4 -> {
      expect value: Int = first
      builtin.equals_data(builtin.i_data(value), second)
    }
    // @builtin BUILTIN-41 selector=5
    5 -> {
      expect value: ByteArray = first
      let encode = builtin.b_data
      let changed = builtin.append_bytearray(value, #"00")
      builtin.equals_data(encode(changed), second)
    }
    // @builtin BUILTIN-42 selector=6
    6 -> {
      let pair = builtin.un_constr_data(first)
      builtin.fst_pair(pair) == 0
    }
    // @builtin BUILTIN-43 selector=7
    7 -> builtin.null_list(builtin.un_map_data(first))
    // @builtin BUILTIN-44 selector=8
    8 -> builtin.null_list(builtin.un_list_data(first))
    // @builtin BUILTIN-45 selector=9
    9 -> builtin.un_i_data(first) == 1
    // @builtin BUILTIN-46 selector=10
    10 -> builtin.un_b_data(first) == #"01"
    // @builtin BUILTIN-47 selector=11
    11 -> builtin.equals_data(first, second)
    // @builtin BUILTIN-51 selector=12
    12 -> builtin.length_of_bytearray(builtin.serialise_data(first)) > 0
    _ -> False
  }
}

validator data {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_data(redeemer)
  }

  else(_) {
    fail
  }
}
