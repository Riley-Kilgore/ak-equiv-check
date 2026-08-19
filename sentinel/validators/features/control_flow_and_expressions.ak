use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use sentinel/redeemer.{FeatureArgs, FeatureRedeemer}

pub type ControlRecord {
  ControlRecord { field: Int, other: Int }
}

pub type PositionalRecord {
  PositionalRecord(Int, Bool)
}

pub fn evaluate_control(raw_redeemer: Data) -> Bool {
  expect FeatureRedeemer { selector, args } = raw_redeemer
  expect FeatureArgs { first, second, third: _ } = args

  when selector is {
    // @feature BOOL-AND-BLOCK selector=0
    0 -> {
      expect a: Bool = first
      expect b: Bool = second
      and {
        a,
        b,
        a == b,
      }
    }
    // @feature BOOL-OR-BLOCK selector=1
    1 -> {
      expect a: Bool = first
      expect b: Bool = second
      or {
        a,
        b,
        a == b,
      }
    }
    // @feature IF-ELSE selector=2
    2 -> {
      expect condition: Bool = first
      if condition {
        True
      } else {
        False
      }
    }
    // @feature IF-ELSE-IF selector=3
    3 -> {
      expect value: Int = first
      if value < 0 {
        False
      } else if value == 7 {
        True
      } else {
        False
      }
    }
    // @feature WHEN selector=4
    4 -> {
      expect value: Int = first
      when value is {
        7 -> True
        _ -> False
      }
    }
    // @feature IF-IS-PATTERN-TYPE selector=5
    5 ->
      if first is value: Int {
        value == 7
      } else {
        False
      }
    // @feature IF-IS-TYPE selector=6
    6 ->
      if first is Int {
        first == 7
      } else {
        False
      }
    // @feature EXPR-GROUPING selector=7
    7 -> {
      expect value: Int = first
      ( value + 1 ) * 2 == 16
    }
    // @feature TRACE-BASIC selector=8
    8 -> {
      expect value: Int = first
      trace @"control"
      value == 7
    }
    // @feature TRACE-LABEL-STRING selector=9
    9 -> {
      expect value: Int = first
      trace @"string label"
      value == 7
    }
    // @feature TRACE-LABEL-BYTEARRAY selector=10
    10 -> {
      expect value: Int = first
      trace @"bytearray label"
      value == 7
    }
    // @feature TRACE-LABEL-EXPRESSION selector=11
    11 -> {
      expect value: Int = first
      trace if value == 7 {
        @"seven"
      } else {
        @"other"
      }
      value == 7
    }
    // @feature TRACE-ARGS selector=12
    12 -> {
      expect value: Int = first
      trace @"value": value
      value == 7
    }
    // @feature TRACE-DEFAULT-CONT selector=13
    13 -> {
      expect value: Int = first
      let traced = fn() {
        trace @"default continuation"
        Void
      }
      traced() == Void && value == 7
    }
    // @feature TRACE-QUESTION selector=14
    14 -> {
      expect value: Bool = first
      value?
    }
    // @feature FAIL-BARE selector=15
    15 -> {
      expect value: Int = first
      if value == 7 {
        fail
      } else {
        False
      }
    }
    // @feature FAIL-REASON selector=16
    16 -> {
      expect value: Int = first
      if value == 7 {
        fail @"sentinel failure"
      } else {
        False
      }
    }
    // @feature TODO-BARE selector=17
    17 -> {
      expect value: Int = first
      if value == 7 {
        todo
      } else {
        False
      }
    }
    // @feature TODO-REASON selector=18
    18 -> {
      expect value: Int = first
      if value == 7 {
        todo @"sentinel todo"
      } else {
        False
      }
    }
    // @feature ERROR-ALIAS selector=19
    19 -> {
      expect value: Int = first
      if value == 7 {
        fail @"sentinel error"
      } else {
        False
      }
    }
    // @feature ACCESS-RECORD selector=20
    20 -> {
      expect value: Int = first
      let record = ControlRecord { field: value, other: 1 }
      record.field == value
    }
    // @feature ACCESS-TUPLE selector=21
    21 -> {
      expect value: Int = first
      let tuple = (value, True)
      tuple.1st == value
    }
    // @feature ACCESS-PAIR selector=22
    22 -> {
      expect value: Int = first
      let pair = Pair(value, True)
      pair.1st == value
    }
    // @feature RECORD-CONSTRUCT-NAMED selector=23
    23 -> {
      expect value: Int = first
      ControlRecord { field: value, other: 1 }.field == value
    }
    // @feature RECORD-CONSTRUCT-POSITIONAL selector=24
    24 -> {
      expect value: Int = first
      let record = PositionalRecord(value, True)
      when record is {
        PositionalRecord(inner, _) -> inner == value
      }
    }
    // @feature RECORD-FIELD-ORDER selector=25
    25 -> {
      expect value: Int = first
      let record = ControlRecord { other: 1, field: value }
      record.field == value
    }
    // @feature RECORD-PUNNING selector=26
    26 -> {
      expect field: Int = first
      let record = ControlRecord { field, other: 1 }
      record.field == field
    }
    // @feature RECORD-UPDATE selector=27
    27 -> {
      expect value: Int = first
      let base = ControlRecord { field: 0, other: 1 }
      let updated = ControlRecord { ..base, field: value }
      updated.field == value
    }
    -1 -> True
    _ -> False
  }
}

validator control_flow_and_expressions {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_control(redeemer)
  }

  else(_) {
    fail
  }
}
