use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use sentinel/pattern_support
use sentinel/redeemer.{FeatureArgs, FeatureRedeemer}

pub type PatternRecord {
  PatternRecord { field: Int, other: Int }
}

pub type PatternTriple {
  PatternTriple(Int, Int, Int)
}

pub type PatternChoice {
  PatternA(Int)
  PatternB(Int)
}

fn sum_pattern_pair((left, right): (Int, Int)) -> Int {
  left + right
}

pub fn evaluate_patterns(raw_redeemer: Data) -> Bool {
  expect FeatureRedeemer { selector, args } = raw_redeemer
  expect FeatureArgs { first, second, third: _ } = args

  when selector is {
    // @feature PAT-INT-DECIMAL selector=0
    0 -> {
      expect value: Int = first
      when value is {
        42 -> True
        _ -> False
      }
    }
    // @feature PAT-INT-SEPARATOR selector=1
    1 -> {
      expect value: Int = first
      when value is {
        1_000 -> True
        _ -> False
      }
    }
    // @feature PAT-INT-HEX selector=2
    2 -> {
      expect value: Int = first
      when value is {
        0xff -> True
        _ -> False
      }
    }
    // @feature PAT-INT-NEGATIVE selector=3
    3 -> {
      expect value: Int = first
      when value is {
        -42 -> True
        _ -> False
      }
    }
    // @feature PAT-BYTEARRAY-LIST-DECIMAL selector=4
    4 -> {
      expect value: ByteArray = first
      when value is {
        #[1, 2] -> True
        _ -> False
      }
    }
    // @feature PAT-BYTEARRAY-LIST-HEX selector=5
    5 -> {
      expect value: ByteArray = first
      when value is {
        #[0x01, 0xff] -> True
        _ -> False
      }
    }
    // @feature PAT-BYTEARRAY-UTF8 selector=6
    6 -> {
      expect value: ByteArray = first
      when value is {
        "ok" -> True
        _ -> False
      }
    }
    // @feature PAT-BYTEARRAY-HEX selector=7
    7 -> {
      expect value: ByteArray = first
      when value is {
        #"00ff" -> True
        _ -> False
      }
    }
    // @feature PAT-BOOL selector=8
    8 -> {
      expect value: Bool = first
      when value is {
        True -> True
        False -> False
      }
    }
    // @feature PAT-VARIABLE selector=9
    9 ->
      when first is {
        value -> value == first
      }
    // @feature PAT-DISCARD selector=10
    10 ->
      when first is {
        _ -> True
      }
    // @feature PAT-NAMED-DISCARD selector=11
    11 ->
      when first is {
        _unused -> True
      }
    // @feature PAT-AS selector=12
    12 -> {
      expect value: Int = first
      let subject = Some(value)
      when subject is {
        Some(inner) as whole -> inner == value && whole == subject
        None -> False
      }
    }
    // @feature PAT-LIST-EXACT selector=13
    13 -> {
      expect values: List<Int> = first
      when values is {
        [a, b] -> a + b == 3
        _ -> False
      }
    }
    // @feature PAT-LIST-TAIL selector=14
    14 -> {
      expect values: List<Int> = first
      when values is {
        [head, ..] -> head == 1
        _ -> False
      }
    }
    // @feature PAT-LIST-NAMED-TAIL selector=15
    15 -> {
      expect values: List<Int> = first
      when values is {
        [head, ..tail] -> head == 1 && tail == [2]
        _ -> False
      }
    }
    // @feature PAT-PAIR selector=16
    16 -> {
      expect pair: Pair<Int, Int> = first
      when pair is {
        Pair(a, b) -> a + b == 3
      }
    }
    // @feature PAT-TUPLE selector=17
    17 -> {
      expect tuple: (Int, Int) = first
      when tuple is {
        (a, b) -> a + b == 3
      }
    }
    // @feature PAT-CONSTRUCTOR-POSITIONAL selector=18
    18 -> {
      expect value: Int = first
      when Some(value) is {
        Some(inner) -> inner == value
        None -> False
      }
    }
    // @feature PAT-CONSTRUCTOR-RECORD selector=19
    19 -> {
      expect value: Int = first
      let subject = PatternRecord { field: value, other: 1 }
      when subject is {
        PatternRecord { field, other: _ } -> field == value
      }
    }
    // @feature PAT-CONSTRUCTOR-POSITIONAL-SPREAD selector=20
    20 -> {
      expect value: Int = first
      let subject = PatternTriple(value, 2, 3)
      when subject is {
        PatternTriple(first_value, ..) -> first_value == value
      }
    }
    // @feature PAT-RECORD-SPREAD selector=21
    21 -> {
      expect value: Int = first
      let subject = PatternRecord { field: value, other: 1 }
      when subject is {
        PatternRecord { field, .. } -> field == value
      }
    }
    // @feature PAT-MODULE-QUALIFIED selector=22
    22 -> {
      expect value: Int = first
      let subject = pattern_support.Support(value)
      when subject is {
        pattern_support.Support(inner) -> inner == value
      }
    }
    // @feature PAT-TYPE-QUALIFIED selector=23
    23 -> {
      expect value: Int = first
      let subject = PatternA(value)
      when subject is {
        PatternA(inner) -> inner == value
        PatternB(_) -> False
      }
    }
    // @feature PAT-NESTED selector=24
    24 -> {
      expect values: List<Int> = first
      let subject = Some(values)
      when subject is {
        Some([head, ..tail]) -> head == 1 && tail == [2]
        _ -> False
      }
    }
    // @feature PAT-ALTERNATIVE selector=25
    25 -> {
      expect value: Int = first
      expect pick_a: Bool = second
      let subject = if pick_a {
        PatternA(value)
      } else {
        PatternB(value)
      }
      when subject is {
        PatternA(inner) | PatternB(inner) -> inner == value
      }
    }
    // @feature PAT-FIELD-PUNNING selector=26
    26 -> {
      expect value: Int = first
      let subject = PatternRecord { field: value, other: 1 }
      when subject is {
        PatternRecord { field, .. } -> field == value
      }
    }
    // @feature PAT-FIELD-RENAME selector=27
    27 -> {
      expect value: Int = first
      let subject = PatternRecord { field: value, other: 1 }
      when subject is {
        PatternRecord { field: local, .. } -> local == value
      }
    }
    // @feature PAT-ARG-DESTRUCTURE selector=28
    28 -> {
      expect pair: (Int, Int) = first
      sum_pattern_pair(pair) == 3
    }
    // @feature PAT-LET-DESTRUCTURE selector=29
    29 -> {
      expect pair: (Int, Int) = first
      let (a, b) = pair
      a + b == 3
    }
    // @feature PAT-EXPECT-DESTRUCTURE selector=30
    30 -> {
      expect pair: (Int, Int) = first
      expect (a, b) = pair
      a + b == 3
    }
    _ -> False
  }
}

validator patterns {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_patterns(redeemer)
  }

  else(_) {
    fail
  }
}
