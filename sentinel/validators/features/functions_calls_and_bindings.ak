use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
use sentinel/redeemer.{FeatureArgs, FeatureRedeemer}

fn add(left: Int, right: Int) -> Int {
  left + right
}

fn add_one(value: Int) -> Int {
  value + 1
}

fn apply_function(value: Int, function: fn(Int) -> Int) -> Int {
  function(value)
}

fn apply_binary(left: Int, function: fn(Int, Int) -> Int, right: Int) -> Int {
  function(left, right)
}

fn factorial(value: Int) -> Int {
  if value <= 1 {
    1
  } else {
    value * factorial(value - 1)
  }
}

fn sum_function_pair((left, right): (Int, Int)) -> Int {
  left + right
}

fn sum_function_data_pair(Pair(left, right): Pair<Int, Int>) -> Int {
  left + right
}

fn empty_body_todo() -> Bool {
  todo
}

fn labelled_add(left: Int, right: Int) -> Int {
  left + right
}

fn make_adder(left: Int) -> fn(Int) -> Int {
  fn(right) { left + right }
}

fn with_int(value: Int, then: fn(Int) -> Bool) -> Bool {
  then(value)
}

// @feature FN-ARG-NAMED
fn named_argument(value: Int) -> Int {
  value
}

// @feature FN-ARG-DISCARD
fn discarded_argument(_value: Int) -> Bool {
  True
}

// @feature FN-ARG-LABEL
fn labelled_argument(label value: Int) -> Int {
  value
}

// @feature FN-ARG-LABEL-OVERRIDE
fn overridden_label(external local_name: Int) -> Int {
  local_name
}

// @feature FN-ARG-LABELLED-DISCARD
fn labelled_discard(ignored _value: Int) -> Bool {
  True
}

pub fn evaluate_functions(raw_redeemer: Data) -> Bool {
  expect FeatureRedeemer { selector, args } = raw_redeemer
  expect FeatureArgs { first, second: _, third: _ } = args

  when selector is {
    // @feature EXPR-VARIABLE selector=0
    0 -> {
      expect value: Int = first
      let bound = value
      bound == value
    }
    // @feature FN-ANONYMOUS selector=1
    1 -> {
      expect value: Int = first
      let add_one = fn(x) { x + 1 }
      add_one(value) == 8
    }
    // @feature FN-FIRST-CLASS selector=2
    2 -> {
      expect value: Int = first
      let function = add_one
      function(value) == 8
    }
    // @feature FN-HIGHER-ORDER selector=3
    3 -> {
      expect value: Int = first
      apply_function(value, add_one) == 8
    }
    // @feature FN-RECURSION selector=4
    4 -> {
      expect value: Int = first
      factorial(value) == 5040
    }
    // @feature FN-ARG-DESTRUCTURE selector=5
    5 -> {
      expect pair: (Int, Int) = first
      sum_function_pair(pair) == 3
    }
    // @feature FN-ARG-DESTRUCTURE-ANNOTATED selector=6
    6 -> {
      expect pair: Pair<Int, Int> = first
      sum_function_data_pair(pair) == 3
    }
    // @feature FN-EMPTY-BODY-TODO selector=7
    7 -> {
      expect value: Int = first
      if value == 7 {
        empty_body_todo()
      } else {
        False
      }
    }
    // @feature CALL-POSITIONAL selector=8
    8 -> {
      expect value: Int = first
      add(value, 1) == 8
    }
    // @feature CALL-LABELLED selector=9
    9 -> {
      expect value: Int = first
      labelled_add(right: 1, left: value) == 8
    }
    // @feature CALL-MIXED selector=10
    10 -> {
      expect value: Int = first
      labelled_add(value, right: 1) == 8
    }
    // @feature CALL-PUNNING selector=11
    11 -> {
      expect left: Int = first
      let right = 1
      labelled_add(left: left, right: right) == 8
    }
    // @feature CAPTURE-FUNCTION selector=12
    12 -> {
      expect value: Int = first
      let add_to_one = add(_, 1)
      add_to_one(value) == 8
    }
    // @feature CAPTURE-CONSTRUCTOR selector=13
    13 -> {
      expect value: Int = first
      let wrap = Some(_)
      wrap(value) == Some(value)
    }
    // @feature FN-ANON-BINOP selector=14
    14 -> {
      expect value: Int = first
      apply_binary(value, +, 1) == 8
    }
    // @feature PIPE-BARE selector=15
    15 -> {
      expect value: Int = first
      ( value |> add_one ) == 8
    }
    // @feature PIPE-CALL-INSERT selector=16
    16 -> {
      expect value: Int = first
      ( value |> add(1) ) == 8
    }
    // @feature PIPE-CAPTURE selector=17
    17 -> {
      expect value: Int = first
      ( value |> add(1, _) ) == 8
    }
    // @feature PIPE-RESULT-CALL selector=18
    18 -> {
      expect value: Int = first
      let result = value |> make_adder
      result(1) == 8
    }
    // @feature PIPE-ONE-LINE selector=19
    19 -> {
      expect value: Int = first
      ( value |> add_one |> add_one ) == 9
    }
    // @feature PIPE-MULTILINE selector=20
    20 -> {
      expect value: Int = first
      (
        value
          |> add_one
          |> add_one
      ) == 9
    }
    // @feature BLOCK-EXPRESSION selector=21
    21 -> {
      expect value: Int = first
      let result = {
        let incremented = value + 1
        incremented
      }
      result == 8
    }
    // @feature SEQUENCE-EXPRESSION selector=22
    22 -> {
      expect value: Int = first
      let result = {
        trace @"sequence"
        value + 1
      }
      result == 8
    }
    // @feature LET-VARIABLE selector=23
    23 -> {
      expect value: Int = first
      let result = value + 1
      result == 8
    }
    // @feature LET-MULTIPLE selector=24
    24 -> {
      expect value: Int = first
      let first_value = value
      let second_value = first_value + 1
      second_value == 8
    }
    // @feature LET-DESTRUCTURE selector=25
    25 -> {
      expect pair: (Int, Int) = first
      let (left, right) = pair
      left + right == 3
    }
    // @feature LET-SHADOW selector=26
    26 -> {
      expect value: Int = first
      let value = value + 1
      value == 8
    }
    // @feature LET-BACKPASS selector=27
    27 -> {
      expect value: Int = first
      let inner <- with_int(value)
      inner == value
    }
    // @feature EXPECT-PATTERN selector=28
    28 -> {
      expect value: Int = first
      expect Some(inner) = Some(value)
      inner == value
    }
    // @feature EXPECT-BOOLEAN selector=29
    29 -> {
      expect value: Int = first
      expect value == 7
      True
    }
    // @feature EXPECT-BACKPASS selector=30
    30 -> {
      expect value: Int = first
      expect 7 <- with_int(value)
      True
    }
    -1 -> True
    _ -> False
  }
}

validator functions_calls_and_bindings {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_functions(redeemer)
  }

  else(_) {
    fail
  }
}
