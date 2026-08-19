// @feature IMPORT-BUILTIN-MODULE
use aiken/builtin
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}
// @feature SELECT-MODULE
use sentinel/definition_support
use sentinel/redeemer.{FeatureArgs, FeatureRedeemer}

// @feature DEF-FN-PRIVATE
fn private_increment(value: Int) -> Int {
  value + 1
}

// @feature DEF-FN-PUBLIC
pub fn public_increment(value: Int) -> Int {
  value + 1
}

// @feature DEF-CONST-PRIVATE
const private_constant = 7

// @feature DEF-CONST-PUBLIC
pub const public_constant = 7

// @feature DEF-TYPE-PRIVATE
type PrivateType {
  PrivateType(Int)
}

// @feature DEF-TYPE-PUBLIC
// @feature SELECT-TYPE-NAMESPACE
pub type PublicType {
  PublicType(Int)
}

// @feature DEF-TYPE-OPAQUE-PRIVATE
opaque type PrivateOpaque {
  PrivateOpaque(Int)
}

// @feature DEF-TYPE-OPAQUE-PUBLIC
pub opaque type PublicOpaque {
  PublicOpaque(Int)
}

// @feature TYPE-CONSTRUCTOR-ZERO
pub type ZeroConstructor {
  Zero
}

// @feature TYPE-CONSTRUCTOR-POSITIONAL
pub type PositionalConstructor {
  Positional(Int)
}

// @feature TYPE-CONSTRUCTOR-RECORD
pub type ConstructorRecordType {
  ConstructorRecord { value: Int }
}

// @feature TYPE-SHORTHAND-RECORD
pub type ShorthandRecord {
  value: Int,
}

// @feature TYPE-MULTI-CONSTRUCTOR
pub type MultiChoice {
  ChoiceA
  ChoiceB(Int)
}

// @feature TYPE-RECURSIVE
pub type Tree<a> {
  Leaf(a)
  Node(Tree<a>, Tree<a>)
}

// @feature TYPE-GENERIC
pub type GenericBox<a> {
  GenericBox(a)
}

// @feature TYPE-OPAQUE-NEWTYPE
pub opaque type OpaqueNewtype<a> {
  value: a,
}

// @feature ENC-DEFAULT-TAG-ORDER
pub type DefaultTags {
  DefaultFirst(Int)
  DefaultSecond(Int)
}

// @feature ENC-TAG-TYPE-DECIMAL
@tag(42)
pub type DecimalTaggedType {
  value: Int,
}

// @feature ENC-TAG-TYPE-HEX
@tag(0x2a)
pub type HexTaggedType {
  value: Int,
}

pub type DecimalTaggedConstructors {
  // @feature ENC-TAG-CONSTRUCTOR-DECIMAL
  @tag(42)
  DecimalTagged(Int)
}

pub type HexTaggedConstructors {
  // @feature ENC-TAG-CONSTRUCTOR-HEX
  @tag(0x2a)
  HexTagged(Int)
}

// @feature ENC-LIST
@list
pub type ListEncoded {
  value: Int,
}

pub fn evaluate_modules(raw_redeemer: Data) -> Bool {
  expect FeatureRedeemer { selector, args } = raw_redeemer
  expect FeatureArgs { first, second, third: _ } = args

  when selector is {
    // branch MOD-VALIDATOR selector=0
    0 -> {
      expect value: Int = first
      value == 7
    }
    // branch DEF-FN-PRIVATE selector=1
    1 -> {
      expect value: Int = first
      private_increment(value) == 8
    }
    // branch DEF-FN-PUBLIC selector=2
    2 -> {
      expect value: Int = first
      public_increment(value) == 8
    }
    // branch DEF-CONST-PRIVATE selector=3
    3 -> {
      expect value: Int = first
      value == private_constant
    }
    // branch DEF-CONST-PUBLIC selector=4
    4 -> {
      expect value: Int = first
      value == public_constant
    }
    // branch DEF-TYPE-PRIVATE selector=5
    5 -> {
      expect value: Int = first
      PrivateType(value) == PrivateType(7)
    }
    // branch DEF-TYPE-PUBLIC selector=6
    6 -> {
      expect value: Int = first
      PublicType(value) == PublicType(7)
    }
    // branch DEF-TYPE-OPAQUE-PRIVATE selector=7
    7 -> {
      expect value: Int = first
      PrivateOpaque(value) == PrivateOpaque(7)
    }
    // branch DEF-TYPE-OPAQUE-PUBLIC selector=8
    8 -> {
      expect value: Int = first
      PublicOpaque(value) == PublicOpaque(7)
    }
    // branch DEF-VALIDATOR selector=9
    9 -> {
      expect value: Int = first
      value == 7
    }
    // branch TYPE-CONSTRUCTOR-ZERO selector=10
    10 -> {
      expect value: Int = first
      Zero == Zero && value == 7
    }
    // branch TYPE-CONSTRUCTOR-POSITIONAL selector=11
    11 -> {
      expect value: Int = first
      Positional(value) == Positional(7)
    }
    // branch TYPE-CONSTRUCTOR-RECORD selector=12
    12 -> {
      expect value: Int = first
      ConstructorRecord { value } == ConstructorRecord { value: 7 }
    }
    // branch TYPE-SHORTHAND-RECORD selector=13
    13 -> {
      expect value: Int = first
      ShorthandRecord { value } == ShorthandRecord { value: 7 }
    }
    // branch TYPE-MULTI-CONSTRUCTOR selector=14
    14 -> {
      expect value: Int = first
      ChoiceB(value) == ChoiceB(7)
    }
    // branch TYPE-RECURSIVE selector=15
    15 -> {
      expect value: Int = first
      let tree = Node(Leaf(value), Leaf(value))
      when tree is {
        Node(Leaf(left), Leaf(right)) -> left + right == 14
        _ -> False
      }
    }
    // branch TYPE-GENERIC selector=16
    16 -> {
      expect value: Int = first
      GenericBox(value) == GenericBox(7)
    }
    // branch TYPE-OPAQUE-NEWTYPE selector=17
    17 -> {
      expect value: Int = first
      OpaqueNewtype { value } == OpaqueNewtype { value: 7 }
    }
    // branch ENC-DEFAULT-TAG-ORDER selector=18
    18 -> {
      expect value: Int = first
      let encoded: Data = DefaultSecond(value)
      builtin.equals_data(encoded, second)
    }
    // branch ENC-TAG-TYPE-DECIMAL selector=19
    19 -> {
      expect value: Int = first
      let encoded: Data = DecimalTaggedType { value }
      builtin.equals_data(encoded, second)
    }
    // branch ENC-TAG-TYPE-HEX selector=20
    20 -> {
      expect value: Int = first
      let encoded: Data = HexTaggedType { value }
      builtin.equals_data(encoded, second)
    }
    // branch ENC-TAG-CONSTRUCTOR-DECIMAL selector=21
    21 -> {
      expect value: Int = first
      let encoded: Data = DecimalTagged(value)
      builtin.equals_data(encoded, second)
    }
    // branch ENC-TAG-CONSTRUCTOR-HEX selector=22
    22 -> {
      expect value: Int = first
      let encoded: Data = HexTagged(value)
      builtin.equals_data(encoded, second)
    }
    // branch ENC-LIST selector=23
    23 -> {
      expect value: Int = first
      let encoded: Data = ListEncoded { value }
      builtin.equals_data(encoded, second)
    }
    // branch IMPORT-BUILTIN-MODULE selector=24
    24 -> {
      expect value: Int = first
      builtin.add_integer(value, 1) == 8
    }
    // branch SELECT-MODULE selector=25
    25 -> {
      expect value: Int = first
      definition_support.increment(value) == 8
    }
    // branch SELECT-TYPE-NAMESPACE selector=26
    26 -> {
      expect value: Int = first
      PublicType(value) == PublicType(7)
    }
    _ -> False
  }
}

// @feature DEF-VALIDATOR
validator definition_feature {
  mint(_redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    True
  }

  else(_) {
    fail
  }
}

// @feature MOD-VALIDATOR
validator modules_definitions_imports {
  mint(redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    evaluate_modules(redeemer)
  }

  else(_) {
    fail
  }
}
