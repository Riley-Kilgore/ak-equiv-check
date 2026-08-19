use config
use env
use sentinel/redeemer.{FeatureArgs, FeatureRedeemer}

pub fn evaluate_project(raw_redeemer: Data) -> Bool {
  expect FeatureRedeemer { selector, args } = raw_redeemer
  expect FeatureArgs { first, second: _, third: _ } = args
  expect value: Int = first

  when selector is {
    // @feature TARGET-PLUTUS-V3 selector=0
    0 -> value == 7
    // @feature PROJECT-ENV-DEFAULT selector=1
    1 ->
      (
        env.environment_name == @"default" || env.environment_name == @"preview"
      ) && value == 7
    // @feature PROJECT-ENV-NAMED selector=2
    2 ->
      (
        env.environment_name == @"default" || env.environment_name == @"preview"
      ) && env.network_id >= 0 && value == 7
    // @feature PROJECT-CONFIG-DEFAULT selector=3
    3 -> config.price > 0 && value == 7
    // @feature PROJECT-CONFIG-NAMED selector=4
    4 -> config.price > 0 && value == 7
    // @feature PROJECT-CONDITIONAL-MODULE selector=5
    5 -> env.network_id >= 0 && config.price > 0 && value == 7
    // @feature CONFIG-INT selector=6
    6 -> config.price > 0 && value == 7
    // @feature CONFIG-BOOL selector=7
    7 -> ( config.is_mainnet || !config.is_mainnet ) && value == 7
    // @feature CONFIG-BYTEARRAY-UTF8-STRING selector=8
    8 ->
      ( config.network == "mainnet" || config.network == "preview" ) && value == 7
    // @feature CONFIG-BYTEARRAY-UTF8-MAP selector=9
    9 -> config.network_utf8 == "preview" && value == 7
    // @feature CONFIG-BYTEARRAY-HEX-MAP selector=10
    10 -> config.policy_hex == #"deadbeef" && value == 7
    // @feature CONFIG-LIST selector=11
    11 -> config.quotas != [] && value == 7
    // @feature CONFIG-TUPLE selector=12
    12 -> {
      let (asset_name, quantity) = config.asset
      asset_name == "HOSKY" && quantity == 42 && value == 7
    }
    // @feature TRACE-LEVEL-SILENT selector=13
    13 -> {
      trace @"silent profile"
      value == 7
    }
    // @feature TRACE-LEVEL-COMPACT selector=14
    14 -> {
      trace @"compact profile"
      value == 7
    }
    // @feature TRACE-LEVEL-VERBOSE selector=15
    15 -> {
      trace @"verbose profile": value
      value == 7
    }
    // @feature TRACE-SOURCE-USER selector=16
    16 -> {
      trace @"user-defined source"
      value == 7
    }
    // @feature TRACE-SOURCE-COMPILER selector=17
    17 -> {
      expect decoded: Int = first
      decoded == value
    }
    // @feature TRACE-SOURCE-ALL selector=18
    18 -> {
      trace @"combined source"
      expect decoded: Int = first
      decoded == value
    }
    // @feature COMMENT-EXPECT selector=19
    19 -> {
      /// custom expect failure
          expect decoded: Int = first
      decoded == value
    }
    _ -> False
  }
}

pub fn project_contract_surface() -> Bool {
  let value = 7
  // @feature PROJECT-TOML
  expect value == 7
  // @feature PROJECT-COMPILER-PIN
  expect value == 7
  // @feature PROJECT-LOCK
  expect value == 7
  // @feature PROJECT-DEPENDENCY
  expect value == 7
  // @feature PROJECT-DEPENDENCY-GITHUB
  expect value == 7
  // @feature PROJECT-MONOREPO
  expect value == 7
  // @feature PROJECT-MONOREPO-GLOB
  expect value == 7
  // @feature PROJECT-BLUEPRINT
  expect value == 7
  True
}
