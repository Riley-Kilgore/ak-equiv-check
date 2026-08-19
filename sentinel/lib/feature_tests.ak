use project_features
use sentinel/redeemer.{FeatureArgs, FeatureRedeemer}

fn constant_fuzzer(value: a) -> Fuzzer<a> {
  fn(prng) { Some((prng, value)) }
}

// @feature FRAMEWORK-PRNG
fn preserve_prng(prng: PRNG) -> PRNG {
  prng
}

// @feature FRAMEWORK-FUZZER
fn framework_fuzzer() -> Fuzzer<Int> {
  constant_fuzzer(7)
}

// @feature TEST-FUZZER-NAMED
fn named_fuzzer() -> Fuzzer<Int> {
  constant_fuzzer(7)
}

// @feature TEST-FUZZER-COMPOSED
fn composed_fuzzer() -> Fuzzer<Int> {
  fn(prng) {
    when named_fuzzer()(prng) is {
      Some((next_prng, value)) -> Some((preserve_prng(next_prng), value + 1))
      None -> None
    }
  }
}

fn pair_fuzzer() -> Fuzzer<(Int, Int)> {
  fn(prng) { Some((prng, (7, 8))) }
}

// @feature FRAMEWORK-SAMPLER
// @feature BENCH-SAMPLER-NAMED
fn named_sampler() -> Sampler<Int> {
  fn(size) { constant_fuzzer(size) }
}

// @feature BENCH-SAMPLER-COMPOSED
fn composed_sampler() -> Sampler<(Int, Int)> {
  fn(_size) { pair_fuzzer() }
}

// @feature TEST-UNIT
test unit_feature() {
  True
}

// @feature TEST-PROPERTY-VIA
test property_via(value via constant_fuzzer(7)) {
  value == 7
}

// @feature TEST-MULTI-VIA
test multiple_via_values((left, right) via pair_fuzzer()) {
  left + right == 15
}

// @feature TEST-VALIDATOR
test validator_behavior() {
  let raw: Data = FeatureRedeemer {
    selector: -1,
    args: FeatureArgs { first: 7, second: 0, third: 0 },
  }
  project_features.evaluate_project(raw) == False
}

// @feature TEST-FAIL
test expected_failure() fail {
  False
}

// @feature TEST-FAIL-ONCE
test expected_failure_once(value via constant_fuzzer(7)) fail once {
  value != 7
}

// @feature TEST-TRACE
test trace_production(value via constant_fuzzer(7)) {
  trace @"sentinel test trace": value
  value == 7
}

// @feature BENCH-VIA
bench benchmark_via(value via named_sampler()) {
  value >= 0
}

// @feature BENCH-MULTI-VIA
bench benchmark_multiple_values((left, right) via composed_sampler()) {
  left + right == 15
}
