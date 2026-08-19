// @feature NEG-NONEXHAUSTIVE-WHEN
pub fn non_exhaustive(value: Bool) -> Int {
  when value is {
    True -> 1
  }
}
