// @feature NEG-STRING-PATTERN
pub fn string_pattern(value: String) -> Bool {
  when value is {
    @"forbidden" -> True
    _ -> False
  }
}
