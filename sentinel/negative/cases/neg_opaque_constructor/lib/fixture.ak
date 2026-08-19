use hidden

// @feature NEG-OPAQUE-CONSTRUCTOR
pub fn reveal() -> hidden.Secret {
  hidden.Secret(42)
}
