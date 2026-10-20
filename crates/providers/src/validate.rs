//! Local (no network) validation.

use crate::error::ProviderError;

/// Lowercase, strip the trailing dot, and check it is an exact
/// (non wildcard) ASCII hostname with at least two labels.
pub fn normalize_hostname(
  hostname: &str,
) -> Result<String, ProviderError> {
  let hostname =
    hostname.trim().trim_end_matches('.').to_ascii_lowercase();
  let bad = |why: String| {
    ProviderError::invalid(format!(
      "Invalid hostname '{hostname}': {why}"
    ))
  };
  if hostname.len() > 253 {
    return Err(bad("it is longer than 253 characters".into()));
  }
  let labels: Vec<&str> = hostname.split('.').collect();
  if labels.len() < 2 {
    return Err(bad(
      "it needs a domain suffix, eg. app.example.com".into(),
    ));
  }
  for label in labels {
    if label.is_empty() {
      return Err(bad(
        "it has an empty part (two dots in a row)".into(),
      ));
    }
    if label.len() > 63 {
      return Err(bad(format!(
        "'{label}' is longer than 63 characters"
      )));
    }
    if label.contains('_') {
      return Err(bad(format!(
        "'{label}' contains an underscore, which DNS hostnames do not allow. Use a hyphen instead, eg. '{}'",
        label.replace('_', "-")
      )));
    }
    if label.starts_with('-') || label.ends_with('-') {
      return Err(bad(format!(
        "'{label}' cannot start or end with a hyphen"
      )));
    }
    if let Some(c) = label
      .chars()
      .find(|c| !(c.is_ascii_alphanumeric() || *c == '-'))
    {
      return Err(bad(format!(
        "'{label}' contains '{c}'; only letters, digits and hyphens are allowed"
      )));
    }
  }
  Ok(hostname)
}

#[cfg(test)]
mod tests {
  use super::normalize_hostname;

  #[test]
  fn hostnames() {
    assert_eq!(
      normalize_hostname(" Who.EXAMPLE.com. ").unwrap(),
      "who.example.com"
    );
    for bad in ["localhost", "a..b", "a_b.top", "-a.top", "*.a.top"] {
      assert!(normalize_hostname(bad).is_err(), "{bad}");
    }
  }
}
