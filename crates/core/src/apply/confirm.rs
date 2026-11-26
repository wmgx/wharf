use wharf_api_types::{ApiError, ErrorCode};

pub(super) fn require(
  plan_id: &str,
  needs_confirm: &[String],
  confirmed: &[String],
  can_confirm: bool,
) -> Result<(), ApiError> {
  let missing: Vec<&String> = needs_confirm
    .iter()
    .filter(|a| !confirmed.contains(a))
    .collect();
  if !missing.is_empty() {
    let flags: String =
      missing.iter().map(|a| format!(" --confirm {a}")).collect();
    let addresses: Vec<&str> =
      missing.iter().map(|s| s.as_str()).collect();
    return Err(
      ApiError::new(
        ErrorCode::ConfirmRequired,
        format!(
          "计划里有高风险项，需要确认：{}",
          addresses.join("、")
        ),
      )
      .with_hint("先看清楚 plan 里这些项的 reason，再确认")
      .suggest(format!("wharf apply {}{flags}", plan_id)),
    );
  }
  if !needs_confirm.is_empty() && !can_confirm {
    return Err(
      ApiError::new(
        ErrorCode::Forbidden,
        "计划里有高风险项，当前 token 只能执行安全的计划",
      )
      .with_hint(
        "请用户在页面上确认执行，或用有 confirm 权限的 token",
      ),
    );
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  #[test]
  fn denied_without_confirm_permission() {
    let confirmed = ["route/share.example.test".into()];
    let error = super::require("p1", &confirmed, &confirmed, false)
      .unwrap_err();
    assert_eq!(error.code, wharf_api_types::ErrorCode::Forbidden);
    assert!(
      super::require("p1", &confirmed, &confirmed, true).is_ok()
    );
  }
}
