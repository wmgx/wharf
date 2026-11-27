use serde_yaml_ng::Value;

use crate::ApiError;

pub fn normalize_stop_signal(raw: &str) -> Result<String, ApiError> {
  let mut signal = raw.trim().to_ascii_uppercase();
  if !signal.starts_with("SIG") {
    signal.insert_str(0, "SIG");
  }
  match signal.as_str() {
    "SIGTERM" | "SIGINT" | "SIGQUIT" | "SIGHUP" | "SIGUSR1" | "SIGUSR2"
    | "SIGWINCH" | "SIGALRM" | "SIGRTMIN+3" => Ok(signal),
    _ => Err(ApiError::invalid("停机信号不支持").with_hint(
      "常用信号：SIGTERM、SIGINT、SIGQUIT、SIGHUP、SIGUSR1、SIGUSR2、SIGWINCH",
    )),
  }
}

pub fn parse_compose_max_grace_secs(yaml: &str) -> u64 {
  let Ok(mut value) = serde_yaml_ng::from_str::<Value>(yaml) else {
    return 10;
  };
  if value.apply_merge().is_err() {
    return 10;
  }
  value
    .get("services")
    .and_then(Value::as_mapping)
    .into_iter()
    .flat_map(|services| services.values())
    .map(|service| {
      let grace = service.get("stop_grace_period");
      grace
        .and_then(Value::as_u64)
        .or_else(|| {
          grace.and_then(Value::as_str).and_then(duration_secs)
        })
        .unwrap_or(10)
        .min(600)
    })
    .max()
    .unwrap_or(10)
}

fn duration_secs(mut input: &str) -> Option<u64> {
  if let Ok(secs) = input.parse() {
    return Some(secs);
  }
  let mut total = 0.0;
  while !input.is_empty() {
    let end =
      input.find(|c: char| !c.is_ascii_digit() && c != '.')?;
    let n: f64 = input[..end].parse().ok()?;
    let (unit, scale) = [
      ("ms", 0.001),
      ("us", 0.000_001),
      ("µs", 0.000_001),
      ("ns", 0.000_000_001),
      ("h", 3600.0),
      ("m", 60.0),
      ("s", 1.0),
    ]
    .into_iter()
    .find(|(unit, _)| input[end..].starts_with(unit))?;
    total += n * scale;
    input = &input[end + unit.len()..];
  }
  Some(total.ceil() as u64)
}
