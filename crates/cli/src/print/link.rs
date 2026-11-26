pub fn rotate_link(v: &serde_json::Value) {
  let gateway = v["gateway"].as_str().unwrap_or_default();
  let what =
    match (v["rotated_token"].as_bool(), v["rotated_cert"].as_bool())
    {
      (Some(true), Some(true)) => "密钥和证书",
      (Some(true), _) => "密钥",
      _ => "证书",
    };
  println!("已轮换网关 {gateway} 的反向隧道{what}");
  if let Some(expires) = v["cert_expires_at"].as_str() {
    println!("证书到期 {expires}");
  }
  println!("执行 wharf plan 查看变更");
}
