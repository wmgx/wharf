pub fn render_proxy_options(
  out: &mut String,
  trusted_proxies: &[String],
) {
  if !trusted_proxies.is_empty() {
    let cidrs = trusted_proxies.join(" ");
    out.push_str(&format!("\t\ttrusted_proxies static {cidrs}\n\t\ttrusted_proxies_strict\n"));
  }
}

pub fn render_proxy_headers(
  out: &mut String,
  trusted_proxies: &[String],
) {
  if !trusted_proxies.is_empty() {
    let cidrs = trusted_proxies.join(" ");
    out.push_str(&format!(
      "\n(wharf_strip_forwarded) {{\n\t@wharf_untrusted_proxy not remote_ip {cidrs}\n\trequest_header @wharf_untrusted_proxy -X-Real-IP\n\trequest_header @wharf_untrusted_proxy -Forwarded\n\trequest_header @wharf_untrusted_proxy -CF-Connecting-IP\n\trequest_header @wharf_untrusted_proxy -True-Client-IP\n\trequest_header X-Real-IP {{client_ip}}\n}}\n"
    ));
  }
}
