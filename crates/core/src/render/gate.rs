use super::Gate;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use wharf_api_types::spec::LoginTakeover;

pub(super) fn render_gate(
  out: &mut String,
  gate: &Gate,
  gate_public: Option<&str>,
) {
  if gate.site_endpoints {
    let host_header = if gate.core.starts_with("https://") {
      "\n\t\t\theader_up Host {upstream_hostport}"
    } else {
      ""
    };
    out.push_str(&format!("\t@wharf_site path /_wharf/*\n\thandle @wharf_site {{\n\t\turi replace /_wharf/ /gate/site/\n\t\treverse_proxy {} {{{host_header}\n\t\t}}\n\t}}\n",gate.core));
  }
  out.push_str(&format!(
    "\twharf_sso {{\n\t\tpublic_key {}\n\t\tcore {}\n\t\tlogin {}\n",
    gate_public.unwrap_or(""),
    gate.core,
    gate.login
  ));
  if gate.public {
    out.push_str("\t\tpublic\n");
  }
  if let Some((takeover, entry)) = &gate.takeover {
    #[derive(Serialize)]
    struct Takeover<'a> {
      #[serde(flatten)]
      config: &'a LoginTakeover,
      entry: &'a str,
    }
    let config = serde_json::to_vec(&Takeover {
      config: takeover,
      entry,
    })
    .unwrap();
    out.push_str(&format!(
      "\t\ttakeover {}\n",
      URL_SAFE_NO_PAD.encode(config)
    ));
  }
  if gate.app_login {
    out.push_str("\t\tapp_login on\n");
  }
  if !gate.skip_paths.is_empty() {
    out
      .push_str(&format!("\t\tskip {}\n", gate.skip_paths.join(" ")));
  }
  if let Some(header) = &gate.user_header {
    out.push_str(&format!("\t\tuser_header {header}\n"));
  }
  if !gate.trusted.is_empty() {
    out.push_str(&format!("\t\ttrust {}\n", gate.trusted.join(" ")));
  }
  out.push_str("\t}\n");
}
