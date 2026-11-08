//! CLI ↔ 控制面的加密通道（`/api/tunnel` WebSocket），仿 HTTPS，但不用证书：
//!
//! 1. CLI 发 [TunnelHello]：临时 X25519 公钥和 nonce；
//! 2. 控制面回 [TunnelWelcome]：自己的临时公钥，以及用控制面 ed25519 私钥对 [tunnel_payload] 的签名；
//! 3. CLI 用 `wharf login --core-key` 记下的控制面公钥验证签名，双方派生会话密钥（[crate::seal]）；
//! 4. 之后每个二进制帧是加密的一段原始字节流，里面跑普通的 HTTP/1.1（含 WebSocket 升级），
//!    token 照旧在请求头里，只是不再以明文出现在网络上。

use serde::{Deserialize, Serialize};

pub const TUNNEL_PATH: &str = "/api/tunnel";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelHello {
  pub kx: String,
  pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelWelcome {
  pub kx: String,
  pub signature: String,
}

/// 控制面签名的内容。角色和 agent 握手不同，签名不能互相挪用。
pub fn tunnel_payload(nonce: &str, core_kx: &str, cli_kx: &str) -> Vec<u8> {
  format!("wharf-tunnel-v1|core|{nonce}|{core_kx},{cli_kx}").into_bytes()
}
