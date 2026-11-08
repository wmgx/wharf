//! agent 和控制面之间的消息加密（应用层，不依赖 TLS，`ws://` 明文内网也安全）。
//!
//! - 握手时双方各生成一个临时 X25519 密钥，公钥写进各自的签名内容
//!   （[crate::agent::auth_payload_v2]），中间人换不掉；
//! - ECDH 结果经 HKDF-SHA256（盐是握手的两个 nonce）派生两个方向各自的 ChaCha20-Poly1305 密钥；
//! - 握手之后每条消息是一个二进制帧：`密文 + 16 字节标签`。nonce 是各方向从 0 开始的计数，
//!   不随帧发送，所以丢帧、重放、乱序、篡改都会解密失败，收到失败就断开连接。

use chacha20poly1305::{
  ChaCha20Poly1305, Key, KeyInit, Nonce, aead::Aead,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// 本端是哪一方，决定用哪个方向的密钥发送。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
  Core,
  Agent,
}

const CORE_TO_AGENT: &[u8] = b"wharf-seal-v1 core->agent";
const AGENT_TO_CORE: &[u8] = b"wharf-seal-v1 agent->core";

#[derive(Debug)]
pub enum SealError {
  BadKey,
  Decrypt,
}

impl std::fmt::Display for SealError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      SealError::BadKey => f.write_str("对方的临时公钥无效"),
      SealError::Decrypt => {
        f.write_str("消息解密失败（被篡改、重放或丢帧）")
      }
    }
  }
}

impl std::error::Error for SealError {}

/// 本端的临时密钥。每次连接新生成一个，用完即丢。
pub struct KeyShare {
  secret: StaticSecret,
  /// 公钥，hex。
  pub public: String,
}

impl KeyShare {
  pub fn generate() -> Self {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("随机数不可用");
    let secret = StaticSecret::from(bytes);
    let public = hex::encode(PublicKey::from(&secret).as_bytes());
    Self { secret, public }
  }

  /// `peer`：对方的临时公钥（hex）；`salt`：握手里的 challenge nonce 和 agent nonce。
  pub fn finish(
    self,
    peer: &str,
    salt: &str,
    role: Role,
  ) -> Result<(Sealer, Opener), SealError> {
    let peer: [u8; 32] = hex::decode(peer)
      .ok()
      .and_then(|b| b.try_into().ok())
      .ok_or(SealError::BadKey)?;
    let shared = self.secret.diffie_hellman(&PublicKey::from(peer));
    // 低阶点会让共享密钥变成全零，必须拒绝。
    if !shared.was_contributory() {
      return Err(SealError::BadKey);
    }
    let hk =
      Hkdf::<Sha256>::new(Some(salt.as_bytes()), shared.as_bytes());
    let derive = |info: &[u8]| {
      let mut key = [0u8; 32];
      hk.expand(info, &mut key).expect("32 字节在 HKDF 上限内");
      ChaCha20Poly1305::new(Key::from_slice(&key))
    };
    let (send, recv) = match role {
      Role::Core => (CORE_TO_AGENT, AGENT_TO_CORE),
      Role::Agent => (AGENT_TO_CORE, CORE_TO_AGENT),
    };
    Ok((
      Sealer {
        cipher: derive(send),
        counter: 0,
      },
      Opener {
        cipher: derive(recv),
        counter: 0,
      },
    ))
  }
}

fn nonce(counter: u64) -> Nonce {
  let mut n = [0u8; 12];
  n[4..].copy_from_slice(&counter.to_be_bytes());
  *Nonce::from_slice(&n)
}

/// 发送方向。
pub struct Sealer {
  cipher: ChaCha20Poly1305,
  counter: u64,
}

impl Sealer {
  pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
    let out = self
      .cipher
      .encrypt(&nonce(self.counter), plaintext)
      .expect("ChaCha20-Poly1305 加密不会失败");
    self.counter += 1;
    out
  }
}

/// 接收方向。解密失败后计数不再可信，调用方必须断开连接。
pub struct Opener {
  cipher: ChaCha20Poly1305,
  counter: u64,
}

impl Opener {
  pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>, SealError> {
    let out = self
      .cipher
      .decrypt(&nonce(self.counter), frame)
      .map_err(|_| SealError::Decrypt)?;
    self.counter += 1;
    Ok(out)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn round_trip_and_rejects_tamper_and_replay() {
    let core = KeyShare::generate();
    let agent = KeyShare::generate();
    let (core_pub, agent_pub) =
      (core.public.clone(), agent.public.clone());
    let (mut c_tx, mut c_rx) =
      core.finish(&agent_pub, "n1n2", Role::Core).unwrap();
    let (mut a_tx, mut a_rx) =
      agent.finish(&core_pub, "n1n2", Role::Agent).unwrap();

    let f1 = c_tx.seal(b"hello");
    assert_eq!(a_rx.open(&f1).unwrap(), b"hello");
    // 重放同一帧：计数已经前进，解不开。
    assert!(a_rx.open(&f1).is_err());

    let mut f2 = a_tx.seal(b"report");
    f2[0] ^= 1;
    assert!(c_rx.open(&f2).is_err());
  }

  #[test]
  fn rejects_low_order_key() {
    let zero = hex::encode([0u8; 32]);
    assert!(
      KeyShare::generate().finish(&zero, "s", Role::Core).is_err()
    );
  }
}
