use std::{
  io,
  net::{Ipv4Addr, SocketAddrV4},
  time::Duration,
};

use tokio::net::{TcpStream, UdpSocket};
use wharf_api_types::service_checks::{PortCheck, PortCheckSpec};

use crate::exec::Ctx;

pub async fn run(checks: Vec<PortCheck>, ctx: &Ctx) -> Vec<bool> {
  tokio::select! {
    results = futures_util::future::join_all(checks.iter().map(check)) => results,
    _ = ctx.cancel.cancelled() => vec![],
  }
}

async fn check(check: &PortCheck) -> bool {
  let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, check.port);
  let Some(probe) = &check.udp else {
    return tokio::time::timeout(
      Duration::from_secs(5),
      TcpStream::connect(addr),
    )
    .await
    .is_ok_and(|r| r.is_ok());
  };
  tokio::time::timeout(Duration::from_secs(3), udp(addr, probe))
    .await
    .is_ok_and(|r| matches!(r, Ok(true)))
}

async fn udp(
  addr: SocketAddrV4,
  probe: &PortCheckSpec,
) -> io::Result<bool> {
  if probe.validate_stored(true).is_err() {
    return Ok(false);
  }
  let (send, expect, dns) = match probe {
    PortCheckSpec::Off => return Ok(false),
    PortCheckSpec::Dns { domain } => {
      let mut id = [0; 2];
      if getrandom::fill(&mut id).is_err() {
        return Ok(false);
      }
      (dns_query(domain, id), id.to_vec(), true)
    }
    PortCheckSpec::Custom { send, expect } => (
      hex::decode(send).unwrap(),
      hex::decode(expect).unwrap(),
      false,
    ),
  };
  let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
  sock.connect(addr).await?;
  sock.send(&send).await?;
  let mut buf = vec![0; if dns { 12 } else { expect.len() }];
  let len = sock.recv(&mut buf).await?;
  Ok(
    buf[..len].starts_with(&expect)
      && (!dns || len >= 12 && buf[2] & 0x80 != 0),
  )
}

fn dns_query(domain: &str, id: [u8; 2]) -> Vec<u8> {
  let mut packet = vec![id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
  if domain != "." {
    for label in domain.trim_end_matches('.').split('.') {
      packet.push(label.len() as u8);
      packet.extend(label.as_bytes());
    }
  }
  packet.extend([0, 0, if domain == "." { 2 } else { 1 }, 0, 1]);
  packet
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn local_tcp_and_udp_checks() {
    let listener =
      tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let mut target = PortCheck {
      port: listener.local_addr().unwrap().port(),
      udp: None,
    };
    let wire = serde_json::to_vec(
      &wharf_api_types::agent::AgentOp::PortChecks {
        checks: vec![target.clone()],
      },
    )
    .unwrap();
    let wharf_api_types::agent::AgentOp::PortChecks { checks } =
      serde_json::from_slice(&wire).unwrap()
    else {
      panic!("expected a port-check batch")
    };
    assert_eq!(run(checks, &Ctx::detached()).await, [true]);
    let unlistened = tokio::net::TcpSocket::new_v4().unwrap();
    unlistened.bind((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    target.port = unlistened.local_addr().unwrap().port();
    assert!(!check(&target).await);

    let sock =
      UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    target.port = sock.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
      let mut bytes = [0; 512];
      let (n, peer) = sock.recv_from(&mut bytes).await.unwrap();
      sock.send_to(&bytes[..n], peer).await.unwrap();
      let (n, peer) = sock.recv_from(&mut bytes).await.unwrap();
      bytes[0] ^= 1;
      bytes[2] |= 0x80;
      sock.send_to(&bytes[..n], peer).await.unwrap();
    });
    target.udp = Some(PortCheckSpec::Custom {
      send: "1234".into(),
      expect: "12".into(),
    });
    assert!(check(&target).await);
    target.udp = Some(PortCheckSpec::Dns {
      domain: "example.test".into(),
    });
    assert!(!check(&target).await);
    echo.await.unwrap();
  }
}
