//! 只读推演访问令牌的有效期、来源、服务范围和接口权限点。

use std::{collections::BTreeSet, net::IpAddr, sync::Arc};

use axum::{
  Json,
  extract::{Path, Query, State},
  http::{Method, Uri},
};
use chrono::{DateTime, Utc};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use wharf_api_types::{
  ApiError, ErrorCode,
  view::{ExplainVerdict, Perm, TokenExplain, TokenExplainItem},
};

use crate::{
  api::ApiResult,
  auth::{
    Auth, TokenPeer, check_token, decode_perms, invalid_token,
    require_perm, scope_values,
  },
  db::{TokenRow, sql_err},
  state::AppState,
};

const CUSTOM_NOTE: &str = "令牌层放行；接口内部还会检查权限点和对象归属，explain 不推演这部分";

#[derive(Default, Deserialize)]
pub(crate) struct ExplainQuery {
  service: Option<String>,
  from: Option<String>,
  method: Option<String>,
  path: Option<String>,
}

pub(crate) async fn get(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(query): Query<ExplainQuery>,
) -> ApiResult<TokenExplain> {
  auth.require(Perm::Admin)?;
  let row = s.db.call(move |c| {
    c.query_row(
      "SELECT name, scope, expires_at, allowed_from, services FROM api_tokens WHERE name = ?1",
      [&name],
      TokenRow::read,
    )
    .optional()
    .map_err(sql_err)?
    .ok_or_else(|| {
      ApiError::not_found(format!("没有访问令牌 {name}"))
        .with_hint("wharf token list")
    })
  }).await?;
  Ok(Json(explain(&row, Utc::now(), query)?))
}

struct Explanation<'a> {
  row: &'a TokenRow,
  now: DateTime<Utc>,
  peer: TokenPeer<'a>,
  source_note: Option<String>,
  perms: Option<BTreeSet<Perm>>,
}

impl Explanation<'_> {
  fn item(
    &self,
    op: &str,
    method: Method,
    path: String,
    perm: Option<Perm>,
    note: Option<&str>,
  ) -> TokenExplainItem {
    // 鉴权看 URI 的 path，查询参数只用于展示请求。
    let gate_path =
      path.split_once('?').map_or(path.as_str(), |(path, _)| path);
    let gate =
      check_token(self.row, self.now, self.peer, &method, gate_path);
    let mut reasons = Vec::new();
    if let Some(source) = &self.source_note
      && !gate
        .as_ref()
        .is_err_and(|e| e.code == ErrorCode::Unauthorized)
    {
      reasons.push(source.clone());
    }
    let granted = gate.and_then(|()| {
      if let Some(perm) = perm {
        require_perm(
          self.perms.as_ref().ok_or_else(invalid_token)?,
          perm,
        )?;
      }
      Ok(())
    });
    let verdict = match granted {
      Err(error) => {
        reasons.push(error.message);
        ExplainVerdict::Deny
      }
      Ok(()) => {
        if !reasons.is_empty() && perm.is_some() {
          reasons.push("服务范围和权限点通过".into());
        }
        reasons.extend(note.map(str::to_owned));
        if reasons.is_empty() {
          ExplainVerdict::Allow
        } else {
          ExplainVerdict::Depends
        }
      }
    };
    TokenExplainItem {
      op: op.into(),
      method: method.to_string(),
      path,
      perm,
      verdict,
      reason: (!reasons.is_empty()).then(|| reasons.join("；")),
    }
  }
}

fn explain(
  row: &TokenRow,
  now: DateTime<Utc>,
  query: ExplainQuery,
) -> Result<TokenExplain, ApiError> {
  let ExplainQuery {
    service,
    from,
    method,
    path,
  } = query;
  let peer = match from.as_deref() {
    Some(label) => {
      let ip = label.parse::<IpAddr>().map_err(|_| {
        ApiError::invalid("from 必须是合法的 IP 地址")
      })?;
      TokenPeer::Address {
        ip: Some(ip),
        label,
      }
    }
    None => TokenPeer::AssumeAllowed,
  };
  let source_note = row.allowed_from.as_deref().and_then(|raw| {
    let ranges = scope_values(raw).collect::<Vec<_>>();
    (from.is_none() && !ranges.is_empty()).then(|| {
      format!(
        "只允许从 {} 使用，没给 --from 无法判断",
        ranges.join("、")
      )
    })
  });
  let explanation = Explanation {
    row,
    now,
    peer,
    source_note,
    perms: decode_perms(&row.perms),
  };
  let (service, items) = match (method, path) {
    (Some(method), Some(path)) => {
      let method =
        Method::from_bytes(method.as_bytes()).map_err(|_| {
          ApiError::invalid("method 必须是合法的 HTTP 方法")
        })?;
      if !path.starts_with("/api/")
        || path.contains('#')
        || path.parse::<Uri>().is_err()
      {
        return Err(ApiError::invalid(
          "path 必须是以 /api/ 开头的请求路径",
        ));
      }
      (
        None,
        vec![explanation.item(
          "自定义请求",
          method,
          path,
          None,
          Some(CUSTOM_NOTE),
        )],
      )
    }
    (None, None) => {
      let service = service.or_else(|| {
        row
          .services
          .as_deref()
          .and_then(|raw| scope_values(raw).min())
      });
      let items = fixed_items(&explanation, service.as_deref());
      (service, items)
    }
    _ => {
      return Err(ApiError::invalid("method 和 path 必须同时指定"));
    }
  };
  Ok(TokenExplain {
    token: row.name.clone(),
    service,
    from,
    items,
  })
}

fn fixed_items(
  explanation: &Explanation<'_>,
  service: Option<&str>,
) -> Vec<TokenExplainItem> {
  use Perm::{Admin, Apply, Exec, Host, Plan, Read};

  let scoped = explanation.row.services.is_some();

  let service_segment = service.map(urlencoding::encode);
  [
    (
      "查看状态",
      Method::GET,
      "/api/status",
      Read,
      scoped.then_some("受限令牌只看到名下的服务和域名"),
    ),
    ("查看服务", Method::GET, "/api/services/{svc}", Read, None),
    (
      "看服务日志",
      Method::GET,
      "/api/services/{svc}/logs",
      Read,
      None,
    ),
    (
      "生成计划",
      Method::POST,
      "/api/plan",
      Plan,
      scoped.then_some("计划内容还要按服务范围核对"),
    ),
    (
      "执行计划",
      Method::POST,
      "/api/apply",
      Apply,
      Some(if scoped {
        "需核对计划范围；高风险项还要 confirm，触达宿主机的要 host 且目标机开对应开关（控制面所在机还需 admin）"
      } else {
        "高风险项还要 confirm，触达宿主机的要 host 且目标机开对应开关（控制面所在机还需 admin）"
      }),
    ),
    (
      "重启服务",
      Method::POST,
      "/api/services/{svc}/restart",
      Apply,
      None,
    ),
    ("容器内执行命令", Method::POST, "/api/services/{svc}/exec", Exec, None),
    ("预览服务配置", Method::GET, "/api/services/{svc}/render", Read, None),
    (
      "进容器终端",
      Method::GET,
      "/api/services/{svc}/terminal",
      Exec,
      None,
    ),
    (
      "下载服务文件",
      Method::GET,
      "/api/services/{svc}/files/download",
      Read,
      None,
    ),
    (
      "确认告警",
      Method::POST,
      "/api/alerts/ack",
      Apply,
      scoped.then_some("受限令牌只能确认名下服务和域名的告警"),
    ),
    (
      "看任务完整触发地址",
      Method::GET,
      "/api/tasks/<任务>?reveal=true",
      Read,
      Some(if scoped {
        "还要核对任务归属和对应的执行权限，具体权限取决于任务类型"
      } else {
        "还要核对对应的执行权限，具体权限取决于任务类型"
      }),
    ),
    (
      "宿主机执行命令",
      Method::POST,
      "/api/servers/<服务器>/exec",
      Host,
      Some("目标服务器还要开启 host_exec；若为控制面所在机还需 admin"),
    ),
    ("看操作审计", Method::GET, "/api/audit", Admin, None),
    ("管理密钥", Method::PUT, "/api/secrets/<密钥>", Admin, None),
    ("管理令牌", Method::GET, "/api/tokens", Admin, None),
  ]
  .into_iter()
  .map(|(op, method, path, perm, note)| {
    let missing_service = path.contains("{svc}") && service.is_none();
    let path = path.replace(
      "{svc}",
      service_segment.as_deref().unwrap_or("<服务>"),
    );
    let mut item = explanation.item(
      op,
      method,
      path,
      (!missing_service).then_some(perm),
      if missing_service {
        Some("没指定服务")
      } else {
        note
      },
    );
    item.perm = Some(perm);
    item
  })
  .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  fn row() -> TokenRow {
    TokenRow {
      name: "ai".into(),
      perms: "read,apply".into(),
      expires_at: None,
      allowed_from: Some("10.0.0.0/8".into()),
      services: Some("blog".into()),
    }
  }

  #[test]
  fn explain_matches_real_gate() {
    use ExplainVerdict::{Allow, Deny, Depends};

    let row = row();
    let now = Utc::now();
    for (service, from, suffix, verdict, gate_passes) in [
      ("blog", Some("10.1.2.3"), "logs", Allow, true),
      ("other", Some("10.1.2.3"), "logs", Deny, false),
      ("blog", Some("1.2.3.4"), "logs", Deny, false),
      ("blog", None, "logs", Depends, true),
      ("blog", Some("10.1.2.3"), "terminal", Deny, true),
    ] {
      let path = format!("/api/services/{service}/{suffix}");
      let result = explain(
        &row,
        now,
        ExplainQuery {
          service: Some(service.into()),
          from: from.map(str::to_owned),
          ..ExplainQuery::default()
        },
      )
      .unwrap();
      let item =
        result.items.iter().find(|item| item.path == path).unwrap();
      assert_eq!(item.verdict, verdict);
      let peer = from.map_or(TokenPeer::AssumeAllowed, |label| {
        TokenPeer::Address {
          ip: Some(label.parse().unwrap()),
          label,
        }
      });
      let gate = check_token(&row, now, peer, &Method::GET, &path);
      assert_eq!(gate.is_ok(), gate_passes);
      if let Err(error) = gate {
        assert_eq!(
          item.reason.as_deref(),
          Some(error.message.as_str())
        );
      }
      let reason = item.reason.as_deref().unwrap_or_default();
      match (service, from, suffix) {
        ("other", _, _) => assert_eq!(
          reason,
          crate::token_scope::forbidden(
            &row.name,
            &BTreeSet::from(["blog".into()]),
            ""
          )
          .message,
        ),
        (_, Some("1.2.3.4"), _) => {
          assert!(reason.contains("只允许从 10.0.0.0/8 使用"))
        }
        (_, None, _) => {
          assert!(reason.contains("没给 --from 无法判断"));
          assert!(reason.contains("服务范围和权限点通过"));
        }
        (_, _, "terminal") => {
          assert!(reason.contains("当前 token 没有 exec 权限"))
        }
        _ => assert!(item.reason.is_none()),
      }
    }
  }

  #[test]
  fn fixed_items_explain_scope_and_host_requirements() {
    use ExplainVerdict::{Allow, Deny, Depends};

    for (services, perms, scope_verdict, host_verdict) in [
      (None, "read,plan,apply,exec", Allow, Deny),
      (Some("blog".into()), "read,plan,apply,exec", Depends, Deny),
      (None, "read,host", Allow, Depends),
    ] {
      let scoped = services.is_some();
      let row = TokenRow {
        allowed_from: None,
        services,
        perms: perms.into(),
        ..row()
      };
      let result =
        explain(&row, Utc::now(), ExplainQuery::default()).unwrap();
      assert_eq!(result.items.len(), 14);
      let item = |op: &str| {
        result.items.iter().find(|item| item.op == op).unwrap()
      };
      if perms != "read,host" {
        for (op, note) in [
          ("查看状态", "受限令牌只看到名下的服务和域名"),
          ("生成计划", "计划内容还要按服务范围核对"),
          ("确认告警", "受限令牌只能确认名下服务和域名的告警"),
        ] {
          assert_eq!(item(op).verdict, scope_verdict);
          assert_eq!(
            item(op).reason.as_deref(),
            scoped.then_some(note)
          );
        }
        let apply = item("执行计划").reason.as_deref().unwrap();
        assert!(apply.contains("host") && apply.contains("admin"));
        assert_eq!(apply.contains("需核对计划范围"), scoped);
        let reveal =
          item("看任务完整触发地址").reason.as_deref().unwrap();
        assert_eq!(reveal.contains("任务归属"), scoped);
      }
      let host = item("宿主机执行命令");
      assert_eq!(host.perm, Some(Perm::Host));
      assert_eq!(host.verdict, host_verdict);
      if host_verdict == Depends {
        let reason = host.reason.as_deref().unwrap();
        assert!(
          reason.contains("host_exec")
            && reason.contains("控制面所在机还需 admin")
        );
      }
    }
  }

  #[test]
  fn explain_expired_token_denies_all() {
    let mut row = row();
    row.expires_at = Some(0);
    let result =
      explain(&row, Utc::now(), ExplainQuery::default()).unwrap();
    assert_eq!(result.items.len(), 14);
    for item in result.items {
      assert_eq!(item.verdict, ExplainVerdict::Deny);
      assert_eq!(
        item.reason.as_deref(),
        Some("访问令牌 ai 已在 1970-01-01 00:00 UTC 过期"),
      );
    }
  }
}
