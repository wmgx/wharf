use std::collections::HashSet;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use wharf_api_types::backup::{
  BackupRetention, validate_note, validate_retention,
};

use super::*;

pub(super) fn encode_note_tag(
  note: &str,
) -> Result<String, ApiError> {
  Ok(format!(
    "{NOTE_TAG_PREFIX}{}",
    URL_SAFE_NO_PAD.encode(validate_note(note)?)
  ))
}

fn decode_tags(s: &mut Snapshot) {
  s.keep = s.tags.iter().any(|t| t == KEEP_TAG);
  s.note = s.tags.iter().find_map(|t| {
    let bytes = URL_SAFE_NO_PAD
      .decode(t.strip_prefix(NOTE_TAG_PREFIX)?)
      .ok()?;
    let note = String::from_utf8(bytes).ok()?;
    validate_note(&note).ok()?;
    Some(note)
  });
}

pub(super) async fn snapshots(
  j: &Job<'_>,
  ctx: &Ctx,
) -> Result<Vec<Snapshot>, ApiError> {
  let out = j
    .restic(&["snapshots", "--json"], SHORT_TIMEOUT, false, ctx)
    .await?;
  if out.code == Some(NO_REPO) {
    return Ok(Vec::new());
  }
  if out.code == Some(WRONG_PASSWORD) {
    return Err(ApiError::new(
      ErrorCode::Forbidden,
      "备份仓库口令不匹配",
    ));
  }
  let out = out.check("restic snapshots")?;
  let mut list: Vec<Snapshot> = serde_json::from_str(&out.stdout)
    .map_err(|_| ApiError::internal("解析 restic 快照列表失败"))?;
  for snapshot in &mut list {
    decode_tags(snapshot);
  }
  list.sort_by_key(|s| std::cmp::Reverse(s.time));
  Ok(list)
}

pub(super) async fn tag(
  j: &Job<'_>,
  id: &str,
  keep: bool,
  note: Option<&str>,
  clear_note: bool,
  ctx: &Ctx,
) -> Result<(String, Snapshot), ApiError> {
  check_snapshot(id)?;
  if clear_note && note.is_some() {
    return Err(ApiError::invalid("设置备注和清除备注不能同时使用"));
  }
  let matches = snapshots(j, ctx).await?;
  let mut matches = matches
    .into_iter()
    .filter(|s| id == "latest" || s.id.starts_with(id));
  let before = matches
    .next()
    .ok_or_else(|| ApiError::not_found("没有找到快照"))?;
  if id != "latest" && matches.next().is_some() {
    return Err(ApiError::invalid("快照 id 不唯一，请使用完整 id"));
  }
  let mut args = vec![
    "tag",
    "--json",
    if keep { "--add" } else { "--remove" },
    KEEP_TAG,
  ];
  let new_note = note.map(encode_note_tag).transpose()?;
  if new_note.is_some() || clear_note {
    for tag in &before.tags {
      if tag.starts_with(NOTE_TAG_PREFIX)
        && Some(tag) != new_note.as_ref()
      {
        args.extend(["--remove", tag]);
      }
    }
  }
  if let Some(note) = &new_note {
    args.extend(["--add", note]);
  }
  args.push(&before.id);
  let out = j
    .restic(&args, SHORT_TIMEOUT, false, ctx)
    .await?
    .check("restic tag")?;
  #[derive(Deserialize)]
  struct Changed {
    old_snapshot_id: String,
    new_snapshot_id: String,
  }
  let id = out
    .stdout
    .lines()
    .filter_map(|line| serde_json::from_str::<Changed>(line).ok())
    .find(|changed| changed.old_snapshot_id == before.id)
    .map_or_else(
      || before.id.clone(),
      |changed| changed.new_snapshot_id,
    );
  let after = snapshots(j, ctx)
    .await?
    .into_iter()
    .find(|s| s.id == id)
    .ok_or_else(|| ApiError::not_found("找不到更新后的快照"))?;
  Ok((before.id, after))
}

fn forget_args(
  r: BackupRetention,
  keep: Option<&str>,
) -> Vec<String> {
  let mut args = vec!["forget".to_owned()];
  for (flag, count) in [
    ("--keep-daily", r.daily),
    ("--keep-weekly", r.weekly),
    ("--keep-monthly", r.monthly),
  ] {
    if count != 0 {
      args.extend([flag.to_owned(), count.to_string()]);
    }
  }
  if let Some(keep) = keep {
    args.extend(["--keep-tag".to_owned(), keep.to_owned()]);
  }
  args
}

async fn removed(
  j: &Job<'_>,
  args: &[String],
  ctx: &Ctx,
) -> Result<Vec<Snapshot>, ApiError> {
  let mut cmd: Vec<_> = args.iter().map(String::as_str).collect();
  cmd.extend(["--dry-run", "--json"]);
  let out = j
    .restic(&cmd, SHORT_TIMEOUT, false, ctx)
    .await?
    .check("restic forget --dry-run")?;
  #[derive(Deserialize)]
  struct Group {
    remove: Option<Vec<Snapshot>>,
  }
  if out.stdout.trim().is_empty() {
    return Ok(Vec::new());
  }
  let groups: Vec<Group> = serde_json::from_str(&out.stdout)
    .map_err(|_| ApiError::internal("无法解析快照清理预览"))?;
  Ok(
    groups
      .into_iter()
      .filter_map(|g| g.remove)
      .flatten()
      .collect(),
  )
}

fn transition_removals(
  new: Vec<Snapshot>,
  old: Vec<Snapshot>,
  before: DateTime<Utc>,
) -> Vec<String> {
  let old: HashSet<_> = old.into_iter().map(|s| s.id).collect();
  new
    .into_iter()
    .filter(|s| s.time > before || old.contains(&s.id))
    .map(|s| s.id)
    .collect()
}

pub(super) async fn prune(
  j: &Job<'_>,
  retention: BackupRetention,
  keep: Option<&str>,
  protect_before: Option<DateTime<Utc>>,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  validate_retention(retention)?;
  let args = forget_args(retention, keep);
  ctx.say(format!(
    "清理旧快照：保留 {} 日 / {} 周 / {} 月",
    retention.daily, retention.weekly, retention.monthly
  ));
  if let Some(before) =
    protect_before.filter(|_| retention != BackupRetention::default())
  {
    let new = removed(j, &args, ctx).await?;
    if new.is_empty() {
      return Ok(());
    }
    let old =
      removed(j, &forget_args(BackupRetention::default(), keep), ctx)
        .await?;
    let ids = transition_removals(new, old, before);
    for batch in ids.chunks(1000) {
      for id in batch {
        if id.len() != 64 {
          return Err(ApiError::internal("快照清理预览缺少完整 id"));
        }
        check_snapshot(id)?;
      }
      let mut cmd = vec!["forget"];
      cmd.extend(batch.iter().map(String::as_str));
      j.restic(&cmd, LONG_TIMEOUT, true, ctx)
        .await?
        .check("restic forget")?;
    }
    if !ids.is_empty() {
      j.restic(&["prune"], LONG_TIMEOUT, true, ctx)
        .await?
        .check("restic prune")?;
    }
  } else {
    let mut args: Vec<_> = args.iter().map(String::as_str).collect();
    args.push("--prune");
    j.restic(&args, LONG_TIMEOUT, true, ctx)
      .await?
      .check("restic forget")?;
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn note_tag_roundtrip_and_prune_keeps_tag() {
    let text = "升 v2.0 前, 含逗号和空格";
    let tag = encode_note_tag(text).unwrap();
    assert!(!tag.contains(','));
    let mut snapshot: Snapshot = serde_json::from_value(serde_json::json!({
      "id":"a", "short_id":"a", "time":"2026-01-01T00:00:00Z", "hostname":"s1",
      "tags":[KEEP_TAG, tag]
    })).unwrap();
    decode_tags(&mut snapshot);
    assert!(snapshot.keep);
    assert_eq!(snapshot.note.as_deref(), Some(text));
    assert!(
      forget_args(BackupRetention::default(), Some(KEEP_TAG))
        .windows(2)
        .any(|pair| pair == ["--keep-tag", KEEP_TAG])
    );
  }

  #[test]
  fn custom_retention_protects_legacy_snapshots_until_old_policy_expires_them()
   {
    let snapshot = |id: &str, at| Snapshot {
      id: id.into(),
      short_id: id.into(),
      time: DateTime::from_timestamp(at, 0).unwrap(),
      hostname: "s1".into(),
      paths: vec![],
      tags: vec![],
      keep: false,
      note: None,
    };
    let new = vec![
      snapshot("before", 1),
      snapshot("expired", 2),
      snapshot("after", 4),
    ];
    let remove = transition_removals(
      new,
      vec![snapshot("expired", 2)],
      DateTime::from_timestamp(3, 0).unwrap(),
    );
    assert_eq!(remove, ["expired", "after"]);
  }
}
