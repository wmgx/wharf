//! 页面静态文件，构建时打包进二进制（`web/dist`）。
//!
//! 没有构建页面时（例如只跑单测）目录不存在，访问页面会得到提示而不是报错。

use axum::{
  http::{StatusCode, Uri, header},
  response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/../../web/dist"]
#[allow_missing = true]
struct Assets;

pub async fn serve(uri: Uri) -> Response {
  let path = uri.path().trim_start_matches('/');
  if let Some(file) = Assets::get(path).filter(|_| !path.is_empty()) {
    // vite 产物带内容 hash，可以长期缓存；index.html 每次都要重新取。
    let cache = if path.starts_with("assets/") {
      "public, max-age=31536000, immutable"
    } else {
      "no-cache"
    };
    return (
      [
        (header::CONTENT_TYPE, file.metadata.mimetype().to_string()),
        (header::CACHE_CONTROL, cache.to_string()),
      ],
      file.data,
    )
      .into_response();
  }
  // 其余路径交给前端路由。
  match Assets::get("index.html") {
    Some(file) => (
      [
        (header::CONTENT_TYPE, "text/html; charset=utf-8"),
        (header::CACHE_CONTROL, "no-cache"),
      ],
      file.data,
    )
      .into_response(),
    None => (
      StatusCode::NOT_FOUND,
      "这个 wharf-core 构建时没有打包页面（web/dist 不存在）。",
    )
      .into_response(),
  }
}
