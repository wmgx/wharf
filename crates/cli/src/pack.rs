//! `wharf deploy <目录>`：打包规则在 `wharf-pack` 里，和 agent 打包服务器目录一致。

use std::path::PathBuf;

use wharf_api_types::build::SourceTree;
pub use wharf_pack::pack;

/// 部署前在本机预览：用和 agent 一样的逻辑判断语言和启动命令。
pub struct LocalTree(pub PathBuf);

impl SourceTree for LocalTree {
  fn read(&self, path: &str) -> Option<String> {
    let path = self.0.join(path);
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
      return None;
    }
    std::fs::read_to_string(path).ok()
  }

  fn list(&self, dir: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(self.0.join(dir)) else {
      return vec![];
    };
    entries
      .filter_map(Result::ok)
      .map(|e| {
        let name = e.file_name().to_string_lossy().to_string();
        if e.file_type().is_ok_and(|t| t.is_dir()) {
          format!("{name}/")
        } else {
          name
        }
      })
      .collect()
  }
}
