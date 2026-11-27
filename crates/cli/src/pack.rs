//! 预览只读即将进入包的文件。

use std::{
  collections::BTreeSet,
  path::{Path, PathBuf},
};

use wharf_api_types::{
  build::SourceTree, symlink::check_relative_entry,
};

pub struct PackedTree<'a> {
  pub root: &'a Path,
  pub allowed: BTreeSet<PathBuf>,
}

impl SourceTree for PackedTree<'_> {
  fn exists(&self, path: &str) -> bool {
    check_relative_entry(Path::new(path)).is_ok_and(|p| {
      self.allowed.contains(&p) && self.root.join(p).is_file()
    })
  }

  fn read(&self, path: &str) -> Option<String> {
    if !self.exists(path) {
      return None;
    }
    let path = self.root.join(path);
    let target = path.canonicalize().ok()?;
    if !target.starts_with(self.root)
      || target.metadata().ok()?.len() > 1024 * 1024
    {
      return None;
    }
    std::fs::read_to_string(target).ok()
  }

  fn list(&self, dir: &str) -> Vec<String> {
    self
      .allowed
      .iter()
      .filter_map(|p| {
        let rel = p.strip_prefix(dir).ok()?;
        let mut parts = rel.iter();
        let name = parts.next()?.to_str()?;
        Some(if parts.next().is_some() {
          format!("{name}/")
        } else {
          name.into()
        })
      })
      .collect::<BTreeSet<_>>()
      .into_iter()
      .collect()
  }
}
