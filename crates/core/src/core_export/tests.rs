use super::*;

fn fixture(root: &Path, password: &str) -> PathBuf {
  let source = root.join("source");
  fs::create_dir(&source).unwrap();
  drop(crate::db::Db::open(&source.join("wharf.db")).unwrap());
  fs::write(source.join("core.key"), hex::encode([19; 32])).unwrap();
  let files: Vec<_> = REQUIRED
    .iter()
    .map(|name| Artifact::read(&source, name).unwrap())
    .collect();
  let manifest = Manifest {
    format: FORMAT.into(),
    created_at: chrono::Utc::now(),
    wharf_version: "test".into(),
    wharf_build: "test".into(),
    schema_version: crate::db::SCHEMA_VERSION,
    core_key_fingerprint: files[2].sha256.clone(),
    secrets_key_fingerprint: files[1].sha256.clone(),
    core_server: None,
    files,
  };
  let output = root.join("export.enc");
  let keys: Vec<_> = REQUIRED[1..]
    .iter()
    .map(|name| fs::read(source.join(name)).unwrap())
    .collect();
  encrypt(
    &source.join("wharf.db"),
    &keys,
    &output,
    &manifest,
    password,
    &CancellationToken::new(),
  )
  .unwrap();
  output
}

#[test]
fn core_export_contains_no_plaintext_and_rejects_tamper_or_wrong_password()
 {
  let dir = tempfile::tempdir().unwrap();
  let password = crate::backup::random_hex();
  let file = fixture(dir.path(), &password);
  let mut bytes = fs::read(&file).unwrap();
  let secret =
    fs::read(dir.path().join("source/secrets.key")).unwrap();
  for hidden in [
    b"SQLite format 3".as_slice(),
    secret.as_slice(),
    hex::encode([19; 32]).as_bytes(),
    b"manifest.json",
  ] {
    assert!(!bytes.windows(hidden.len()).any(|part| part == hidden));
  }
  let stage = TempDir::new(dir.path(), "test-").unwrap();
  assert_eq!(
    decrypt_to_staging(&file, &crate::backup::random_hex(), &stage.0)
      .unwrap_err()
      .code,
    ErrorCode::Forbidden
  );
  *bytes.last_mut().unwrap() ^= 1;
  fs::write(&file, &bytes).unwrap();
  assert_eq!(
    decrypt_to_staging(&file, &password, &stage.0)
      .unwrap_err()
      .code,
    ErrorCode::Forbidden
  );
  bytes.pop();
  fs::write(&file, &bytes).unwrap();
  assert!(decrypt_to_staging(&file, &password, &stage.0).is_err());
}

#[test]
fn core_restore_from_export_file_validates_and_archives_old() {
  let dir = tempfile::tempdir().unwrap();
  let password = crate::backup::random_hex();
  let file = fixture(dir.path(), &password);
  let dest = dir.path().join("dest");
  fs::create_dir(&dest).unwrap();
  fs::write(dest.join("wharf.db"), b"old").unwrap();
  let run = |yes| {
    crate::core_restore::restore(&dest, &file, yes, || {
      Ok(password.clone())
    })
  };
  assert_eq!(
    run(false).unwrap_err().code,
    ErrorCode::ConfirmRequired
  );
  run(true).unwrap();
  let archive = fs::read_dir(&dest)
    .unwrap()
    .flatten()
    .find(|e| {
      e.file_name()
        .to_string_lossy()
        .starts_with(".wharf-before-restore-")
    })
    .unwrap();
  assert_eq!(
    fs::read(archive.path().join("wharf.db")).unwrap(),
    b"old"
  );
  for name in REQUIRED {
    assert_eq!(
      fs::metadata(dest.join(name)).unwrap().permissions().mode()
        & 0o777,
      0o600
    );
  }
  let malicious = dir.path().join("malicious.enc");
  let header = new_header().unwrap();
  // 恶意条目也有合法 AEAD，验证仍须拒绝归档内的软链。
  let mut file = File::create(&malicious).unwrap();
  file.write_all(&header).unwrap();
  let frames = Frames::new(file, header, &password).unwrap();
  let mut tar =
    tar::Builder::new(GzEncoder::new(frames, Compression::default()));
  let mut item = tar::Header::new_gnu();
  item.set_entry_type(tar::EntryType::Symlink);
  item.set_size(0);
  tar
    .append_link(&mut item, "wharf.db", "../wharf.db")
    .unwrap();
  let mut frames = tar.into_inner().unwrap().finish().unwrap();
  frames.emit(true).unwrap();
  let before = fs::read(dest.join("wharf.db")).unwrap();
  assert_eq!(
    crate::core_restore::restore(&dest, &malicious, true, || Ok(
      password.clone()
    ))
    .unwrap_err()
    .code,
    ErrorCode::InvalidInput,
  );
  assert_eq!(fs::read(dest.join("wharf.db")).unwrap(), before);
}
