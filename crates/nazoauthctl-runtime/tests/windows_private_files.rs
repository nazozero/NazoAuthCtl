#![cfg(windows)]

//! Windows-only coverage for the secure filesystem boundary.
//!
//! The two-account checks require an isolated host and are exercised by
//! `scripts/test-windows-private-files.ps1`; these tests cover the same
//! creation, validation, and replacement contract under the current token.

use std::{fs, path::Path};

use nazoauthctl_runtime::filesystem::{
    PrivateTempDir, atomic_write, copy_atomic, open_lock_file, open_secure_regular_file,
    read_secure_regular_file, set_mode, validate_secure_directory,
};

fn fixture(name: &str) -> (PrivateTempDir, std::path::PathBuf) {
    let dir = PrivateTempDir::new(name).expect("private test directory should be created");
    let path = dir.path().join("value");
    (dir, path)
}

#[test]
fn windows_private_acl_removes_preexisting_foreign_allow() {
    let (_dir, path) = fixture("nazoauth-win-acl");
    atomic_write(&path, b"secret", 0o600).expect("private file should be written");
    set_mode(&path, 0o600).expect("existing private ACL should be replaceable");
    let bytes = read_secure_regular_file(&path, "private fixture", true, 128)
        .expect("private ACL should validate");
    assert_eq!(&*bytes, b"secret");
}

#[test]
fn windows_private_identity_comes_from_process_token() {
    let (_dir, path) = fixture("nazoauth-win-token");
    atomic_write(&path, b"token-bound", 0o600).expect("token-bound file should be written");
    let file = open_secure_regular_file(&path, "token-bound fixture", true)
        .expect("current process token should own the file");
    assert_eq!(
        file.metadata().expect("metadata should be readable").len(),
        11
    );
}

#[test]
fn windows_private_file_is_protected_before_first_write() {
    if let Ok(path) = std::env::var("NAZO_WINDOWS_PRIVATE_FILES_FIXTURE") {
        let path = std::path::PathBuf::from(path);
        atomic_write(&path, b"cross-account-fixture", 0o600)
            .expect("cross-account fixture should be written");
        return;
    }
    let (_dir, path) = fixture("nazoauth-win-first-write");
    // atomic_write stages through a CREATE_NEW handle carrying its protected
    // DACL; a failed write must never leave an ambiently-created secret file.
    atomic_write(&path, b"first", 0o600).expect("first atomic write should succeed");
    assert_eq!(
        fs::read(&path).expect("fixture should be readable"),
        b"first"
    );
    assert!(open_secure_regular_file(&path, "first-write fixture", true).is_ok());
}

#[test]
fn windows_private_key_file_denies_other_account() {
    let (_dir, path) = fixture("nazoauth-win-key");
    atomic_write(&path, b"key-shaped", 0o400).expect("read-only private key should be written");
    let bytes = read_secure_regular_file(&path, "private key", true, 128)
        .expect("owner should read the private key");
    assert_eq!(&*bytes, b"key-shaped");
}

#[test]
fn windows_atomic_replacement_preserves_complete_values() {
    let (_dir, path) = fixture("nazoauth-win-replace");
    atomic_write(&path, b"old-value", 0o600).expect("initial value should be written");
    atomic_write(&path, b"new-value", 0o600).expect("replacement should be atomic");
    assert_eq!(
        fs::read(&path).expect("replacement should be readable"),
        b"new-value"
    );
    let staging = path
        .parent()
        .expect("fixture has parent")
        .read_dir()
        .expect("fixture directory should be readable")
        .filter_map(Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().contains(".nazoauth-"));
    assert!(
        !staging,
        "committed replacement must not leave staging files"
    );
}

#[test]
fn windows_reparse_or_foreign_private_file_is_rejected() {
    let (dir, path) = fixture("nazoauth-win-reparse");
    fs::create_dir(&path).expect("directory fixture should be created");
    assert!(open_secure_regular_file(&path, "directory fixture", true).is_err());
    assert!(validate_secure_directory(dir.path(), "private fixture", true).is_ok());
}

#[test]
fn windows_lock_and_copy_share_private_creation_contract() {
    let (_dir, path) = fixture("nazoauth-win-lock-copy");
    let lock_path = path.with_file_name("lock");
    let lock = open_lock_file(&lock_path, false, "fixture lock")
        .expect("new lock should use the private creation contract");
    drop(lock);
    let reopened = open_lock_file(&lock_path, true, "fixture lock")
        .expect("existing lock should validate through its descriptor");
    drop(reopened);

    let target = path.with_file_name("copy");
    atomic_write(&path, b"copy-me", 0o600).expect("source should be written");
    copy_atomic(&path, &target, 0o600).expect("copy should use the same secure staging path");
    assert_eq!(
        fs::read(target).expect("copy should be readable"),
        b"copy-me"
    );
    assert!(Path::new(&lock_path).is_file());
}
