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
    let (_dir, path) = fixture("nazoauth-win-first-write");
    let prefix = std::env::var_os("NAZO_WINDOWS_PRIVATE_FILES_FIXTURE")
        .map(std::path::PathBuf::from)
        .unwrap_or(path);
    for mode in [0o400, 0o440, 0o444, 0o600] {
        let mut name = prefix.as_os_str().to_os_string();
        name.push(format!(".{mode:04o}"));
        let path = std::path::PathBuf::from(name);
        atomic_write(&path, b"cross-account-fixture", mode)
            .expect("fixture should be written through the private staging path");
        assert_eq!(
            read_secure_regular_file(&path, "cross-account fixture", true, 128)
                .expect("owner should read the fixture with a protected trusted-only ACL")
                .as_slice(),
            b"cross-account-fixture"
        );
    }
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
fn windows_read_only_mode_does_not_grant_owner_write() {
    let (_dir, path) = fixture("nazoauth-win-mode");
    for mode in [0o400, 0o440, 0o444] {
        atomic_write(&path, b"read-only", mode).expect("read-only private key should be written");
        assert_eq!(
            fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect_err("read-only modes must deny newly opened write handles")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            read_secure_regular_file(&path, "read-only fixture", true, 128)
                .expect("owner should still read the file")
                .as_slice(),
            b"read-only"
        );
    }
    atomic_write(&path, b"writable", 0o600).expect("writable mode should replace read-only value");
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("0600 must retain owner write access");
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
fn windows_rename_failure_preserves_target_and_removes_stage() {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

    let (_dir, path) = fixture("nazoauth-win-rename-failure");
    atomic_write(&path, b"old-value", 0o600).expect("initial value should be written");
    // A reader without delete sharing prevents the actual Win32 rename.
    let reader = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&path)
        .expect("blocking reader should open");
    let error = atomic_write(&path, b"new-value", 0o444)
        .expect_err("rename must fail while the target is not shared for deletion");
    assert!(
        error
            .to_string()
            .contains("SetFileInformationByHandle(FileRenameInfo)")
    );
    assert_eq!(fs::read(&path).unwrap(), b"old-value");
    assert_eq!(path.parent().unwrap().read_dir().unwrap().count(), 1);
    drop(reader);
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
    for mode in [0o400, 0o440, 0o444, 0o600] {
        copy_atomic(&path, &target, mode).expect("copy should use the same secure staging path");
        assert_eq!(
            read_secure_regular_file(&target, "private copy", true, 128)
                .expect("copied file must retain the final protected trusted-only ACL")
                .as_slice(),
            b"copy-me"
        );
    }
    assert!(Path::new(&lock_path).is_file());
}
