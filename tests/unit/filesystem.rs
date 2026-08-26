use std::{fs, path::Path};

use super::*;

#[test]
fn private_temporary_directory_is_unique_private_and_removed_on_drop() {
    let first = PrivateTempDir::new("nazoauthctl-filesystem-test").unwrap();
    let second = PrivateTempDir::new("nazoauthctl-filesystem-test").unwrap();
    assert_ne!(first.path(), second.path());
    assert!(first.path().is_dir());
    assert_eq!(fs::canonicalize(first.path()).unwrap(), first.path());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(first.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    let removed = first.path().to_owned();
    drop(first);
    assert!(!removed.exists());
}

#[test]
fn durable_file_helpers_round_trip_bytes_digest_and_absent_removal() {
    let work = PrivateTempDir::new("nazoauthctl-file-round-trip").unwrap();
    let source = work.path().join("nested/source");
    atomic_write(&source, b"abc", 0o640).unwrap();
    assert_eq!(fs::read(&source).unwrap(), b"abc");
    assert_eq!(
        sha256(&source).unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    let copy = work.path().join("copied");
    copy_atomic(&source, &copy, 0o600).unwrap();
    assert_eq!(fs::read(&copy).unwrap(), b"abc");
    remove_file_durable(&copy).unwrap();
    remove_file_durable(&copy).unwrap();
    assert!(!copy.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o777,
            0o640
        );
        set_mode(&source, 0o400).unwrap();
        assert_eq!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o777,
            0o400
        );
    }
}

#[test]
fn persisted_secrets_are_stable_single_line_regular_files() {
    let work = PrivateTempDir::new("nazoauthctl-secret-test").unwrap();
    let path = work.path().join("secrets/value");
    let generated = generate_secret(&path).unwrap();
    assert_eq!(generated.len(), 64);
    assert!(
        generated
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    );
    assert_eq!(generate_secret(&path).unwrap(), generated);

    #[cfg(unix)]
    set_mode(&path, 0o600).unwrap();
    fs::write(&path, "multiline\nsecret").unwrap();
    assert!(generate_secret(&path).is_err());
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(generate_secret(&path).is_err());
}

#[test]
fn filesystem_helpers_fail_closed_without_clobbering_staging_or_non_files() {
    let work = PrivateTempDir::new("nazoauthctl-filesystem-errors").unwrap();
    let target = work.path().join("target");
    atomic_write(&target, b"first", 0o600).unwrap();
    atomic_write(&target, b"replacement", 0o600).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"replacement");

    let directory = work.path().join("directory");
    fs::create_dir(&directory).unwrap();
    assert!(atomic_write(&directory, b"replacement", 0o600).is_err());
    assert!(remove_file_durable(&directory).is_err());
    assert!(copy_atomic(&work.path().join("missing"), &target, 0o600).is_err());
    let source = work.path().join("verified-source");
    atomic_write(&source, b"candidate", 0o600).unwrap();
    assert!(copy_atomic_verified(&source, &target, 0o600, &"00".repeat(32)).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"replacement");
    assert!(sha256(&work.path().join("missing")).is_err());
    assert!(
        PrivateTempDir::new(&format!("nazoauthctl-missing-{}/child", std::process::id())).is_err()
    );
}

#[test]
fn private_directory_is_created_and_revalidated_without_opening_as_a_file() {
    let work = PrivateTempDir::new("nazoauth-private-directory-test").unwrap();
    let workspace = work.path().join("rehearsal");

    ensure_private_directory(&workspace, "recovery rehearsal workspace").unwrap();
    validate_secure_directory(&workspace, "recovery rehearsal workspace", true).unwrap();
    assert!(workspace.is_dir());
    assert!(
        validate_secure_directory(Path::new("relative/rehearsal"), "workspace", false).is_err()
    );

    #[cfg(windows)]
    assert!(
        !fs::symlink_metadata(&workspace)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[cfg(unix)]
#[test]
fn secure_regular_file_rejects_a_symlink_before_open() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let work = PrivateTempDir::new("nazoauth-secure-open-symlink").unwrap();
    let target = work.path().join("target");
    fs::write(&target, b"trusted").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    let link = work.path().join("link");
    symlink(&target, &link).unwrap();

    assert!(open_secure_regular_file(&link, "secure test file", true).is_err());
}

#[cfg(unix)]
#[test]
fn secure_regular_file_returns_the_post_open_validated_descriptor() {
    use std::{io::Read as _, os::unix::fs::PermissionsExt as _};

    let work = PrivateTempDir::new("nazoauth-secure-open-descriptor").unwrap();
    let path = work.path().join("record");
    fs::write(&path, b"before replacement").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let mut opened = open_secure_regular_file(&path, "secure test file", true).unwrap();
    let replacement = work.path().join("replacement");
    fs::write(&replacement, b"after replacement").unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&replacement, &path).unwrap();

    let mut contents = String::new();
    opened.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "before replacement");
}

#[cfg(unix)]
#[test]
fn secure_regular_file_reader_is_bounded_and_uses_owner_only_input() {
    use std::os::unix::fs::PermissionsExt as _;

    let work = PrivateTempDir::new("nazoauth-secure-read-bounded").unwrap();
    let path = work.path().join("secret");
    fs::write(&path, b"secret").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let bytes = read_secure_regular_file(&path, "secure test secret", true, 64).unwrap();
    assert_eq!(bytes.as_slice(), b"secret");

    fs::write(&path, vec![b'x'; 65]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_secure_regular_file(&path, "secure test secret", true, 64).is_err());

    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(read_secure_regular_file(&path, "secure test secret", true, 64).is_err());
}

#[cfg(unix)]
#[test]
fn secure_secret_reader_allows_read_only_group_acl_but_not_world_read() {
    use std::os::unix::fs::PermissionsExt as _;

    let work = PrivateTempDir::new("nazoauth-secure-secret-reader").unwrap();
    let path = work.path().join("secret");
    fs::write(&path, b"secret").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o440)).unwrap();
    assert_eq!(
        read_secure_secret_file(&path, "secure provider secret", 64)
            .unwrap()
            .as_slice(),
        b"secret"
    );

    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
    assert!(read_secure_secret_file(&path, "secure provider secret", 64).is_err());
}

#[cfg(unix)]
#[test]
fn symlink_activation_preserves_foreign_staging_and_commits_only_its_unique_link() {
    use std::os::unix::fs::symlink;

    let work = PrivateTempDir::new("nazoauthctl-symlink-test").unwrap();
    let first = work.path().join("first");
    let second = work.path().join("second");
    fs::write(&first, "first").unwrap();
    fs::write(&second, "second").unwrap();
    let link = work.path().join("current");
    let staging = link.with_extension(format!("next-{}", std::process::id()));
    symlink(&first, &staging).unwrap();

    symlink_atomic(&second, &link).unwrap();
    assert_eq!(fs::read_link(&link).unwrap(), second);
    assert_eq!(fs::read_link(&staging).unwrap(), first);

    let staged_links = fs::read_dir(work.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("current.next-"))
        .collect::<Vec<_>>();
    assert_eq!(
        staged_links,
        vec![staging.file_name().unwrap().to_string_lossy().into_owned()]
    );
}

/// P1-13 positive + negative real-machine test (Windows): after set_mode the
/// ACL must carry NO inherited ACEs, must not include broad groups such as
/// Users/Everyone/Authenticated Users, and must still grant the current
/// account. The negative half proves the read-only mode strips write access
/// for the owner as well.
#[cfg(windows)]
#[test]
fn windows_owner_only_acl_strips_inheritance_and_broad_groups() {
    use std::process::Command;

    fn icacls_dump(path: &Path) -> String {
        let output = Command::new("icacls").arg(path).output().unwrap();
        assert!(output.status.success(), "icacls dump failed");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    let work = PrivateTempDir::new("nazoauthctl-windows-acl").unwrap();
    let dir = work.path().join("secure-dir");
    fs::create_dir(&dir).unwrap();
    set_secure_directory_mode(&dir, "test secure directory", 0o700).unwrap();

    let dir_acl = icacls_dump(&dir);
    // Negative half: stripping inheritance must remove every broad-group
    // ACE that the parent granted. The only remaining grants are SYSTEM,
    // Administrators and the current account.
    for group in ["BUILTIN\\Users", "Everyone", "Authenticated Users"] {
        assert!(
            !dir_acl.contains(group),
            "{group} must not hold an ACE: {dir_acl}"
        );
    }
    let account = std::env::var("USERNAME").unwrap();
    assert!(
        dir_acl.contains(r"\SYSTEM") && dir_acl.contains("Administrators"),
        "SYSTEM/Administrators grants missing: {dir_acl}"
    );
    assert!(
        dir_acl.contains(&format!("\\{account}:")),
        "the current account lost its grant: {dir_acl}"
    );

    // Negative: a 0440 file keeps READ but loses write/full grants — even
    // for the owner.
    let file = dir.join("secret.txt");
    fs::write(&file, b"payload").unwrap();
    set_mode(&file, 0o440).unwrap();
    let file_acl = icacls_dump(&file);
    assert!(
        !file_acl.contains("(F)") && !file_acl.contains("(W)") && !file_acl.contains("(M)"),
        "write/full grants must be stripped from a 0440 file: {file_acl}"
    );

    // Positive contrast: a 0600 file DOES keep full control for the owner.
    set_mode(&file, 0o600).unwrap();
    let writable_acl = icacls_dump(&file);
    assert!(
        writable_acl.contains("(F)"),
        "owner full control missing on the 0600 file: {writable_acl}"
    );
}
