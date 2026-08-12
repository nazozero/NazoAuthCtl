#[cfg(unix)]
use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::{MetadataExt, chown},
};

#[cfg(unix)]
use super::{Backup, Builder, validate_secret};
#[cfg(unix)]
use tar::{EntryType, Header};

#[cfg(unix)]
use crate::filesystem::PrivateTempDir;

#[cfg(unix)]
fn complete_backup(path: &std::path::Path) {
    let backup = Backup {
        path: path.to_owned(),
    };
    backup.write_checksums().unwrap();
    backup.write_completion_marker().unwrap();
}

#[cfg(unix)]
#[test]
fn backup_secret_validation_rejects_symlink_unsafe_mode_and_oversize_inputs() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let work = PrivateTempDir::new("backup-secret-boundaries").unwrap();
    let path = work.path().join("provider-secret");
    fs::write(&path, b"one-line-secret").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    validate_secret(&path).unwrap();

    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
    assert!(validate_secret(&path).is_err());

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, vec![b'x'; 16 * 1024 + 1]).unwrap();
    assert!(validate_secret(&path).is_err());

    let decoy = work.path().join("provider-secret-decoy");
    fs::write(&decoy, b"one-line-secret").unwrap();
    fs::set_permissions(&decoy, fs::Permissions::from_mode(0o400)).unwrap();
    fs::remove_file(&path).unwrap();
    symlink(&decoy, &path).unwrap();
    assert!(validate_secret(&path).is_err());
}

#[cfg(unix)]
#[test]
fn incomplete_backup_never_enters_snapshot_restore() {
    let work = PrivateTempDir::new("backup-incomplete-marker").unwrap();
    let backup_path = work.path().join("backup");
    fs::create_dir(&backup_path).unwrap();
    let error = Backup { path: backup_path }
        .restore_snapshots(&[])
        .unwrap_err();
    assert!(error.to_string().contains("completion marker"));
}

#[cfg(unix)]
#[test]
fn snapshot_restore_does_not_preserve_archived_numeric_ownership_when_running_as_root() {
    let work = PrivateTempDir::new("backup-ownership").unwrap();
    if fs::metadata(work.path()).unwrap().uid() != 0 {
        return;
    }

    let parent = work.path().join("runtime");
    let target = parent.join("secrets");
    fs::create_dir_all(&target).unwrap();
    let secret = target.join("client-secret-pepper");
    fs::write(&secret, b"secret").unwrap();
    chown(&target, Some(10001), Some(10001)).unwrap();
    chown(&secret, Some(10001), Some(10001)).unwrap();

    let backup_path = work.path().join("backup");
    fs::create_dir(&backup_path).unwrap();
    let file = File::create(backup_path.join("snapshot-0.tar")).unwrap();
    let mut archive = Builder::new(file);
    archive.append_dir_all("secrets", &target).unwrap();
    archive.finish().unwrap();
    let mut path_file = File::create(backup_path.join("snapshot-0.path")).unwrap();
    writeln!(path_file, "{}", target.display()).unwrap();
    complete_backup(&backup_path);

    Backup { path: backup_path }
        .restore_snapshots(std::slice::from_ref(&target))
        .unwrap();

    let directory = fs::metadata(&target).unwrap();
    let restored_secret = fs::metadata(&secret).unwrap();
    assert_ne!((directory.uid(), directory.gid()), (10001, 10001));
    assert_ne!(
        (restored_secret.uid(), restored_secret.gid()),
        (10001, 10001)
    );
}

#[cfg(unix)]
#[test]
fn snapshot_restore_binds_manifest_to_current_configured_path() {
    let work = PrivateTempDir::new("backup-path-authority").unwrap();
    let parent = work.path().join("runtime");
    let target = parent.join("secrets");
    let sibling = parent.join("other");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&sibling).unwrap();
    fs::write(target.join("marker"), b"current").unwrap();

    let backup_path = work.path().join("backup");
    fs::create_dir(&backup_path).unwrap();
    let file = File::create(backup_path.join("snapshot-0.tar")).unwrap();
    let mut archive = Builder::new(file);
    archive.append_dir_all("secrets", &target).unwrap();
    archive.finish().unwrap();
    fs::write(
        backup_path.join("snapshot-0.path"),
        format!("{}\n", sibling.display()),
    )
    .unwrap();
    complete_backup(&backup_path);

    let error = Backup { path: backup_path }
        .restore_snapshots(std::slice::from_ref(&target))
        .unwrap_err();
    assert!(error.to_string().contains("does not match"));
    assert_eq!(fs::read(target.join("marker")).unwrap(), b"current");
}

#[cfg(unix)]
#[test]
fn snapshot_restore_rejects_traversal_and_special_archive_entries() {
    for (name, entry_type) in [
        ("../escaped", EntryType::Regular),
        ("secrets/link", EntryType::Symlink),
    ] {
        let work = PrivateTempDir::new("backup-archive-boundary").unwrap();
        let parent = work.path().join("runtime");
        let target = parent.join("secrets");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("marker"), b"current").unwrap();
        let backup_path = work.path().join("backup");
        fs::create_dir(&backup_path).unwrap();
        let file = File::create(backup_path.join("snapshot-0.tar")).unwrap();
        let mut archive = Builder::new(file);

        let mut root = Header::new_gnu();
        root.set_entry_type(EntryType::Directory);
        root.set_size(0);
        root.set_cksum();
        archive.append_data(&mut root, "secrets", &[][..]).unwrap();
        let mut malicious = Header::new_gnu();
        malicious.set_entry_type(entry_type);
        malicious.set_size(0);
        let name = name.as_bytes();
        malicious.as_mut_bytes()[..name.len()].copy_from_slice(name);
        malicious.set_cksum();
        archive.append(&malicious, &[][..]).unwrap();
        archive.finish().unwrap();
        fs::write(
            backup_path.join("snapshot-0.path"),
            format!("{}\n", target.display()),
        )
        .unwrap();
        complete_backup(&backup_path);

        let error = Backup { path: backup_path }
            .restore_snapshots(std::slice::from_ref(&target))
            .unwrap_err();
        assert!(error.to_string().contains("unsafe") || error.to_string().contains("unsupported"));
        assert_eq!(fs::read(target.join("marker")).unwrap(), b"current");
        assert!(!parent.join("escaped").exists());
    }
}
