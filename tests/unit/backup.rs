#[cfg(unix)]
use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::{MetadataExt, chown},
};

#[cfg(unix)]
use super::{Backup, Builder};

#[cfg(unix)]
use crate::filesystem::PrivateTempDir;

#[cfg(unix)]
#[test]
fn snapshot_restore_preserves_numeric_ownership_when_running_as_root() {
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

    Backup { path: backup_path }.restore_snapshots().unwrap();

    let directory = fs::metadata(&target).unwrap();
    let restored_secret = fs::metadata(&secret).unwrap();
    assert_eq!((directory.uid(), directory.gid()), (10001, 10001));
    assert_eq!(
        (restored_secret.uid(), restored_secret.gid()),
        (10001, 10001)
    );
}
