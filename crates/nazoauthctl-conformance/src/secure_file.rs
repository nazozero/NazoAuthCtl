//! Shared secure file primitives for credentials, private evidence, bundles,
//! and matrix inputs.  The caller chooses whether the final directory/file is
//! private; the path and descriptor checks are shared so a new persistence
//! call cannot accidentally reintroduce a weaker implementation.

use std::fs;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use rand_core::{OsRng, RngCore as _};
#[cfg(unix)]
use rustix::fs::{CWD, Mode, OFlags};
#[cfg(unix)]
use std::{
    fs::File,
    io::{Read as _, Write as _},
};

#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum SecureFileError {
    // This is emitted by the Windows/unsupported-platform branches and must
    // remain part of the shared error contract even though Unix builds cannot
    // construct it.
    #[allow(dead_code)]
    UnsupportedPlatform,
    NotFound,
    Oversize,
    UnsafePath,
    Io,
}

/// Return a lexical absolute path.  Parent components are rejected rather
/// than normalized through an attacker-controlled symlink.
pub(crate) fn normalize_absolute(path: &Path) -> Result<PathBuf, SecureFileError> {
    let source = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| SecureFileError::Io)?
            .join(path)
    };
    let mut result = PathBuf::new();
    for component in source.components() {
        match component {
            Component::Prefix(prefix) => result.push(prefix.as_os_str()),
            Component::RootDir => result.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::Normal(value) => result.push(value),
            Component::ParentDir => return Err(SecureFileError::UnsafePath),
        }
    }
    if result.as_os_str().is_empty() {
        return Err(SecureFileError::UnsafePath);
    }
    Ok(result)
}

/// Ensure a directory exists one component at a time.  No ancestor may be a
/// symlink, and owner/mode checks are applied before and after creation.
pub(crate) fn ensure_directory(path: &Path, private: bool) -> Result<PathBuf, SecureFileError> {
    let absolute = normalize_absolute(path)?;
    #[cfg(all(not(unix), windows))]
    if private {
        return Err(SecureFileError::UnsupportedPlatform);
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = private;
        return Err(SecureFileError::UnsupportedPlatform);
    }
    #[cfg(windows)]
    {
        fs::create_dir_all(&absolute).map_err(|_| SecureFileError::Io)?;
        let metadata = fs::symlink_metadata(&absolute).map_err(|_| SecureFileError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SecureFileError::UnsafePath);
        }
        Ok(absolute)
    }
    #[cfg(unix)]
    {
        let _ = open_directory_chain(&absolute, private, true)?;
        Ok(absolute)
    }
}

/// Atomically replace a regular file.  The temporary is random, owner-only,
/// fsynced before rename, and its parent is fsynced after rename.
pub(crate) fn write_atomic(
    path: &Path,
    bytes: &[u8],
    private: bool,
) -> Result<(), SecureFileError> {
    let absolute = normalize_absolute(path)?;
    let parent = absolute.parent().ok_or(SecureFileError::UnsafePath)?;
    ensure_directory(parent, private)?;
    #[cfg(all(not(unix), windows))]
    if private {
        return Err(SecureFileError::UnsupportedPlatform);
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = (bytes, private);
        return Err(SecureFileError::UnsupportedPlatform);
    }
    #[cfg(windows)]
    {
        let _ = bytes;
        Err(SecureFileError::UnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        let parent_file = open_directory_chain(parent, private, false)?;
        let target_name = absolute
            .file_name()
            .ok_or(SecureFileError::UnsafePath)?
            .to_owned();
        match openat_file(&parent_file, &target_name, OFlags::RDONLY) {
            Ok(target) => validate_file_metadata(
                &target.metadata().map_err(|_| SecureFileError::Io)?,
                private,
            )?,
            Err(SecureFileError::NotFound) => {}
            Err(error) => return Err(error),
        }
        let file_name = target_name.to_string_lossy();
        let mut random = [0u8; 16];
        for _ in 0..16 {
            OsRng.fill_bytes(&mut random);
            let temporary = parent.join(format!(".{file_name}.tmp-{}", hex_suffix(&random)));
            let temp_name = temporary
                .file_name()
                .ok_or(SecureFileError::UnsafePath)?
                .to_owned();
            let owned = match rustix::fs::openat(
                &parent_file,
                &temp_name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(if private { 0o600 } else { 0o644 }),
            ) {
                Ok(handle) => handle,
                Err(error) if error.raw_os_error() == libc::EEXIST => continue,
                Err(_) => return Err(SecureFileError::Io),
            };
            let mut handle = File::from(owned);
            let result = (|| {
                handle.write_all(bytes).map_err(|_| SecureFileError::Io)?;
                rustix::fs::fsync(&handle).map_err(|_| SecureFileError::Io)?;
                rustix::fs::renameat(&parent_file, &temp_name, &parent_file, &target_name)
                    .map_err(|_| SecureFileError::Io)?;
                rustix::fs::fsync(&parent_file).map_err(|_| SecureFileError::Io)
            })();
            if result.is_err() {
                let _ =
                    rustix::fs::unlinkat(&parent_file, &temp_name, rustix::fs::AtFlags::empty());
            }
            return result;
        }
        Err(SecureFileError::Io)
    }
}

/// Open and read a bounded regular file with O_NOFOLLOW.  Metadata is checked
/// both before and after reading, preventing replacement races from being
/// mistaken for a successful read.
pub(crate) fn read_bounded(
    path: &Path,
    max_bytes: usize,
    private: bool,
) -> Result<Vec<u8>, SecureFileError> {
    let absolute = normalize_absolute(path)?;
    let parent = absolute.parent().ok_or(SecureFileError::UnsafePath)?;
    #[cfg(all(not(unix), windows))]
    if private {
        return Err(SecureFileError::UnsupportedPlatform);
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = max_bytes;
        return Err(SecureFileError::UnsupportedPlatform);
    }
    #[cfg(unix)]
    let mut file = {
        let parent_file = open_directory_chain(parent, private, false)?;
        let name = absolute.file_name().ok_or(SecureFileError::UnsafePath)?;
        openat_file(&parent_file, name, OFlags::RDONLY)?
            .try_clone()
            .map_err(|_| SecureFileError::Io)?
    };
    #[cfg(windows)]
    {
        let _ = (&absolute, parent, max_bytes, private);
        Err(SecureFileError::UnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        let before = file.metadata().map_err(|_| SecureFileError::Io)?;
        let opened = file.metadata().map_err(|_| SecureFileError::Io)?;
        validate_file_metadata(&opened, private)?;
        if !same_file(&before, &opened) {
            return Err(SecureFileError::UnsafePath);
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(max_bytes.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| SecureFileError::Io)?;
        if bytes.len() > max_bytes {
            return Err(SecureFileError::Oversize);
        }
        let after = file.metadata().map_err(|_| SecureFileError::Io)?;
        if !same_file(&opened, &after) {
            return Err(SecureFileError::UnsafePath);
        }
        Ok(bytes)
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = (&absolute, parent, max_bytes, private);
        Err(SecureFileError::UnsupportedPlatform)
    }
}

/// Read an inherited regular descriptor.  `/proc/self/fd/N` is a kernel
/// descriptor alias (not an attacker-selected path); identity is checked on
/// the opened handle and again after the bounded read.
#[cfg(unix)]
pub(crate) fn read_descriptor(
    fd: u32,
    max_bytes: usize,
    private: bool,
) -> Result<Vec<u8>, SecureFileError> {
    if fd < 3 {
        return Err(SecureFileError::UnsafePath);
    }
    let path = format!("/proc/self/fd/{fd}");
    let mut file = File::open(path).map_err(|_| SecureFileError::Io)?;
    let before = file.metadata().map_err(|_| SecureFileError::Io)?;
    validate_descriptor_metadata(&before, private)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SecureFileError::Io)?;
    if bytes.len() > max_bytes {
        return Err(SecureFileError::Oversize);
    }
    let after = file.metadata().map_err(|_| SecureFileError::Io)?;
    if !same_file(&before, &after) {
        return Err(SecureFileError::UnsafePath);
    }
    Ok(bytes)
}

#[cfg(unix)]
pub(crate) fn remove_file(path: &Path, private: bool) -> Result<(), SecureFileError> {
    let absolute = normalize_absolute(path)?;
    let parent = absolute.parent().ok_or(SecureFileError::UnsafePath)?;
    #[cfg(unix)]
    {
        let parent_file = open_directory_chain(parent, private, false)?;
        let name = absolute.file_name().ok_or(SecureFileError::UnsafePath)?;
        let file = openat_file(&parent_file, name, OFlags::RDONLY)?;
        validate_file_metadata(&file.metadata().map_err(|_| SecureFileError::Io)?, private)?;
        rustix::fs::unlinkat(&parent_file, name, rustix::fs::AtFlags::empty())
            .map_err(|_| SecureFileError::Io)
    }
}

#[cfg(unix)]
fn open_directory_chain(path: &Path, private: bool, create: bool) -> Result<File, SecureFileError> {
    let absolute = normalize_absolute(path)?;
    let mut directory = File::from(
        rustix::fs::openat(
            CWD,
            Path::new("/"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_errno)?,
    );
    let components = absolute.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            continue;
        };
        let final_component = index + 1 == components.len();
        let next = match rustix::fs::openat(
            &directory,
            Path::new(name),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(next) => next,
            Err(error) if error.raw_os_error() == libc::ENOENT && create => {
                rustix::fs::mkdirat(
                    &directory,
                    Path::new(name),
                    Mode::from_raw_mode(if private && final_component {
                        0o700
                    } else {
                        0o755
                    }),
                )
                .map_err(map_errno)?;
                rustix::fs::openat(
                    &directory,
                    Path::new(name),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(map_errno)?
            }
            Err(error) => return Err(map_errno(error)),
        };
        let next = File::from(next);
        let metadata = next.metadata().map_err(|_| SecureFileError::Io)?;
        validate_directory_metadata(&metadata, private && final_component)?;
        directory = next;
    }
    let metadata = directory.metadata().map_err(|_| SecureFileError::Io)?;
    validate_directory_metadata(&metadata, private && components.len() <= 1)?;
    Ok(directory)
}

#[cfg(unix)]
fn openat_file<F: rustix::fd::AsFd>(
    directory: F,
    name: &std::ffi::OsStr,
    flags: OFlags,
) -> Result<File, SecureFileError> {
    rustix::fs::openat(
        directory,
        Path::new(name),
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(map_errno)
}

#[cfg(unix)]
fn map_errno(error: rustix::io::Errno) -> SecureFileError {
    match error.raw_os_error() {
        libc::ENOENT => SecureFileError::NotFound,
        libc::ELOOP | libc::ENOTDIR | libc::EACCES | libc::EPERM => SecureFileError::UnsafePath,
        _ => SecureFileError::Io,
    }
}

#[cfg(unix)]
fn validate_directory_metadata(
    metadata: &fs::Metadata,
    private: bool,
) -> Result<(), SecureFileError> {
    use std::os::unix::fs::MetadataExt;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || !owner_is_current_or_root(metadata.uid())
    {
        return Err(SecureFileError::UnsafePath);
    }
    let mode = metadata.mode();
    if private {
        if mode & 0o077 != 0 {
            return Err(SecureFileError::UnsafePath);
        }
    } else if mode & 0o002 != 0 && mode & 0o1000 == 0 {
        return Err(SecureFileError::UnsafePath);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_file_metadata(metadata: &fs::Metadata, private: bool) -> Result<(), SecureFileError> {
    use std::os::unix::fs::MetadataExt;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || !owner_is_current_or_root(metadata.uid())
    {
        return Err(SecureFileError::UnsafePath);
    }
    let mode = metadata.mode();
    if private {
        if mode & 0o077 != 0 || mode & 0o400 == 0 {
            return Err(SecureFileError::UnsafePath);
        }
    } else if mode & 0o002 != 0 {
        return Err(SecureFileError::UnsafePath);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_descriptor_metadata(
    metadata: &fs::Metadata,
    private: bool,
) -> Result<(), SecureFileError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    if metadata.file_type().is_fifo() {
        if !owner_is_current_or_root(metadata.uid()) || (private && metadata.mode() & 0o077 != 0) {
            return Err(SecureFileError::UnsafePath);
        }
        return Ok(());
    }
    validate_file_metadata(metadata, private)
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
fn owner_is_current_or_root(uid: u32) -> bool {
    uid == 0 || rustix::process::geteuid().as_raw() == uid
}

#[cfg(unix)]
fn hex_suffix(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(all(test, unix))]
mod tests {
    #[test]
    fn current_effective_user_is_an_accepted_owner() {
        let current = rustix::process::geteuid().as_raw();
        assert!(super::owner_is_current_or_root(current));
        assert!(super::owner_is_current_or_root(0));
    }
}
