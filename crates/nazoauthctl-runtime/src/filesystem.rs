use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use sha2::{Digest, Sha256};

pub struct PrivateTempDir {
    path: PathBuf,
}

impl PrivateTempDir {
    pub fn new(prefix: &str) -> anyhow::Result<Self> {
        let root = std::env::temp_dir();
        for _ in 0..32 {
            let suffix = hex(&rand::random::<[u8; 12]>());
            let path = root.join(format!("{prefix}.{suffix}"));
            match fs::create_dir(&path) {
                Ok(()) => {
                    set_mode(&path, 0o700)?;
                    let canonical = fs::canonicalize(&path)
                        .inspect_err(|_| {
                            let _ = fs::remove_dir(&path);
                        })
                        .with_context(|| {
                            format!(
                                "failed to canonicalize private temporary directory {}",
                                path.display()
                            )
                        })?;
                    return Ok(Self { path: canonical });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to create {}", path.display()));
                }
            }
        }
        bail!("failed to allocate a unique private temporary directory")
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .context("atomic-write target has no parent directory")?;
    ensure_directory_chain(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        bail!(
            "atomic-write target is not a regular file: {}",
            path.display()
        );
    }
    // `std::fs::rename` cannot atomically replace an existing destination on
    // Windows. A two-rename fallback creates a power-loss window in which the
    // authoritative journal/configuration path does not exist. Keep the
    // replacement in one platform-native commit operation instead. The
    // implementation also anchors Unix operations to the opened parent
    // directory, so a concurrent ancestor rename cannot redirect the commit.
    let mut file = atomic_write_file::AtomicWriteFile::open(path)
        .with_context(|| format!("failed to stage atomic write for {}", path.display()))?;
    set_file_mode(file.as_file(), mode)?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write staged {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to persist staged {}", path.display()))?;
    file.commit()
        .with_context(|| format!("failed to atomically activate {}", path.display()))?;
    sync_parent(path)?;
    Ok(())
}

/// Open a controller-owned regular file without accepting a symlink, a hard
/// link, an unsafe ancestor, or a path replacement between the initial stat
/// and the open.  The returned descriptor is the object that must be read;
/// callers should not re-open the path after this function succeeds.
///
/// Unix ownership and permission checks are intentionally kept behind cfg so
/// the controller remains buildable on Windows, where these metadata concepts
/// do not have a portable std equivalent.  Windows callers therefore get
/// path/reparse-point validation, but this function does not claim an
/// owner-only ACL guarantee.
pub fn open_secure_regular_file(path: &Path, label: &str, private: bool) -> anyhow::Result<File> {
    open_secure_regular_file_with_owner(path, label, private, None)
}

/// Open a secure file that is intentionally owned by a known runtime service
/// account rather than by the controller. Root and the controller remain
/// accepted because installation and recovery may legitimately transition the
/// file before handing it to the service. No arbitrary third-party owner is
/// accepted, and the same policy is applied to every ancestor.
#[cfg(unix)]
pub fn open_secure_regular_file_for_uid(
    path: &Path,
    label: &str,
    private: bool,
    expected_owner_uid: u32,
) -> anyhow::Result<File> {
    open_secure_regular_file_with_owner(path, label, private, Some(expected_owner_uid))
}

fn open_secure_regular_file_with_owner(
    path: &Path,
    label: &str,
    private: bool,
    #[cfg_attr(not(unix), allow(unused_variables))] expected_owner_uid: Option<u32>,
) -> anyhow::Result<File> {
    validate_normalized_absolute_path(path, label)?;
    validate_secure_ancestors_for_owner(
        path.parent().context("secure file has no parent")?,
        label,
        expected_owner_uid,
    )?;
    let before = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    validate_secure_file_metadata(&before, path, label, private, expected_owner_uid)?;

    let mut options = OpenOptions::new();
    options.read(true);
    configure_secure_open(&mut options);
    let file = options
        .open(path)
        .with_context(|| format!("failed to open {label} {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("failed to inspect opened {label} {}", path.display()))?;
    validate_secure_file_metadata(&opened, path, label, private, expected_owner_uid)?;
    validate_same_file(&before, &opened, label)?;
    Ok(file)
}

/// Read a controller-owned regular file through the descriptor returned by
/// [`open_secure_regular_file`].  The path is resolved and validated once;
/// callers never re-open it after validation.  A hard byte limit is required
/// for every secret/configuration reader so a FIFO replacement or an
/// unexpectedly large file cannot consume unbounded memory.
pub fn read_secure_regular_file(
    path: &Path,
    label: &str,
    private: bool,
    max_bytes: u64,
) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut file = open_secure_regular_file(path, label, private)?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let mut limited = (&mut file).take(max_bytes.saturating_add(1));
    limited
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        bail!(
            "{label} exceeds the {max_bytes}-byte limit: {}",
            path.display()
        );
    }
    Ok(bytes)
}

#[cfg(unix)]
pub fn read_secure_regular_file_for_uid(
    path: &Path,
    label: &str,
    private: bool,
    max_bytes: u64,
    expected_owner_uid: u32,
) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut file = open_secure_regular_file_for_uid(path, label, private, expected_owner_uid)?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let mut limited = (&mut file).take(max_bytes.saturating_add(1));
    limited
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        bail!(
            "{label} exceeds the {max_bytes}-byte limit: {}",
            path.display()
        );
    }
    Ok(bytes)
}

/// Read a secret input whose service account may legitimately have a
/// read-only group ACL (for example root:service 0440).  Group/world write,
/// world read, execute bits, symlinks, hard links, and path races remain
/// rejected by the descriptor primitive and this additional policy check.
pub fn read_secure_secret_file(
    path: &Path,
    label: &str,
    max_bytes: u64,
) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut file = open_secure_regular_file(path, label, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let mode = file.metadata()?.mode() & 0o7777;
        if mode & 0o007 != 0 || mode & 0o111 != 0 || mode & 0o400 == 0 {
            bail!(
                "{label} has unsafe secret-file permissions: {}",
                path.display()
            );
        }
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let mut limited = (&mut file).take(max_bytes.saturating_add(1));
    limited
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        bail!(
            "{label} exceeds the {max_bytes}-byte limit: {}",
            path.display()
        );
    }
    Ok(bytes)
}

/// Validate a directory chain and, when present, the leaf directory.  A
/// missing leaf is allowed so lifecycle validation can run before a rehearsal
/// workspace is created; `ensure_private_directory` performs the create and
/// re-checks the result.
pub fn validate_secure_directory(path: &Path, label: &str, private: bool) -> anyhow::Result<()> {
    validate_normalized_absolute_path(path, label)?;
    validate_secure_ancestors(
        path.parent().context("secure directory has no parent")?,
        label,
    )?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || is_reparse_point(&metadata)
                || !metadata.is_dir()
            {
                bail!(
                    "{label} must be a regular non-symlink, non-reparse directory: {}",
                    path.display()
                );
            }
            validate_secure_directory_metadata(&metadata, path, label, private, None)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {label} {}", path.display()));
        }
    }
    Ok(())
}

/// Create a private directory chain and verify it after creation.  Existing
/// ancestors are never relaxed; only the requested leaf is made owner-only on
/// Unix.  On Windows, the standard library cannot inspect or enforce ACLs, so
/// `private` means the path is normalized and contains no symlink/reparse-point
/// component; callers must apply an external ACL policy when one is required.
pub fn ensure_private_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    validate_secure_directory(path, label, false)?;
    ensure_directory_chain(path)?;
    set_secure_directory_mode(path, label, 0o700)?;
    validate_secure_directory(path, label, true)
}

/// Open a lifecycle lock without following or replacing a symlink.  Creation
/// uses `create_new`; an existing entry is opened only after the same secure
/// metadata checks used by key and driver readers.
pub fn open_lock_file(path: &Path, read_only: bool, label: &str) -> anyhow::Result<File> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        bail!("{label} must be a normalized absolute path");
    }
    let parent = path.parent().context("lock path has no parent directory")?;
    if read_only {
        return open_secure_regular_file(path, label, true);
    }
    validate_secure_ancestors(parent, label)?;
    ensure_directory_chain(parent)?;
    validate_secure_ancestors(parent, label)?;

    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    configure_secure_open(&mut options);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = match options.open(path) {
        Ok(file) => {
            set_file_mode(&file, 0o600)?;
            file
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return open_secure_regular_file(path, label, true);
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to create {label} {}", path.display()));
        }
    };
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect opened {label} {}", path.display()))?;
    validate_secure_file_metadata(&metadata, path, label, true, None)?;
    Ok(file)
}

#[cfg(unix)]
fn set_secure_directory_mode(path: &Path, label: &str, mode: u32) -> anyhow::Result<()> {
    validate_secure_directory(path, label, false)?;
    let before = fs::symlink_metadata(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    configure_secure_open(&mut options);
    let file = options.open(path)?;
    let opened = file.metadata()?;
    validate_same_file(&before, &opened, label)?;
    set_file_mode(&file, mode)?;
    let after = fs::symlink_metadata(path)?;
    validate_same_file(&opened, &after, label)
}

#[cfg(not(unix))]
fn set_secure_directory_mode(path: &Path, label: &str, _mode: u32) -> anyhow::Result<()> {
    // Windows ACLs are not represented by the portable std metadata API.  Do
    // not open the directory as a regular File (which fails on Windows), and
    // do not silently present this branch as equivalent to Unix 0700.
    validate_secure_directory(path, label, false)
}

fn validate_secure_ancestors(path: &Path, label: &str) -> anyhow::Result<()> {
    validate_secure_ancestors_for_owner(path, label, None)
}

fn validate_secure_ancestors_for_owner(
    path: &Path,
    label: &str,
    #[cfg_attr(not(unix), allow(unused_variables))] expected_owner_uid: Option<u32>,
) -> anyhow::Result<()> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                    bail!(
                        "{label} path contains a symlink/reparse-point ancestor: {}",
                        candidate.display()
                    );
                }
                if !metadata.is_dir() {
                    bail!(
                        "{label} path ancestor is not a directory: {}",
                        candidate.display()
                    );
                }
                validate_secure_directory_metadata(
                    &metadata,
                    candidate,
                    label,
                    false,
                    expected_owner_uid,
                )?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect {label} ancestor {}", candidate.display())
                });
            }
        }
        current = candidate.parent();
    }
    Ok(())
}

fn validate_secure_file_metadata(
    metadata: &fs::Metadata,
    path: &Path,
    label: &str,
    private: bool,
    #[cfg_attr(not(unix), allow(unused_variables))] expected_owner_uid: Option<u32>,
) -> anyhow::Result<()> {
    if metadata.file_type().is_symlink() || is_reparse_point(metadata) || !metadata.is_file() {
        bail!(
            "{label} must be a regular non-symlink, non-reparse file: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode() & 0o7777;
        if !owner_is_allowed(metadata.uid(), expected_owner_uid) {
            bail!("{label} has an unexpected owner: {}", path.display());
        }
        if metadata.nlink() != 1 {
            bail!(
                "{label} must have exactly one hard link: {}",
                path.display()
            );
        }
        if mode & 0o022 != 0 {
            bail!(
                "{label} must not be group/world writable: {}",
                path.display()
            );
        }
        if private && (mode & 0o077 != 0 || mode & 0o400 == 0 || mode & 0o111 != 0) {
            bail!(
                "{label} must be owner-readable and private: {}",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, private);
    }
    Ok(())
}

fn validate_secure_directory_metadata(
    metadata: &fs::Metadata,
    path: &Path,
    label: &str,
    private: bool,
    #[cfg_attr(not(unix), allow(unused_variables))] expected_owner_uid: Option<u32>,
) -> anyhow::Result<()> {
    if metadata.file_type().is_symlink() || is_reparse_point(metadata) || !metadata.is_dir() {
        bail!(
            "{label} must be a regular non-symlink, non-reparse directory: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode() & 0o7777;
        if !owner_is_allowed(metadata.uid(), expected_owner_uid) {
            bail!("{label} has an unexpected owner: {}", path.display());
        }
        // A sticky system directory such as /tmp is safe as an ancestor: its
        // owner prevents another user from replacing entries owned by the
        // controller.  Non-sticky group/world-writable ancestors are unsafe.
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            bail!(
                "{label} has an unsafe writable ancestor: {}",
                path.display()
            );
        }
        if private && mode & 0o077 != 0 {
            bail!("{label} must be owner-only: {}", path.display());
        }
    }
    #[cfg(not(unix))]
    {
        // Windows ACLs have no portable owner/mode equivalent in std.  The
        // private flag is intentionally limited to the path and reparse-point
        // checks above; it must not be interpreted as an ACL assertion.
        let _ = (path, private);
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn validate_normalized_absolute_path(path: &Path, label: &str) -> anyhow::Result<()> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        bail!("{label} must be a normalized absolute path");
    }
    Ok(())
}

#[cfg(unix)]
fn owner_is_controller_or_root(uid: u32) -> bool {
    uid == 0 || current_uid() == Some(uid)
}

#[cfg(unix)]
fn owner_is_allowed(uid: u32, expected_owner_uid: Option<u32>) -> bool {
    owner_is_controller_or_root(uid) || expected_owner_uid == Some(uid)
}

#[cfg(unix)]
fn current_uid() -> Option<u32> {
    Some(rustix::process::geteuid().as_raw())
}

#[cfg(unix)]
fn validate_same_file(
    before: &fs::Metadata,
    opened: &fs::Metadata,
    label: &str,
) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if before.dev() != opened.dev() || before.ino() != opened.ino() {
        bail!("{label} changed while it was being opened");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_same_file(
    _before: &fs::Metadata,
    _opened: &fs::Metadata,
    _label: &str,
) -> anyhow::Result<()> {
    Ok(())
}

pub fn remove_file_durable(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        validate_directory_chain(parent)?;
    }
    match fs::remove_file(path) {
        Ok(()) => sync_parent(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

/// Ensure a path's directory chain contains no symlink or non-directory
/// component.  This is deliberately used immediately before every lock and
/// atomic write; `create_dir_all` by itself follows an attacker-controlled
/// symlink in an existing parent.
pub fn ensure_directory_chain(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        ensure_directory_chain_at(path)
    }
    #[cfg(not(unix))]
    {
        validate_directory_chain(path)?;
        fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))?;
        validate_directory_chain(path)
    }
}

/// Walk the Unix directory chain through directory descriptors. Each child is
/// opened with `O_NOFOLLOW` relative to the already-open parent, so a rename or
/// symlink substitution cannot redirect creation between a path check and
/// `mkdir`.
#[cfg(unix)]
fn ensure_directory_chain_at(path: &Path) -> anyhow::Result<()> {
    use rustix::fs::{Mode, OFlags, fsync, mkdirat, openat};

    let start = if path.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = openat(rustix::fs::CWD, start, flags, Mode::empty())
        .with_context(|| format!("failed to anchor directory chain for {}", path.display()))?;
    for component in path.components() {
        let name = match component {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(name) => name,
            std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                bail!("directory chain is not normalized: {}", path.display())
            }
        };
        let next = match openat(&directory, name, flags, Mode::empty()) {
            Ok(next) => next,
            Err(rustix::io::Errno::NOENT) => {
                mkdirat(&directory, name, Mode::RWXU).with_context(|| {
                    format!(
                        "failed to create directory component for {}",
                        path.display()
                    )
                })?;
                fsync(&directory).with_context(|| {
                    format!(
                        "failed to persist directory component for {}",
                        path.display()
                    )
                })?;
                openat(&directory, name, flags, Mode::empty()).with_context(|| {
                    format!(
                        "failed to open created directory component for {}",
                        path.display()
                    )
                })?
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("unsafe directory component in {}", path.display()));
            }
        };
        directory = next;
    }
    Ok(())
}

pub fn validate_directory_chain(path: &Path) -> anyhow::Result<()> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                    bail!(
                        "directory path contains a symlink/reparse-point: {}",
                        candidate.display()
                    );
                }
                if !metadata.is_dir() {
                    bail!(
                        "directory path component is not a directory: {}",
                        candidate.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", candidate.display()));
            }
        }
        current = candidate.parent();
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> anyhow::Result<()> {
    let parent = path.parent().context("path has no parent directory")?;
    File::open(parent)
        .with_context(|| format!("failed to open {} for synchronization", parent.display()))?
        .sync_all()
        .with_context(|| format!("failed to synchronize {}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

pub fn copy_atomic(source: &Path, target: &Path, mode: u32) -> anyhow::Result<()> {
    let mut source = open_secure_regular_file(source, "atomic-copy source", false)?;
    copy_atomic_from_file(&mut source, target, mode)
}

/// Verify and activate exactly the same opened source object. This is the
/// required boundary for signed artifacts: a path digest followed by a second
/// path open would allow a replacement between verification and persistence.
pub fn copy_atomic_verified(
    source: &Path,
    target: &Path,
    mode: u32,
    expected_sha256: &str,
) -> anyhow::Result<()> {
    let mut source = open_secure_regular_file(source, "verified atomic-copy source", false)?;
    let actual = sha256_file(&mut source, "verified atomic-copy source")?;
    if actual != expected_sha256 {
        bail!("atomic-copy source does not match the expected SHA-256 digest");
    }
    copy_atomic_from_file(&mut source, target, mode)
}

/// Copy an already-validated source descriptor into an atomic target.  The
/// descriptor is rewound rather than reopening the source path, so callers
/// that validated a digest cannot be redirected to a replacement path between
/// validation and activation.
pub fn copy_atomic_from_file(source: &mut File, target: &Path, mode: u32) -> anyhow::Result<()> {
    source
        .rewind()
        .context("failed to rewind validated source before activation")?;
    let parent = target
        .parent()
        .context("atomic-copy target has no parent directory")?;
    ensure_directory_chain(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(target)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        bail!(
            "atomic-copy target is not a regular file: {}",
            target.display()
        );
    }
    let mut staged = atomic_write_file::AtomicWriteFile::open(target)
        .with_context(|| format!("failed to stage atomic copy for {}", target.display()))?;
    set_file_mode(staged.as_file(), mode)?;
    std::io::copy(source, &mut staged)
        .with_context(|| format!("failed to copy validated source to {}", target.display()))?;
    staged
        .sync_all()
        .with_context(|| format!("failed to persist staged copy for {}", target.display()))?;
    staged
        .commit()
        .with_context(|| format!("failed to activate atomic copy for {}", target.display()))?;
    sync_parent(target)
}

pub fn generate_secret(path: &Path) -> anyhow::Result<zeroize::Zeroizing<String>> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let parent = path.parent().context("persisted secret has no parent")?;
            validate_secure_directory(parent, "persisted secret directory", true)?;
            // Managed dependency files are deliberately 0444 inside an
            // owner-only 0700 directory because OCI bind mounts retain host
            // ownership while the dependency image reads them as its own UID.
            // The private ancestor supplies the confidentiality boundary; the
            // descriptor primitive still rejects links, replacement and
            // writable files.
            let bytes = read_secure_regular_file(path, "persisted managed secret", false, 4096)?;
            let value = String::from_utf8(bytes.to_vec())
                .with_context(|| format!("persisted secret is not UTF-8: {}", path.display()))?;
            if value.is_empty() || value.contains(['\n', '\r', '\0']) {
                bail!("persisted secret is invalid: {}", path.display());
            }
            Ok(zeroize::Zeroizing::new(value))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let value = zeroize::Zeroizing::new(hex(&rand::random::<[u8; 32]>()));
            atomic_write(path, value.as_bytes(), 0o440)?;
            Ok(value)
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect persisted secret {}", path.display())),
    }
}

pub fn sha256(path: &Path) -> anyhow::Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let description = path.display().to_string();
    sha256_file(&mut file, &description)
}

fn configure_secure_open(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = options;
}

pub fn sha256_file(file: &mut File, description: &str) -> anyhow::Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to hash {description}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex(&digest.finalize()))
}

#[cfg(unix)]
pub fn set_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    let mut options = OpenOptions::new();
    options.read(true);
    configure_secure_open(&mut options);
    let file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    set_file_mode(&file, mode)
}

#[cfg(not(unix))]
pub fn set_mode(_path: &Path, _mode: u32) -> anyhow::Result<()> {
    Ok(())
}

fn set_file_mode(file: &File, mode: u32) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .context("failed to set file permissions")?;
    }
    #[cfg(not(unix))]
    let _ = (file, mode);
    Ok(())
}

pub fn symlink_atomic(target: &Path, link: &Path) -> anyhow::Result<()> {
    let next = link.with_extension(format!("next-{}", uuid::Uuid::now_v7()));
    create_symlink(target, &next)?;
    if let Err(error) = fs::rename(&next, link) {
        let cleanup = fs::remove_file(&next);
        if let Err(cleanup) = cleanup {
            return Err(error).with_context(|| {
                format!(
                    "failed to activate symlink {} and failed to remove unique staged link {}: {cleanup}",
                    link.display(),
                    next.display()
                )
            });
        }
        return Err(error)
            .with_context(|| format!("failed to activate symlink {}", link.display()));
    }
    sync_parent(link)
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> anyhow::Result<()> {
    std::os::unix::fs::symlink(target, link)
        .with_context(|| format!("failed to create symlink {}", link.display()))
}

#[cfg(windows)]
fn create_symlink(target: &Path, link: &Path) -> anyhow::Result<()> {
    if target.is_dir() {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    }
    .with_context(|| format!("failed to create symlink {}", link.display()))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
#[path = "../../../tests/unit/filesystem.rs"]
mod tests;
