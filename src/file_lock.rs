use std::{fs::File, path::Path};

use anyhow::Context as _;
use fs2::FileExt as _;

use crate::filesystem::open_lock_file;

pub(crate) struct FileLock {
    file: File,
}

impl FileLock {
    pub(crate) fn acquire(path: &Path) -> anyhow::Result<Self> {
        let file = open_lock_file(path, false, "operation lock")?;
        file.try_lock_exclusive()
            .with_context(|| format!("another operation holds {}", path.display()))?;
        Ok(Self { file })
    }

    pub(crate) fn acquire_shared(path: &Path) -> anyhow::Result<Self> {
        let file = open_lock_file(path, false, "operation lock")?;
        file.try_lock_shared()
            .with_context(|| format!("another operation holds {}", path.display()))?;
        Ok(Self { file })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}
