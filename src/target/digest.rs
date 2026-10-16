use std::io;

use sha2::{Digest as _, Sha256};

/// Hash serialized bytes directly, without retaining a second document buffer.
#[derive(Default)]
pub(super) struct Sha256Writer(Sha256);

impl Sha256Writer {
    pub(super) fn finish(self) -> String {
        hex::encode(self.0.finalize())
    }
}

impl io::Write for Sha256Writer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
