use bytes::Bytes;
use std::borrow::Cow;

/// Owns received HTTP frames without copying their payloads into a single buffer.
#[derive(Clone, Default)]
pub struct ResponseBody {
    first: Bytes,
    rest: Vec<Bytes>,
}

impl From<Bytes> for ResponseBody {
    fn from(first: Bytes) -> Self {
        Self {
            first,
            rest: Vec::new(),
        }
    }
}

impl From<Vec<u8>> for ResponseBody {
    fn from(value: Vec<u8>) -> Self {
        Bytes::from(value).into()
    }
}

impl ResponseBody {
    pub fn push(&mut self, frame: Bytes) {
        if frame.is_empty() {
            return;
        }
        if self.first.is_empty() {
            self.first = frame;
        } else {
            self.rest.push(frame);
        }
    }

    pub fn len(&self) -> usize {
        self.first.len() + self.rest.iter().map(Bytes::len).sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        self.first.is_empty()
    }

    pub fn chunks(&self) -> impl Iterator<Item = &[u8]> + Clone {
        std::iter::once(self.first.as_ref()).chain(self.rest.iter().map(Bytes::as_ref))
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> serde_json::Result<T> {
        if self.rest.is_empty() {
            serde_json::from_slice(&self.first)
        } else {
            let mut deserializer = serde_json::Deserializer::from_chunks(self.chunks());
            let value = T::deserialize(&mut deserializer)?;
            deserializer.end()?;
            Ok(value)
        }
    }

    /// Only consumers requiring contiguous input (the Suite HTML regex) join frames.
    pub fn contiguous(&self) -> Cow<'_, [u8]> {
        if self.rest.is_empty() {
            Cow::Borrowed(&self.first)
        } else {
            let mut bytes = Vec::with_capacity(self.len());
            for chunk in self.chunks() {
                bytes.extend_from_slice(chunk);
            }
            Cow::Owned(bytes)
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/http_body.rs"]
mod tests;
