//! Windows implementation of the secure filesystem primitives.
//!
//! The implementation is kept in the historical sibling file while this
//! path is the platform boundary advertised by the runtime crate.  Keeping a
//! single included implementation avoids two divergent unsafe code paths.

include!("../windows.rs");
