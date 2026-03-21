pub use vti_common::store::*;

// Re-export vsock store types and file I/O functions at the top level
// so they're accessible as crate::store::VsockStore, crate::store::file_read, etc.
#[cfg(feature = "vsock-store")]
pub use vti_common::store::vsock::{VsockKeyspaceHandle, VsockStore, file_exists, file_read, file_write};
