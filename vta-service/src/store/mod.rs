// Re-export the core store types. When vsock-store is active, also export
// the vsock-backed types for use in TEE mode.
pub use vti_common::store::*;

#[cfg(feature = "vsock-store")]
pub use vti_common::store::vsock::{
    VsockKeyspaceHandle, VsockStore,
    file_exists, file_read, file_write,
};
