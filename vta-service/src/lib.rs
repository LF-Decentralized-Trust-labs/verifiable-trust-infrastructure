//! VTA (Verifiable Trust Agent) service library.
//!
//! This is the shared business logic used by both the `vta` binary
//! (local/dev/cloud) and the `vta-enclave` binary (Nitro Enclave).
//!
//! Front-end binaries import this library and call `server::run()`
//! with the appropriate store backend and TEE context.

pub mod acl;
pub mod audit;
pub mod auth;
pub mod config;
pub mod contexts;
pub mod didcomm_bridge;
pub mod error;
pub mod keys;
#[cfg(feature = "didcomm")]
pub mod messaging;
pub mod operations;
#[cfg(feature = "rest")]
pub mod routes;
pub mod seal;
pub mod server;
pub mod status;
pub mod store;
#[cfg(feature = "tee")]
pub mod tee;
#[cfg(feature = "webvh")]
pub mod webvh_client;
#[cfg(feature = "webvh")]
pub mod webvh_didcomm;
#[cfg(feature = "webvh")]
pub mod webvh_store;
