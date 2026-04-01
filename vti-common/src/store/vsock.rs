//! Vsock-backed key-value store for Nitro Enclaves.
//!
//! Sends all storage operations over vsock to the parent EC2 instance,
//! which persists them to fjall on its EBS volume. Data is encrypted
//! enclave-side before crossing vsock — the parent only sees opaque blobs.

use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::error::AppError;

// ---------------------------------------------------------------------------
// Wire protocol (duplicated from enclave-proxy/src/protocol.rs to avoid
// a shared crate dependency — the proxy is a standalone non-workspace crate)
// ---------------------------------------------------------------------------

const OP_GET: u8 = 0x01;
const OP_INSERT: u8 = 0x02;
const OP_DELETE: u8 = 0x03;
const OP_PREFIX_ITER: u8 = 0x04;
const OP_PREFIX_KEYS: u8 = 0x05;
const OP_PERSIST: u8 = 0x06;

const STATUS_OK: u8 = 0x00;
const STATUS_NOT_FOUND: u8 = 0x01;
const STATUS_ERROR: u8 = 0x02;

const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

fn encode_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

fn decode_bytes(data: &[u8], offset: usize) -> Result<(&[u8], usize), String> {
    if offset + 4 > data.len() {
        return Err("truncated length".into());
    }
    let len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    let start = offset + 4;
    let end = start + len;
    if end > data.len() {
        return Err(format!("truncated data at offset {start}"));
    }
    Ok((&data[start..end], end))
}

fn encode_keyspace(buf: &mut Vec<u8>, name: &str) {
    buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
    buf.extend_from_slice(name.as_bytes());
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// A connection to the parent's storage proxy over vsock.
struct VsockConnection {
    stream: tokio_vsock::VsockStream,
}

impl VsockConnection {
    async fn connect(cid: u32, port: u32) -> Result<Self, AppError> {
        let addr = tokio_vsock::VsockAddr::new(cid, port);
        let stream = tokio_vsock::VsockStream::connect(addr).await.map_err(|e| {
            AppError::Internal(format!("vsock connect to CID {cid}:{port} failed: {e}"))
        })?;
        Ok(Self { stream })
    }

    async fn request(&mut self, payload: &[u8]) -> Result<Vec<u8>, AppError> {
        // Write frame
        self.stream
            .write_u32(payload.len() as u32)
            .await
            .map_err(|e| AppError::Internal(format!("vsock write error: {e}")))?;
        self.stream
            .write_all(payload)
            .await
            .map_err(|e| AppError::Internal(format!("vsock write error: {e}")))?;
        self.stream
            .flush()
            .await
            .map_err(|e| AppError::Internal(format!("vsock flush error: {e}")))?;

        // Read frame
        let len = self
            .stream
            .read_u32()
            .await
            .map_err(|e| AppError::Internal(format!("vsock read error: {e}")))?;
        if len > MAX_MESSAGE_SIZE {
            return Err(AppError::Internal(format!("response too large: {len}")));
        }
        let mut buf = vec![0u8; len as usize];
        self.stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| AppError::Internal(format!("vsock read error: {e}")))?;
        Ok(buf)
    }
}

// ---------------------------------------------------------------------------
// VsockStore
// ---------------------------------------------------------------------------

/// CID 3 = parent/host in Nitro Enclaves.
const PARENT_CID: u32 = 3;
/// Default vsock port for the storage proxy.
const DEFAULT_STORAGE_PORT: u32 = 5500;

/// A key-value store backed by the parent's storage proxy over vsock.
///
/// Drop-in replacement for `Store` when running inside a Nitro Enclave.
#[derive(Clone)]
pub struct VsockStore {
    conn: Arc<Mutex<Option<VsockConnection>>>,
    port: u32,
}

impl VsockStore {
    /// Connect to the parent's storage proxy.
    pub async fn connect(port: Option<u32>) -> Result<Self, AppError> {
        let port = port.unwrap_or(DEFAULT_STORAGE_PORT);
        let conn = VsockConnection::connect(PARENT_CID, port).await?;
        info!(port, "connected to parent storage proxy via vsock");
        Ok(Self {
            conn: Arc::new(Mutex::new(Some(conn))),
            port,
        })
    }

    /// Get a keyspace handle. No RPC needed — the keyspace name is sent
    /// with each operation.
    pub fn keyspace(&self, name: &str) -> Result<VsockKeyspaceHandle, AppError> {
        Ok(VsockKeyspaceHandle {
            conn: Arc::clone(&self.conn),
            port: self.port,
            keyspace: name.to_string(),
            #[cfg(feature = "encryption")]
            encryption_key: None,
        })
    }

    /// Flush the parent's store to disk.
    pub async fn persist(&self) -> Result<(), AppError> {
        let payload = vec![OP_PERSIST];
        let resp = self.send(&payload).await?;
        decode_ok(&resp)
    }

    /// Send a request, reconnecting once on failure.
    async fn send(&self, payload: &[u8]) -> Result<Vec<u8>, AppError> {
        let mut guard = self.conn.lock().await;

        // Try on existing connection
        if let Some(ref mut conn) = *guard {
            match conn.request(payload).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    warn!("storage request failed, reconnecting: {e}");
                    *guard = None;
                }
            }
        }

        // Reconnect
        let mut conn = VsockConnection::connect(PARENT_CID, self.port).await?;
        let resp = conn.request(payload).await?;
        *guard = Some(conn);
        Ok(resp)
    }
}

// ---------------------------------------------------------------------------
// VsockKeyspaceHandle
// ---------------------------------------------------------------------------

/// Handle to a keyspace on the parent's storage proxy.
///
/// Same API as `KeyspaceHandle` — get, insert, remove, prefix_iter, etc.
/// Encryption is applied enclave-side before sending over vsock.
#[derive(Clone)]
pub struct VsockKeyspaceHandle {
    conn: Arc<Mutex<Option<VsockConnection>>>,
    port: u32,
    keyspace: String,
    #[cfg(feature = "encryption")]
    encryption_key: Option<Arc<zeroize::Zeroizing<[u8; 32]>>>,
}

/// Raw key-value pair type (same as in the local store).
pub type RawKvPair = (Vec<u8>, Vec<u8>);

impl VsockKeyspaceHandle {
    /// Return a clone with AES-256-GCM encryption enabled.
    #[cfg(feature = "encryption")]
    pub fn with_encryption(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(Arc::new(zeroize::Zeroizing::new(key)));
        self
    }

    pub fn is_encrypted(&self) -> bool {
        #[cfg(feature = "encryption")]
        {
            self.encryption_key.is_some()
        }
        #[cfg(not(feature = "encryption"))]
        {
            false
        }
    }

    pub async fn insert<V: Serialize>(
        &self,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<(), AppError> {
        let key = key.into();
        let bytes = serde_json::to_vec(value)?;
        let bytes = self.maybe_encrypt(bytes)?;
        let mut payload = vec![OP_INSERT];
        encode_keyspace(&mut payload, &self.keyspace);
        encode_bytes(&mut payload, &key);
        encode_bytes(&mut payload, &bytes);
        let resp = self.send(&payload).await?;
        decode_ok(&resp)
    }

    pub async fn get<V: DeserializeOwned + Send + 'static>(
        &self,
        key: impl Into<Vec<u8>>,
    ) -> Result<Option<V>, AppError> {
        let key = key.into();
        let mut payload = vec![OP_GET];
        encode_keyspace(&mut payload, &self.keyspace);
        encode_bytes(&mut payload, &key);
        let resp = self.send(&payload).await?;
        match decode_value(&resp)? {
            Some(bytes) => {
                let bytes = self.maybe_decrypt(&bytes)?;
                Ok(Some(serde_json::from_slice(&bytes)?))
            }
            None => Ok(None),
        }
    }

    pub async fn remove(&self, key: impl Into<Vec<u8>>) -> Result<(), AppError> {
        let key = key.into();
        let mut payload = vec![OP_DELETE];
        encode_keyspace(&mut payload, &self.keyspace);
        encode_bytes(&mut payload, &key);
        let resp = self.send(&payload).await?;
        decode_ok(&resp)
    }

    pub async fn insert_raw(
        &self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<(), AppError> {
        let key = key.into();
        let value = self.maybe_encrypt(value.into())?;
        let mut payload = vec![OP_INSERT];
        encode_keyspace(&mut payload, &self.keyspace);
        encode_bytes(&mut payload, &key);
        encode_bytes(&mut payload, &value);
        let resp = self.send(&payload).await?;
        decode_ok(&resp)
    }

    pub async fn get_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        let key = key.into();
        let mut payload = vec![OP_GET];
        encode_keyspace(&mut payload, &self.keyspace);
        encode_bytes(&mut payload, &key);
        let resp = self.send(&payload).await?;
        match decode_value(&resp)? {
            Some(bytes) => Ok(Some(self.maybe_decrypt(&bytes)?)),
            None => Ok(None),
        }
    }

    pub async fn prefix_iter_raw(
        &self,
        prefix: impl Into<Vec<u8>>,
    ) -> Result<Vec<RawKvPair>, AppError> {
        let prefix = prefix.into();
        let mut payload = vec![OP_PREFIX_ITER];
        encode_keyspace(&mut payload, &self.keyspace);
        encode_bytes(&mut payload, &prefix);
        let resp = self.send(&payload).await?;
        let pairs = decode_kv_list(&resp)?;
        // Decrypt values
        pairs
            .into_iter()
            .map(|(k, v)| {
                let v = self.maybe_decrypt(&v)?;
                Ok((k, v))
            })
            .collect()
    }

    pub async fn prefix_keys(&self, prefix: impl Into<Vec<u8>>) -> Result<Vec<Vec<u8>>, AppError> {
        let prefix = prefix.into();
        let mut payload = vec![OP_PREFIX_KEYS];
        encode_keyspace(&mut payload, &self.keyspace);
        encode_bytes(&mut payload, &prefix);
        let resp = self.send(&payload).await?;
        decode_key_list(&resp)
    }

    pub async fn approximate_len(&self) -> Result<usize, AppError> {
        // Approximate by counting keys with empty prefix
        let keys = self.prefix_keys("").await?;
        Ok(keys.len())
    }

    pub async fn swap<V: Serialize>(
        &self,
        old_key: impl Into<Vec<u8>>,
        new_key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<bool, AppError> {
        let old_key = old_key.into();
        let new_key_bytes = new_key.into();

        // Check if new key exists
        if self.get_raw(new_key_bytes.clone()).await?.is_some() {
            return Ok(false);
        }

        // Insert new, delete old
        let bytes = serde_json::to_vec(value)?;
        let bytes = self.maybe_encrypt(bytes)?;

        let mut insert_payload = vec![OP_INSERT];
        encode_keyspace(&mut insert_payload, &self.keyspace);
        encode_bytes(&mut insert_payload, &new_key_bytes);
        encode_bytes(&mut insert_payload, &bytes);
        let resp = self.send(&insert_payload).await?;
        decode_ok(&resp)?;

        let mut delete_payload = vec![OP_DELETE];
        encode_keyspace(&mut delete_payload, &self.keyspace);
        encode_bytes(&mut delete_payload, &old_key);
        let resp = self.send(&delete_payload).await?;
        decode_ok(&resp)?;

        Ok(true)
    }

    /// Send a request, reconnecting once on failure.
    async fn send(&self, payload: &[u8]) -> Result<Vec<u8>, AppError> {
        let mut guard = self.conn.lock().await;

        if let Some(ref mut conn) = *guard {
            match conn.request(payload).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    warn!("storage request failed, reconnecting: {e}");
                    *guard = None;
                }
            }
        }

        let mut conn = VsockConnection::connect(PARENT_CID, self.port).await?;
        let resp = conn.request(payload).await?;
        *guard = Some(conn);
        Ok(resp)
    }

    fn maybe_encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, AppError> {
        #[cfg(feature = "encryption")]
        {
            match self.encryption_key.as_ref().map(|arc| &***arc) {
                Some(key) => super::encryption::encrypt_value(key, &plaintext),
                None => Ok(plaintext),
            }
        }
        #[cfg(not(feature = "encryption"))]
        {
            Ok(plaintext)
        }
    }

    fn maybe_decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, AppError> {
        #[cfg(feature = "encryption")]
        {
            match self.encryption_key.as_ref().map(|arc| &***arc) {
                Some(key) => super::encryption::maybe_decrypt_bytes(Some(key), ciphertext),
                None => Ok(ciphertext.to_vec()),
            }
        }
        #[cfg(not(feature = "encryption"))]
        {
            Ok(ciphertext.to_vec())
        }
    }
}

// ---------------------------------------------------------------------------
// Response decoders
// ---------------------------------------------------------------------------

fn decode_ok(data: &[u8]) -> Result<(), AppError> {
    if data.is_empty() {
        return Err(AppError::Internal(
            "empty response from storage proxy".into(),
        ));
    }
    match data[0] {
        STATUS_OK => Ok(()),
        STATUS_ERROR => {
            let (msg, _) = decode_bytes(data, 1)
                .map_err(|e| AppError::Internal(format!("decode error: {e}")))?;
            Err(AppError::Internal(format!(
                "storage proxy error: {}",
                String::from_utf8_lossy(msg)
            )))
        }
        s => Err(AppError::Internal(format!("unexpected status: {s:#04x}"))),
    }
}

fn decode_value(data: &[u8]) -> Result<Option<Vec<u8>>, AppError> {
    if data.is_empty() {
        return Err(AppError::Internal(
            "empty response from storage proxy".into(),
        ));
    }
    match data[0] {
        STATUS_OK => {
            let (value, _) = decode_bytes(data, 1)
                .map_err(|e| AppError::Internal(format!("decode error: {e}")))?;
            Ok(Some(value.to_vec()))
        }
        STATUS_NOT_FOUND => Ok(None),
        STATUS_ERROR => {
            let (msg, _) = decode_bytes(data, 1)
                .map_err(|e| AppError::Internal(format!("decode error: {e}")))?;
            Err(AppError::Internal(format!(
                "storage proxy error: {}",
                String::from_utf8_lossy(msg)
            )))
        }
        s => Err(AppError::Internal(format!("unexpected status: {s:#04x}"))),
    }
}

fn decode_kv_list(data: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, AppError> {
    if data.is_empty() {
        return Err(AppError::Internal("empty response".into()));
    }
    match data[0] {
        STATUS_OK => {
            if data.len() < 5 {
                return Err(AppError::Internal("truncated kv list".into()));
            }
            let count = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            let mut offset = 5;
            let mut pairs = Vec::with_capacity(count);
            for _ in 0..count {
                let (key, new_offset) = decode_bytes(data, offset)
                    .map_err(|e| AppError::Internal(format!("decode kv: {e}")))?;
                let (value, new_offset) = decode_bytes(data, new_offset)
                    .map_err(|e| AppError::Internal(format!("decode kv: {e}")))?;
                pairs.push((key.to_vec(), value.to_vec()));
                offset = new_offset;
            }
            Ok(pairs)
        }
        STATUS_ERROR => {
            let (msg, _) = decode_bytes(data, 1)
                .map_err(|e| AppError::Internal(format!("decode error: {e}")))?;
            Err(AppError::Internal(format!(
                "storage proxy error: {}",
                String::from_utf8_lossy(msg)
            )))
        }
        s => Err(AppError::Internal(format!("unexpected status: {s:#04x}"))),
    }
}

fn decode_key_list(data: &[u8]) -> Result<Vec<Vec<u8>>, AppError> {
    if data.is_empty() {
        return Err(AppError::Internal("empty response".into()));
    }
    match data[0] {
        STATUS_OK => {
            if data.len() < 5 {
                return Err(AppError::Internal("truncated key list".into()));
            }
            let count = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            let mut offset = 5;
            let mut keys = Vec::with_capacity(count);
            for _ in 0..count {
                let (key, new_offset) = decode_bytes(data, offset)
                    .map_err(|e| AppError::Internal(format!("decode key: {e}")))?;
                keys.push(key.to_vec());
                offset = new_offset;
            }
            Ok(keys)
        }
        STATUS_ERROR => {
            let (msg, _) = decode_bytes(data, 1)
                .map_err(|e| AppError::Internal(format!("decode error: {e}")))?;
            Err(AppError::Internal(format!(
                "storage proxy error: {}",
                String::from_utf8_lossy(msg)
            )))
        }
        s => Err(AppError::Internal(format!("unexpected status: {s:#04x}"))),
    }
}
