//! ASCII armor for sealed bundles.
//!
//! PGP/SSH-style framing with explicit headers and a trailing CRC24 checksum
//! for early corruption detection on pasted text. Headers are bound to the
//! armored payload via the chunk's AAD (see [`super::chunk`]); the armor
//! itself does not authenticate them — but a tampered header reaches the AEAD,
//! which then fails to open.
//!
//! ```text
//! -----BEGIN VTA SEALED BUNDLE-----
//! Version: 1
//! Bundle-Id: 7f3a9c2e4b1d5a80
//! Chunk: 1/3
//! Digest-Algo: sha256
//!
//! base64base64base64base64base64base64base64base64base64base64base64
//! base64base64base64base64base64base64base64base64base64base64base64
//! =Xy9Q
//! -----END VTA SEALED BUNDLE-----
//! ```

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::bundle::{ArmoredChunk, SealedBundle};
use super::error::SealedTransferError;

const BEGIN: &str = "-----BEGIN VTA SEALED BUNDLE-----";
const END: &str = "-----END VTA SEALED BUNDLE-----";
const LINE_WIDTH: usize = 64;

/// PGP-style CRC24 over the raw (pre-base64) payload bytes.
///
/// Init = 0x00B704CE, polynomial = 0x1864CFB, output 24 bits big-endian.
pub fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0x00B7_04CE;
    for &b in data {
        crc ^= (b as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4CFB;
            }
        }
    }
    crc & 0x00FF_FFFF
}

/// Encode a single chunk as an armored block.
fn encode_chunk(bundle_id: &[u8; 16], digest_algo: &str, chunk: &ArmoredChunk) -> String {
    let mut out = String::new();
    out.push_str(BEGIN);
    out.push('\n');
    out.push_str("Version: 1\n");
    out.push_str(&format!("Bundle-Id: {}\n", hex::encode_lower(bundle_id)));
    out.push_str(&format!(
        "Chunk: {}/{}\n",
        chunk.chunk_index + 1,
        chunk.total_chunks
    ));
    out.push_str(&format!("Digest-Algo: {digest_algo}\n"));
    out.push('\n');

    let b64 = BASE64.encode(&chunk.sealed_bytes);
    for line in b64.as_bytes().chunks(LINE_WIDTH) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ascii"));
        out.push('\n');
    }

    let crc = crc24(&chunk.sealed_bytes);
    let crc_bytes = [
        ((crc >> 16) & 0xff) as u8,
        ((crc >> 8) & 0xff) as u8,
        (crc & 0xff) as u8,
    ];
    out.push('=');
    out.push_str(&BASE64.encode(crc_bytes));
    out.push('\n');
    out.push_str(END);
    out.push('\n');
    out
}

/// Encode a [`SealedBundle`] as one or more armored blocks (one per chunk),
/// concatenated with blank lines between.
pub fn encode(bundle: &SealedBundle) -> String {
    let mut out = String::new();
    let mut first = true;
    for chunk in &bundle.chunks {
        if !first {
            out.push('\n');
        }
        first = false;
        out.push_str(&encode_chunk(&bundle.bundle_id, &bundle.digest_algo, chunk));
    }
    out
}

#[derive(Debug)]
struct ParsedBlock {
    bundle_id: [u8; 16],
    digest_algo: String,
    chunk_index: u16,
    total_chunks: u16,
    sealed_bytes: Vec<u8>,
}

fn parse_block(lines: &[&str]) -> Result<ParsedBlock, SealedTransferError> {
    let mut iter = lines.iter().peekable();

    let mut version: Option<u8> = None;
    let mut bundle_id: Option<[u8; 16]> = None;
    let mut chunk: Option<(u16, u16)> = None;
    let mut digest_algo: Option<String> = None;

    // Parse header lines until blank.
    while let Some(line) = iter.peek() {
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            iter.next();
            break;
        }
        let (key, value) = trimmed
            .split_once(':')
            .ok_or_else(|| SealedTransferError::Armor(format!("bad header: {trimmed}")))?;
        let value = value.trim();
        match key.trim() {
            "Version" => {
                version =
                    Some(value.parse().map_err(|_| {
                        SealedTransferError::Armor(format!("bad Version: {value}"))
                    })?);
            }
            "Bundle-Id" => {
                let bytes = hex::decode(value)
                    .map_err(|e| SealedTransferError::Armor(format!("bad Bundle-Id hex: {e}")))?;
                bundle_id = Some(
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| SealedTransferError::Armor("Bundle-Id != 16 bytes".into()))?,
                );
            }
            "Chunk" => {
                let (a, b) = value.split_once('/').ok_or_else(|| {
                    SealedTransferError::Armor(format!("bad Chunk header: {value}"))
                })?;
                let one_based: u16 = a
                    .parse()
                    .map_err(|_| SealedTransferError::Armor(format!("bad chunk index: {a}")))?;
                let total: u16 = b
                    .parse()
                    .map_err(|_| SealedTransferError::Armor(format!("bad chunk total: {b}")))?;
                if one_based == 0 || one_based > total {
                    return Err(SealedTransferError::Armor(format!(
                        "chunk {one_based}/{total} out of range"
                    )));
                }
                chunk = Some((one_based - 1, total));
            }
            "Digest-Algo" => digest_algo = Some(value.to_string()),
            // Unknown headers are ignored — forward compatibility.
            _ => {}
        }
        iter.next();
    }

    let version = version.ok_or_else(|| SealedTransferError::Armor("missing Version".into()))?;
    if version != 1 {
        return Err(SealedTransferError::UnsupportedVersion(version));
    }
    let bundle_id =
        bundle_id.ok_or_else(|| SealedTransferError::Armor("missing Bundle-Id".into()))?;
    let (chunk_index, total_chunks) =
        chunk.ok_or_else(|| SealedTransferError::Armor("missing Chunk header".into()))?;
    let digest_algo =
        digest_algo.ok_or_else(|| SealedTransferError::Armor("missing Digest-Algo".into()))?;

    // Body: base64 lines until a `=XXXX` checksum line.
    let mut b64 = String::new();
    let mut crc_line: Option<&str> = None;
    for line in iter {
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('=') {
            crc_line = Some(rest);
            break;
        }
        b64.push_str(trimmed);
    }
    let crc_b64 = crc_line.ok_or_else(|| SealedTransferError::Armor("missing CRC line".into()))?;

    let sealed_bytes = BASE64
        .decode(b64.as_bytes())
        .map_err(|e| SealedTransferError::Base64(e.to_string()))?;
    let crc_bytes = BASE64
        .decode(crc_b64.as_bytes())
        .map_err(|e| SealedTransferError::Base64(format!("crc: {e}")))?;
    if crc_bytes.len() != 3 {
        return Err(SealedTransferError::Armor("CRC payload != 3 bytes".into()));
    }
    let expected =
        ((crc_bytes[0] as u32) << 16) | ((crc_bytes[1] as u32) << 8) | (crc_bytes[2] as u32);
    let got = crc24(&sealed_bytes);
    if got != expected {
        return Err(SealedTransferError::Crc24Mismatch { expected, got });
    }

    Ok(ParsedBlock {
        bundle_id,
        digest_algo,
        chunk_index,
        total_chunks,
        sealed_bytes,
    })
}

/// Decode armored input — possibly containing multiple blocks for one or more
/// bundles — and group blocks into [`SealedBundle`]s by `Bundle-Id`.
pub fn decode(input: &str) -> Result<Vec<SealedBundle>, SealedTransferError> {
    let mut bundles: Vec<SealedBundle> = Vec::new();
    let lines: Vec<&str> = input.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() != BEGIN {
            i += 1;
            continue;
        }
        // Find the matching END.
        let body_start = i + 1;
        let mut j = body_start;
        while j < lines.len() && lines[j].trim() != END {
            j += 1;
        }
        if j >= lines.len() {
            return Err(SealedTransferError::Armor(
                "unterminated BEGIN block".into(),
            ));
        }
        let block = parse_block(&lines[body_start..j])?;
        // Group into bundles.
        if let Some(b) = bundles.iter_mut().find(|b| b.bundle_id == block.bundle_id) {
            if b.digest_algo != block.digest_algo {
                return Err(SealedTransferError::ChunkMismatch(
                    "digest_algo across chunks".into(),
                ));
            }
            b.chunks.push(ArmoredChunk {
                chunk_index: block.chunk_index,
                total_chunks: block.total_chunks,
                sealed_bytes: block.sealed_bytes,
            });
        } else {
            bundles.push(SealedBundle {
                bundle_id: block.bundle_id,
                digest_algo: block.digest_algo,
                chunks: vec![ArmoredChunk {
                    chunk_index: block.chunk_index,
                    total_chunks: block.total_chunks,
                    sealed_bytes: block.sealed_bytes,
                }],
            });
        }
        i = j + 1;
    }
    if bundles.is_empty() {
        return Err(SealedTransferError::Armor("no BEGIN blocks found".into()));
    }
    Ok(bundles)
}

// Tiny inline hex helper to avoid pulling in another crate at this layer.
mod hex {
    pub fn encode_lower(bytes: &[u8]) -> String {
        const TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(TABLE[(b >> 4) as usize] as char);
            s.push(TABLE[(b & 0xf) as usize] as char);
        }
        s
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err(format!("odd length: {}", s.len()));
        }
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        for i in (0..bytes.len()).step_by(2) {
            let hi = nibble(bytes[i])?;
            let lo = nibble(bytes[i + 1])?;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }

    fn nibble(c: u8) -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(format!("non-hex byte: 0x{c:02x}")),
        }
    }
}
