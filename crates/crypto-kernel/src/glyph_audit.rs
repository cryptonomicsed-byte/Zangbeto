//! GlyphIndex audit — Zangbeto's night-watch over the sovereign memory layer.
//!
//! Zangbeto never holds decryption keys. What it *can* verify, keylessly:
//!
//! 1. **Structure** — a stored blob really is a well-formed GIX1 envelope
//!    (`"GIX1" | version | flags | nonce(12) | ct||tag(16)`), so a storage
//!    provider cannot silently swap ciphertext formats.
//! 2. **Receipts** — the HMAC-SHA256 receipt an agent emitted for a sealed
//!    blob matches the blob actually stored (given the agent discloses its
//!    MAC key to an auditor, or via the agent re-attesting).
//! 3. **Anchors** — the Merkle root a vault anchored on Sui recomputes from
//!    the blob set (leaf = SHA-256(canonical_id || SHA-256(blob)), leaves
//!    sorted by canonical id, odd leaf promoted).
//! 4. **Naming** — a displayed glyph really is the GIX-FOLD-v1 fold of its
//!    canonical id, so UIs cannot spoof memory identities.
//!
//! Wire formats match the canonical reference implementation
//! (`Vantage/backend/glyph_index.py`) byte-for-byte.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const GIX_MAGIC: &[u8; 4] = b"GIX1";
pub const GIX_VERSION: u8 = 1;
pub const FLAG_ZLIB: u8 = 0x01;
const KNOWN_FLAGS: u8 = FLAG_ZLIB;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GlyphAuditError {
    #[error("blob too short ({0} bytes) for a GIX1 envelope")]
    TooShort(usize),
    #[error("bad magic — not a GIX1 blob")]
    BadMagic,
    #[error("unsupported GIX version {0}")]
    BadVersion(u8),
    #[error("unknown flag bits set: {0:#04x}")]
    UnknownFlags(u8),
    #[error("canonical id is not 32 hex-encoded bytes")]
    BadCanonicalId,
    #[error("receipt HMAC mismatch")]
    ReceiptMismatch,
    #[error("stored blob hash does not match receipt")]
    BlobMismatch,
    #[error("glyph does not match GIX-FOLD-v1 of the canonical id")]
    GlyphSpoofed,
    #[error("merkle root mismatch: expected {expected}, computed {computed}")]
    MerkleMismatch { expected: String, computed: String },
}

/// Parsed (unverified-content) GIX1 envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GixEnvelope<'a> {
    pub version: u8,
    pub flags: u8,
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
    pub tag: &'a [u8],
}

/// Structurally validate a GIX1 blob without any keys.
pub fn parse_gix1(blob: &[u8]) -> Result<GixEnvelope<'_>, GlyphAuditError> {
    if blob.len() < 4 + 2 + 12 + 16 {
        return Err(GlyphAuditError::TooShort(blob.len()));
    }
    if &blob[..4] != GIX_MAGIC {
        return Err(GlyphAuditError::BadMagic);
    }
    let (version, flags) = (blob[4], blob[5]);
    if version != GIX_VERSION {
        return Err(GlyphAuditError::BadVersion(version));
    }
    if flags & !KNOWN_FLAGS != 0 {
        return Err(GlyphAuditError::UnknownFlags(flags));
    }
    Ok(GixEnvelope {
        version,
        flags,
        nonce: &blob[6..18],
        ciphertext: &blob[18..blob.len() - 16],
        tag: &blob[blob.len() - 16..],
    })
}

/// The receipt an agent journals for every sealed chunk — field-compatible
/// with the reference implementation's JSON receipts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlyphReceipt {
    pub canonical_id: String,
    pub blob_sha256: String,
    pub owner: String,
    pub hmac: String,
}

/// Verify a receipt against the agent's (disclosed or re-attested) MAC key:
/// HMAC-SHA256(mac_key, canonical_id_ascii || blob_sha256_bytes).
pub fn verify_receipt(receipt: &GlyphReceipt, mac_key: &[u8]) -> Result<(), GlyphAuditError> {
    let blob_hash =
        hex::decode(&receipt.blob_sha256).map_err(|_| GlyphAuditError::BadCanonicalId)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key).expect("any key size");
    mac.update(receipt.canonical_id.as_bytes());
    mac.update(&blob_hash);
    let expected =
        hex::decode(&receipt.hmac).map_err(|_| GlyphAuditError::ReceiptMismatch)?;
    mac.verify_slice(&expected)
        .map_err(|_| GlyphAuditError::ReceiptMismatch)
}

/// Check that a stored blob is the one the receipt commits to.
pub fn audit_blob_against_receipt(
    blob: &[u8],
    receipt: &GlyphReceipt,
) -> Result<(), GlyphAuditError> {
    parse_gix1(blob)?;
    if hex::encode(Sha256::digest(blob)) != receipt.blob_sha256 {
        return Err(GlyphAuditError::BlobMismatch);
    }
    Ok(())
}

/// Recompute a vault's Merkle root from `(canonical_id_hex, blob)` pairs and
/// compare with the anchored value. Leaf = SHA-256(id_bytes || SHA-256(blob)),
/// leaves sorted by canonical id, odd leaf promoted unchanged.
pub fn audit_merkle_root(
    entries: &[(String, Vec<u8>)],
    expected_root_hex: &str,
) -> Result<(), GlyphAuditError> {
    let computed = merkle_root(entries)?;
    if computed != expected_root_hex {
        return Err(GlyphAuditError::MerkleMismatch {
            expected: expected_root_hex.to_string(),
            computed,
        });
    }
    Ok(())
}

pub fn merkle_root(entries: &[(String, Vec<u8>)]) -> Result<String, GlyphAuditError> {
    let mut sorted: Vec<&(String, Vec<u8>)> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut level: Vec<[u8; 32]> = Vec::with_capacity(sorted.len());
    for (cid, blob) in sorted {
        let id_bytes = hex::decode(cid).map_err(|_| GlyphAuditError::BadCanonicalId)?;
        if id_bytes.len() != 32 {
            return Err(GlyphAuditError::BadCanonicalId);
        }
        let mut h = Sha256::new();
        h.update(&id_bytes);
        h.update(Sha256::digest(blob));
        level.push(h.finalize().into());
    }
    if level.is_empty() {
        return Ok(hex::encode(Sha256::digest(b"GIX1:empty")));
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2 + 1);
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                let mut h = Sha256::new();
                h.update(pair[0]);
                h.update(pair[1]);
                next.push(h.finalize().into());
            } else {
                next.push(pair[0]);
            }
        }
        level = next;
    }
    Ok(hex::encode(level[0]))
}

// ---- GIX-FOLD-v1 (shared display-alias check) ------------------------------

const FOLD_RANGES: [(u32, u32); 3] = [
    (0x0020, 0xD7FF - 0x0020 + 1),
    (0xE000, 0xFDCF - 0xE000 + 1),
    (0xFDF0, 0xFFFD - 0xFDF0 + 1),
];

pub fn glyph_fold(digest: &[u8; 32]) -> char {
    let total: u64 = FOLD_RANGES.iter().map(|(_, c)| *c as u64).sum();
    let mut rem: u64 = 0;
    for byte in digest {
        rem = (rem << 8 | *byte as u64) % total;
    }
    let mut idx = rem as u32;
    for (start, count) in FOLD_RANGES {
        if idx < count {
            return char::from_u32(start + idx).expect("fold ranges exclude invalid points");
        }
        idx -= count;
    }
    unreachable!()
}

/// Reject a UI/index entry whose display glyph is not the fold of its id.
pub fn audit_glyph_name(glyph: char, canonical_id_hex: &str) -> Result<(), GlyphAuditError> {
    let bytes = hex::decode(canonical_id_hex).map_err(|_| GlyphAuditError::BadCanonicalId)?;
    let digest: [u8; 32] = bytes
        .try_into()
        .map_err(|_| GlyphAuditError::BadCanonicalId)?;
    if glyph_fold(&digest) != glyph {
        return Err(GlyphAuditError::GlyphSpoofed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Frozen cross-language vectors (canonical Python reference, Vantage).
    const CID_HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    const CID_GLYPHINDEX: &str =
        "44bb6336e45b2f5daf764930ac1d1f2798ad92c34048f0395686ac4509a0a7ec";
    const EMPTY_ROOT: &str = "58cc47f0d238cea8bb764f7a927a54b398c8baf5de0a2332c03008038c3fd9a8";
    const TWO_LEAF_ROOT: &str =
        "9d28ae8ea43c793835a78e790615e133671eb2f4bd14cb65d6ccc44cdaa698cb";

    fn fake_blob() -> Vec<u8> {
        let mut b = b"GIX1".to_vec();
        b.push(1); // version
        b.push(0); // flags
        b.extend_from_slice(&[7u8; 12]); // nonce
        b.extend_from_slice(b"ciphertext-bytes"); // ct
        b.extend_from_slice(&[9u8; 16]); // tag
        b
    }

    #[test]
    fn parses_wellformed_envelope() {
        let blob = fake_blob();
        let env = parse_gix1(&blob).unwrap();
        assert_eq!(env.version, 1);
        assert_eq!(env.nonce, &[7u8; 12]);
        assert_eq!(env.ciphertext, b"ciphertext-bytes");
    }

    #[test]
    fn rejects_malformed_envelopes() {
        assert_eq!(parse_gix1(b"GIX1"), Err(GlyphAuditError::TooShort(4)));
        let mut bad_magic = fake_blob();
        bad_magic[0] = b'X';
        assert_eq!(parse_gix1(&bad_magic), Err(GlyphAuditError::BadMagic));
        let mut bad_ver = fake_blob();
        bad_ver[4] = 9;
        assert_eq!(parse_gix1(&bad_ver), Err(GlyphAuditError::BadVersion(9)));
        let mut bad_flags = fake_blob();
        bad_flags[5] = 0x80;
        assert_eq!(parse_gix1(&bad_flags), Err(GlyphAuditError::UnknownFlags(0x80)));
    }

    #[test]
    fn receipt_verification_roundtrip() {
        let mac_key = [3u8; 32];
        let blob = fake_blob();
        let blob_sha = hex::encode(Sha256::digest(&blob));
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&mac_key).unwrap();
        mac.update(CID_HELLO.as_bytes());
        mac.update(&hex::decode(&blob_sha).unwrap());
        let receipt = GlyphReceipt {
            canonical_id: CID_HELLO.into(),
            blob_sha256: blob_sha,
            owner: "0xabc123".into(),
            hmac: hex::encode(mac.finalize().into_bytes()),
        };
        verify_receipt(&receipt, &mac_key).unwrap();
        audit_blob_against_receipt(&blob, &receipt).unwrap();
        assert_eq!(
            verify_receipt(&receipt, &[4u8; 32]),
            Err(GlyphAuditError::ReceiptMismatch)
        );
        let mut other = fake_blob();
        other[20] ^= 0xFF;
        assert_eq!(
            audit_blob_against_receipt(&other, &receipt),
            Err(GlyphAuditError::BlobMismatch)
        );
    }

    #[test]
    fn merkle_matches_reference_vectors() {
        assert_eq!(merkle_root(&[]).unwrap(), EMPTY_ROOT);
        let entries = vec![
            (CID_HELLO.to_string(), b"blobA".to_vec()),
            (CID_GLYPHINDEX.to_string(), b"blobB".to_vec()),
        ];
        assert_eq!(merkle_root(&entries).unwrap(), TWO_LEAF_ROOT);
        // Order-independence: the auditor sorts by canonical id.
        let reversed: Vec<_> = entries.into_iter().rev().collect();
        assert_eq!(merkle_root(&reversed).unwrap(), TWO_LEAF_ROOT);
        audit_merkle_root(&reversed, TWO_LEAF_ROOT).unwrap();
        assert!(matches!(
            audit_merkle_root(&reversed, EMPTY_ROOT),
            Err(GlyphAuditError::MerkleMismatch { .. })
        ));
    }

    #[test]
    fn glyph_name_audit_matches_fold_vectors() {
        // "hello" folds to U+5C54 (23636) per the frozen ecosystem vectors.
        audit_glyph_name(char::from_u32(23636).unwrap(), CID_HELLO).unwrap();
        assert_eq!(
            audit_glyph_name('X', CID_HELLO),
            Err(GlyphAuditError::GlyphSpoofed)
        );
    }
}
