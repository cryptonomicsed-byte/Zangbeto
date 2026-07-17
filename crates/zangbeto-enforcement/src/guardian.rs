//! ZÀNGBÉTÒ's guardian signing identity.
//!
//! Every enforcement decision and diagnostic receipt is signed with a real
//! Ed25519 keypair so a caller (e.g. Ọmọ Kọ́dà's diagnostic pipeline) can
//! verify the receipt actually came from this guardian and wasn't forged or
//! replayed with a different payload. Keypair derivation reuses BIPỌ̀N39's
//! `ed25519_keypair_from_seed` -- the same lineage as Ọmọ Kọ́dà's own
//! identity derivation -- rather than inventing a second scheme.
//!
//! The seed itself is NOT derived from anything memorable (no mnemonic): the
//! guardian is an infrastructure daemon, not a sovereign agent with a birth
//! story, so a random 32-byte seed generated once and persisted to disk is
//! the right model here (analogous to how a TLS cert's private key is
//! generated, not derived from a passphrase).

use std::path::{Path, PathBuf};

use bipon39::identity::ed25519_keypair_from_seed;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};

pub struct Guardian {
    signing_key: SigningKey,
}

impl Guardian {
    /// Load the guardian's persisted seed, or generate and persist a new one
    /// on first boot. `seed_path` is typically `<data_dir>/guardian.seed`.
    pub fn load_or_create(seed_path: &Path) -> std::io::Result<Self> {
        let seed = if seed_path.exists() {
            let bytes = std::fs::read(seed_path)?;
            if bytes.len() != 32 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "guardian seed at {:?} is {} bytes, expected 32",
                        seed_path,
                        bytes.len()
                    ),
                ));
            }
            bytes
        } else {
            if let Some(parent) = seed_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut seed = vec![0u8; 32];
            OsRng.fill_bytes(&mut seed);
            std::fs::write(seed_path, &seed)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(seed_path, std::fs::Permissions::from_mode(0o600))?;
            }
            seed
        };

        let (signing_key, _verifying_key) = ed25519_keypair_from_seed(&seed)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        Ok(Self { signing_key })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key().as_bytes())
    }

    /// Sign a receipt: the message is `sha256(receipt_id || canonical_payload)`,
    /// so the signature binds both the receipt's identity and its contents --
    /// a caller who reuses a valid receipt_id with a different payload (or
    /// vice versa) produces a signature that fails verification.
    pub fn sign_receipt(&self, receipt_id: &str, canonical_payload: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(receipt_id.as_bytes());
        hasher.update(canonical_payload);
        let digest = hasher.finalize();
        let sig = self.signing_key.sign(&digest);
        hex::encode(sig.to_bytes())
    }
}

/// Verify a receipt signature against a hex-encoded Ed25519 public key.
/// Standalone (no `Guardian` instance needed) so a remote verifier -- one
/// that only has the guardian's published pubkey, not its private key --
/// can check receipts independently.
pub fn verify_receipt(
    guardian_pubkey_hex: &str,
    receipt_id: &str,
    canonical_payload: &[u8],
    sig_hex: &str,
) -> bool {
    use sha2::{Digest, Sha256};

    let Ok(pubkey_bytes) = hex::decode(guardian_pubkey_hex) else {
        return false;
    };
    let Ok(pubkey_arr): Result<[u8; 32], _> = pubkey_bytes.try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pubkey_arr) else {
        return false;
    };

    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    let mut hasher = Sha256::new();
    hasher.update(receipt_id.as_bytes());
    hasher.update(canonical_payload);
    let digest = hasher.finalize();

    verifying_key.verify(&digest, &sig).is_ok()
}

/// Default on-disk location for the guardian seed, relative to the daemon's
/// working directory.
pub fn default_seed_path() -> PathBuf {
    PathBuf::from(".guardian").join("seed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let dir = std::env::temp_dir().join(format!("zangbeto-guardian-test-{}", std::process::id()));
        let seed_path = dir.join("seed");
        let guardian = Guardian::load_or_create(&seed_path).unwrap();

        let receipt_id = "test-receipt-1";
        let payload = b"agent_id=agent-abc123;action=quarantine";
        let sig = guardian.sign_receipt(receipt_id, payload);

        assert!(verify_receipt(&guardian.public_key_hex(), receipt_id, payload, &sig));
        // Different payload, same signature -> must fail.
        assert!(!verify_receipt(&guardian.public_key_hex(), receipt_id, b"tampered", &sig));
        // Different receipt_id, same signature -> must fail.
        assert!(!verify_receipt(&guardian.public_key_hex(), "other-id", payload, &sig));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_persists_across_instances() {
        let dir = std::env::temp_dir().join(format!("zangbeto-guardian-persist-{}", std::process::id()));
        let seed_path = dir.join("seed");

        let g1 = Guardian::load_or_create(&seed_path).unwrap();
        let g2 = Guardian::load_or_create(&seed_path).unwrap();
        assert_eq!(g1.public_key_hex(), g2.public_key_hex());

        std::fs::remove_dir_all(&dir).ok();
    }
}
