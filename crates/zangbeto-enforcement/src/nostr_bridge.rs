//! Publishing enforcement receipts to the ecosystem's Nostr wire.
//!
//! Zàngbétò audits what an agent did. Until now that audit lived only in
//! [`crate::receipts::ReceiptStore`] — an in-memory `Vec` that dies with the
//! process — and in signatures only a caller holding the guardian's pubkey
//! could check, one at a time, by asking. The swarm could not read it.
//!
//! This module puts enforcement on the same wire every other pillar speaks, so
//! an enforcement decision becomes something other agents can independently
//! see and contest rather than something they must take on trust.
//!
//! # Identity: one seed, two curves
//!
//! [`crate::guardian::Guardian`] holds a random 32-byte seed and feeds it
//! directly to `ed25519_keypair_from_seed`. The Nostr identity here comes off
//! the **same seed**, walked to the standard NIP-06 path `m/44'/1237'/0'/0/0`.
//!
//! Two details of BIPỌ̀N39's API force the shape of this, and both were read
//! out of `derivation.rs` rather than assumed:
//!
//! 1. `derive_path` requires **at least 64 bytes** — it takes `seed[..32]` as
//!    the root key and `seed[32..64]` as the root chain code. The guardian has
//!    32.
//! 2. `derive_path` does **not** apply BIP-32 master derivation itself, so it
//!    contributes no domain separation. (`master_from_seed` is what keys an
//!    HMAC with `MASTER_KEY_NATIVE`/`MASTER_KEY_BIP32`, and it too demands
//!    exactly 64 bytes.)
//!
//! So separation has to be established here, explicitly: the 32-byte seed is
//! expanded to 64 with `HMAC-SHA512` under a version-pinned domain string
//! ([`NOSTR_BRANCH_DOMAIN`]) before the path walk — the same construction
//! Ọmọ Kọ́dà uses for its git-signing branch. The Ed25519 key reads the raw
//! seed and the secp256k1 key reads the expanded one, so recovering either
//! does not yield the other, while one backed-up seed still restores both.
//!
//! Changing [`NOSTR_BRANCH_DOMAIN`] silently rotates every guardian's Nostr
//! identity, which to the swarm is indistinguishable from a new guardian
//! appearing and the old one going quiet. It is versioned for that reason.
//!
//! The guardian is deliberately *not* a birthed sovereign agent — it has no
//! mnemonic and no birth story (see `guardian.rs`). So it does not go through
//! `from_mnemonic`; it derives from the seed it already has.
//!
//! # Kinds: nothing new is minted
//!
//! The production Buzz relay enforces a strict kind allowlist and rejects
//! unknown kinds *after* authentication succeeds — which surfaces as what looks
//! like an auth failure. Only `30174` and `47000..48000` are admitted. So an
//! enforcement receipt travels as a minipae engram (`30174`) and an enforcement
//! decision as a Crucible claim (`47001`); neither is a Zàngbétò invention.
//! [`relay_admits`] fails locally rather than letting the relay report it
//! confusingly.

use bipon39::derivation::derive_path;
use hmac::{Hmac, Mac};
use nostr::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512};

use crate::daemon::EnforcementReceipt;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

// === The shared wire contract ===
// Every constant below is owned by another component and mirrored here, never
// invented. Changing one in isolation breaks interoperability silently.

/// NIP-AE agent engram. Owner: minipae (`KIND_AGENT_ENGRAM`).
pub const KIND_AGENT_ENGRAM: u64 = 30174;
/// Crucible falsifiable claim. Owner: `crucible-core::kinds::CLAIM`.
pub const KIND_CLAIM: u64 = 47001;
/// NIP-42 relay auth. Owner: minipae (`KIND_AUTH`).
pub const KIND_AUTH: u64 = 22242;
/// Crucible's reserved block. Zàngbétò must never mint a kind inside it.
pub const CRUCIBLE_RESERVED: core::ops::Range<u64> = 47000..48000;

/// Slug namespace for everything Zàngbétò writes, kept distinct from
/// `mem/ifa/`, `mem/ga/` and `mem/genteam/` so a merged read view stays
/// separable by origin.
pub const SLUG_PREFIX: &str = "mem/zangbeto";

/// Length of the guardian seed on disk, per `guardian.rs`.
pub const GUARDIAN_SEED_LEN: usize = 32;

/// Domain string separating the guardian's secp256k1/Nostr branch from the
/// Ed25519 branch that reads the same seed. Versioned: changing it rotates
/// every guardian's Nostr identity.
pub const NOSTR_BRANCH_DOMAIN: &[u8] = b"zangbeto-guardian-nostr-v1";

/// NIP-06 path segments. `1237` is Nostr's registered SLIP-44 coin type.
const NIP06_PATH: [u32; 5] = [
    44 | 0x8000_0000,   // purpose'
    1237 | 0x8000_0000, // coin_type'
    0x8000_0000,        // account 0'
    0,                  // change
    0,                  // address_index
];

/// True when the production Buzz relay's allowlist admits `kind`.
pub fn relay_admits(kind: u64) -> bool {
    kind == KIND_AGENT_ENGRAM || CRUCIBLE_RESERVED.contains(&kind)
}

/// Errors from deriving identity or building an event.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("NIP-06 derivation from guardian seed failed: {0}")]
    Derivation(String),
    #[error("event signing failed: {0}")]
    Signing(String),
    #[error("serialising receipt failed: {0}")]
    Serialisation(String),
    #[error("invalid relay url: {0}")]
    RelayUrl(String),
    #[error("kind {0} is not admitted by the Buzz relay allowlist")]
    KindNotAdmitted(u64),
}

/// The guardian's Nostr identity, derived from its existing seed.
///
/// `Debug` deliberately omits the secret: a stray `{:?}` in a daemon log must
/// not leak the key that authenticates every enforcement receipt.
#[derive(Clone)]
pub struct GuardianNostrIdentity {
    keys: Keys,
    public_key_hex: String,
    npub: String,
}

impl std::fmt::Debug for GuardianNostrIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardianNostrIdentity")
            .field("npub", &self.npub)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl GuardianNostrIdentity {
    /// Derive from the guardian's 32-byte seed at the NIP-06 path.
    ///
    /// Deterministic: the same seed always yields the same Nostr identity, so
    /// a restarted daemon keeps publishing under one pubkey rather than
    /// appearing to the swarm as a new guardian each boot.
    pub fn from_guardian_seed(seed: &[u8]) -> Result<Self, BridgeError> {
        if seed.len() != GUARDIAN_SEED_LEN {
            return Err(BridgeError::Derivation(format!(
                "guardian seed must be {GUARDIAN_SEED_LEN} bytes, got {}",
                seed.len()
            )));
        }

        // Expand 32 -> 64 under a distinct domain, since derive_path needs 64
        // bytes and supplies no separation of its own (see module docs).
        let mut mac = HmacSha512::new_from_slice(NOSTR_BRANCH_DOMAIN)
            .expect("HMAC accepts any key length");
        mac.update(seed);
        let expanded = mac.finalize().into_bytes();

        let (derived, _chain) = derive_path(&expanded, &NIP06_PATH)
            .map_err(|e| BridgeError::Derivation(e.to_string()))?;
        let secret = SecretKey::from_slice(&derived)
            .map_err(|e| BridgeError::Derivation(format!("invalid secp256k1 key: {e}")))?;
        let keys = Keys::new(secret);
        let public_key_hex = keys.public_key().to_hex();
        let npub = keys
            .public_key()
            .to_bech32()
            .unwrap_or_else(|_| public_key_hex.clone());
        Ok(Self {
            keys,
            public_key_hex,
            npub,
        })
    }

    /// x-only public key as hex — the `pubkey` on every event this guardian signs.
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// Public key in bech32 `npub1…` form.
    pub fn npub(&self) -> &str {
        &self.npub
    }

    fn secret_bytes(&self) -> Result<[u8; 32], BridgeError> {
        Ok(self
            .keys
            .secret_key()
            .map_err(|e| BridgeError::Signing(e.to_string()))?
            .secret_bytes())
    }
}

/// The wire body of a published enforcement receipt.
///
/// Deliberately a flat, self-describing shape rather than a re-serialisation of
/// [`EnforcementReceipt`]: a Julia, Python or TypeScript reader must be able to
/// interpret it without Zàngbétò's Rust types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnforcementRecord {
    pub receipt_id: String,
    pub anomaly_id: String,
    /// Enforcement action, rendered as a stable string.
    pub action: String,
    pub executed_at: u64,
    pub state_before: String,
    pub state_after: String,
    /// Count of Òrìṣà co-signatures on the decision.
    pub signature_count: usize,
    pub merkle_proof: String,
}

impl From<&EnforcementReceipt> for EnforcementRecord {
    fn from(r: &EnforcementReceipt) -> Self {
        Self {
            receipt_id: r.receipt_id.to_string(),
            anomaly_id: r.anomaly_id.to_string(),
            action: format!("{:?}", r.action_taken),
            executed_at: r.execution_timestamp,
            state_before: hex::encode(r.state_before),
            state_after: hex::encode(r.state_after),
            signature_count: r.orisha_signatures.len(),
            merkle_proof: hex::encode(r.merkle_proof),
        }
    }
}

/// Hash an engram slug into its `d` tag value.
///
/// minipae HMACs the slug rather than publishing it, so a relay operator learns
/// that the guardian wrote something without learning which agent it enforced
/// against. Same construction (`HMAC-SHA256(key, slug)`, hex) so a minipae
/// client holding the key can address the engram.
pub fn d_tag(slug: &str, key: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(slug.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Slug for one enforcement receipt.
pub fn slug_enforcement(receipt_id: &str) -> String {
    format!("{SLUG_PREFIX}/enforcement/{receipt_id}")
}

/// Sign an enforcement receipt as a minipae engram (`kind:30174`).
///
/// `owner_pubkey_hex` is who the record is *for* — normally the enforced
/// agent's own Nostr pubkey, so the agent can read its own enforcement history.
pub fn enforcement_engram(
    identity: &GuardianNostrIdentity,
    receipt: &EnforcementReceipt,
    owner_pubkey_hex: &str,
) -> Result<Event, BridgeError> {
    let record = EnforcementRecord::from(receipt);
    let content =
        serde_json::to_string(&record).map_err(|e| BridgeError::Serialisation(e.to_string()))?;

    let slug = slug_enforcement(&record.receipt_id);
    let key = identity.secret_bytes()?;

    let tags = vec![
        tag("d", &d_tag(&slug, &key))?,
        tag("p", owner_pubkey_hex)?,
        tag("action", &record.action)?,
    ];

    build(identity, KIND_AGENT_ENGRAM, content, tags)
}

/// A falsifiable assertion that an enforcement decision was correct.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnforcementClaim {
    pub statement: String,
    /// Content address of the WASM predicate that returns false if the
    /// enforcement was unwarranted. Crucible rejects a claim without one at
    /// parse time, so this is not optional.
    pub falsifier: String,
    pub receipt_id: String,
    pub half_life_secs: u64,
}

/// Sign an enforcement decision as a Crucible claim (`kind:47001`).
///
/// This is what makes enforcement contestable. An engram records *that* the
/// guardian acted; a claim invites the swarm to check *whether it should have*,
/// and Crucible weighs the answers by independent witnesses rather than by
/// volume — so the guardian cannot ratify itself by asserting more loudly.
pub fn enforcement_claim(
    identity: &GuardianNostrIdentity,
    claim: &EnforcementClaim,
) -> Result<Event, BridgeError> {
    let content =
        serde_json::to_string(claim).map_err(|e| BridgeError::Serialisation(e.to_string()))?;

    let tags = vec![
        tag("falsifier", &claim.falsifier)?,
        tag("receipt", &claim.receipt_id)?,
        tag("half_life", &claim.half_life_secs.to_string())?,
    ];

    build(identity, KIND_CLAIM, content, tags)
}

/// Build the NIP-42 auth response (`kind:22242`) for a relay challenge.
///
/// The Buzz relay refuses writes from unauthenticated connections, so this runs
/// before any publish.
pub fn relay_auth(
    identity: &GuardianNostrIdentity,
    challenge: &str,
    relay_url: &str,
) -> Result<Event, BridgeError> {
    let url = Url::parse(relay_url).map_err(|e| BridgeError::RelayUrl(e.to_string()))?;
    EventBuilder::auth(challenge, url)
        .to_event(&identity.keys)
        .map_err(|e| BridgeError::Signing(e.to_string()))
}

fn tag(name: &str, value: &str) -> Result<Tag, BridgeError> {
    Tag::parse(vec![name, value]).map_err(|e| BridgeError::Serialisation(e.to_string()))
}

fn build(
    identity: &GuardianNostrIdentity,
    kind: u64,
    content: String,
    tags: Vec<Tag>,
) -> Result<Event, BridgeError> {
    if !relay_admits(kind) {
        return Err(BridgeError::KindNotAdmitted(kind));
    }
    EventBuilder::new(Kind::Custom(kind), content, tags)
        .to_event(&identity.keys)
        .map_err(|e| BridgeError::Signing(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_ladder::{EnforcementAction, LogLevel};
    use uuid::Uuid;

    const SEED: [u8; 32] = [7u8; 32];

    fn identity() -> GuardianNostrIdentity {
        GuardianNostrIdentity::from_guardian_seed(&SEED).unwrap()
    }

    fn a_receipt() -> EnforcementReceipt {
        EnforcementReceipt {
            receipt_id: Uuid::new_v4(),
            anomaly_id: Uuid::new_v4(),
            action_taken: EnforcementAction::Observe {
                log_level: LogLevel::Warn,
                retain_evidence: true,
            },
            execution_timestamp: 1_700_000_000,
            state_before: [1u8; 32],
            state_after: [2u8; 32],
            orisha_signatures: Vec::new(),
            merkle_proof: [3u8; 32],
        }
    }

    #[test]
    fn derivation_is_deterministic_across_restarts() {
        // A guardian that reboots must keep its pubkey, or the swarm sees a
        // brand-new guardian every restart and no enforcement history accrues.
        let a = GuardianNostrIdentity::from_guardian_seed(&SEED).unwrap();
        let b = GuardianNostrIdentity::from_guardian_seed(&SEED).unwrap();
        assert_eq!(a.public_key_hex(), b.public_key_hex());
        assert_eq!(a.npub(), b.npub());
    }

    #[test]
    fn different_seeds_are_different_guardians() {
        let a = GuardianNostrIdentity::from_guardian_seed(&[1u8; 32]).unwrap();
        let b = GuardianNostrIdentity::from_guardian_seed(&[2u8; 32]).unwrap();
        assert_ne!(a.public_key_hex(), b.public_key_hex());
    }

    #[test]
    fn nostr_key_is_independent_of_the_ed25519_key() {
        // The two branches are domain-separated. If these ever collide, one
        // seed's compromise would yield both identities.
        let (ed_signing, _) = bipon39::identity::ed25519_keypair_from_seed(&SEED).unwrap();
        let nostr = identity();
        assert_ne!(
            hex::encode(ed_signing.to_bytes()),
            hex::encode(nostr.secret_bytes().unwrap())
        );
    }

    #[test]
    fn pubkey_is_32_byte_x_only_and_npub_prefixed() {
        let id = identity();
        assert_eq!(hex::decode(id.public_key_hex()).unwrap().len(), 32);
        assert!(id.npub().starts_with("npub1"), "npub: {}", id.npub());
    }

    #[test]
    fn an_enforcement_engram_is_signed_and_verifies() {
        let id = identity();
        let event = enforcement_engram(&id, &a_receipt(), id.public_key_hex()).unwrap();
        assert!(event.verify().is_ok());
        assert_eq!(event.kind(), Kind::Custom(KIND_AGENT_ENGRAM));
        assert_eq!(event.pubkey.to_hex(), id.public_key_hex());
    }

    #[test]
    fn engram_content_is_readable_without_zangbeto_types() {
        // A Julia or Python reader must be able to parse this.
        let id = identity();
        let receipt = a_receipt();
        let event = enforcement_engram(&id, &receipt, id.public_key_hex()).unwrap();

        let decoded: EnforcementRecord = serde_json::from_str(event.content()).unwrap();
        assert_eq!(decoded.receipt_id, receipt.receipt_id.to_string());
        assert_eq!(decoded.state_before, hex::encode(receipt.state_before));
    }

    #[test]
    fn engram_carries_the_d_and_p_tags_nip_ae_requires() {
        let id = identity();
        let event = enforcement_engram(&id, &a_receipt(), id.public_key_hex()).unwrap();
        let names: Vec<String> = event
            .tags
            .iter()
            .filter_map(|t| t.as_vec().first().cloned())
            .collect();
        assert!(names.iter().any(|n| n == "d"), "missing d tag");
        assert!(names.iter().any(|n| n == "p"), "missing p tag");
    }

    #[test]
    fn the_enforced_agents_identity_never_appears_in_the_slug_on_the_wire() {
        // The d tag is HMAC'd precisely so a relay operator cannot enumerate
        // who this guardian has enforced against.
        let id = identity();
        let receipt = a_receipt();
        let event = enforcement_engram(&id, &receipt, id.public_key_hex()).unwrap();

        let wire = serde_json::to_string(&event).unwrap();
        assert!(!wire.contains(&slug_enforcement(&receipt.receipt_id.to_string())));
    }

    #[test]
    fn d_tag_is_deterministic_and_key_dependent() {
        let slug = "mem/zangbeto/enforcement/x";
        assert_eq!(d_tag(slug, b"k1"), d_tag(slug, b"k1"));
        assert_ne!(d_tag(slug, b"k1"), d_tag(slug, b"k2"));
        assert_ne!(d_tag(slug, b"k1"), d_tag("mem/zangbeto/enforcement/y", b"k1"));
    }

    #[test]
    fn an_enforcement_claim_is_a_crucible_claim() {
        let id = identity();
        let claim = EnforcementClaim {
            statement: "quarantine of agent-1 was warranted".into(),
            falsifier: "sha256:abc".into(),
            receipt_id: Uuid::new_v4().to_string(),
            half_life_secs: 3600,
        };
        let event = enforcement_claim(&id, &claim).unwrap();
        assert_eq!(event.kind(), Kind::Custom(KIND_CLAIM));
        assert!(event.verify().is_ok());
    }

    #[test]
    fn relay_auth_is_kind_22242() {
        let id = identity();
        let event = relay_auth(&id, "chal", "wss://relay.example.com").unwrap();
        assert_eq!(event.kind(), Kind::Custom(KIND_AUTH));
        assert!(event.verify().is_ok());
    }

    #[test]
    fn a_malformed_relay_url_is_rejected_before_signing() {
        assert!(matches!(
            relay_auth(&identity(), "c", "not a url"),
            Err(BridgeError::RelayUrl(_))
        ));
    }

    #[test]
    fn publishing_under_an_unadmitted_kind_fails_locally() {
        // Guards the failure the relay would otherwise report as a confusing
        // post-auth rejection.
        let err = build(&identity(), 31337, "{}".into(), vec![]).unwrap_err();
        assert!(matches!(err, BridgeError::KindNotAdmitted(31337)));
    }

    #[test]
    fn zangbeto_mints_no_kind_inside_crucibles_block() {
        for k in [KIND_AGENT_ENGRAM, KIND_CLAIM] {
            assert!(relay_admits(k), "kind {k} would be rejected at ingest");
        }
        assert!(!relay_admits(31337));
    }

    #[test]
    fn a_wrong_length_seed_is_rejected_with_a_clear_error() {
        // guardian.rs already validates this on load; failing here too means a
        // caller constructing the identity by another route cannot slip past.
        let err = GuardianNostrIdentity::from_guardian_seed(&[0u8; 31]).unwrap_err();
        assert!(matches!(err, BridgeError::Derivation(_)));
        assert!(GuardianNostrIdentity::from_guardian_seed(&[]).is_err());
    }

    #[test]
    fn the_guardian_exposes_the_same_identity_the_bridge_derives() {
        // The two entry points must not drift apart: a guardian publishing via
        // Guardian::nostr_identity and a verifier deriving from the same seed
        // have to land on one pubkey.
        let dir = std::env::temp_dir().join(format!("zb-guardian-{}", Uuid::new_v4()));
        let seed_path = dir.join("guardian.seed");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&seed_path, SEED).unwrap();

        let guardian = crate::guardian::Guardian::load_or_create(&seed_path).unwrap();
        assert_eq!(
            guardian.nostr_identity().unwrap().public_key_hex(),
            identity().public_key_hex()
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn debug_rendering_does_not_leak_the_secret() {
        let id = identity();
        let rendered = format!("{id:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&hex::encode(id.secret_bytes().unwrap())));
    }
}
