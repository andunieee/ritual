use crate::{Kind, PubKey, Signature, Tags, Timestamp, ID};
use secp256k1::{schnorr, XOnlyPublicKey, SECP256K1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// represents a signed nostr event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: ID,
    pub pubkey: PubKey,
    pub created_at: Timestamp,
    pub kind: Kind,
    pub tags: Tags,
    pub content: String,
    pub sig: Signature,
}

impl Event {
    pub fn verify_signature(&self) -> bool {
        let pubkey = match XOnlyPublicKey::from_byte_array(self.pubkey.0) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let signature = schnorr::Signature::from_byte_array(self.sig.0);

        let hash = Sha256::digest(&self.serialize());
        SECP256K1.verify_schnorr(&signature, &hash, &pubkey).is_ok()
    }

    /// check if the event ID matches the computed ID
    pub fn check_id(&self) -> bool {
        let serialized = self.serialize();
        let hash = Sha256::digest(&serialized);
        let id = ID::from_bytes(hash.into());

        id == self.id
    }

    /// serialize the event for ID computation
    pub fn serialize(&self) -> Vec<u8> {
        let array = serde_json::json!([
            0,
            self.pubkey,
            self.created_at.0,
            self.kind,
            self.tags.0,
            self.content
        ]);
        array.to_string().into_bytes()
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(json) => write!(f, "{}", json),
            Err(err) => write!(f, "Event({} >> {})", self.id, err),
        }
    }
}

impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Event {}

impl std::hash::Hash for Event {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
