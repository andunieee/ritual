use crate::{Kind, PubKey, Signature, Tags, Timestamp, ID};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Represents a Nostr event
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
    /// Create a new event
    pub fn new(
        pubkey: PubKey,
        created_at: Timestamp,
        kind: Kind,
        tags: Tags,
        content: String,
    ) -> Self {
        let mut event = Self {
            id: ID::from_bytes([0; 32]),
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig: Signature::from_bytes([0; 64]),
        };
        event.id = event.get_id();
        event
    }

    /// Get the event ID by serializing and hashing
    pub fn get_id(&self) -> ID {
        let serialized = self.serialize();
        let hash = Sha256::digest(&serialized);
        ID::from_bytes(hash.into())
    }

    /// Check if the event ID matches the computed ID
    pub fn check_id(&self) -> bool {
        self.get_id() == self.id
    }

    /// Serialize the event for ID computation
    pub fn serialize(&self) -> Vec<u8> {
        let array = serde_json::json!([
            0,
            self.pubkey.to_hex(),
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
            Err(_) => write!(f, "Event({})", self.id),
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
