use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// A 32-byte event ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ID(pub [u8; 32]);

impl ID {
    /// Create a new ID from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the bytes of the ID
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create ID from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut bytes)?;
        Ok(Self(bytes))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl Serialize for ID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ID::from_hex(&s).map_err(Error::custom)
    }
}

impl fmt::Display for ID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "id::{}", self.to_hex())
    }
}

/// A 32-byte public key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PubKey(pub [u8; 32]);

impl PubKey {
    /// Create a new public key from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the bytes of the public key
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create public key from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut bytes)?;
        Ok(Self(bytes))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl Serialize for PubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        PubKey::from_hex(&s).map_err(Error::custom)
    }
}

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pk::{}", self.to_hex())
    }
}

/// A 64-byte signature
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    /// Create a new signature from bytes
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Get the bytes of the signature
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Create signature from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        let mut bytes = [0u8; 64];
        hex::decode_to_slice(hex_str, &mut bytes)?;
        Ok(Self(bytes))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Signature::from_hex(&s).map_err(Error::custom)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sig::{}", self.to_hex())
    }
}

/// Map of tag names to values for filtering
pub type TagMap = std::collections::HashMap<String, Vec<String>>;

/// Relay event combining an event with its source relay
#[derive(Debug, Clone)]
pub struct RelayEvent {
    pub event: crate::Event,
    pub relay_url: String,
}

impl fmt::Display for RelayEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] >> {}", self.relay_url, self.event)
    }
}
