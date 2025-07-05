use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IDError {
    #[error("invalid hex encoding")]
    InvalidHex(#[from] lowercase_hex::FromHexError),
    #[error("invalid ID length: expected 32 bytes, got {0}")]
    InvalidLength(usize),
}

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("invalid hex encoding")]
    InvalidHex(#[from] lowercase_hex::FromHexError),
    #[error("invalid signature length: expected 64 bytes, got {0}")]
    InvalidLength(usize),
}

/// A 32-byte event ID
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ID(pub [u8; 32]);

impl ID {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_u64_lossy(&self) -> u64 {
        let bytes: [u8; 8] = self.0[8..16].try_into().unwrap();
        u64::from_be_bytes(bytes)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, IDError> {
        if hex_str.len() != 64 {
            return Err(IDError::InvalidLength(hex_str.len() / 2));
        }
        let mut bytes = [0u8; 32];
        lowercase_hex::decode_to_slice(hex_str, &mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn to_hex(&self) -> String {
        lowercase_hex::encode(self.0)
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

impl fmt::Debug for ID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<id:{}>", self.to_hex())
    }
}

impl fmt::Display for ID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<id={}>", self.to_hex())
    }
}

/// A 64-byte signature
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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
    pub fn from_hex(hex_str: &str) -> Result<Self, SignatureError> {
        if hex_str.len() != 128 {
            return Err(SignatureError::InvalidLength(hex_str.len() / 2));
        }
        let mut bytes = [0u8; 64];
        lowercase_hex::decode_to_slice(hex_str, &mut bytes)?;
        Ok(Self(bytes))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        lowercase_hex::encode(self.0)
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

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<sig:{}>", self.to_hex())
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<sig={}>", self.to_hex())
    }
}

/// map of tag names to values for filtering
pub type TagMap = std::collections::HashMap<String, Vec<String>>;

/// event kind type
#[derive(
    Copy, Error, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize,
)]
pub struct Kind(pub u16);

impl Kind {
    /// check if this kind is regular (1-9999, excluding 0 and 3)
    pub fn is_regular(&self) -> bool {
        self.0 < 10000 && self.0 != 0 && self.0 != 3
    }

    /// check if this kind is replaceable (0, 3, or 10000-19999)
    pub fn is_replaceable(&self) -> bool {
        self.0 == 0 || self.0 == 3 || (10000..20000).contains(&self.0)
    }

    /// check if this kind is ephemeral (20000-29999)
    pub fn is_ephemeral(&self) -> bool {
        (20000..30000).contains(&self.0)
    }

    /// check if this kind is addressable (30000-39999)
    pub fn is_addressable(&self) -> bool {
        (30000..40000).contains(&self.0)
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
