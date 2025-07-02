use crate::PubKey;
use secp256k1::{global::SECP256K1, Keypair, SecretKey as Secp256k1SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("secret key should be at most 64-char hex, got '{0}'")]
    InvalidLength(String),
    #[error("invalid hex encoding")]
    InvalidHex(#[from] lowercase_hex::FromHexError),
    #[error("invalid secret key")]
    InvalidSecretKey,
}

pub type Result<T> = std::result::Result<T, KeyError>;

/// A 32-byte secret key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretKey(pub [u8; 32]);

impl SecretKey {
    /// generate a new random secret key
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("getrandom call should never fail");
        SecretKey(bytes)
    }

    /// create a new secret key from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// get the bytes of the secret key
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// create secret key from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = if hex_str.len() < 64 {
            format!("{:0>64}", hex_str)
        } else if hex_str.len() > 64 {
            return Err(KeyError::InvalidLength(hex_str.to_string()));
        } else {
            hex_str.to_string()
        };

        let mut bytes = [0u8; 32];
        lowercase_hex::decode_to_slice(&hex_str, &mut bytes)?;
        Ok(Self(bytes))
    }

    /// convert to hex string
    pub fn to_hex(&self) -> String {
        lowercase_hex::encode(self.0)
    }

    /// get the public key for this secret key
    pub fn public_key(&self) -> PubKey {
        let secret_key = Secp256k1SecretKey::from_byte_array(self.0).expect("valid secret key");
        let keypair = Keypair::from_secret_key(SECP256K1, &secret_key);
        let (xonly_pk, _) = XOnlyPublicKey::from_keypair(&keypair);
        PubKey::from_bytes(xonly_pk.serialize())
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sk::{}", self.to_hex())
    }
}
