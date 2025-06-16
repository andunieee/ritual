use crate::{PubKey, Result};
use rand::RngCore;
use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey as Secp256k1SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A 32-byte secret key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// Create a new secret key from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the bytes of the secret key
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create secret key from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = if hex_str.len() < 64 {
            format!("{:0>64}", hex_str)
        } else if hex_str.len() > 64 {
            return Err(format!("secret key should be at most 64-char hex, got '{}'", hex_str).into());
        } else {
            hex_str.to_string()
        };

        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&hex_str, &mut bytes)?;
        Ok(Self(bytes))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get the public key for this secret key
    pub fn public_key(&self) -> PubKey {
        get_public_key(*self)
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sk::{}", self.to_hex())
    }
}

/// Generate a new random secret key
pub fn generate() -> SecretKey {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    SecretKey(bytes)
}

/// Get the public key for a secret key
pub fn get_public_key(secret_key: SecretKey) -> PubKey {
    let secp = Secp256k1::new();
    let secret_key = Secp256k1SecretKey::from_slice(&secret_key.0).expect("valid secret key");
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly_pk, _) = XOnlyPublicKey::from_keypair(&keypair);
    PubKey::from_bytes(xonly_pk.serialize())
}

/// Check if a slice contains a specific public key
pub fn contains_pub_key(haystack: &[PubKey], needle: PubKey) -> bool {
    haystack.contains(&needle)
}

/// Key constant for testing
pub const KEY_ONE: SecretKey = SecretKey([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

/// Zero public key constant
pub const ZERO_PK: PubKey = PubKey([0; 32]);
