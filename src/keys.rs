use secp256k1::{
    global::SECP256K1, rand, Keypair, SecretKey as Secp256k1SecretKey, XOnlyPublicKey,
};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecretKeyError {
    #[error("secret key should be at most 64-char hex, got '{0}'")]
    InvalidLength(String),
    #[error("invalid hex encoding")]
    InvalidHex(#[from] lowercase_hex::FromHexError),
    #[error("invalid secret key")]
    InvalidSecretKey,
}

#[derive(Error, Debug)]
pub enum PubKeyError {
    #[error("invalid hex encoding")]
    InvalidHex(#[from] lowercase_hex::FromHexError),
    #[error("invalid public key length: expected 32 bytes, got {0}")]
    InvalidLength(usize),
    #[error("public key not in curve")]
    InvalidPublicKey,
}

/// A 32-byte secret key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretKey(pub [u8; 32]);

impl SecretKey {
    /// generate a new random secret key
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let keypair = secp256k1::Keypair::new(SECP256K1, &mut rng);
        SecretKey(keypair.secret_bytes())
    }

    /// create a new secret key from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, SecretKeyError> {
        // ensure it is in the curve
        let _ = secp256k1::SecretKey::from_byte_array(bytes)
            .map_err(|_| SecretKeyError::InvalidSecretKey)?;

        Ok(Self(bytes))
    }

    /// get the bytes of the secret key
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// create secret key from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, SecretKeyError> {
        let hex_str = if hex_str.len() < 64 {
            format!("{:0>64}", hex_str)
        } else if hex_str.len() > 64 {
            return Err(SecretKeyError::InvalidLength(hex_str.to_string()));
        } else {
            hex_str.to_string()
        };

        let mut bytes = [0u8; 32];
        lowercase_hex::decode_to_slice(&hex_str, &mut bytes)?;

        // ensure it is in the curve
        let _ = secp256k1::SecretKey::from_byte_array(bytes)
            .map_err(|_| SecretKeyError::InvalidSecretKey)?;

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
            .expect("this works because we checked the secret key first")
    }

    pub fn to_ecdsa_key(&self) -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_byte_array(self.0).expect("we know the buffer is valid")
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sk::{}", self.to_hex())
    }
}

/// a 32-byte public key
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PubKey(pub [u8; 32]);

impl PubKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PubKeyError> {
        // ensure the public key is valid
        let _ = secp256k1::XOnlyPublicKey::from_byte_array(bytes)
            .map_err(|_| PubKeyError::InvalidPublicKey)?;

        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_u64_lossy(&self) -> u64 {
        let bytes: [u8; 8] = self.0[8..16].try_into().unwrap();
        u64::from_be_bytes(bytes)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, PubKeyError> {
        if hex_str.len() != 64 {
            return Err(PubKeyError::InvalidLength(hex_str.len() / 2));
        }
        let mut bytes = [0u8; 32];
        lowercase_hex::decode_to_slice(hex_str, &mut bytes)?;

        // ensure the public key is valid
        let _ = secp256k1::XOnlyPublicKey::from_byte_array(bytes)
            .map_err(|_| PubKeyError::InvalidPublicKey)?;

        Ok(Self(bytes))
    }

    pub fn to_hex(&self) -> String {
        lowercase_hex::encode(self.0)
    }

    pub fn to_ecdsa_key(&self) -> secp256k1::PublicKey {
        let mut buf = [0u8; 33];

        buf[0] = 2;
        buf[1..].clone_from_slice(&self.0);

        secp256k1::PublicKey::from_byte_array_compressed(buf).expect("we know the buffer is valid")
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

impl fmt::Debug for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<pk:{}>", self.to_hex())
    }
}

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<pk={}>", self.to_hex())
    }
}
