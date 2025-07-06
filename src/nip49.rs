//! NIP-49: Private Key Encryption
//!
//! This module implements NIP-49 for encrypting and decrypting private keys
//! using a password-based key derivation function (scrypt) and XChaCha20-Poly1305.

use crate::{keys, SecretKey};
use bech32::{Bech32, Hrp};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use scrypt::{scrypt, Params};
use secp256k1::rand::TryRngCore;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

#[derive(Error, Debug)]
pub enum Nip49Error {
    #[error("bech32 encoding/decoding error")]
    Bech32(#[from] bech32::DecodeError),
    #[error("expected prefix ncryptsec")]
    InvalidPrefix,
    #[error("invalid data length")]
    InvalidDataLength,
    #[error("expected version 0x02, got {0:#x}")]
    InvalidVersion(u8),
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("invalid decrypted key length")]
    InvalidKeyLength,
    #[error("scrypt parameter error")]
    ScryptParams(#[from] scrypt::errors::InvalidParams),
    #[error("scrypt operation error")]
    ScryptOperation(#[from] scrypt::errors::InvalidOutputLen),
    #[error("invalid key length for cipher")]
    InvalidCipherKeyLength,
    #[error("encrypted key is not valid")]
    InvalidSecretKey(#[from] keys::SecretKeyError),
}

pub type Result<T> = std::result::Result<T, Nip49Error>;

/// key security byte values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySecurityByte {
    KnownToHaveBeenHandledInsecurely = 0x00,
    NotKnownToHaveBeenHandledInsecurely = 0x01,
    ClientDoesNotTrackThisData = 0x02,
}

impl From<u8> for KeySecurityByte {
    fn from(value: u8) -> Self {
        match value {
            0x00 => KeySecurityByte::KnownToHaveBeenHandledInsecurely,
            0x01 => KeySecurityByte::NotKnownToHaveBeenHandledInsecurely,
            _ => KeySecurityByte::ClientDoesNotTrackThisData,
        }
    }
}

impl From<KeySecurityByte> for u8 {
    fn from(ksb: KeySecurityByte) -> Self {
        ksb as u8
    }
}

/// encrypt a secret key with a password
pub fn encrypt(
    secret_key: &SecretKey,
    password: &str,
    logn: u8,
    ksb: KeySecurityByte,
) -> Result<String> {
    let mut rng = secp256k1::rand::rng();
    let mut salt = [0u8; 16];
    rng.try_fill_bytes(&mut salt).expect("infallible");

    let n = 1u32 << logn;
    let key = get_key(password, &salt, n)?;

    let mut concat = vec![0u8; 91];
    concat[0] = 0x02; // version
    concat[1] = logn;
    concat[2..2 + 16].copy_from_slice(&salt);

    let mut nonce = [0u8; 24];
    secp256k1::rand::rng()
        .try_fill_bytes(&mut nonce)
        .expect("infallible");
    concat[2 + 16..2 + 16 + 24].copy_from_slice(&nonce);

    let ad = [ksb.into()];
    concat[2 + 16 + 24] = ad[0];

    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|_| Nip49Error::InvalidCipherKeyLength)?;
    let xnonce = XNonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(
            xnonce,
            Payload {
                msg: secret_key.as_bytes(),
                aad: &ad,
            },
        )
        .map_err(|err| Nip49Error::EncryptionFailed(err.to_string()))?;

    concat[2 + 16 + 24 + 1..].copy_from_slice(&ciphertext);

    let encoded = bech32::encode::<Bech32>(Hrp::parse_unchecked("ncryptsec"), concat.as_slice())
        .expect("encoding never fails");
    Ok(encoded)
}

/// decrypt to raw bytes
pub fn decrypt(bech32_string: &str, password: &str) -> Result<SecretKey> {
    let (hrp, data) = bech32::decode(bech32_string)?;

    if hrp.as_str() != "ncryptsec1" {
        return Err(Nip49Error::InvalidPrefix);
    }

    if data.len() < 91 {
        return Err(Nip49Error::InvalidDataLength);
    }

    let version = data[0];
    if version != 0x02 {
        return Err(Nip49Error::InvalidVersion(version));
    }

    let logn = data[1];
    let n = 1u32 << logn;
    let salt = &data[2..2 + 16];
    let nonce = &data[2 + 16..2 + 16 + 24];
    let ad = &data[2 + 16 + 24..2 + 16 + 24 + 1];
    let encrypted_key = &data[2 + 16 + 24 + 1..];

    let key = get_key(password, salt, n)?;

    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|_| Nip49Error::InvalidCipherKeyLength)?;
    let xnonce = XNonce::from_slice(nonce);
    let decrypted = cipher
        .decrypt(
            xnonce,
            Payload {
                msg: encrypted_key,
                aad: ad,
            },
        )
        .map_err(|err| Nip49Error::DecryptionFailed(err.to_string()))?;

    if decrypted.len() != 32 {
        return Err(Nip49Error::InvalidKeyLength);
    }

    Ok(SecretKey::from_bytes(decrypted.try_into().unwrap())?)
}

fn get_key(password: &str, salt: &[u8], n: u32) -> Result<Vec<u8>> {
    // Normalize password using NFKC
    let normalized_password: String = password.nfkc().collect();

    let params = Params::new(
        (n as f64).log2() as u8,
        8,  // r
        1,  // p
        32, // output length
    )?;

    let mut key = vec![0u8; 32];
    scrypt(normalized_password.as_bytes(), salt, &params, &mut key)?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SecretKey;

    #[test]
    fn test_decrypt_key_from_nip_text() {
        let ncrypt = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";
        let secret_key = decrypt(ncrypt, "nostr").unwrap();
        let expected =
            SecretKey::from_hex("3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683")
                .unwrap();
        assert_eq!(secret_key, expected);
    }

    #[test]
    fn test_encrypt_and_decrypt() {
        let test_cases = vec![
            (
                ".ksjabdk.aselqwe",
                "14c226dbdd865d5e1645e72c7470fd0a17feb42cc87b750bab6538171b3a3f8a",
                1,
                KeySecurityByte::KnownToHaveBeenHandledInsecurely,
            ),
            (
                "skjdaklrnçurbç l",
                "f7f2f77f98890885462764afb15b68eb5f69979c8046ecb08cad7c4ae6b221ab",
                2,
                KeySecurityByte::NotKnownToHaveBeenHandledInsecurely,
            ),
            (
                "777z7z7z7z7z7z7z",
                "11b25a101667dd9208db93c0827c6bdad66729a5b521156a7e9d3b22b3ae8944",
                3,
                KeySecurityByte::ClientDoesNotTrackThisData,
            ),
            (
                "",
                "f7f2f77f98890885462764afb15b68eb5f69979c8046ecb08cad7c4ae6b221ab",
                4,
                KeySecurityByte::KnownToHaveBeenHandledInsecurely,
            ),
            (
                "ÅΩẛ̣",
                "11b25a101667dd9208db93c0827c6bdad66729a5b521156a7e9d3b22b3ae8944",
                9,
                KeySecurityByte::NotKnownToHaveBeenHandledInsecurely,
            ),
        ];

        for (password, secret_hex, logn, ksb) in test_cases {
            let sk = SecretKey::from_hex(secret_hex).unwrap();
            let bech32_code = encrypt(&sk, password, logn, ksb).unwrap();

            assert!(bech32_code.starts_with("ncryptsec1"));
            assert_eq!(bech32_code.len(), 162);

            let decrypted_sk = decrypt(&bech32_code, password).unwrap();
            assert_eq!(sk, decrypted_sk);
        }
    }

    #[test]
    fn test_normalization() {
        let nonce = [1u8; 16];
        let n = 8;

        // different Unicode representations of the same string
        let key1 = get_key(
            &String::from_utf8(vec![
                0xE2, 0x84, 0xAB, 0xE2, 0x84, 0xA6, 0xE1, 0xBA, 0x9B, 0xCC, 0xA3,
            ])
            .unwrap(),
            &nonce,
            n,
        )
        .unwrap();
        let key2 = get_key(
            &String::from_utf8(vec![0xC3, 0x85, 0xCE, 0xA9, 0xE1, 0xB9, 0xA9]).unwrap(),
            &nonce,
            n,
        )
        .unwrap();
        let key3 = get_key("ÅΩẛ̣", &nonce, n).unwrap();
        let key4 = get_key("ÅΩẛ̣", &nonce, n).unwrap();

        assert_eq!(key1, key2, "normalization failed");
        assert_eq!(key2, key3, "normalization failed");
        assert_eq!(key3, key4, "normalization failed");
    }
}
