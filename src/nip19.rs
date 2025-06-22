//! NIP-19: bech32-encoded entities
//!
//! this module provides encoding and decoding functions for NIP-19 bech32-encoded entities.

use crate::{pointers::*, Kind, PubKey, SecretKey, ID};
use bech32::{Bech32, Hrp};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Nip19Error {
    #[error("bech32 decoding error")]
    Bech32(#[from] bech32::DecodeError),
    #[error("invalid data length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("no {0} found")]
    MissingField(String),
    #[error("incomplete {0}")]
    Incomplete(String),
    #[error("unknown prefix '{0}'")]
    UnknownPrefix(String),
    #[error("unexpected decode result for {0}")]
    UnexpectedResult(String),
    #[error("TLV value too long")]
    TlvTooLong,
    #[error("UTF-8 conversion error")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("invalid uint32 value for kind")]
    InvalidKind,
}

pub type Result<T> = std::result::Result<T, Nip19Error>;

const TLV_DEFAULT: u8 = 0;
const TLV_RELAY: u8 = 1;
const TLV_AUTHOR: u8 = 2;
const TLV_KIND: u8 = 3;

#[derive(Debug, Clone, PartialEq)]
pub enum DecodeResult {
    SecretKey(SecretKey),
    PubKey(PubKey),
    Profile(ProfilePointer),
    Event(EventPointer),
    Entity(EntityPointer),
}

/// decode a bech32-encoded NIP-19 string
pub fn decode(bech32_string: &str) -> Result<DecodeResult> {
    let (prefix, data) = bech32::decode(bech32_string)?;

    match prefix.as_str() {
        "nsec" => {
            if data.len() != 32 {
                return Err(Nip19Error::InvalidLength {
                    expected: 32,
                    actual: data.len(),
                });
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data);
            Ok(DecodeResult::SecretKey(SecretKey::from_bytes(bytes)))
        }
        "note" => {
            if data.len() != 32 {
                return Err(Nip19Error::InvalidLength {
                    expected: 32,
                    actual: data.len(),
                });
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data);
            Ok(DecodeResult::Event(EventPointer {
                id: ID::from_bytes(bytes),
                relays: Vec::new(),
                author: None,
                kind: None,
            }))
        }
        "npub" => {
            if data.len() != 32 {
                return Err(Nip19Error::InvalidLength {
                    expected: 32,
                    actual: data.len(),
                });
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data);
            Ok(DecodeResult::PubKey(PubKey::from_bytes(bytes)))
        }
        "nprofile" => {
            let mut result = ProfilePointer {
                public_key: PubKey::from_bytes([0u8; 32]),
                relays: Vec::new(),
            };
            let mut curr = 0;
            let mut found_pubkey = false;

            while curr < data.len() {
                let (typ, value) = read_tlv_entry(&data[curr..])?;
                if value.is_empty() {
                    break;
                }

                match typ {
                    TLV_DEFAULT => {
                        if value.len() != 32 {
                            return Err(Nip19Error::InvalidLength {
                                expected: 32,
                                actual: value.len(),
                            });
                        }
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&value);
                        result.public_key = PubKey::from_bytes(bytes);
                        found_pubkey = true;
                    }
                    TLV_RELAY => {
                        result.relays.push(String::from_utf8(value.clone())?);
                    }
                    _ => {
                        // ignore unknown TLV types
                    }
                }

                curr += 2 + value.len();
            }

            if !found_pubkey {
                return Err(Nip19Error::MissingField("pubkey for nprofile".to_string()));
            }

            Ok(DecodeResult::Profile(result))
        }
        "nevent" => {
            let mut result = EventPointer {
                id: ID::from_bytes([0u8; 32]),
                relays: Vec::new(),
                author: None,
                kind: None,
            };
            let mut curr = 0;
            let mut found_id = false;

            while curr < data.len() {
                let (typ, value) = read_tlv_entry(&data[curr..])?;
                if value.is_empty() {
                    break;
                }

                match typ {
                    TLV_DEFAULT => {
                        if value.len() != 32 {
                            return Err(Nip19Error::InvalidLength {
                                expected: 32,
                                actual: value.len(),
                            });
                        }
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&value);
                        result.id = ID::from_bytes(bytes);
                        found_id = true;
                    }
                    TLV_RELAY => {
                        result.relays.push(String::from_utf8(value.clone())?);
                    }
                    TLV_AUTHOR => {
                        if value.len() != 32 {
                            return Err(Nip19Error::InvalidLength {
                                expected: 32,
                                actual: value.len(),
                            });
                        }
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&value);
                        result.author = Some(PubKey::from_bytes(bytes));
                    }
                    TLV_KIND => {
                        if value.len() != 4 {
                            return Err(Nip19Error::InvalidKind);
                        }
                        let kind_bytes: [u8; 4] = value.clone().try_into().unwrap();
                        result.kind = Some(u32::from_be_bytes(kind_bytes) as Kind);
                    }
                    _ => {
                        // ignore unknown TLV types
                    }
                }

                curr += 2 + value.len();
            }

            if !found_id {
                return Err(Nip19Error::MissingField("id for nevent".to_string()));
            }

            Ok(DecodeResult::Event(result))
        }
        "naddr" => {
            let mut result = EntityPointer {
                public_key: PubKey::from_bytes([0u8; 32]),
                kind: 0,
                identifier: String::new(),
                relays: Vec::new(),
            };
            let mut curr = 0;
            let mut found_kind = false;
            let mut found_identifier = false;
            let mut found_pubkey = false;

            while curr < data.len() {
                let (typ, value) = read_tlv_entry(&data[curr..])?;
                if value.is_empty() {
                    break;
                }

                match typ {
                    TLV_DEFAULT => {
                        result.identifier = String::from_utf8(value.clone())?;
                        found_identifier = true;
                    }
                    TLV_RELAY => {
                        result.relays.push(String::from_utf8(value.clone())?);
                    }
                    TLV_AUTHOR => {
                        if value.len() != 32 {
                            return Err(Nip19Error::InvalidLength {
                                expected: 32,
                                actual: value.len(),
                            });
                        }
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&value);
                        result.public_key = PubKey::from_bytes(bytes);
                        found_pubkey = true;
                    }
                    TLV_KIND => {
                        if value.len() != 4 {
                            return Err(Nip19Error::InvalidKind);
                        }
                        let kind_bytes: [u8; 4] = value.clone().try_into().unwrap();
                        result.kind = u32::from_be_bytes(kind_bytes) as Kind;
                        found_kind = true;
                    }
                    _ => {
                        // ignore unknown TLV types
                    }
                }

                curr += 2 + value.len();
            }

            if !found_kind || !found_identifier || !found_pubkey {
                return Err(Nip19Error::Incomplete("naddr".to_string()));
            }

            Ok(DecodeResult::Entity(result))
        }
        _ => Err(Nip19Error::UnknownPrefix(prefix.to_string())),
    }
}

/// encode a secret key as nsec
pub fn encode_nsec(sk: &SecretKey) -> String {
    bech32::encode::<Bech32>(Hrp::parse_unchecked("nsec"), sk.as_bytes()).unwrap()
}

/// encode a public key as npub
pub fn encode_npub(pk: &PubKey) -> String {
    bech32::encode::<Bech32>(Hrp::parse_unchecked("npub"), pk.as_bytes()).unwrap()
}

/// encode a profile pointer as nprofile
pub fn encode_nprofile(pk: &PubKey, relays: &[String]) -> String {
    let mut buf = Vec::new();
    write_tlv_entry(&mut buf, TLV_DEFAULT, pk.as_bytes());

    for relay in relays {
        write_tlv_entry(&mut buf, TLV_RELAY, relay.as_bytes());
    }

    bech32::encode::<Bech32>(Hrp::parse_unchecked("nprofile"), &buf).unwrap()
}

/// encode an event pointer as nevent
pub fn encode_nevent(id: &ID, relays: &[String], author: Option<&PubKey>) -> String {
    let mut buf = Vec::new();
    write_tlv_entry(&mut buf, TLV_DEFAULT, id.as_bytes());

    for relay in relays {
        write_tlv_entry(&mut buf, TLV_RELAY, relay.as_bytes());
    }

    if let Some(author) = author {
        write_tlv_entry(&mut buf, TLV_AUTHOR, author.as_bytes());
    }

    bech32::encode::<Bech32>(Hrp::parse_unchecked("nevent"), &buf).unwrap()
}

/// encode an entity pointer as naddr
pub fn encode_naddr(pk: &PubKey, kind: Kind, identifier: &str, relays: &[String]) -> String {
    let mut buf = Vec::new();
    write_tlv_entry(&mut buf, TLV_DEFAULT, identifier.as_bytes());

    for relay in relays {
        write_tlv_entry(&mut buf, TLV_RELAY, relay.as_bytes());
    }

    write_tlv_entry(&mut buf, TLV_AUTHOR, pk.as_bytes());

    let kind_bytes = (kind as u32).to_be_bytes();
    write_tlv_entry(&mut buf, TLV_KIND, &kind_bytes);

    bech32::encode::<Bech32>(Hrp::parse_unchecked("naddr"), &buf).unwrap()
}

/// encode a pointer using the appropriate encoding
pub fn encode_pointer(pointer: &Pointer) -> String {
    match pointer {
        Pointer::Profile(p) => {
            if p.relays.is_empty() {
                encode_npub(&p.public_key)
            } else {
                encode_nprofile(&p.public_key, &p.relays)
            }
        }
        Pointer::Event(p) => encode_nevent(&p.id, &p.relays, p.author.as_ref()),
        Pointer::Entity(p) => encode_naddr(&p.public_key, p.kind, &p.identifier, &p.relays),
    }
}

/// convert a bech32 string to a pointer
pub fn to_pointer(code: &str) -> Result<Pointer> {
    match decode(code)? {
        DecodeResult::PubKey(pk) => Ok(Pointer::Profile(ProfilePointer {
            public_key: pk,
            relays: Vec::new(),
        })),
        DecodeResult::Profile(p) => Ok(Pointer::Profile(p)),
        DecodeResult::Event(p) => Ok(Pointer::Event(p)),
        DecodeResult::Entity(p) => Ok(Pointer::Entity(p)),
        _ => Err(Nip19Error::UnexpectedResult(code.to_string())),
    }
}

/// read a TLV entry from data
fn read_tlv_entry(data: &[u8]) -> Result<(u8, Vec<u8>)> {
    if data.len() < 2 {
        return Ok((0, Vec::new()));
    }

    let typ = data[0];
    let length = data[1] as usize;

    if data.len() < 2 + length {
        return Ok((typ, Vec::new()));
    }

    let value = data[2..2 + length].to_vec();
    Ok((typ, value))
}

/// write a TLV entry to buffer
fn write_tlv_entry(buf: &mut Vec<u8>, typ: u8, value: &[u8]) {
    buf.push(typ);
    buf.push(value.len() as u8);
    buf.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_npub() {
        let pk =
            PubKey::from_hex("d91191e30e00444b942c0e82cad470b32af171764c2275bee0bd99377efd4075")
                .unwrap();
        let npub = encode_npub(&pk);
        assert_eq!(
            npub,
            "npub1mygerccwqpzyh9pvp6pv44rskv40zutkfs38t0hqhkvnwlhagp6s3psn5p"
        );

        let result = decode(&npub).unwrap();
        if let DecodeResult::PubKey(decoded_pk) = result {
            assert_eq!(decoded_pk, pk);
        } else {
            panic!("Expected PubKey result");
        }
    }

    #[test]
    fn test_encode_decode_nsec() {
        let sk_hex = "fe20f3381b9404e9a35afb49b3dc070a4dc1ffd321ab8f3eae979ab96f601e3a";
        let sk = SecretKey::from_hex(sk_hex).unwrap();
        let nsec = encode_nsec(&sk);
        assert_eq!(
            nsec,
            "nsec1lcs0xwqmjszwng66ldym8hq8pfxurl7nyx4c704wj7dtjmmqrcaqazp4dg"
        );

        let result = decode(&nsec).unwrap();
        if let DecodeResult::SecretKey(decoded_sk) = result {
            assert_eq!(decoded_sk.as_bytes(), sk.as_bytes());
        } else {
            panic!("Expected SecretKey result");
        }
    }

    #[test]
    fn test_encode_decode_nprofile() {
        let pk =
            PubKey::from_hex("d91191e30e00444b942c0e82cad470b32af171764c2275bee0bd99377efd4075")
                .unwrap();
        let relays = vec![
            "wss://relay.primal.net".to_string(),
            "wss://nostr.land".to_string(),
        ];

        let nprofile = encode_nprofile(&pk, &relays);
        assert_eq!(nprofile, "nprofile1qqsdjyv3uv8qq3ztjskqaqk263ctx2h3w9mycgn4hmstmxfh0m75qagpzemhxue69uhhyetvv9ujuurjd9kkzmpwdejhgqgswaehxw309ahx7um5wghxcctwvs3a0whv");

        let result = decode(&nprofile).unwrap();
        if let DecodeResult::Profile(profile) = result {
            assert_eq!(profile.public_key, pk);
            assert_eq!(profile.relays, relays);
        } else {
            panic!("Expected Profile result");
        }
    }
}
