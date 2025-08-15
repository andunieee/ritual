use crate::{keys, pointers::*, Kind, PubKey, SecretKey, ID};
use bech32::{Bech32, Hrp};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("bech32 decoding error")]
    Bech32(#[from] bech32::DecodeError),

    #[error("invalid data length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("pubkey is invalid")]
    InvalidPubKey(#[from] keys::PubKeyError),

    #[error("secret key is invalid")]
    InvalidSecretKey(#[from] keys::SecretKeyError),

    #[error("incomplete code {0}")]
    Incomplete(Hrp),

    #[error("unknown prefix {0}")]
    UnknownPrefix(Hrp),

    #[error("malformed code {0}: {0}")]
    Malformed(Hrp, String),

    #[error("although valid, this code cannot be converted to a pointer")]
    NotAPointer,
}

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
    Address(AddressPointer),
}

pub fn decode(bech32_string: &str) -> Result<DecodeResult, DecodeError> {
    let (prefix, data) = bech32::decode(bech32_string)?;

    match prefix.as_str() {
        "nsec" => {
            if data.len() != 32 {
                return Err(DecodeError::InvalidLength {
                    expected: 32,
                    actual: data.len(),
                });
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data);
            Ok(DecodeResult::SecretKey(SecretKey::from_bytes(bytes)?))
        }
        "note" => {
            if data.len() != 32 {
                return Err(DecodeError::InvalidLength {
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
                return Err(DecodeError::InvalidLength {
                    expected: 32,
                    actual: data.len(),
                });
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data);
            Ok(DecodeResult::PubKey(PubKey::from_bytes(bytes)?))
        }
        "nprofile" => {
            let mut curr = 0;
            let mut relays = Vec::new();
            let mut pubkey = None;

            while curr < data.len() {
                let (typ, value) = read_tlv_entry(&data[curr..]);
                if value.is_empty() {
                    break;
                }

                curr += 2 + value.len();

                match typ {
                    TLV_DEFAULT => {
                        if value.len() != 32 {
                            return Err(DecodeError::InvalidLength {
                                expected: 32,
                                actual: value.len(),
                            });
                        }
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&value);
                        pubkey = Some(PubKey::from_bytes(bytes)?);
                    }
                    TLV_RELAY => {
                        relays.push(String::from_utf8(value).map_err(|err| {
                            DecodeError::Malformed(prefix, format!("utf8 error: {}", err))
                        })?);
                    }
                    _ => {
                        // ignore unknown TLV types
                    }
                }
            }

            match pubkey {
                Some(pubkey) => Ok(DecodeResult::Profile(ProfilePointer { pubkey, relays })),
                None => Err(DecodeError::Incomplete(prefix)),
            }
        }
        "nevent" => {
            let mut curr = 0;
            let mut relays = Vec::new();
            let mut author = None;
            let mut kind = None;
            let mut id = None;

            while curr < data.len() {
                let (typ, value) = read_tlv_entry(&data[curr..]);
                if value.is_empty() {
                    break;
                }
                curr += 2 + value.len();

                match typ {
                    TLV_DEFAULT => {
                        if value.len() != 32 {
                            return Err(DecodeError::InvalidLength {
                                expected: 32,
                                actual: value.len(),
                            });
                        }
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&value);
                        id = Some(ID::from_bytes(bytes));
                    }
                    TLV_RELAY => {
                        relays.push(String::from_utf8(value).map_err(|err| {
                            DecodeError::Malformed(prefix, format!("utf8 error: {}", err))
                        })?);
                    }
                    TLV_AUTHOR => {
                        if value.len() != 32 {
                            return Err(DecodeError::InvalidLength {
                                expected: 32,
                                actual: value.len(),
                            });
                        }
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&value);
                        author = Some(PubKey::from_bytes(bytes)?);
                    }
                    TLV_KIND => {
                        if value.len() != 4 {
                            return Err(DecodeError::Malformed(
                                prefix,
                                "invalid kind length".to_string(),
                            ));
                        }
                        let kind_bytes: [u8; 4] = (&value[0..4]).try_into().unwrap();
                        kind = Some(Kind(u32::from_be_bytes(kind_bytes) as u16));
                    }
                    _ => {
                        // ignore unknown TLV types
                    }
                }
            }

            match id {
                Some(id) => Ok(DecodeResult::Event(EventPointer {
                    id,
                    relays,
                    author,
                    kind,
                })),
                None => Err(DecodeError::Incomplete(prefix)),
            }
        }
        "naddr" => {
            let mut curr = 0;
            let mut kind = None;
            let mut identifier = None;
            let mut pubkey = None;
            let mut relays = Vec::new();

            while curr < data.len() {
                let (typ, value) = read_tlv_entry(&data[curr..]);
                if value.is_empty() {
                    break;
                }
                curr += 2 + value.len();

                match typ {
                    TLV_DEFAULT => {
                        let str = String::from_utf8(value).map_err(|err| {
                            DecodeError::Malformed(prefix, format!("utf8 error: {}", err))
                        })?;
                        identifier = Some(str);
                    }
                    TLV_RELAY => {
                        relays.push(String::from_utf8(value).map_err(|err| {
                            DecodeError::Malformed(prefix, format!("utf8 error: {}", err))
                        })?);
                    }
                    TLV_AUTHOR => {
                        if value.len() != 32 {
                            return Err(DecodeError::InvalidLength {
                                expected: 32,
                                actual: value.len(),
                            });
                        }
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&value);
                        pubkey = Some(PubKey::from_bytes(bytes)?);
                    }
                    TLV_KIND => {
                        if value.len() != 4 {
                            return Err(DecodeError::Malformed(
                                prefix,
                                "invalid kind length".to_string(),
                            ));
                        }
                        let kind_bytes: [u8; 4] = value.try_into().unwrap();
                        kind = Some(Kind(u32::from_be_bytes(kind_bytes) as u16));
                    }
                    _ => {
                        // ignore unknown TLV types
                    }
                }
            }

            match (kind, pubkey, identifier) {
                (Some(kind), Some(pubkey), Some(identifier)) => {
                    Ok(DecodeResult::Address(AddressPointer {
                        pubkey,
                        kind,
                        identifier,
                        relays,
                    }))
                }
                _ => Err(DecodeError::Incomplete(prefix)),
            }
        }
        _ => Err(DecodeError::UnknownPrefix(prefix)),
    }
}

#[derive(Error, Debug)]
pub enum EncodeError {
    #[error("bech32 encoding error: {0}")]
    Bech32(#[from] bech32::EncodeError),
}

/// encode a profile pointer as nprofile
pub fn encode_nprofile(pk: &PubKey, relays: &[String]) -> String {
    let mut buf = Vec::new();
    write_tlv_entry(&mut buf, TLV_DEFAULT, pk.as_bytes());

    for relay in relays {
        write_tlv_entry(&mut buf, TLV_RELAY, relay.as_bytes());
    }

    bech32::encode::<Bech32>(Hrp::parse_unchecked("nprofile"), &buf)
        .expect("failed to encode nprofile")
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

    bech32::encode::<Bech32>(Hrp::parse_unchecked("nevent"), &buf).expect("failed to encode nevent")
}

/// encode an entity pointer as naddr
pub fn encode_naddr(pk: &PubKey, kind: Kind, identifier: &str, relays: &[String]) -> String {
    let mut buf = Vec::new();
    write_tlv_entry(&mut buf, TLV_DEFAULT, identifier.as_bytes());

    for relay in relays {
        write_tlv_entry(&mut buf, TLV_RELAY, relay.as_bytes());
    }

    write_tlv_entry(&mut buf, TLV_AUTHOR, pk.as_bytes());

    let kind_bytes = (kind.0 as u32).to_be_bytes();
    write_tlv_entry(&mut buf, TLV_KIND, &kind_bytes);

    bech32::encode::<Bech32>(Hrp::parse_unchecked("naddr"), &buf).expect("failed to encode naddr")
}

/// encode a pointer using the appropriate encoding
pub fn encode_pointer(pointer: &Pointer) -> String {
    match pointer {
        Pointer::Profile(p) => {
            if p.relays.is_empty() {
                p.pubkey.to_npub()
            } else {
                encode_nprofile(&p.pubkey, &p.relays)
            }
        }
        Pointer::Event(p) => encode_nevent(&p.id, &p.relays, p.author.as_ref()),
        Pointer::Address(p) => encode_naddr(&p.pubkey, p.kind, &p.identifier, &p.relays),
    }
}

/// convert a bech32 string to a pointer
pub fn to_pointer(code: &str) -> Result<Pointer, DecodeError> {
    match decode(code)? {
        DecodeResult::PubKey(pk) => Ok(Pointer::Profile(ProfilePointer {
            pubkey: pk,
            relays: Vec::new(),
        })),
        DecodeResult::Profile(p) => Ok(Pointer::Profile(p)),
        DecodeResult::Event(p) => Ok(Pointer::Event(p)),
        DecodeResult::Address(p) => Ok(Pointer::Address(p)),
        _ => Err(DecodeError::NotAPointer),
    }
}

/// read a TLV entry from data
fn read_tlv_entry(data: &[u8]) -> (u8, Vec<u8>) {
    if data.len() < 2 {
        return (0, Vec::new());
    }

    let typ = data[0];
    let length = data[1] as usize;

    if data.len() < 2 + length {
        return (typ, Vec::new());
    }

    let value = data[2..2 + length].to_vec();
    (typ, value)
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
        let npub = pk.to_npub();
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
        let nsec = &sk.to_nsec();
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
            assert_eq!(profile.pubkey, pk);
            assert_eq!(profile.relays, relays);
        } else {
            panic!("Expected Profile result");
        }
    }
}
