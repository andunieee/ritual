//! NIP-19: bech32-encoded entities
//!
//! this module provides encoding and decoding functions for NIP-19 bech32-encoded entities.

use crate::{pointers::*, Kind, PubKey, SecretKey, ID};
use bech32::{self, FromBase32, ToBase32, Variant};

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
pub fn decode(bech32_string: &str) -> crate::Result<(String, DecodeResult)> {
    let (prefix, data, _variant) = bech32::decode(bech32_string)?;
    let data = Vec::<u8>::from_base32(&data)?;

    match prefix.as_str() {
        "nsec" => {
            if data.len() != 32 {
                return Err(format!("nsec should be 32 bytes ({})", data.len()).into());
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data);
            Ok((
                prefix,
                DecodeResult::SecretKey(SecretKey::from_bytes(bytes)),
            ))
        }
        "note" => {
            if data.len() != 32 {
                return Err(format!("note should be 32 bytes ({})", data.len()).into());
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data);
            Ok((
                prefix,
                DecodeResult::Event(EventPointer {
                    id: ID::from_bytes(bytes),
                    relays: Vec::new(),
                    author: None,
                    kind: None,
                }),
            ))
        }
        "npub" => {
            if data.len() != 32 {
                return Err(format!("npub should be 32 bytes ({})", data.len()).into());
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data);
            Ok((prefix, DecodeResult::PubKey(PubKey::from_bytes(bytes))))
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
                            return Err(
                                format!("pubkey should be 32 bytes ({})", value.len()).into()
                            );
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
                return Err("no pubkey found for nprofile".into());
            }

            Ok((prefix, DecodeResult::Profile(result)))
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
                            return Err(format!("id should be 32 bytes ({})", value.len()).into());
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
                            return Err(
                                format!("author should be 32 bytes ({})", value.len()).into()
                            );
                        }
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&value);
                        result.author = Some(PubKey::from_bytes(bytes));
                    }
                    TLV_KIND => {
                        if value.len() != 4 {
                            return Err(
                                format!("invalid uint32 value for kind ({:?})", value).into()
                            );
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
                return Err("no id found for nevent".into());
            }

            Ok((prefix, DecodeResult::Event(result)))
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
                            return Err(
                                format!("author should be 32 bytes ({})", value.len()).into()
                            );
                        }
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&value);
                        result.public_key = PubKey::from_bytes(bytes);
                        found_pubkey = true;
                    }
                    TLV_KIND => {
                        if value.len() != 4 {
                            return Err(
                                format!("invalid uint32 value for kind ({:?})", value).into()
                            );
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
                return Err("incomplete naddr".into());
            }

            Ok((prefix, DecodeResult::Entity(result)))
        }
        _ => Err(format!("unknown prefix '{}'", prefix).into()),
    }
}

/// encode a secret key as nsec
pub fn encode_nsec(sk: &SecretKey) -> crate::Result<String> {
    let bits5 = sk.as_bytes().to_base32();
    Ok(bech32::encode("nsec", bits5, Variant::Bech32)?)
}

/// encode a public key as npub
pub fn encode_npub(pk: &PubKey) -> crate::Result<String> {
    let bits5 = pk.as_bytes().to_base32();
    Ok(bech32::encode("npub", bits5, Variant::Bech32)?)
}

/// encode a profile pointer as nprofile
pub fn encode_nprofile(pk: &PubKey, relays: &[String]) -> crate::Result<String> {
    let mut buf = Vec::new();
    write_tlv_entry(&mut buf, TLV_DEFAULT, pk.as_bytes())?;

    for relay in relays {
        write_tlv_entry(&mut buf, TLV_RELAY, relay.as_bytes())?;
    }

    let bits5 = buf.to_base32();
    Ok(bech32::encode("nprofile", bits5, Variant::Bech32)?)
}

/// encode an event pointer as nevent
pub fn encode_nevent(id: &ID, relays: &[String], author: Option<&PubKey>) -> crate::Result<String> {
    let mut buf = Vec::new();
    write_tlv_entry(&mut buf, TLV_DEFAULT, id.as_bytes())?;

    for relay in relays {
        write_tlv_entry(&mut buf, TLV_RELAY, relay.as_bytes())?;
    }

    if let Some(author) = author {
        write_tlv_entry(&mut buf, TLV_AUTHOR, author.as_bytes())?;
    }

    let bits5 = buf.to_base32();
    Ok(bech32::encode("nevent", bits5, Variant::Bech32)?)
}

/// encode an entity pointer as naddr
pub fn encode_naddr(
    pk: &PubKey,
    kind: Kind,
    identifier: &str,
    relays: &[String],
) -> crate::Result<String> {
    let mut buf = Vec::new();

    write_tlv_entry(&mut buf, TLV_DEFAULT, identifier.as_bytes())?;

    for relay in relays {
        write_tlv_entry(&mut buf, TLV_RELAY, relay.as_bytes())?;
    }

    write_tlv_entry(&mut buf, TLV_AUTHOR, pk.as_bytes())?;

    let kind_bytes = (kind as u32).to_be_bytes();
    write_tlv_entry(&mut buf, TLV_KIND, &kind_bytes)?;

    let bits5 = buf.to_base32();
    Ok(bech32::encode("naddr", bits5, Variant::Bech32)?)
}

/// encode a pointer using the appropriate encoding
pub fn encode_pointer(pointer: &Pointer) -> crate::Result<String> {
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
pub fn to_pointer(code: &str) -> crate::Result<Pointer> {
    let (prefix, data) = decode(code)?;

    match prefix.as_str() {
        "npub" => {
            if let DecodeResult::PubKey(pk) = data {
                Ok(Pointer::Profile(ProfilePointer {
                    public_key: pk,
                    relays: Vec::new(),
                }))
            } else {
                Err("unexpected decode result for npub".into())
            }
        }
        "nprofile" => {
            if let DecodeResult::Profile(p) = data {
                Ok(Pointer::Profile(p))
            } else {
                Err("unexpected decode result for nprofile".into())
            }
        }
        "nevent" => {
            if let DecodeResult::Event(p) = data {
                Ok(Pointer::Event(p))
            } else {
                Err("unexpected decode result for nevent".into())
            }
        }
        "note" => {
            if let DecodeResult::Event(p) = data {
                Ok(Pointer::Event(p))
            } else {
                Err("unexpected decode result for note".into())
            }
        }
        "naddr" => {
            if let DecodeResult::Entity(p) = data {
                Ok(Pointer::Entity(p))
            } else {
                Err("unexpected decode result for naddr".into())
            }
        }
        _ => Err(format!("unexpected prefix '{}' to '{}'", prefix, code).into()),
    }
}

/// read a TLV entry from data
fn read_tlv_entry(data: &[u8]) -> crate::Result<(u8, Vec<u8>)> {
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
fn write_tlv_entry(buf: &mut Vec<u8>, typ: u8, value: &[u8]) -> crate::Result<()> {
    let length = value.len();
    if length > 255 {
        return Err("TLV value too long".into());
    }

    buf.push(typ);
    buf.push(length as u8);
    buf.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_npub() {
        let pk =
            PubKey::from_hex("d91191e30e00444b942c0e82cad470b32af171764c2275bee0bd99377efd4075")
                .unwrap();
        let npub = encode_npub(&pk).unwrap();
        assert_eq!(
            npub,
            "npub1mygerccwqpzyh9pvp6pv44rskv40zutkfs38t0hqhkvnwlhagp6s3psn5p"
        );

        let (prefix, result) = decode(&npub).unwrap();
        assert_eq!(prefix, "npub");
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
        let nsec = encode_nsec(&sk).unwrap();
        assert_eq!(
            nsec,
            "nsec1lcs0xwqmjszwng66ldym8hq8pfxurl7nyx4c704wj7dtjmmqrcaqazp4dg"
        );

        let (prefix, result) = decode(&nsec).unwrap();
        assert_eq!(prefix, "nsec");
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

        let nprofile = encode_nprofile(&pk, &relays).unwrap();
        assert_eq!(nprofile, "nprofile1qqsdjyv3uv8qq3ztjskqaqk263ctx2h3w9mycgn4hmstmxfh0m75qagpzemhxue69uhhyetvv9ujuurjd9kkzmpwdejhgqgswaehxw309ahx7um5wghxcctwvs3a0whv");

        let (prefix, result) = decode(&nprofile).unwrap();
        assert_eq!(prefix, "nprofile");
        if let DecodeResult::Profile(profile) = result {
            assert_eq!(profile.public_key, pk);
            assert_eq!(profile.relays, relays);
        } else {
            panic!("Expected Profile result");
        }
    }
}
