use thiserror::Error;

use crate::{helpers::is_valid_relay_url, Event, Filter, Kind, PubKey, Tag, ID};

/// Unified pointer enum for all Nostr pointer types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pointer {
    Profile(ProfilePointer),
    Event(EventPointer),
    Address(AddressPointer),
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("tag should have at least 2 elements")]
    ShortTag,

    #[error("something is invalid")]
    Invalid,
}

/// Pointer to a Nostr profile
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePointer {
    pub pubkey: PubKey,
    pub relays: Vec<String>,
}

impl ProfilePointer {
    /// Create a ProfilePointer from a tag
    pub fn from_tag(tag: &Tag) -> Result<Self, Error> {
        if tag.len() < 2 {
            return Err(Error::ShortTag);
        }

        let pubkey = PubKey::from_hex(&tag[1]).map_err(|_| Error::Invalid)?;
        let relays = if tag.len() > 2 && is_valid_relay_url(&tag[2]) {
            vec![tag[2].clone()]
        } else {
            vec![]
        };

        Ok(Self { pubkey, relays })
    }
}

/// Pointer to a Nostr event
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventPointer {
    pub id: ID,
    pub relays: Vec<String>,
    pub author: Option<PubKey>,
    pub kind: Option<Kind>,
}

impl EventPointer {
    /// Create an EventPointer from a tag
    pub fn from_tag(tag: &Tag) -> Result<Self, Error> {
        if tag.len() < 2 {
            return Err(Error::ShortTag);
        }

        let id = ID::from_hex(&tag[1]).map_err(|_| Error::Invalid)?;
        let relays = if tag.len() > 2 && is_valid_relay_url(&tag[2]) {
            vec![tag[2].clone()]
        } else {
            vec![]
        };

        let author = if tag.len() > 3 {
            PubKey::from_hex(&tag[3]).ok()
        } else {
            None
        };

        Ok(Self {
            id,
            relays,
            author,
            kind: None,
        })
    }
}

/// Pointer to a Nostr entity (addressable event)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressPointer {
    pub pubkey: PubKey,
    pub kind: Kind,
    pub identifier: String,
    pub relays: Vec<String>,
}

impl AddressPointer {
    /// create an AddressPointer from a tag
    pub fn from_tag(tag: &Tag) -> Result<Self, Error> {
        if tag.len() < 2 {
            return Err(Error::ShortTag);
        }

        let parts: Vec<&str> = tag[1].splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(Error::Invalid);
        }

        let kind: u16 = parts[0].parse().map_err(|_| Error::Invalid)?;

        let pubkey = PubKey::from_hex(parts[1]).map_err(|_| Error::Invalid)?;
        let identifier = parts[2].to_string();

        let relays = if tag.len() > 2 && is_valid_relay_url(&tag[2]) {
            vec![tag[2].clone()]
        } else {
            vec![]
        };

        Ok(Self {
            kind: Kind(kind),
            relays,
            pubkey,
            identifier,
        })
    }
}

impl Pointer {
    /// returns the pointer as a string as it would be seen in the value of a tag
    pub fn as_tag_reference(&self) -> String {
        match self {
            Pointer::Profile(p) => p.pubkey.to_hex(),
            Pointer::Event(p) => p.id.to_hex(),
            Pointer::Address(p) => format!("{}:{}:{}", p.kind, p.pubkey.to_hex(), p.identifier),
        }
    }

    /// converts the pointer to a tag that can be included in events
    pub fn as_tag(&self) -> Tag {
        match self {
            Pointer::Profile(p) => {
                let mut tag = vec!["p".to_string(), p.pubkey.to_hex()];
                if !p.relays.is_empty() {
                    tag.push(p.relays[0].clone());
                }
                tag
            }
            Pointer::Event(p) => {
                let mut tag = vec!["e".to_string(), p.id.to_hex()];
                if !p.relays.is_empty() {
                    tag.push(p.relays[0].clone());
                    if let Some(author) = &p.author {
                        tag.push(author.to_hex());
                    }
                }
                tag
            }
            Pointer::Address(p) => {
                let mut tag = vec!["a".to_string(), self.as_tag_reference()];
                if !p.relays.is_empty() {
                    tag.push(p.relays[0].clone());
                }
                tag
            }
        }
    }

    /// converts the pointer to a Filter that can be used to query for it
    pub fn as_filter(&self) -> Filter {
        match self {
            Pointer::Profile(p) => Filter {
                authors: Some(vec![p.pubkey]),
                ..Default::default()
            },
            Pointer::Event(p) => Filter {
                ids: Some(vec![p.id]),
                ..Default::default()
            },
            Pointer::Address(p) => Filter {
                kinds: Some(vec![p.kind]),
                authors: Some(vec![p.pubkey]),
                tags: Some(vec![("d".to_string(), vec![p.identifier.clone()])]),
                ..Default::default()
            },
        }
    }

    /// check if the pointer matches an event
    pub fn matches_event(&self, event: &Event) -> bool {
        match self {
            Pointer::Profile(_) => false,
            Pointer::Event(p) => event.id == p.id,
            Pointer::Address(p) => {
                event.pubkey == p.pubkey
                    && event.kind == p.kind
                    && event.tags.get_d() == p.identifier
            }
        }
    }
}
