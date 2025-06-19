use crate::{Event, Filter, Kind, PubKey, Tag, TagMap, ID};

/// Unified pointer enum for all Nostr pointer types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pointer {
    Profile(ProfilePointer),
    Event(EventPointer),
    Entity(EntityPointer),
}

/// Pointer to a Nostr profile
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePointer {
    pub public_key: PubKey,
    pub relays: Vec<String>,
}

impl ProfilePointer {
    /// Create a ProfilePointer from a tag
    pub fn from_tag(tag: &Tag) -> crate::Result<Self> {
        if tag.len() < 2 {
            return Err("tag must have at least 2 elements".into());
        }

        let public_key = PubKey::from_hex(&tag[1])?;
        let relays = if tag.len() > 2 && crate::utils::is_valid_relay_url(&tag[2]) {
            vec![tag[2].clone()]
        } else {
            vec![]
        };

        Ok(Self { public_key, relays })
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
    pub fn from_tag(tag: &Tag) -> crate::Result<Self> {
        if tag.len() < 2 {
            return Err("tag must have at least 2 elements".into());
        }

        let id = ID::from_hex(&tag[1])?;
        let relays = if tag.len() > 2 && crate::utils::is_valid_relay_url(&tag[2]) {
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
pub struct EntityPointer {
    pub public_key: PubKey,
    pub kind: Kind,
    pub identifier: String,
    pub relays: Vec<String>,
}

impl EntityPointer {
    /// create an EntityPointer from a tag
    pub fn from_tag(tag: &Tag) -> crate::Result<Self> {
        if tag.len() < 2 {
            return Err("tag must have at least 2 elements".into());
        }

        let parts: Vec<&str> = tag[1].splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(format!("invalid addr ref '{}'", tag[1]).into());
        }

        let kind: u16 = parts[0]
            .parse()
            .map_err(|_| format!("invalid addr kind '{}'", parts[0]))?;

        let public_key = PubKey::from_hex(parts[1])?;
        let identifier = parts[2].to_string();

        let relays = if tag.len() > 2 && crate::utils::is_valid_relay_url(&tag[2]) {
            vec![tag[2].clone()]
        } else {
            vec![]
        };

        Ok(Self {
            kind,
            relays,
            public_key,
            identifier,
        })
    }
}

impl Pointer {
    /// returns the pointer as a string as it would be seen in the value of a tag
    pub fn as_tag_reference(&self) -> String {
        match self {
            Pointer::Profile(p) => p.public_key.to_hex(),
            Pointer::Event(p) => p.id.to_hex(),
            Pointer::Entity(p) => format!("{}:{}:{}", p.kind, p.public_key.to_hex(), p.identifier),
        }
    }

    /// converts the pointer to a tag that can be included in events
    pub fn as_tag(&self) -> Tag {
        match self {
            Pointer::Profile(p) => {
                let mut tag = vec!["p".to_string(), p.public_key.to_hex()];
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
            Pointer::Entity(p) => {
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
                authors: Some(vec![p.public_key]),
                ..Default::default()
            },
            Pointer::Event(p) => Filter {
                ids: Some(vec![p.id]),
                ..Default::default()
            },
            Pointer::Entity(p) => {
                let mut tags = TagMap::new();
                tags.insert("d".to_string(), vec![p.identifier.clone()]);

                Filter {
                    kinds: Some(vec![p.kind]),
                    authors: Some(vec![p.public_key]),
                    tags: Some(tags),
                    ..Default::default()
                }
            }
        }
    }

    /// check if the pointer matches an event
    pub fn matches_event(&self, event: &Event) -> bool {
        match self {
            Pointer::Profile(_) => false,
            Pointer::Event(p) => event.id == p.id,
            Pointer::Entity(p) => {
                event.pubkey == p.public_key
                    && event.kind == p.kind
                    && event.tags.get_d() == p.identifier
            }
        }
    }
}
