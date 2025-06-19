use crate::{Event, Filter, Kind, PubKey, Tag, TagMap, ID};

pub trait Pointer {
    /// returns the pointer as a string as it would be seen in the value of a tag
    fn as_tag_reference(&self) -> String;

    /// converts the pointer to a tag that can be included in events
    fn as_tag(&self) -> Tag;

    /// converts the pointer to a Filter that can be used to query for it
    fn as_filter(&self) -> Filter;

    /// check if the pointer matches an event
    fn matches_event(&self, event: &Event) -> bool;
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

impl Pointer for ProfilePointer {
    fn as_tag_reference(&self) -> String {
        self.public_key.to_hex()
    }

    fn as_tag(&self) -> Tag {
        let mut tag = vec!["p".to_string(), self.public_key.to_hex()];
        if !self.relays.is_empty() {
            tag.push(self.relays[0].clone());
        }
        tag
    }

    fn as_filter(&self) -> Filter {
        Filter {
            authors: Some(vec![self.public_key]),
            ..Default::default()
        }
    }

    fn matches_event(&self, _event: &Event) -> bool {
        false
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

impl Pointer for EventPointer {
    fn as_tag_reference(&self) -> String {
        self.id.to_hex()
    }

    fn as_tag(&self) -> Tag {
        let mut tag = vec!["e".to_string(), self.id.to_hex()];
        if !self.relays.is_empty() {
            tag.push(self.relays[0].clone());
            if let Some(author) = &self.author {
                tag.push(author.to_hex());
            }
        }
        tag
    }

    fn as_filter(&self) -> Filter {
        Filter {
            ids: Some(vec![self.id]),
            ..Default::default()
        }
    }

    fn matches_event(&self, event: &Event) -> bool {
        event.id == self.id
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
    /// Create an EntityPointer from a tag
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

        if kind > (1 << 16) {
            return Err(format!("invalid addr kind '{}'", parts[0]).into());
        }

        let public_key = PubKey::from_hex(parts[1])?;
        let identifier = parts[2].to_string();

        let relays = if tag.len() > 2 && crate::utils::is_valid_relay_url(&tag[2]) {
            vec![tag[2].clone()]
        } else {
            vec![]
        };

        Ok(Self {
            public_key,
            kind,
            identifier,
            relays,
        })
    }
}

impl Pointer for EntityPointer {
    fn as_tag_reference(&self) -> String {
        format!(
            "{}:{}:{}",
            self.kind,
            self.public_key.to_hex(),
            self.identifier
        )
    }

    fn as_tag(&self) -> Tag {
        let mut tag = vec!["a".to_string(), self.as_tag_reference()];
        if !self.relays.is_empty() {
            tag.push(self.relays[0].clone());
        }
        tag
    }

    fn as_filter(&self) -> Filter {
        let mut tags = TagMap::new();
        tags.insert("d".to_string(), vec![self.identifier.clone()]);

        Filter {
            kinds: Some(vec![self.kind]),
            authors: Some(vec![self.public_key]),
            tags: Some(tags),
            ..Default::default()
        }
    }

    fn matches_event(&self, event: &Event) -> bool {
        event.pubkey == self.public_key
            && event.kind == self.kind
            && event.tags.get_d() == self.identifier
    }
}
