#[derive(Debug, Clone)]
pub struct Profile {
    pub metadata: Metadata,
    pub pubkey: crate::PubKey,
}

impl Profile {
    pub fn blank_from_pubkey(pk: crate::PubKey) -> Self {
        Profile {
            metadata: Metadata::default(),
            pubkey: pk,
        }
    }

    /// deserialize metadata from a kind 0 event's content
    pub fn from_event(event: &crate::Event) -> Self {
        Self {
            metadata: serde_json::from_str(&event.content).unwrap_or_default(),
            pubkey: event.pubkey,
        }
    }

    pub fn render_name(&self) -> String {
        if let Some(name) = &self.metadata.name {
            if name.len() < 21 {
                name.to_owned()
            } else {
                format!("{}…", &name[0..20])
            }
        } else {
            let npub = self.pubkey.to_npub();
            format!("{}…{}", &npub[0..8], &npub[npub.len() - 7..])
        }
    }
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Profile({}, {})",
            self.pubkey.to_npub(),
            self.render_name()
        )
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub lud16: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub nip05: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

impl Metadata {
    /// create an event template from this metadata
    pub fn to_event_template(&self) -> crate::EventTemplate {
        let content = serde_json::to_string(self)
            .expect("serialization should always work for valid metadata");

        crate::EventTemplate {
            created_at: crate::Timestamp::now(),
            kind: crate::Kind(0),
            tags: crate::Tags::default(),
            content,
        }
    }
}

impl std::fmt::Display for Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self.name.as_deref().unwrap_or("<no name>");
        let about = self.about.as_deref().unwrap_or("<no about>");
        write!(f, "Metadata(name: {}, about: {}, ...)", name, about)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_deserialize_metadata() {
        let json = r#"{"name":"alice","about":"developer","website":"https://example.com"}"#;
        // create a mock event for testing
        let event = crate::Event {
            id: crate::ID::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
            pubkey: "7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9".parse().unwrap(),
            created_at: crate::Timestamp::now(),
            kind: crate::Kind(0),
            tags: crate::Tags::default(),
            content: json.to_string(),
            sig: crate::Signature::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f97ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
        };
        let metadata = Profile::from_event(&event);

        assert_eq!(metadata.metadata.name, Some("alice".to_string()));
        assert_eq!(metadata.metadata.about, Some("developer".to_string()));
        assert_eq!(
            metadata.metadata.website,
            Some("https://example.com".to_string())
        );
        assert_eq!(metadata.metadata.banner, None);
        assert_eq!(metadata.metadata.picture, None);
    }

    #[test]
    fn test_serialize_to_event_template() {
        let metadata = Metadata {
            name: Some("bob".to_string()),
            about: Some("artist".to_string()),
            website: None,
            banner: Some("https://example.com/banner.jpg".to_string()),
            picture: None,

            ..Default::default()
        };
        let template = metadata.to_event_template();
        assert_eq!(template.kind, crate::Kind(0));

        // verify we can deserialize back
        let event = crate::Event {
            id: crate::ID::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
            pubkey: "7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9".parse().unwrap(),
            created_at: crate::Timestamp::now(),
            kind: crate::Kind(0),
            tags: crate::Tags::default(),
            content: template.content,
            sig: crate::Signature::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f97ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
        };
        let parsed = Profile::from_event(&event);

        assert_eq!(parsed.metadata.name, metadata.name);
        assert_eq!(parsed.metadata.about, metadata.about);
        assert_eq!(parsed.metadata.banner, metadata.banner);
    }

    #[test]
    fn test_blank_metadata() {
        let profile = Profile::blank_from_pubkey(
            crate::PubKey::from_str(
                "8be4898b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f8",
            )
            .unwrap(),
        );
        let template = profile.metadata.to_event_template();

        // should serialize to empty json object
        assert_eq!(template.content, "{}");
    }

    #[test]
    fn test_metadata_from_event() {
        let pk = "7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9"
            .parse()
            .unwrap();
        let event = crate::Event {
            id: crate::ID::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
            pubkey: pk,
            created_at: crate::Timestamp::now(),
            kind: crate::Kind(0),
            tags: crate::Tags::default(),
            content: "{\"name\":\"lllllllllll\"}".to_string(),
            sig: crate::Signature::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f97ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
        };
        let parsed = Profile::from_event(&event);

        assert_eq!(parsed.pubkey, pk);
        assert_eq!(parsed.metadata.name, Some("lllllllllll".to_string()));
        assert_eq!(parsed.metadata.about, None);
    }

    #[test]
    fn test_invalid_json() {
        let event = crate::Event {
            id: crate::ID::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
            pubkey: "7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9".parse().unwrap(),
            created_at: crate::Timestamp::now(),
            kind: crate::Kind(0),
            tags: crate::Tags::default(),
            content: "not json at all".to_string(),
            sig: crate::Signature::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f97ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
        };
        let profile = Profile::from_event(&event);
        assert_eq!(
            serde_json::to_string(&profile.metadata).unwrap(),
            "{}".to_string()
        );
    }
}
