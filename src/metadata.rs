/// represents nostr profile metadata from kind 0 events
#[derive(std::fmt::Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
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

    #[serde(skip_serializing)]
    pub pubkey: Option<crate::PubKey>,
}

impl Metadata {
    pub fn blank_from_pubkey(pk: crate::PubKey) -> Self {
        let mut m = Self::default();
        m.pubkey = Some(pk);
        m
    }

    /// deserialize metadata from a kind 0 event's content
    pub fn from_event(event: &crate::Event) -> Result<Self, serde_json::Error> {
        let mut metadata: Self = serde_json::from_str(&event.content)?;
        metadata.pubkey = Some(event.pubkey);
        Ok(metadata)
    }

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

    pub fn render_name(&self) -> String {
        if let Some(name) = &self.name {
            if name.len() < 21 {
                name.to_owned()
            } else {
                format!("{}…", &name[0..20])
            }
        } else {
            let npub = self.pubkey.expect("metadata must have pubkey").to_npub();
            format!("{}…{}", &npub[0..8], &npub[npub.len() - 7..])
        }
    }
}

impl std::fmt::Display for Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self.name.as_deref().unwrap_or("<no name>");
        let about = self.about.as_deref().unwrap_or("<no about>");
        write!(f, "Metadata(name: {}, about: {})", name, about)
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
        let metadata = Metadata::from_event(&event).unwrap();

        assert_eq!(metadata.name, Some("alice".to_string()));
        assert_eq!(metadata.about, Some("developer".to_string()));
        assert_eq!(metadata.website, Some("https://example.com".to_string()));
        assert_eq!(metadata.banner, None);
        assert_eq!(metadata.picture, None);
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
        let parsed = Metadata::from_event(&event).unwrap();

        assert_eq!(parsed.name, metadata.name);
        assert_eq!(parsed.about, metadata.about);
        assert_eq!(parsed.banner, metadata.banner);
    }

    #[test]
    fn test_blank_metadata() {
        let metadata = Metadata::blank_from_pubkey(
            crate::PubKey::from_str(
                "8be4898b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f8",
            )
            .unwrap(),
        );
        let template = metadata.to_event_template();
        // should serialize to empty json object
        assert_eq!(template.content, "{}");
    }

    #[test]
    fn test_metadata_from_event() {
        // should deserialize back to empty metadata
        let event = crate::Event {
            id: crate::ID::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
            pubkey: "7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9".parse().unwrap(),
            created_at: crate::Timestamp::now(),
            kind: crate::Kind(0),
            tags: crate::Tags::default(),
            content: "{\"name\":\"lllllllllll\"}".to_string(),
            sig: crate::Signature::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f97ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
        };
        let parsed = Metadata::from_event(&event).unwrap();

        assert_eq!(parsed.name, Some("lllllllllll".to_string()));
        assert_eq!(parsed.about, None);
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
        let result = Metadata::from_event(&event);
        assert!(result.is_err());
    }
}
