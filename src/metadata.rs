use crate::{Event, EventTemplate, Kind, PubKey, Tags, Timestamp};
use serde::{Deserialize, Serialize};

/// represents nostr profile metadata from kind 0 events
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    pub pubkey: Option<PubKey>,
}

impl Metadata {
    /// create new empty metadata
    pub fn new() -> Self {
        Self::default()
    }

    /// deserialize metadata from a kind 0 event's content
    pub fn from_event(event: &Event) -> Result<Self, serde_json::Error> {
        let mut metadata: Self = serde_json::from_str(&event.content)?;
        metadata.pubkey = Some(event.pubkey);
        Ok(metadata)
    }

    /// create an event template from this metadata
    pub fn to_event_template(&self) -> EventTemplate {
        let content = serde_json::to_string(self)
            .expect("serialization should always work for valid metadata");

        EventTemplate {
            created_at: Timestamp::now(),
            kind: Kind(0),
            tags: Tags::default(),
            content,
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
    use super::*;

    #[test]
    fn test_deserialize_metadata() {
        let json = r#"{"name":"alice","about":"developer","website":"https://example.com"}"#;
        // create a mock event for testing
        let event = Event {
            id: crate::ID::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
            pubkey: "7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9".parse().unwrap(),
            created_at: Timestamp::now(),
            kind: Kind(0),
            tags: Tags::default(),
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
        assert_eq!(template.kind, Kind(0));

        // verify we can deserialize back
        let event = Event {
            id: crate::ID::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
            pubkey: "7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9".parse().unwrap(),
            created_at: Timestamp::now(),
            kind: Kind(0),
            tags: Tags::default(),
            content: template.content,
            sig: crate::Signature::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f97ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
        };
        let parsed = Metadata::from_event(&event).unwrap();

        assert_eq!(parsed.name, metadata.name);
        assert_eq!(parsed.about, metadata.about);
        assert_eq!(parsed.banner, metadata.banner);
    }

    #[test]
    fn test_empty_metadata() {
        let metadata = Metadata::new();
        let template = metadata.to_event_template();
        // should serialize to empty json object
        assert_eq!(template.content, "{}");

        // should deserialize back to empty metadata
        let event = Event {
            id: crate::ID::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
            pubkey: "7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9".parse().unwrap(),
            created_at: Timestamp::now(),
            kind: Kind(0),
            tags: Tags::default(),
            content: template.content,
            sig: crate::Signature::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f97ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
        };
        let parsed = Metadata::from_event(&event).unwrap();

        assert_eq!(parsed.name, None);
        assert_eq!(parsed.about, None);
    }

    #[test]
    fn test_invalid_json() {
        let event = Event {
            id: crate::ID::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
            pubkey: "7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9".parse().unwrap(),
            created_at: Timestamp::now(),
            kind: Kind(0),
            tags: Tags::default(),
            content: "not json at all".to_string(),
            sig: crate::Signature::from_hex("7ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f97ad1758b4a75dd6a5d0b6a96870afc63375c3e8f9b38885aabd049450b2588f9").unwrap(),
        };
        let result = Metadata::from_event(&event);
        assert!(result.is_err());
    }
}
