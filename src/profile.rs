const INDEXER_RELAYS: [&'static str; 5] = [
    "relay.damus.io",
    "purplepag.es",
    "relay.primal.net",
    "indexer.coracle.social",
    "nos.lol",
];

const FALLBACK_METADATA_RELAYS: [&'static str; 4] = [
    "relay.damus.io",
    "purplepag.es",
    "relay.primal.net",
    "relay.nostr.band",
];

#[derive(Debug, Clone)]
pub struct Profile {
    pub metadata: crate::Metadata,
    pub pubkey: crate::PubKey,
    pub event: Option<crate::Event>,
}

impl Profile {
    pub fn blank_from_pubkey(pk: crate::PubKey) -> Self {
        Profile {
            metadata: crate::Metadata::default(),
            pubkey: pk,
            event: None,
        }
    }

    pub fn from_event(event: &crate::Event) -> Self {
        Self {
            metadata: serde_json::from_str(&event.content).unwrap_or_default(),
            pubkey: event.pubkey,
            event: Some(event.clone()),
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

    pub async fn fetch_metadata(&mut self, pool: &crate::Pool) {
        let pk = self.pubkey;
        let mut events = pool
            .query(
                INDEXER_RELAYS,
                crate::Filter {
                    kinds: Some(vec![10002.into()]),
                    authors: Some(vec![pk]),
                    limit: Some(1),
                    ..Default::default()
                },
                crate::SubscriptionOptions::default(),
            )
            .await;

        let filter = crate::Filter {
            kinds: Some(vec![0.into()]),
            authors: Some(vec![pk]),
            limit: Some(1),
            ..Default::default()
        };

        let mut metadata_events = if events.is_empty() {
            pool.query(
                FALLBACK_METADATA_RELAYS,
                filter,
                crate::SubscriptionOptions::default(),
            )
            .await
        } else {
            events.sort_by_key(|event| event.created_at);
            let crate::Event { tags, .. } = events.pop().unwrap();
            let relays: Vec<String> = tags
                .into_iter()
                .filter(|t| t.len() >= 2 && &t[0] == "r" && (t.len() == 2 || &t[2] == "write"))
                .filter_map(|t| crate::normalize_url(&t[1]).ok().map(|url| url.to_string()))
                .collect();
            pool.query(relays, filter, crate::SubscriptionOptions::default())
                .await
        };
        if metadata_events.is_empty() {
            return;
        }

        metadata_events.sort_by_key(|event| event.created_at);
        let event = metadata_events.pop().unwrap();

        if self.event.is_none() || event.created_at > self.event.as_ref().unwrap().created_at {
            self.metadata = serde_json::from_str(&event.content).unwrap_or_default();
            self.event = Some(event);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

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
        let metadata = crate::Metadata {
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
