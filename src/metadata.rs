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
