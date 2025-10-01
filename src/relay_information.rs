#[derive(thiserror::Error, Debug)]
pub enum RelayInformationError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("URL normalization error")]
    Normalize(#[from] url::ParseError),
}

pub type Result<T> = std::result::Result<T, RelayInformationError>;

/// relay information document
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct RelayInformationDocument {
    #[serde(skip)]
    pub url: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub pubkey: Option<crate::PubKey>,
    #[serde(default)]
    pub icon: String,
}

/// fetch the metadata for a relay
pub async fn fetch(url: &str) -> Result<RelayInformationDocument> {
    let normalized_url = crate::normalize_url(url)?;

    let mut info = RelayInformationDocument {
        url: normalized_url.to_string(),
        name: normalized_url
            .host_str()
            .map(|s| s.to_string())
            .unwrap_or("".to_string()),
        description: String::new(),
        pubkey: None,
        icon: String::new(),
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(7))
        .build()?;

    let response = client
        .get(format!("http{}", &normalized_url.as_str()[2..]))
        .header("Accept", "application/nostr+json")
        .send()
        .await?;

    if response.status().is_success() {
        let received_info: RelayInformationDocument = response.json().await?;
        info.name = received_info.name;
        info.description = received_info.description;
        info.icon = received_info.icon;
        if received_info.pubkey.is_some() {
            info.pubkey = received_info.pubkey;
        }
    }

    if info.icon == "" {
        let mut icon = normalized_url.clone();
        icon.set_path("/favicon.ico");
        info.icon = format!("http{}", &icon.as_str()[2..]);
    }

    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch() {
        let test_cases = vec![
            ("wss://nostr.wine", false, "wss://nostr.wine/"),
            ("https://nostr.land", false, "wss://nostr.land/"),
            ("nostr.wine", false, "wss://nostr.wine/"),
            ("relay.damus.io", false, "wss://relay.damus.io/"),
            ("https://relay.nostr.band", false, "wss://relay.nostr.band/"),
            ("wss://relay.primal.net", false, "wss://relay.primal.net/"),
            ("wlenwqkeqwe.asjdaskd", true, "wss://wlenwqkeqwe.asjdaskd/"),
            ("bligblag", true, "wss://bligblag/"),
        ];

        for (input_url, expect_error, expected_url) in test_cases {
            let result = fetch(input_url).await;

            if expect_error {
                assert!(result.is_err(), "expected error for URL: {}", input_url);
                // even on error, we should get the URL back
                if let Err(RelayInformationError::Http(_)) = result {
                    // this is expected for invalid domains
                }
            } else {
                match result {
                    Ok(info) => {
                        assert_eq!(info.url, expected_url);
                        // name might be empty for some relays, that's ok
                    }
                    Err(e) => {
                        panic!("warning: failed to fetch {}: {}", input_url, e);
                    }
                }
            }
        }
    }
}
