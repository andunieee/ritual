use crate::{keys, ProfilePointer, PubKey};
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AddressError {
    #[error("invalid identifier")]
    InvalidIdentifier,

    #[error("missing domain")]
    MissingDomain,

    #[error("no entry for name '{0}'")]
    NoEntry(String),

    #[error("got an invalid public key '{0}'")]
    InvalidPublicKey(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("public key parsing error")]
    PubKeyParsing(#[from] keys::PubKeyError),
}

pub type Result<T> = std::result::Result<T, AddressError>;

/// well-known response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WellKnownResponse {
    pub names: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relays: Option<HashMap<String, Vec<String>>>,
}

lazy_static::lazy_static! {
    static ref REGEX: Regex = Regex::new(r"^(?:([\w.+-]+)@)?([\w_-]+(\.[\w_-]+)+)$").unwrap();
}

/// check if an identifier is valid according to address format
pub fn is_valid_identifier(input: &str) -> bool {
    REGEX.is_match(input)
}

/// parse a identifier into name and domain parts
pub fn parse_identifier(fullname: &str) -> Result<(String, String)> {
    let captures = REGEX
        .captures(fullname)
        .ok_or(AddressError::InvalidIdentifier)?;

    let name = captures
        .get(1)
        .map(|m| m.as_str())
        .unwrap_or("_")
        .to_string();
    let domain = captures
        .get(2)
        .ok_or(AddressError::MissingDomain)?
        .as_str()
        .to_string();

    Ok((name, domain))
}

/// query a identifier and return the profile pointer
pub async fn query_identifier(fullname: &str) -> Result<ProfilePointer> {
    let (result, name) = fetch(fullname).await?;

    let pubkey_hex = result
        .names
        .get(&name)
        .ok_or_else(|| AddressError::NoEntry(name.clone()))?;

    let pubkey = PubKey::from_hex(pubkey_hex)
        .map_err(|_| AddressError::InvalidPublicKey(pubkey_hex.clone()))?;

    let relays = if let Some(relays_map) = &result.relays {
        relays_map.get(pubkey_hex).cloned().unwrap_or_default()
    } else {
        Vec::new()
    };

    Ok(ProfilePointer { pubkey, relays })
}

/// fetch the well-known response for a identifier
pub async fn fetch(fullname: &str) -> Result<(WellKnownResponse, String)> {
    let (name, domain) = parse_identifier(fullname)?;

    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let url = format!("https://{}/.well-known/nostr.json?name={}", domain, name);

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        return Err(AddressError::Http(reqwest::Error::from(
            response.error_for_status().unwrap_err(),
        )));
    }

    let result: WellKnownResponse = response.json().await?;

    Ok((result, name))
}

/// normalize a identifier
pub fn normalize_identifier(fullname: &str) -> String {
    if fullname.starts_with("_@") {
        fullname[2..].to_string()
    } else {
        fullname.to_string()
    }
}

/// convert a identifier to its well-known URL
pub fn identifier_to_url(address: &str) -> String {
    let parts: Vec<&str> = address.split('@').collect();
    if parts.len() == 1 {
        format!("https://{}/.well-known/nostr.json?name=_", parts[0])
    } else {
        format!(
            "https://{}/.well-known/nostr.json?name={}",
            parts[1], parts[0]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let test_cases = vec![
            ("saknd@yyq.com", "saknd", "yyq.com", false),
            (
                "287354gkj+asbdfo8gw3rlicbsopifbcp3iougb5piseubfdikswub5ks@yyq.com",
                "287354gkj+asbdfo8gw3rlicbsopifbcp3iougb5piseubfdikswub5ks",
                "yyq.com",
                false,
            ),
            ("asdn.com", "_", "asdn.com", false),
            ("_@uxux.com.br", "_", "uxux.com.br", false),
            ("821yh498ig21", "", "", true),
            ("////", "", "", true),
        ];

        for (input, expected_name, expected_domain, expect_error) in test_cases {
            match parse_identifier(input) {
                Ok((name, domain)) => {
                    assert!(!expect_error, "expected error for input: {}", input);
                    assert_eq!(name, expected_name);
                    assert_eq!(domain, expected_domain);
                }
                Err(_) => {
                    assert!(expect_error, "did not expect error for input: {}", input);
                }
            }
        }
    }

    #[test]
    fn test_normalize_identifier() {
        assert_eq!(normalize_identifier("_@example.com"), "example.com");
        assert_eq!(normalize_identifier("user@example.com"), "user@example.com");
        assert_eq!(normalize_identifier("example.com"), "example.com");
    }

    #[test]
    fn test_identifier_to_url() {
        assert_eq!(
            identifier_to_url("example.com"),
            "https://example.com/.well-known/nostr.json?name=_"
        );
        assert_eq!(
            identifier_to_url("user@example.com"),
            "https://example.com/.well-known/nostr.json?name=user"
        );
    }

    #[tokio::test]
    async fn test_fetch_name() {
        assert_eq!(
            query_identifier("mike@mikedilger.com").await.unwrap(),
            ProfilePointer {
                pubkey: PubKey::from_hex(
                    "ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49"
                )
                .unwrap(),
                relays: vec![
                    "wss://chorus.mikedilger.com:444/".to_string(),
                    "wss://nostr.einundzwanzig.space/".to_string(),
                    "wss://nostrue.com/".to_string(),
                ]
            },
        );

        assert_eq!(
            query_identifier("nvk.org").await.unwrap(),
            ProfilePointer {
                pubkey: PubKey::from_hex(
                    "e88a691e98d9987c964521dff60025f60700378a4879180dcbbb4a5027850411"
                )
                .unwrap(),
                relays: vec![]
            },
        );
    }
}
