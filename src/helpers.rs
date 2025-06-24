use url::Url;

use crate::{PubKey, Timestamp, ID};

/// escape a string for JSON encoding
pub fn escape_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');

    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\u{08}' => result.push_str("\\b"),
            '\u{09}' => result.push_str("\\t"),
            '\u{0A}' => result.push_str("\\n"),
            '\u{0C}' => result.push_str("\\f"),
            '\u{0D}' => result.push_str("\\r"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }

    result.push('"');
    result
}

/// extract subscription ID from JSON string
pub fn extract_sub_id(json_str: &str) -> Option<String> {
    // Look for "EVENT" pattern
    let start = json_str.find("\"EVENT\"")?;
    let remaining = &json_str[start + 7..];

    // Find the next quote
    let quote_start = remaining.find('"')?;
    let remaining = &remaining[quote_start + 1..];

    // Find the ending quote
    let quote_end = remaining.find('"')?;

    Some(remaining[..quote_end].to_string())
}

/// extract event ID from JSON string
pub fn extract_event_id(json_str: &str) -> Option<ID> {
    let start = json_str.find("\"id\"")?;
    let remaining = &json_str[start + 4..];

    let quote_start = remaining.find('"')?;
    let id_str = &remaining[quote_start + 1..quote_start + 1 + 64];

    ID::from_hex(id_str).ok()
}

/// extract event public key from JSON string
pub fn extract_event_pubkey(json_str: &str) -> Option<PubKey> {
    let start = json_str.find("\"pubkey\"")?;
    let remaining = &json_str[start + 8..];

    let quote_start = remaining.find('"')?;
    let pk_str = &remaining[quote_start + 1..quote_start + 1 + 64];

    if pk_str.len() == 64 {
        PubKey::from_hex(pk_str).ok()
    } else {
        None
    }
}

/// extract d tag from JSON string
pub fn extract_d_tag(json_str: &str) -> Option<String> {
    let start = json_str.find("[\"d\"")?;
    let remaining = &json_str[start + 4..];

    let quote_start = remaining.find('"')?;
    let remaining = &remaining[quote_start + 1..];

    let quote_end = remaining.find('"')?;

    Some(remaining[..quote_end].to_string())
}

/// extract timestamp from JSON string
pub fn extract_timestamp(json_str: &str) -> Option<Timestamp> {
    let start = json_str.find("\"created_at\"")?;
    let remaining = &json_str[start + 12..];

    // find the next number
    let mut num_start = None;
    for (i, c) in remaining.char_indices() {
        if c.is_ascii_digit() {
            num_start = Some(i);
            break;
        }
    }

    let num_start = num_start?;
    let remaining = &remaining[num_start..];

    // find the end of the number
    let mut num_end = remaining.len();
    for (i, c) in remaining.char_indices() {
        if matches!(c, ',' | '}' | ' ') {
            num_end = i;
            break;
        }
    }

    let num_str = &remaining[..num_end];
    num_str.parse::<i64>().ok().map(Timestamp::from)
}

/// check if a URL is a valid relay URL (ws:// or wss://)
pub fn is_valid_relay_url(url_str: &str) -> bool {
    match Url::parse(url_str) {
        Ok(url) => matches!(url.scheme(), "ws" | "wss"),
        Err(_) => false,
    }
}

extern crate test;

#[cfg(test)]
mod tests {
    use crate::Event;

    use super::*;
    use test::Bencher;

    #[test]
    fn test_extract_event_id() {
        let id =
            ID::from_hex("9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5").ok();

        assert_eq!(
            extract_event_id(
                r#"{"kind":1,"id":"9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5","pubkey":"37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba","created_at":1750711742,"tags":[],"content":"hello world","sig":"a1ecbf1636f5e752f1b918a86b065a8031b1387f0785f0ca19b84cc155d7937fece1f3ae53b79d347fbce5555a0f2da8db96334cab154f8d92300f8c1936710c"}"#
            ),
            id,
        );

        assert_eq!(
            id,
            Some(ID([
                0x94, 0x29, 0xb2, 0xe1, 0x16, 0x40, 0xbf, 0xd8, 0x69, 0x71, 0xf0, 0xd9, 0xf7, 0x43,
                0x51, 0x99, 0xb5, 0x7e, 0x12, 0x1a, 0x36, 0x32, 0x13, 0xdf, 0x11, 0xd5, 0xb4, 0x26,
                0x80, 0x7e, 0x49, 0xf5,
            ]))
        );
    }

    #[bench]
    fn bench_get_id_serde(b: &mut Bencher) {
        let eventj = r#"{"kind":1,"pubkey":"37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba","created_at":1750711742,"tags":[],"content":"hello world","sig":"a1ecbf1636f5e752f1b918a86b065a8031b1387f0785f0ca19b84cc155d7937fece1f3ae53b79d347fbce5555a0f2da8db96334cab154f8d92300f8c1936710c","id":"9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5"}"#;
        b.iter(|| {
            let id = serde_json::from_str::<Event>(eventj).map(|evt| evt.id).ok();
            id
        });
    }

    #[bench]
    fn bench_get_id_manual(b: &mut Bencher) {
        let eventj = r#"{"kind":1,"pubkey":"37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba","created_at":1750711742,"tags":[],"content":"hello world","sig":"a1ecbf1636f5e752f1b918a86b065a8031b1387f0785f0ca19b84cc155d7937fece1f3ae53b79d347fbce5555a0f2da8db96334cab154f8d92300f8c1936710c","id":"9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5"}"#;
        b.iter(|| {
            let id = extract_event_id(eventj);
            id
        });
    }
}
