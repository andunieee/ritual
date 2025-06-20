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

    if id_str.len() == 64 {
        ID::from_hex(id_str).ok()
    } else {
        None
    }
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

/// Check if string is lowercase hex
pub fn is_lower_hex(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// convert subscription ID to serial number
pub fn sub_id_to_serial(sub_id: &str) -> Option<i64> {
    let colon_pos = sub_id.find(':')?;
    sub_id[..colon_pos].parse().ok()
}

/// check if a URL is a valid relay URL (ws:// or wss://)
pub fn is_valid_relay_url(url_str: &str) -> bool {
    match Url::parse(url_str) {
        Ok(url) => matches!(url.scheme(), "ws" | "wss"),
        Err(_) => false,
    }
}
