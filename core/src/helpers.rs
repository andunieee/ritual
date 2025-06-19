use crate::{PubKey, Timestamp, ID};
use std::sync::Mutex;

/// Maximum number of named locks
const MAX_LOCKS: usize = 50;

/// Pool of named mutexes for synchronization
static NAMED_MUTEX_POOL: [Mutex<()>; MAX_LOCKS] = [
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
    Mutex::new(()),
];

/// Get a named lock for synchronization
pub fn named_lock(name: &str) -> std::sync::MutexGuard<'static, ()> {
    let hash = simple_hash(name.as_bytes());
    let idx = (hash as usize) % MAX_LOCKS;
    NAMED_MUTEX_POOL[idx].lock().unwrap()
}

/// Simple hash function for strings
fn simple_hash(data: &[u8]) -> u64 {
    let mut hash = 0u64;
    for &byte in data {
        hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
    }
    hash
}

/// Check if two slices contain the same elements (order doesn't matter)
pub fn similar<T: PartialEq>(a: &[T], b: &[T]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    for item_a in a {
        if !b.contains(item_a) {
            return false;
        }
    }
    true
}

/// Check if two ID slices are similar
pub fn similar_id(a: &[ID], b: &[ID]) -> bool {
    similar(a, b)
}

/// Check if two PubKey slices are similar
pub fn similar_public_key(a: &[PubKey], b: &[PubKey]) -> bool {
    similar(a, b)
}

/// Escape a string for JSON encoding
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

/// Extract subscription ID from JSON string
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

/// Extract event ID from JSON string
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

/// Extract event public key from JSON string
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

/// Extract d tag from JSON string
pub fn extract_d_tag(json_str: &str) -> Option<String> {
    let start = json_str.find("[\"d\"")?;
    let remaining = &json_str[start + 4..];

    let quote_start = remaining.find('"')?;
    let remaining = &remaining[quote_start + 1..];

    let quote_end = remaining.find('"')?;

    Some(remaining[..quote_end].to_string())
}

/// Extract timestamp from JSON string
pub fn extract_timestamp(json_str: &str) -> Option<Timestamp> {
    let start = json_str.find("\"created_at\"")?;
    let remaining = &json_str[start + 12..];

    // Find the next number
    let mut num_start = None;
    for (i, c) in remaining.char_indices() {
        if c.is_ascii_digit() {
            num_start = Some(i);
            break;
        }
    }

    let num_start = num_start?;
    let remaining = &remaining[num_start..];

    // Find the end of the number
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

/// Convert subscription ID to serial number
pub fn sub_id_to_serial(sub_id: &str) -> Option<i64> {
    let colon_pos = sub_id.find(':')?;
    sub_id[..colon_pos].parse().ok()
}
