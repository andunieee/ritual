use crate::{Event, Timestamp, ID};
use std::cmp::Ordering;
use url::Url;

/// Check if a URL is a valid relay URL (ws:// or wss://)
pub fn is_valid_relay_url(url_str: &str) -> bool {
    match Url::parse(url_str) {
        Ok(url) => matches!(url.scheme(), "ws" | "wss"),
        Err(_) => false,
    }
}

/// Check if a string is a valid 32-byte hex string
pub fn is_valid_32_byte_hex(s: &str) -> bool {
    if s.len() != 64 {
        return false;
    }
    
    if !crate::helpers::is_lower_hex(s) {
        return false;
    }
    
    hex::decode(s).is_ok()
}

/// Compare events for sorting (by timestamp, then by ID)
pub fn compare_event(a: &Event, b: &Event) -> Ordering {
    match a.created_at.cmp(&b.created_at) {
        Ordering::Equal => a.id.as_bytes().cmp(b.id.as_bytes()),
        other => other,
    }
}

/// Compare events in reverse order
pub fn compare_event_reverse(a: &Event, b: &Event) -> Ordering {
    compare_event(b, a)
}

/// Add items to a vector only if they don't already exist
pub fn append_unique<T: PartialEq + Clone>(mut vec: Vec<T>, items: &[T]) -> Vec<T> {
    for item in items {
        if !vec.contains(item) {
            vec.push(item.clone());
        }
    }
    vec
}
