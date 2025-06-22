use crate::{Event, Kind, PubKey, TagMap, Timestamp, ID};
use serde::{Deserialize, Serialize};
use std::fmt;

/// filter for querying events
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<ID>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<Kind>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<PubKey>>,

    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub tags: Option<TagMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<Timestamp>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<Timestamp>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
}

impl Filter {
    /// create a new empty filter
    pub fn new() -> Self {
        Self::default()
    }

    /// check if an event matches this filter
    pub fn matches(&self, event: &Event) -> bool {
        if !self.matches_ignoring_timestamp_constraints(event) {
            return false;
        }

        if let Some(since) = self.since {
            if event.created_at < since {
                return false;
            }
        }

        if let Some(until) = self.until {
            if event.created_at > until {
                return false;
            }
        }

        true
    }

    /// check if an event matches this filter ignoring timestamp constraints
    pub fn matches_ignoring_timestamp_constraints(&self, event: &Event) -> bool {
        if let Some(ref ids) = self.ids {
            if !ids.contains(&event.id) {
                return false;
            }
        }

        if let Some(ref kinds) = self.kinds {
            if !kinds.contains(&event.kind) {
                return false;
            }
        }

        if let Some(ref authors) = self.authors {
            if !authors.contains(&event.pubkey) {
                return false;
            }
        }

        if let Some(ref tags) = self.tags {
            for (tag_name, tag_values) in tags {
                if !event.tags.contains_any(tag_name, tag_values) {
                    return false;
                }
            }
        }

        true
    }

    /// clone the filter
    pub fn clone_filter(&self) -> Self {
        self.clone()
    }

    /// get the theoretical limit of events this filter could return
    pub fn get_theoretical_limit(&self) -> usize {
        if let Some(ref ids) = self.ids {
            return ids.len();
        }

        // TODO: Implement more sophisticated limit calculation
        // based on replaceable events, addressable events, etc.

        usize::MAX
    }
}

impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(json) => write!(f, "{}", json),
            Err(_) => write!(f, "Filter"),
        }
    }
}

/// check if two filters are equal
pub fn filter_equal(a: &Filter, b: &Filter) -> bool {
    a.ids == b.ids
        && a.kinds == b.kinds
        && a.authors == b.authors
        && a.tags == b.tags
        && a.since == b.since
        && a.until == b.until
        && a.search == b.search
        && a.limit == b.limit
}
