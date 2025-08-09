use crate::{Event, Kind, PubKey, Timestamp, ID};
use serde::{
    de::{MapAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    pub ids: Option<Vec<ID>>,
    pub kinds: Option<Vec<Kind>>,
    pub authors: Option<Vec<PubKey>>,
    pub tags: Option<Vec<(String, Vec<String>)>>,
    pub since: Option<Timestamp>,
    pub until: Option<Timestamp>,
    pub limit: Option<usize>,
    pub search: Option<String>,
}

impl Serialize for Filter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut len = [
            self.ids.is_some(),
            self.authors.is_some(),
            self.kinds.is_some(),
            self.since.is_some(),
            self.until.is_some(),
            self.limit.is_some(),
            self.search.is_some(),
        ]
        .iter()
        .fold(0, |sum, v| sum + if *v { 1 } else { 0 });
        if let Some(ref tags) = self.tags {
            len += tags.len();
        }

        let mut map = serializer.serialize_map(Some(len))?;
        if let Some(ref ids) = self.ids {
            map.serialize_entry("ids", ids)?;
        }
        if let Some(ref authors) = self.authors {
            map.serialize_entry("authors", authors)?;
        }
        if let Some(ref kinds) = self.kinds {
            map.serialize_entry("kinds", kinds)?;
        }
        if let Some(s) = self.since {
            map.serialize_entry("since", &s)?;
        }
        if let Some(u) = self.until {
            map.serialize_entry("until", &u)?;
        }
        if let Some(l) = self.limit {
            map.serialize_entry("limit", &l)?;
        }
        if let Some(s) = &self.search {
            map.serialize_entry("search", s)?;
        }
        if let Some(ref tags) = self.tags {
            for (tag, values) in tags {
                let key = format!("#{}", tag);
                let vec_values: Vec<&String> = values.iter().collect();
                map.serialize_entry(&key, &vec_values)?;
            }
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Filter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FilterVisitor;
        impl<'v> Visitor<'v> for FilterVisitor {
            type Value = Filter;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a Nostr filter object")
            }
            fn visit_map<M>(self, mut map: M) -> Result<Filter, M::Error>
            where
                M: MapAccess<'v>,
            {
                let mut ids = None;
                let mut authors = None;
                let mut kinds = None;
                let mut since = None;
                let mut until = None;
                let mut limit = None;
                let mut search = None;
                let mut tags: Option<Vec<(String, Vec<String>)>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "ids" => ids = Some(map.next_value()?),
                        "authors" => authors = Some(map.next_value()?),
                        "kinds" => kinds = Some(map.next_value()?),
                        "since" => since = Some(map.next_value()?),
                        "until" => until = Some(map.next_value()?),
                        "limit" => limit = Some(map.next_value()?),
                        "search" => search = Some(map.next_value()?),
                        k if k.starts_with('#') && k.len() > 1 => {
                            let tag = k.trim_start_matches('#').to_string();
                            let vals: Vec<String> = map.next_value()?;
                            let tags_list = tags.get_or_insert_with(|| Vec::with_capacity(2));
                            tags_list.push((tag, vals));
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(Filter {
                    ids,
                    authors,
                    kinds,
                    since,
                    until,
                    limit,
                    search,
                    tags,
                })
            }
        }
        deserializer.deserialize_map(FilterVisitor)
    }
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
        // if ids are specified, return the number of ids
        if let Some(ref ids) = self.ids {
            return ids.len();
        }

        // if until is less than since, return 0
        if let (Some(until), Some(since)) = (self.until, self.since) {
            if until < since {
                return 0;
            }
        }

        // if both authors and kinds are specified
        if let (Some(ref authors), Some(ref kinds)) = (&self.authors, &self.kinds) {
            // check if all kinds are replaceable
            let all_are_replaceable = kinds.iter().all(|k| k.is_replaceable());
            if all_are_replaceable {
                return authors.len() * kinds.len();
            }

            // check if we have d tags and all kinds are addressable
            if let Some(ref tags) = &self.tags {
                if let Some(d_tags) = tags.iter().find(|tag| tag.0 == "d") {
                    let all_are_addressable = kinds.iter().all(|k| k.is_addressable());
                    if all_are_addressable {
                        return authors.len() * kinds.len() * d_tags.1.len();
                    }
                }
            }
        }

        // default to maximum value
        usize::MAX
    }
}

impl std::fmt::Display for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
