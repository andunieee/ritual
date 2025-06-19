use std::fmt;

use serde::{Deserialize, Serialize};

/// a single tag (array of strings)
pub type Tag = Vec<String>;

/// collection of tags
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tags(pub Vec<Tag>);

impl Tags {
    /// get the first "d" tag value or empty string
    pub fn get_d(&self) -> String {
        for tag in &self.0 {
            if tag.len() >= 2 && tag[0] == "d" {
                return tag[1].clone();
            }
        }
        String::new()
    }

    /// find the first tag with the given key that has at least one value
    pub fn find(&self, key: String) -> Option<&Tag> {
        for tag in &self.0 {
            if tag.len() >= 2 && tag[0] == key {
                return Some(tag);
            }
        }
        None
    }

    /// find all tags with the given key that have at least one value
    pub fn find_all(&self, key: String) -> impl Iterator<Item = &Tag> {
        self.0
            .iter()
            .filter(move |tag| tag.len() >= 2 && tag[0] == key)
    }

    /// find tag with specific key and value
    pub fn find_with_value(&self, key: &str, value: &str) -> Option<&Tag> {
        for tag in &self.0 {
            if tag.len() >= 2 && tag[0] == key && tag[1] == value {
                return Some(tag);
            }
        }
        None
    }

    /// find the last tag with the given key
    pub fn find_last(&self, key: &str) -> Option<&Tag> {
        for tag in self.0.iter().rev() {
            if tag.len() >= 2 && tag[0] == key {
                return Some(tag);
            }
        }
        None
    }

    /// find the last tag with specific key and value
    pub fn find_last_with_value(&self, key: &str, value: &str) -> Option<&Tag> {
        for tag in self.0.iter().rev() {
            if tag.len() >= 2 && tag[0] == key && tag[1] == value {
                return Some(tag);
            }
        }
        None
    }

    /// check if tags contain any of the given values for a tag name
    pub fn contains_any(&self, tag_name: &str, values: &[String]) -> bool {
        for tag in &self.0 {
            if tag.len() < 2 || tag[0] != tag_name {
                continue;
            }
            if values.contains(&tag[1]) {
                return true;
            }
        }
        false
    }
}

impl fmt::Display for Tags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(json) => write!(f, "{}", json),
            Err(err) => write!(f, "Tags({})", err),
        }
    }
}

impl Default for Tags {
    fn default() -> Self {
        Tags(vec![])
    }
}

impl From<Vec<Tag>> for Tags {
    fn from(tags: Vec<Tag>) -> Self {
        Self(tags)
    }
}

impl From<Tags> for Vec<Tag> {
    fn from(tags: Tags) -> Self {
        tags.0
    }
}
