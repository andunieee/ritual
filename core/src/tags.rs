use serde::{Deserialize, Serialize};

/// A single tag (array of strings)
pub type Tag = Vec<String>;

/// Collection of tags
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tags(pub Vec<Tag>);

impl Tags {
    /// Create new empty tags
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Get the first "d" tag value or empty string
    pub fn get_d(&self) -> String {
        for tag in &self.0 {
            if tag.len() >= 2 && tag[0] == "d" {
                return tag[1].clone();
            }
        }
        String::new()
    }

    /// Find the first tag with the given key that has at least one value
    pub fn find(&self, key: &str) -> Option<&Tag> {
        for tag in &self.0 {
            if tag.len() >= 2 && tag[0] == key {
                return Some(tag);
            }
        }
        None
    }

    /// Find all tags with the given key that have at least one value
    pub fn find_all(&self, key: &str) -> impl Iterator<Item = &Tag> {
        self.0.iter().filter(move |tag| tag.len() >= 2 && tag[0] == key)
    }

    /// Find tag with specific key and value
    pub fn find_with_value(&self, key: &str, value: &str) -> Option<&Tag> {
        for tag in &self.0 {
            if tag.len() >= 2 && tag[0] == key && tag[1] == value {
                return Some(tag);
            }
        }
        None
    }

    /// Find the last tag with the given key
    pub fn find_last(&self, key: &str) -> Option<&Tag> {
        for tag in self.0.iter().rev() {
            if tag.len() >= 2 && tag[0] == key {
                return Some(tag);
            }
        }
        None
    }

    /// Find the last tag with specific key and value
    pub fn find_last_with_value(&self, key: &str, value: &str) -> Option<&Tag> {
        for tag in self.0.iter().rev() {
            if tag.len() >= 2 && tag[0] == key && tag[1] == value {
                return Some(tag);
            }
        }
        None
    }

    /// Clone the tags (shallow copy)
    pub fn clone_tags(&self) -> Self {
        Self(self.0.clone())
    }

    /// Clone the tags deeply
    pub fn clone_deep(&self) -> Self {
        Self(self.0.iter().map(|tag| tag.clone()).collect())
    }

    /// Check if tags contain any of the given values for a tag name
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

    /// Add a tag
    pub fn push(&mut self, tag: Tag) {
        self.0.push(tag);
    }

    /// Get length
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for Tags {
    fn default() -> Self {
        Self::new()
    }
}

impl std::ops::Deref for Tags {
    type Target = Vec<Tag>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Tags {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
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

impl Tag {
    /// Clone the tag
    pub fn clone_tag(&self) -> Self {
        self.clone()
    }
}
