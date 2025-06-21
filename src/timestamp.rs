use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// unix timestamp in seconds
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp(pub u32);

impl Timestamp {
    pub fn now() -> Self {
        Self(Utc::now().timestamp() as u32)
    }

    pub fn to_datetime(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.0 as i64, 0).unwrap_or_default()
    }

    pub fn from_datetime(dt: DateTime<Utc>) -> Self {
        Self(dt.timestamp() as u32)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for Timestamp {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Timestamp> for u32 {
    fn from(timestamp: Timestamp) -> Self {
        timestamp.0
    }
}

impl From<i64> for Timestamp {
    fn from(value: i64) -> Self {
        Self(value as u32)
    }
}

impl From<Timestamp> for i64 {
    fn from(timestamp: Timestamp) -> Self {
        timestamp.0 as i64
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Timestamp::now()
    }
}
