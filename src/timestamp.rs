/// unix timestamp in seconds
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct Timestamp(pub u32);

impl Timestamp {
    pub fn now() -> Self {
        Self(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32,
        )
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

// additional conversions from various integer types
impl From<u16> for Timestamp {
    fn from(value: u16) -> Self {
        Self(value as u32)
    }
}

impl From<u64> for Timestamp {
    fn from(value: u64) -> Self {
        Self(value as u32)
    }
}

impl From<i32> for Timestamp {
    fn from(value: i32) -> Self {
        Self(value as u32)
    }
}

impl From<usize> for Timestamp {
    fn from(value: usize) -> Self {
        Self(value as u32)
    }
}

impl From<std::time::SystemTime> for Timestamp {
    fn from(value: std::time::SystemTime) -> Self {
        let duration = value
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self(duration.as_secs() as u32)
    }
}

impl From<Timestamp> for std::time::SystemTime {
    fn from(timestamp: Timestamp) -> Self {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp.0 as u64)
    }
}
