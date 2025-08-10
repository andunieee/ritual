use rkyv::rancor;

use crate::{event::ArchivedEvent, Event, Filter, ID};

pub type Result<T> = std::result::Result<T, DatabaseError>;

#[derive(thiserror::Error, Debug)]
pub enum DatabaseError {
    #[error("LMDB error: {0}")]
    LMDB(#[from] heed::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] rancor::Error),

    #[error("event with values out of expected boundaries {created_at}/{kind}")]
    OutOfBounds { created_at: i64, kind: u16 },

    #[error("duplicate event")]
    DuplicateEvent,

    #[error("event not found")]
    EventNotFound,

    #[error("invalid query: {0}")]
    InvalidFilter(String),
}

pub trait EventDatabase {
    fn save_event(&self, event: &Event) -> Result<()>;

    fn delete_event(&self, id: &ID) -> Result<()>;

    fn query_events<F>(&self, filters: Vec<Filter>, max_limit: usize, cb: F) -> Result<()>
    where
        F: FnMut(&ArchivedEvent) -> Result<()>;

    fn replace_event(&self, event: &Event, with_address: bool) -> Result<()>;
}

pub static TAGS_VALUE: phf::Map<&'static str, u8> = phf_map! {
    "d" => 9,
    "e" => 8,
    "E" => 8,
    "h" => 7,
    "P" => 3,
    "p" => 2,
    "k" => 2,
    "K" => 1,
};
