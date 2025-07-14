//! LMDB-based event store implementation using heed
//!
//! This module provides an LMDB-backed event store for Nostr events.

use crate::{Event, Filter, Timestamp, ID};
use fasthash::MumHasher;
use heed::byteorder::LittleEndian;
use heed::{byteorder, types::*, DefaultComparator};
use heed::{Database, Env, EnvOpenOptions, RoTxn, RwTxn};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;
use thiserror::Error;
use velcro::hash_map;

#[derive(Error, Debug)]
pub enum LMDBError {
    #[error("LMDB error: {0}")]
    Heed(#[from] heed::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("event with values out of expected boundaries {created_at}/{kind}")]
    OutOfBounds { created_at: i64, kind: u16 },
    #[error("duplicate event")]
    DuplicateEvent,
    #[error("event not found")]
    EventNotFound,
}

pub type Result<T> = std::result::Result<T, LMDBError>;

/// LMDB backend for event storage
pub struct LMDBStore {
    pub path: String,
    pub map_size: Option<usize>,

    env: Env,

    // databases
    events_by_id: Database<U64<byteorder::LittleEndian>, Bytes>,
    index_created_at: Database<Bytes, U64<byteorder::LittleEndian>>,
    index_kind: Database<Bytes, U64<byteorder::LittleEndian>>,
    index_pubkey: Database<Bytes, U64<byteorder::LittleEndian>>,
    index_pubkey_kind: Database<Bytes, U64<byteorder::LittleEndian>>,
    index_tag: Database<Bytes, U64<byteorder::LittleEndian>>,
}

impl LMDBStore {
    /// initialize the database and return a new instance
    pub fn init(path: impl AsRef<Path>, map_size: Option<usize>) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();

        // create directory if it doesn't exist
        fs::create_dir_all(&path_str)?;

        // open environment
        let mut env_builder = EnvOpenOptions::new();
        env_builder.max_dbs(12);
        env_builder.max_readers(1000);

        if let Some(map_size) = map_size {
            env_builder.map_size(map_size);
        } else {
            env_builder.map_size(1 << 38); // ~273GB
        }

        let env = unsafe { env_builder.open(&path_str)? };

        // create databases
        let mut wtxn = env.write_txn()?;

        let events_by_id = env.create_database(&mut wtxn, Some("events"))?;
        let index_created_at = env.create_database(&mut wtxn, Some("created_at"))?;
        let index_kind = env.create_database(&mut wtxn, Some("kind"))?;
        let index_pubkey = env.create_database(&mut wtxn, Some("pubkey"))?;
        let index_pubkey_kind = env.create_database(&mut wtxn, Some("pubkeyKind"))?;
        let index_tag = env.create_database(&mut wtxn, Some("tag"))?;

        wtxn.commit()?;

        let store = Self {
            path: path_str,
            map_size,
            env,
            events_by_id,
            index_created_at,
            index_kind,
            index_pubkey,
            index_pubkey_kind,
            index_tag,
        };

        Ok(store)
    }

    /// close the database
    pub fn close(&self) {
        // heed automatically closes when dropped
    }

    /// save an event
    pub fn save_event(&self, event: &Event) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;

        // check if we already have this id
        if self
            .events_by_id
            .get(&wtxn, &event.id.as_u64_lossy())?
            .is_some()
        {
            return Err(LMDBError::DuplicateEvent);
        }

        self.save(&mut wtxn, event)?;
        wtxn.commit()?;

        Ok(())
    }

    /// internal save function
    fn save(&self, wtxn: &mut RwTxn, event: &Event) -> Result<()> {
        let event_data = serde_json::to_vec(event)?;
        let id = event.id.as_u64_lossy();

        // save raw event
        self.events_by_id.put(wtxn, &id, &event_data)?;

        // save indexes
        for index_key in self.get_index_keys_for_event(event) {
            index_key.db.put(wtxn, &index_key.key, &id)?
        }

        Ok(())
    }

    /// delete an event
    pub fn delete_event(&self, id: &ID) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.delete(&mut wtxn, id)?;
        wtxn.commit()?;
        Ok(())
    }

    /// internal delete function
    fn delete(&self, wtxn: &mut RwTxn, id: &ID) -> Result<()> {
        let id = &id.as_u64_lossy();

        // get the event data to compute indexes
        let event_data = self
            .events_by_id
            .get(wtxn, id)?
            .ok_or(LMDBError::EventNotFound)?;
        let event: Event = serde_json::from_slice(event_data)?;

        // delete all indexes
        for index_key in self.get_index_keys_for_event(&event) {
            index_key.db.delete(wtxn, &index_key.key)?;
        }

        // delete raw event
        self.events_by_id.delete(wtxn, id)?;

        Ok(())
    }

    /// query events
    pub fn query_events(&self, filter: &Filter, max_limit: usize) -> Result<Vec<Event>> {
        if filter.search.is_some() {
            return Ok(vec![]); // search not supported
        }

        let limit = filter.limit.unwrap_or(max_limit).min(max_limit);
        if limit == 0 {
            return Ok(vec![]);
        }

        let rtxn = self.env.read_txn()?;
        let results = self.query(&rtxn, filter, limit)?;
        rtxn.commit()?;

        Ok(results)
    }

    /// internal query function
    fn query(&self, rtxn: &RoTxn, filter: &Filter, limit: usize) -> Result<Vec<Event>> {
        let mut results = Vec::new();

        // simplified query - just iterate through created_at index
        // TODO: do the actual query
        let iter = self.index_created_at.rev_iter(rtxn)?;

        for item in iter {
            let (_, id) = item?;
            let event_data = self
                .events_by_id
                .get(rtxn, &id)?
                .ok_or(LMDBError::EventNotFound)?;
            let event: Event = serde_json::from_slice(event_data)?;

            if filter.matches(&event) {
                results.push(event);
                if results.len() >= limit {
                    break;
                }
            }
        }

        Ok(results)
    }

    /// count events matching filter
    pub fn count_events(&self, filter: &Filter) -> Result<u32> {
        let rtxn = self.env.read_txn()?;
        let mut count = 0u32;

        let iter = self.index_created_at.rev_iter(&rtxn)?;

        for item in iter {
            let (_, id) = item?;
            let event_data = self
                .events_by_id
                .get(&rtxn, &id)?
                .ok_or(LMDBError::EventNotFound)?;
            let event: Event = serde_json::from_slice(event_data)?;

            if filter.matches(&event) {
                count += 1;
            }
        }

        rtxn.commit()?;
        Ok(count)
    }

    /// replace event
    pub fn replace_event(&self, event: &Event) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;

        // create filter to find existing events
        let mut filter = Filter::new();
        filter.kinds = Some(vec![event.kind]);
        filter.authors = Some(vec![event.pubkey]);
        filter.limit = Some(10);

        if event.kind.is_addressable() {
            // addressable event - add d tag
            let d_tag = event.tags.get_d();
            if !d_tag.is_empty() {
                filter.tags = Some(hash_map!("d".to_string(): vec![d_tag]));
            }
        }

        // find and delete older events
        let rtxn = self.env.read_txn()?;
        let existing = self.query(&rtxn, &filter, 10)?;
        rtxn.commit()?;

        let mut should_store = true;
        for existing_event in existing {
            if existing_event.created_at < event.created_at {
                self.delete(&mut wtxn, &existing_event.id)?;
            } else {
                should_store = false; // newer event already exists
            }
        }

        if should_store {
            self.save(&mut wtxn, event)?;
        }

        wtxn.commit()?;
        Ok(())
    }

    /// generate index keys for an event
    fn get_index_keys_for_event(&self, event: &Event) -> Vec<IndexKey> {
        let mut keys = Vec::new();

        // this is so the events are ordered from newer to older
        let ts_bytes = inverted_timestamp_bytes(&event.created_at);

        // by date only
        {
            let mut key = [INDEX_CREATED_AT_PREFIX; 1 + 4];
            key[1..].copy_from_slice(&ts_bytes);
            keys.push(IndexKey {
                db: self.index_created_at,
                key: key.to_vec(),
            });
        }

        // by kind + date
        {
            let mut key = [INDEX_KIND_PREFIX; 1 + 2 + 4];
            key[1..1 + 2].copy_from_slice(&event.kind.0.to_be_bytes());
            key[1 + 2..].copy_from_slice(&ts_bytes);
            keys.push(IndexKey {
                db: self.index_kind,
                key: key.to_vec(),
            });
        }

        // by pubkey + date
        {
            let mut key = [INDEX_PUBKEY_PREFIX; 1 + 8 + 4];
            key[1..1 + 8].copy_from_slice(&event.pubkey.as_bytes()[0..8]);
            key[1 + 8..].copy_from_slice(&ts_bytes);
            keys.push(IndexKey {
                db: self.index_pubkey,
                key: key.to_vec(),
            });
        }

        // by pubkey + kind + date
        {
            let mut key = [INDEX_PUBKEY_KIND_PREFIX; 1 + 8 + 2 + 4];
            key[1..1 + 8].copy_from_slice(&event.pubkey.as_bytes()[0..8]);
            key[1 + 8..1 + 8 + 2].copy_from_slice(&event.kind.0.to_be_bytes());
            key[1 + 8 + 2..].copy_from_slice(&ts_bytes);
            keys.push(IndexKey {
                db: self.index_pubkey_kind,
                key: key.to_vec(),
            });
        }

        // by tag value + date
        for tag in &event.tags.0 {
            if tag.len() < 2 || tag[0].len() != 1 {
                continue;
            }

            let mut s: MumHasher = Default::default();
            tag[1].hash(&mut s);
            let hash = s.finish();

            let mut key = [INDEX_TAG_PREFIX; 1 + 8 + 4];
            key[1..1 + 8].copy_from_slice(hash.to_le_bytes().as_slice());
            key[1 + 8..].copy_from_slice(&ts_bytes);

            keys.push(IndexKey {
                db: self.index_tag,
                key: key.to_vec(),
            });
        }

        keys
    }
}

#[derive(Debug)]
struct IndexKey {
    db: Database<Bytes, U64<LittleEndian>, DefaultComparator>,
    key: Vec<u8>,
}

const INDEX_CREATED_AT_PREFIX: u8 = 1;
const INDEX_KIND_PREFIX: u8 = 2;
const INDEX_PUBKEY_PREFIX: u8 = 3;
const INDEX_PUBKEY_KIND_PREFIX: u8 = 4;
const INDEX_TAG_PREFIX: u8 = 5;

fn inverted_timestamp_bytes(created_at: &Timestamp) -> [u8; 4] {
    let inverted_timestamp = 0xffffffff - created_at.0;
    inverted_timestamp.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{event_template::EventTemplate, Filter, Kind, SecretKey, Timestamp};

    #[test]
    fn test_init_and_close() {
        let temp_dir = std::env::temp_dir().join("lmdb_test_init");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = LMDBStore::init(&temp_dir, None).expect("failed to initialize store");
        store.close();

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_save_and_query_event() {
        let temp_dir = std::env::temp_dir().join("lmdb_test_save_query");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = LMDBStore::init(&temp_dir, None).expect("failed to initialize store");
        let event = EventTemplate {
            content: "nothing".to_string(),
            ..Default::default()
        }
        .finalize(&SecretKey::generate());

        // save the event
        store.save_event(&event).expect("failed to save event");

        // query all events
        let filter = Filter::new();
        let results = store
            .query_events(&filter, 100)
            .expect("failed to query events");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, event.id);
        assert_eq!(results[0].content, event.content);

        store.close();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_duplicate_event() {
        let temp_dir = std::env::temp_dir().join("lmdb_test_duplicate");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = LMDBStore::init(&temp_dir, None).expect("failed to initialize store");
        let event = EventTemplate {
            content: "nothing".to_string(),
            ..Default::default()
        }
        .finalize(&SecretKey::generate());

        // save the event
        store.save_event(&event).expect("failed to save event");

        // try to save the same event again
        let result = store.save_event(&event);
        assert!(matches!(result, Err(LMDBError::DuplicateEvent)));

        store.close();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_delete_event() {
        let temp_dir = std::env::temp_dir().join("lmdb_test_delete");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = LMDBStore::init(&temp_dir, None).expect("failed to initialize store");
        let event = EventTemplate {
            content: "nothing".to_string(),
            ..Default::default()
        }
        .finalize(&SecretKey::generate());

        // save the event
        store.save_event(&event).expect("failed to save event");

        // verify it exists
        let filter = Filter::new();
        let results = store
            .query_events(&filter, 100)
            .expect("failed to query events");
        assert_eq!(results.len(), 1);

        // delete the event
        store
            .delete_event(&event.id)
            .expect("failed to delete event");

        // verify it's gone
        let results = store
            .query_events(&filter, 100)
            .expect("failed to query events");
        assert_eq!(results.len(), 0);

        store.close();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_count_events() {
        let temp_dir = std::env::temp_dir().join("lmdb_test_count");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = LMDBStore::init(&temp_dir, None).expect("failed to initialize store");

        // save multiple events
        for i in 0..5 {
            let event = EventTemplate {
                content: format!("{}", i),
                created_at: Timestamp(i),
                ..Default::default()
            }
            .finalize(&SecretKey::generate());
            store.save_event(&event).expect("failed to save event");
        }

        // count all events
        let filter = Filter::new();
        let count = store.count_events(&filter).expect("failed to count events");
        assert_eq!(count, 5);

        store.close();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_filter_by_kind() {
        let temp_dir = std::env::temp_dir().join("lmdb_test_filter_kind");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = LMDBStore::init(&temp_dir, None).expect("failed to initialize store");

        // save events with different kinds
        for i in 0..3 {
            let event = EventTemplate {
                content: format!("{}", i),
                created_at: Timestamp(i),
                kind: Kind(i as u16),
                ..Default::default()
            }
            .finalize(&SecretKey::generate());
            store.save_event(&event).expect("failed to save event");
        }

        // filter by kind 1
        let mut filter = Filter::new();
        filter.kinds = Some(vec![Kind(1)]);
        let results = store
            .query_events(&filter, 100)
            .expect("failed to query events");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].kind, Kind(1));

        store.close();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
