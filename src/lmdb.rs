//! LMDB-based event store implementation using heed
//!
//! This module provides an LMDB-backed event store for Nostr events.

use crate::{event::ArchivedEvent, Event, Filter, Timestamp, ID};
use heed::byteorder::LittleEndian;
use heed::{byteorder, types::*, DefaultComparator, RoTxn};
use heed::{Database, Env, EnvOpenOptions, RwTxn};
use rkyv::rancor;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LMDBError {
    #[error("LMDB error: {0}")]
    Heed(#[from] heed::Error),

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

pub type Result<T> = std::result::Result<T, LMDBError>;

/// LMDB backend for event storage
pub struct LMDBStore {
    pub path: String,
    pub map_size: Option<usize>,

    env: Env,

    // indexes
    events_by_id: Database<U64<byteorder::LittleEndian>, Bytes>,
    index_created_at: Database<Bytes, U64<byteorder::LittleEndian>>,
    index_kind: Database<Bytes, U64<byteorder::LittleEndian>>,
    index_pubkey: Database<Bytes, U64<byteorder::LittleEndian>>,
    index_pubkey_kind: Database<Bytes, U64<byteorder::LittleEndian>>,
    index_tag: Database<Bytes, U64<byteorder::LittleEndian>>,
    index_tag32: Database<Bytes, U64<byteorder::LittleEndian>>,
    index_ptag_ktag: Database<Bytes, U64<byteorder::LittleEndian>>,
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
        let index_created_at = env.create_database(&mut wtxn, Some("createdat"))?;
        let index_kind = env.create_database(&mut wtxn, Some("kind"))?;
        let index_pubkey = env.create_database(&mut wtxn, Some("pubkey"))?;
        let index_pubkey_kind = env.create_database(&mut wtxn, Some("pubkey_kind"))?;
        let index_tag = env.create_database(&mut wtxn, Some("tag"))?;
        let index_tag32 = env.create_database(&mut wtxn, Some("tag32"))?;
        let index_ptag_ktag = env.create_database(&mut wtxn, Some("ptag_ktag"))?;

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
            index_tag32,
            index_ptag_ktag,
        };

        Ok(store)
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
        let event_data = rkyv::to_bytes::<rancor::Error>(event)?;
        let id_u64 = &event.id.as_u64_lossy();

        // save raw event
        self.events_by_id.put(wtxn, id_u64, &event_data)?;

        // save indexes
        self.get_index_keys_for_event(
            unsafe { &rkyv::from_bytes_unchecked::<Event, rancor::Error>(&event_data)? },
            |index_key| {
                index_key.db.put(wtxn, &index_key.key, id_u64)?;
                Ok(())
            },
        )?;

        Ok(())
    }

    /// delete an event
    pub fn delete_event(&self, id: &ID) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.delete_internal(&mut wtxn, id.as_u64_lossy())?;
        wtxn.commit()?;
        Ok(())
    }

    /// internal delete function
    fn delete_internal(&self, wtxn: &mut RwTxn, id: u64) -> Result<()> {
        // get the event data to compute indexes
        let raw = self
            .events_by_id
            .get(wtxn, &id)?
            .ok_or(LMDBError::EventNotFound)?;

        let event = unsafe { rkyv::from_bytes_unchecked::<Event, rancor::Error>(raw)? };

        // delete all indexes
        self.get_index_keys_for_event(&event, |index_key| {
            index_key.db.delete(wtxn, &index_key.key)?;
            Ok(())
        })?;

        // delete raw event
        self.events_by_id.delete(wtxn, &id)?;

        Ok(())
    }

    /// query events
    pub fn query_events<F>(&self, filter: &Filter, max_limit: usize, mut cb: F) -> Result<()>
    where
        F: FnMut(&ArchivedEvent) -> Result<()>,
    {
        if filter.search.is_some() {
            return Err(LMDBError::InvalidFilter("search not supported".to_string()));
        }

        let limit = filter.limit.unwrap_or(max_limit).min(max_limit);
        if limit == 0 {
            return Ok(());
        }

        let rtxn = self.env.read_txn()?;

        if let Some(ids) = &filter.ids {
            return self.query_by_ids(&rtxn, ids, cb);
        }

        self.query_by_filter(&rtxn, filter, limit, cb)?;
        rtxn.commit()?;

        Ok(())
    }

    fn query_by_ids<F>(&self, rtxn: &RoTxn, ids: &Vec<ID>, mut cb: F) -> Result<()>
    where
        F: FnMut(&ArchivedEvent) -> Result<()>,
    {
        for id in ids {
            if let Ok(Some(raw)) = self.events_by_id.get(rtxn, &id.as_u64_lossy()) {
                let event = unsafe { rkyv::access_unchecked::<ArchivedEvent>(raw) };
                cb(event)?;
            }
        }

        Ok(())
    }

    fn query_by_filter<F>(
        &self,
        rtxn: &RoTxn,
        filter: &Filter,
        limit: usize,
        mut cb: F,
    ) -> Result<()>
    where
        F: FnMut(&ArchivedEvent) -> Result<()>,
    {
        if let Some(tags) = filter.tags {
            for (tag_name, tag_values) in tags {
            if tag_name ==
            }
        }

        let iter = self.index_created_at.rev_iter(rtxn)?;

        for item in iter {
            let (_, id) = item?;
            let raw = self
                .events_by_id
                .get(rtxn, &id)?
                .ok_or(LMDBError::EventNotFound)?;
            let event: &ArchivedEvent = unsafe { rkyv::access_unchecked(raw) };
            cb(event)?
        }

        Ok(())
    }

    /// replace event
    pub fn replace_event(&self, event: &Event, with_address: bool) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;

        // create filter to find existing events
        let mut filter = Filter::new();
        filter.kinds = Some(vec![event.kind]);
        filter.authors = Some(vec![event.pubkey]);
        filter.limit = Some(10);

        if with_address {
            filter.tags = Some(vec![("d".to_string(), vec![event.tags.get_d()])]);
        }

        let mut should_store = true;

        // find and delete older events
        let rtxn = self.env.read_txn()?;
        self.query_by_filter(&rtxn, &filter, 10, |existing_event| {
            if existing_event.created_at.0 < event.created_at.0 {
                self.delete_internal(
                    &mut wtxn,
                    u64::from_ne_bytes(existing_event.id.0[8..16].try_into().unwrap()),
                )?;
            } else {
                should_store = false; // newer event already exists
            }

            Ok(())
        })?;
        rtxn.commit()?;

        if should_store {
            self.save(&mut wtxn, event)?;
        }

        wtxn.commit()?;
        Ok(())
    }

    fn get_index_keys_for_event<F>(&self, event: &Event, mut cb: F) -> Result<()>
    where
        F: FnMut(IndexKey) -> Result<()>,
    {
        // this is so the events are ordered from newer to older
        let ts_bytes = inverted_timestamp_bytes(&event.created_at);

        // by date only
        {
            cb(IndexKey {
                db: self.index_created_at,
                key: &ts_bytes,
            })?;
        }

        // by kind + date
        {
            let mut key = [0u8, 2 + 4];
            key[0..2].copy_from_slice(&event.kind.0.to_ne_bytes());
            key[2..].copy_from_slice(&ts_bytes);
            cb(IndexKey {
                db: self.index_kind,
                key: &key,
            })?;
        }

        // by pubkey + date
        {
            let mut key = [8 + 4];
            key[0..8].copy_from_slice(&event.pubkey.as_u64_lossy().to_ne_bytes());
            key[8..].copy_from_slice(&ts_bytes);
            cb(IndexKey {
                db: self.index_pubkey,
                key: &key,
            })?;
        }

        // by pubkey + kind + date
        {
            let mut key = [0u8; 8 + 2 + 4];
            key[0..8].copy_from_slice(&event.pubkey.as_u64_lossy().to_ne_bytes());
            key[8..8 + 2].copy_from_slice(&event.kind.0.to_ne_bytes());
            key[8 + 2..].copy_from_slice(&ts_bytes);
            cb(IndexKey {
                db: self.index_pubkey_kind,
                key: &key,
            })?;
        }

        // by tag value + date
        let mut tag_key: Option<[u8; 8 + 4]> = None;
        for tag in &event.tags.0 {
            if tag.len() < 2 || tag[0].len() != 1 {
                continue;
            }

            let key = tag_key.get_or_insert_with(|| {
                let mut key = [0u8; 8 + 4];
                key[8..].copy_from_slice(&ts_bytes);
                key
            });

            if tag[1].len() == 64 {
                if lowercase_hex::decode_to_slice(&tag[1][8 * 2..8 * 2 + 8 * 2], &mut key[0..8])
                    .is_ok()
                {
                    cb(IndexKey {
                        db: self.index_tag32,
                        key: key,
                    })?;
                    continue;
                }
            }

            let mut s: lmdb_store_hasher::AHasher = Default::default();
            tag[1].hash(&mut s);
            let hash = s.finish();

            key[0..8].copy_from_slice(hash.to_ne_bytes().as_slice());
            key[8..].copy_from_slice(&ts_bytes);

            cb(IndexKey {
                db: self.index_tag,
                key: key,
            })?;
        }

        // by p-tag + k-tag (includes all variantions possible)
        let mut kp_key: Option<[u8; 8 + 2 + 4]> = None;
        for (k_tagname, p_tagname) in vec![("k", "p"), ("K", "p"), ("k", "P"), ("K", "P")] {
            for k_tag in &event.tags.0 {
                if k_tag.len() >= 2 && k_tag[0] == k_tagname {
                    if let Ok(k) = k_tag[1].parse::<u16>() {
                        let key = kp_key.get_or_insert_with(|| {
                            let mut key = [0u8; 8 + 2 + 4];
                            key[8 + 2..].copy_from_slice(&ts_bytes); // prefill date for all
                            key
                        });

                        key[8..8 + 2].copy_from_slice(&k.to_ne_bytes()); // prefill "k" for these

                        for p_tag in &event.tags.0 {
                            if p_tag.len() >= 2 && p_tag[0] == p_tagname && p_tag[1].len() == 64 {
                                if lowercase_hex::decode_to_slice(
                                    &p_tag[1][8 * 2..8 * 2 + 8 * 2],
                                    &mut key[0..8],
                                )
                                .is_ok()
                                {
                                    cb(IndexKey {
                                        db: self.index_ptag_ktag,
                                        key: key,
                                    })?;
                                }
                            }
                        }
                    }

                    // only do one k-tag per event
                    break;
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
struct IndexKey<'a> {
    db: Database<Bytes, U64<LittleEndian>, DefaultComparator>,
    key: &'a [u8],
}

#[inline]
fn inverted_timestamp_bytes(created_at: &Timestamp) -> [u8; 4] {
    let inverted_timestamp = 0xffffffff - created_at.0;
    inverted_timestamp.to_ne_bytes()
}

#[cfg(test)]
mod tests {
    use rkyv::Deserialize;

    use super::*;
    use crate::{event_template::EventTemplate, ArchivedKind, Filter, Kind, SecretKey, Timestamp};

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
        let mut results = Vec::new();
        store
            .query_events(&filter, 100, |event| {
                results.push(rkyv::deserialize::<Event, rancor::Error>(event).unwrap());
                Ok(())
            })
            .expect("failed to query events");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, event.id);
        assert_eq!(results[0].content, event.content);

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
        let mut count = 0;
        store
            .query_events(&filter, 100, |_| {
                count += 1;
                Ok(())
            })
            .expect("failed to query events");
        assert_eq!(count, 1);

        // delete the event
        store
            .delete_event(&event.id)
            .expect("failed to delete event");

        // verify it's gone
        let mut newcount = 0;
        store
            .query_events(&filter, 100, |_| {
                newcount += 1;
                Ok(())
            })
            .expect("failed to query events");
        assert_eq!(newcount, 0);

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
        let mut results = Vec::new();
        store
            .query_events(&filter, 100, |event| {
                results.push(event.kind.0);
                Ok(())
            })
            .expect("failed to query events");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], 1);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
