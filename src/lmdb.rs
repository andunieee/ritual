//! LMDB-based event store implementation using heed
//!
//! This module provides an LMDB-backed event store for Nostr events.

use crate::database::{DatabaseError, EventDatabase, Result, TAGS_VALUE};
use crate::filter::TagQuery;
use crate::{event::ArchivedEvent, Event, Filter, ID};
use crate::{Kind, PubKey};
use heed::{byteorder, DefaultComparator, RoTxn};
use heed::{Database, Env, EnvOpenOptions, RwTxn};
use rkyv::rancor;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::range::Range;
use std::{cmp, fs};

pub struct HeedEventDatabase {
    pub path: String,
    pub map_size: Option<usize>,

    env: Env,

    // indexes
    events_by_id: Database<heed::types::U64<byteorder::NativeEndian>, heed::types::Bytes>,
    index_created_at: Database<heed::types::Bytes, heed::types::U64<byteorder::NativeEndian>>,
    index_kind: Database<heed::types::Bytes, heed::types::U64<byteorder::NativeEndian>>,
    index_pubkey: Database<heed::types::Bytes, heed::types::U64<byteorder::NativeEndian>>,
    index_pubkey_kind: Database<heed::types::Bytes, heed::types::U64<byteorder::NativeEndian>>,
    index_tag: Database<heed::types::Bytes, heed::types::U64<byteorder::NativeEndian>>,
    index_ptag_ktag: Database<heed::types::Bytes, heed::types::U64<byteorder::NativeEndian>>,
}

impl HeedEventDatabase {
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
            index_ptag_ktag,
        };

        Ok(store)
    }

    /// internal save function
    fn save_internal(&self, wtxn: &mut RwTxn, event: &Event) -> Result<()> {
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

    /// internal delete function
    fn delete_internal(&self, wtxn: &mut RwTxn, id: u64) -> Result<()> {
        // get the event data to compute indexes
        let raw = self
            .events_by_id
            .get(wtxn, &id)?
            .ok_or(DatabaseError::EventNotFound)?;

        let event = unsafe { rkyv::from_bytes_unchecked::<Event, rancor::Error>(raw)? };

        // delete all indexes
        self.get_index_keys_for_event(&event, |index_key| {
            let key = index_key.key;
            index_key.db.delete(wtxn, &key)?;
            Ok(())
        })?;

        // delete raw event
        self.events_by_id.delete(wtxn, &id)?;

        Ok(())
    }

    fn execute<F>(&self, rtxn: &RoTxn, queries: Vec<Query>, mut cb: F) -> Result<()>
    where
        F: FnMut(&ArchivedEvent) -> Result<()>,
    {
        let cursors = queries.iter().flat_map(|query| {
            query.sub_queries.iter().map(|starting_point| {
                let mut ending_point = starting_point.clone();
                ending_point[starting_point.len() - 4..].copy_from_slice(&query.until);
                let range: Range<[u8]> = &(ending_point.into()..=(*starting_point.into()));
                let rev_iter = query.db.rev_range(&rtxn, &range);
            })
        });

        let iter = self.index_created_at.rev_iter(rtxn)?;

        for item in iter {
            let (_, id) = item?;
            let raw = self
                .events_by_id
                .get(rtxn, &id)?
                .ok_or(DatabaseError::EventNotFound)?;
            let event: &ArchivedEvent = unsafe { rkyv::access_unchecked(raw) };
            cb(event)?
        }

        Ok(())
    }

    fn plan_query(&self, filter: Filter, queries: &mut Vec<Query>, max_limit: usize) {
        let since = filter.since.map(|ts| ts.0).unwrap_or(0).to_ne_bytes();
        let until = filter
            .until
            .map(|ts| ts.0)
            .unwrap_or(u32::MAX)
            .to_ne_bytes();
        let mut extra_tag: Option<TagQuery> = None;

        if let Some(mut tags) = filter.tags {
            tags.sort_unstable_by(|(a, _), (b, _)| {
                if TAGS_VALUE.get(b).unwrap_or(&6) > TAGS_VALUE.get(a).unwrap_or(&6) {
                    cmp::Ordering::Less
                } else if TAGS_VALUE.get(b).unwrap_or(&6) < TAGS_VALUE.get(a).unwrap_or(&6) {
                    cmp::Ordering::Greater
                } else {
                    cmp::Ordering::Equal
                }
            });
            let (tag_name, tag_values) = tags
                .get(0)
                .expect("there must always be at least one tag if tags is present");

            if TAGS_VALUE.get(tag_name).unwrap_or(&6) > &5 {
                // use tag query as the main index
                queries.push(Query {
                    db: self.index_tag,
                    sub_queries: tag_values
                        .iter()
                        .map(|v| {
                            let mut key = [0u8; 8 + 4];
                            key[8..].copy_from_slice(&since);

                            match lowercase_hex::decode_to_slice(v, &mut key[0..8]) {
                                Ok(_) => Vec::from(&key[..]),
                                Err(_) => {
                                    let mut s: lmdb_store_hasher::AHasher = Default::default();
                                    v.hash(&mut s);
                                    let hash = s.finish();
                                    key[0..8].copy_from_slice(&hash.to_ne_bytes());
                                    Vec::from(&key[..])
                                }
                            }
                        })
                        .collect(),
                    until: until,
                    limit: max_limit,
                    extra_tag: tags.get(1).cloned(), // get the second tag if it exists as secondary filter
                    extra_kinds: filter.kinds.clone(),
                    extra_authors: filter.authors.clone(),
                });
            }

            if let Some(tag) = tags.get(0) {
                // use the first tag as the extra tag filter
                extra_tag.insert(tag.clone());
            }
        }

        if let (Some(authors), Some(kinds)) = (&filter.authors, &filter.kinds) {
            // use pubkey-kind as the main index
            let mut sub_queries = Vec::with_capacity(authors.len() * kinds.len());

            for author in authors {
                for kind in kinds {
                    let mut key = Vec::from([0u8; 8 + 4 + 4]);
                    key[8 + 4..].copy_from_slice(&since);

                    key[0..8].copy_from_slice(&author.as_u64_lossy().to_ne_bytes());
                    key[8..8 + 4].copy_from_slice(&kind.0.to_ne_bytes());
                    sub_queries.push(key);
                }
            }

            queries.push(Query {
                db: self.index_pubkey_kind,
                sub_queries,
                until: until,
                limit: max_limit,
                extra_tag,
                extra_kinds: None,
                extra_authors: None,
            });
        } else if let Some(authors) = filter.authors {
            queries.push(Query {
                db: self.index_pubkey_kind,
                sub_queries: authors
                    .iter()
                    .map(|a| {
                        let mut key = Vec::from([0u8; 8 + 4]);
                        key[8..].copy_from_slice(&since);
                        key[0..8].copy_from_slice(&a.as_u64_lossy().to_ne_bytes());
                        key
                    })
                    .collect(),
                until: until,
                limit: max_limit,
                extra_tag,
                extra_kinds: None,
                extra_authors: None,
            });
        } else if let Some(kinds) = filter.kinds {
            queries.push(Query {
                db: self.index_pubkey_kind,
                sub_queries: kinds
                    .iter()
                    .map(|k| {
                        let mut key = Vec::from([0u8; 4 + 4]);
                        key[4..].copy_from_slice(&since);
                        key[0..4].copy_from_slice(&k.0.to_ne_bytes());
                        key
                    })
                    .collect(),
                until: until,
                limit: max_limit,
                extra_tag,
                extra_kinds: None,
                extra_authors: None,
            });
        }
    }

    fn get_index_keys_for_event<F>(&self, event: &Event, mut cb: F) -> Result<()>
    where
        F: FnMut(IndexKey) -> Result<()>,
    {
        // this is so the events are ordered from newer to older
        let ts_bytes = &event.created_at.0.to_ne_bytes();

        // by date only
        {
            cb(IndexKey {
                db: self.index_created_at,
                key: ts_bytes,
            })?;
        }

        // by kind + date
        {
            let mut key = [0u8, 2 + 4];
            key[0..2].copy_from_slice(&event.kind.0.to_ne_bytes());
            key[2..].copy_from_slice(ts_bytes);
            cb(IndexKey {
                db: self.index_kind,
                key: &key,
            })?;
        }

        // by pubkey + date
        {
            let mut key = [8 + 4];
            key[0..8].copy_from_slice(&event.pubkey.as_u64_lossy().to_ne_bytes());
            key[8..].copy_from_slice(ts_bytes);
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
            key[8 + 2..].copy_from_slice(ts_bytes);
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
                key[8..].copy_from_slice(ts_bytes);
                key
            });

            if tag[1].len() == 64 {
                if lowercase_hex::decode_to_slice(&tag[1][8 * 2..8 * 2 + 8 * 2], &mut key[0..8])
                    .is_ok()
                {
                    cb(IndexKey {
                        db: self.index_tag,
                        key: key,
                    })?;
                    continue;
                }
            }

            let mut s: lmdb_store_hasher::AHasher = Default::default();
            tag[1].hash(&mut s);
            let hash = s.finish();

            key[0..8].copy_from_slice(hash.to_ne_bytes().as_slice());
            key[8..].copy_from_slice(ts_bytes);

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
                            key[8 + 2..].copy_from_slice(ts_bytes); // prefill date for all
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

impl EventDatabase for HeedEventDatabase {
    fn save_event(&self, event: &Event) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;

        // check if we already have this id
        if self
            .events_by_id
            .get(&wtxn, &event.id.as_u64_lossy())?
            .is_some()
        {
            return Err(DatabaseError::DuplicateEvent);
        }

        self.save_internal(&mut wtxn, event)?;
        wtxn.commit()?;

        Ok(())
    }

    fn replace_event(&self, event: &Event, with_address: bool) -> Result<()> {
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

        let mut queries: Vec<Query> = Vec::with_capacity(1);
        self.plan_query(filter, &mut queries, 1);
        self.execute(&rtxn, queries, |existing_event| {
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
            self.save_internal(&mut wtxn, event)?;
        }

        wtxn.commit()?;
        Ok(())
    }

    fn query_events<F>(&self, filters: Vec<Filter>, max_limit: usize, mut cb: F) -> Result<()>
    where
        F: FnMut(&ArchivedEvent) -> Result<()>,
    {
        let mut queries: Vec<Query> = Vec::with_capacity(64);

        let rtxn = self.env.read_txn()?;

        for filter in filters {
            if filter.search.is_some() {
                return Err(DatabaseError::InvalidFilter(
                    "search not supported".to_string(),
                ));
            }

            // id query, just process these ids and move on
            if let Some(ids) = &filter.ids {
                for id in ids {
                    if let Ok(Some(raw)) = self.events_by_id.get(&rtxn, &id.as_u64_lossy()) {
                        let event = unsafe { rkyv::access_unchecked::<ArchivedEvent>(raw) };
                        cb(event)?;
                    }
                }
                continue;
            }

            // otherwise prepare queries to scan the database with
            let limit = filter.limit.unwrap_or(max_limit).min(max_limit);
            if limit == 0 {
                // limit zero, ignore this one
                continue;
            }

            self.plan_query(filter, &mut queries, limit);
        }

        if queries.len() > 0 {
            self.execute(&rtxn, queries, |_| Ok(()))?;
        }

        rtxn.commit()?;
        Ok(())
    }

    fn delete_event(&self, id: &ID) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.delete_internal(&mut wtxn, id.as_u64_lossy())?;
        wtxn.commit()?;
        Ok(())
    }
}

#[derive(Debug)]
struct IndexKey<'a> {
    db: Database<heed::types::Bytes, heed::types::U64<byteorder::NativeEndian>, DefaultComparator>,
    key: &'a [u8],
}

#[derive(Debug)]
struct Query {
    db: Database<heed::types::Bytes, heed::types::U64<byteorder::NativeEndian>, DefaultComparator>,

    // this is the main index we'll use, the values are the starting points
    // the prefix should be just the initial bytes (anything besides the last 4 bytes)
    sub_queries: Vec<Vec<u8>>,

    // we'll scan each index up to this point (the last 4 bytes)
    until: [u8; 4],

    // max number of results we'll return from this
    limit: usize,

    // these extra values will be matched against after we've read an event from the database
    extra_tag: Option<TagQuery>,
    extra_kinds: Option<Vec<Kind>>,
    extra_authors: Option<Vec<PubKey>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{event_template::EventTemplate, Filter, Kind, SecretKey, Timestamp};

    #[test]
    fn test_save_and_query_event() {
        let temp_dir = std::env::temp_dir().join("lmdb_test_save_query");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = HeedEventDatabase::init(&temp_dir, None).expect("failed to initialize store");
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
            .query_events(vec![filter], 100, |event| {
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

        let store = HeedEventDatabase::init(&temp_dir, None).expect("failed to initialize store");
        let event = EventTemplate {
            content: "nothing".to_string(),
            ..Default::default()
        }
        .finalize(&SecretKey::generate());

        // save the event
        store.save_event(&event).expect("failed to save event");

        // try to save the same event again
        let result = store.save_event(&event);
        assert!(matches!(result, Err(DatabaseError::DuplicateEvent)));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_delete_event() {
        let temp_dir = std::env::temp_dir().join("lmdb_test_delete");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = HeedEventDatabase::init(&temp_dir, None).expect("failed to initialize store");
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
            .query_events(vec![filter.clone()], 100, |_| {
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
            .query_events(vec![filter], 100, |_| {
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

        let store = HeedEventDatabase::init(&temp_dir, None).expect("failed to initialize store");

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
            .query_events(vec![filter], 100, |event| {
                results.push(event.kind.0);
                Ok(())
            })
            .expect("failed to query events");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], 1);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
