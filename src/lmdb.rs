//! LMDB-based event store implementation using lmdb-master-sys
//!
//! This module provides an LMDB-backed event store for Nostr events.

use crate::database::{DatabaseError, EventDatabase, Result, TAGS_VALUE};
use crate::filter::TagQuery;
use crate::{event::ArchivedEvent, Event, Filter, ID};
use crate::{Kind, PubKey};
use lmdb_master_sys as ffi;
use rkyv::rancor;
use std::ffi::CString;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::collections::HashSet;
use std::ptr;
use std::slice;
use std::{cmp, fs};

// macro to check LMDB return codes
macro_rules! check_lmdb {
    ($expr:expr) => {{
        let rc = $expr;
        if rc != 0 {
            return Err(DatabaseError::LMDB(lmdb_error(rc)));
        }
    }    };
}

pub struct HeedEventDatabase {
    pub path: String,
    pub map_size: Option<usize>,

    env: *mut ffi::MDB_env,

    // indexes
    events_by_id: ffi::MDB_dbi,
    index_created_at: ffi::MDB_dbi,
    index_kind: ffi::MDB_dbi,
    index_pubkey: ffi::MDB_dbi,
    index_pubkey_kind: ffi::MDB_dbi,
    index_tag: ffi::MDB_dbi,
    index_ptag_ktag: ffi::MDB_dbi,
}

impl Drop for HeedEventDatabase {
    fn drop(&mut self) {
        unsafe {
            if !self.env.is_null() {
                ffi::mdb_env_close(self.env);
            }
        }
    }
}

impl HeedEventDatabase {
    /// initialize the database and return a new instance
    pub fn init(path: impl AsRef<Path>, map_size: Option<usize>) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();

        // create directory if it doesn't exist
        fs::create_dir_all(&path_str)?;

        unsafe {
            // create environment
            let mut env: *mut ffi::MDB_env = ptr::null_mut();
            check_lmdb!(ffi::mdb_env_create(&mut env));

            // set max databases
            check_lmdb!(ffi::mdb_env_set_maxdbs(env, 12));

            // set max readers
            check_lmdb!(ffi::mdb_env_set_maxreaders(env, 1000));

            // set map size
            let size = map_size.unwrap_or(1 << 38); // ~273GB
            check_lmdb!(ffi::mdb_env_set_mapsize(env, size));

            // open environment
            let c_path = CString::new(path_str.clone()).unwrap();
            check_lmdb!(ffi::mdb_env_open(
                env,
                c_path.as_ptr(),
                ffi::MDB_NOSUBDIR,
                0o644
            ));

            // create databases
            let mut txn: *mut ffi::MDB_txn = ptr::null_mut();
            check_lmdb!(ffi::mdb_txn_begin(env, ptr::null_mut(), 0, &mut txn));

            let events_by_id = open_db(txn, "events")?;
            let index_created_at = open_db(txn, "createdat")?;
            let index_kind = open_db(txn, "kind")?;
            let index_pubkey = open_db(txn, "pubkey")?;
            let index_pubkey_kind = open_db(txn, "pubkey_kind")?;
            let index_tag = open_db(txn, "tag")?;
            let index_ptag_ktag = open_db(txn, "ptag_ktag")?;

            check_lmdb!(ffi::mdb_txn_commit(txn));

            Ok(Self {
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
            })
        }
    }

    /// internal save function
    fn save_internal(&self, txn: *mut ffi::MDB_txn, event: &Event) -> Result<()> {
        unsafe {
            let event_data = rkyv::to_bytes::<rancor::Error>(event)?;
            let id_u64 = event.id.as_u64_lossy();
            let id_bytes = id_u64.to_ne_bytes();

            // save raw event
            let key = ffi::MDB_val {
                mv_size: id_bytes.len(),
                mv_data: id_bytes.as_ptr() as *mut _,
            };
            let data = ffi::MDB_val {
                mv_size: event_data.len(),
                mv_data: event_data.as_ptr() as *mut _,
            };
            check_lmdb!(ffi::mdb_put(txn, self.events_by_id, &key, &data, 0));

            // save indexes
            self.get_index_keys_for_event(
                &rkyv::from_bytes_unchecked::<Event, rancor::Error>(&event_data)?,
                |index_key| {
                    let key = ffi::MDB_val {
                        mv_size: index_key.key.len(),
                        mv_data: index_key.key.as_ptr() as *mut _,
                    };
                    let data = ffi::MDB_val {
                        mv_size: id_bytes.len(),
                        mv_data: id_bytes.as_ptr() as *mut _,
                    };
                    check_lmdb!(ffi::mdb_put(txn, index_key.db, &key, &data, 0));
                    Ok(())
                },
            )?;
        }

        Ok(())
    }

    /// internal delete function
    fn delete_internal(&self, txn: *mut ffi::MDB_txn, id: u64) -> Result<()> {
        unsafe {
            let id_bytes = id.to_ne_bytes();
            let key = ffi::MDB_val {
                mv_size: id_bytes.len(),
                mv_data: id_bytes.as_ptr() as *mut _,
            };

            // get the event data to compute indexes
            let mut data = ffi::MDB_val {
                mv_size: 0,
                mv_data: ptr::null_mut(),
            };
            let rc = ffi::mdb_get(txn, self.events_by_id, &key, &mut data);
            if rc == ffi::MDB_NOTFOUND {
                return Err(DatabaseError::EventNotFound);
            }
            check_lmdb!(rc);

            let raw = slice::from_raw_parts(data.mv_data as *const u8, data.mv_size);
            let event = rkyv::from_bytes_unchecked::<Event, rancor::Error>(raw)?;

            // delete all indexes
            self.get_index_keys_for_event(&event, |index_key| {
                let key = ffi::MDB_val {
                    mv_size: index_key.key.len(),
                    mv_data: index_key.key.as_ptr() as *mut _,
                };
                check_lmdb!(ffi::mdb_del(txn, index_key.db, &key, ptr::null()));
                Ok(())
            })?;

            // delete raw event
            let key = ffi::MDB_val {
                mv_size: id_bytes.len(),
                mv_data: id_bytes.as_ptr() as *mut _,
            };
            check_lmdb!(ffi::mdb_del(txn, self.events_by_id, &key, ptr::null()));
        }

        Ok(())
    }

    fn execute<F>(&self, txn: *mut ffi::MDB_txn, queries: Vec<Query>, mut cb: F) -> Result<()>
    where
        F: FnMut(&ArchivedEvent) -> Result<()>,
    {
        unsafe {
            let mut processed_ids = std::collections::HashSet::new();
            let mut total_count = 0;
            
            for query in queries {
                if total_count >= query.limit {
                    break;
                }
                
                let mut cursor: *mut ffi::MDB_cursor = ptr::null_mut();
                check_lmdb!(ffi::mdb_cursor_open(txn, query.db, &mut cursor));
                
                for sub_query in query.sub_queries {
                    if total_count >= query.limit {
                        break;
                    }
                    
                    // set cursor to starting point
                    let mut key = ffi::MDB_val {
                        mv_size: sub_query.len(),
                        mv_data: sub_query.as_ptr() as *mut _,
                    };
                    let mut data = ffi::MDB_val {
                        mv_size: 0,
                        mv_data: ptr::null_mut(),
                    };
                    
                    // position cursor at or after the key
                    let mut rc = ffi::mdb_cursor_get(cursor, &mut key, &mut data, ffi::MDB_SET_RANGE);
                    
                    while rc == 0 && total_count < query.limit {
                        // check if we've gone past the until timestamp
                        if key.mv_size >= 4 {
                            let key_bytes = slice::from_raw_parts(key.mv_data as *const u8, key.mv_size);
                            let timestamp_bytes = &key_bytes[key_bytes.len() - 4..];
                            if timestamp_bytes > query.until.as_slice() {
                                break;
                            }
                        }
                        
                        // get the event id from the data
                        let id = u64::from_ne_bytes(
                            slice::from_raw_parts(data.mv_data as *const u8, data.mv_size)
                                .try_into()
                                .unwrap_or([0u8; 8]),
                        );
                        
                        // skip if we've already processed this event
                        if processed_ids.contains(&id) {
                            rc = ffi::mdb_cursor_get(cursor, &mut key, &mut data, ffi::MDB_NEXT);
                            continue;
                        }
                        
                        // get the actual event
                        let id_bytes = id.to_ne_bytes();
                        let event_key = ffi::MDB_val {
                            mv_size: id_bytes.len(),
                            mv_data: id_bytes.as_ptr() as *mut _,
                        };
                        let mut event_data = ffi::MDB_val {
                            mv_size: 0,
                            mv_data: ptr::null_mut(),
                        };
                        
                        if ffi::mdb_get(txn, self.events_by_id, &event_key, &mut event_data) == 0 {
                            let raw = slice::from_raw_parts(
                                event_data.mv_data as *const u8,
                                event_data.mv_size,
                            );
                            let event: &ArchivedEvent = rkyv::access_unchecked(raw);
                            
                            // apply extra filters
                            let mut matches = true;
                            
                            if let Some(ref extra_kinds) = query.extra_kinds {
                                if !extra_kinds.iter().any(|k| k.0 == event.kind.0) {
                                    matches = false;
                                }
                            }
                            
                            if matches && query.extra_authors.is_some() {
                                let extra_authors = query.extra_authors.as_ref().unwrap();
                                if !extra_authors.iter().any(|a| a.as_u64_lossy() == event.pubkey.as_u64_lossy()) {
                                    matches = false;
                                }
                            }
                            
                            if matches && query.extra_tag.is_some() {
                                // TODO: implement tag matching
                            }
                            
                            if matches {
                                processed_ids.insert(id);
                                cb(event)?;
                                total_count += 1;
                            }
                        }
                        
                        rc = ffi::mdb_cursor_get(cursor, &mut key, &mut data, ffi::MDB_NEXT);
                    }
                }
                
                ffi::mdb_cursor_close(cursor);
            }
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
                db: self.index_pubkey,
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
                db: self.index_kind,
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
            let mut key = [0u8; 2 + 4];
            key[0..2].copy_from_slice(&event.kind.0.to_ne_bytes());
            key[2..].copy_from_slice(ts_bytes);
            cb(IndexKey {
                db: self.index_kind,
                key: &key,
            })?;
        }

        // by pubkey + date
        {
            let mut key = [0u8; 8 + 4];
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

                    let mut key = vec![0u8; 8 + 4 + 4];
                        let mut key = vec![0u8; 8 + 4];
                        let mut key = vec![0u8; 4 + 4];
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
        unsafe {
            let mut txn: *mut ffi::MDB_txn = ptr::null_mut();
            check_lmdb!(ffi::mdb_txn_begin(self.env, ptr::null_mut(), 0, &mut txn));

            // check if we already have this id
            let id_bytes = event.id.as_u64_lossy().to_ne_bytes();
            let key = ffi::MDB_val {
                mv_size: id_bytes.len(),
                mv_data: id_bytes.as_ptr() as *mut _,
            };
            let mut data = ffi::MDB_val {
                mv_size: 0,
                mv_data: ptr::null_mut(),
            };

            if ffi::mdb_get(txn, self.events_by_id, &key, &mut data) == 0 {
                ffi::mdb_txn_abort(txn);
                return Err(DatabaseError::DuplicateEvent);
            }

            self.save_internal(txn, event)?;
            check_lmdb!(ffi::mdb_txn_commit(txn));
        }

        Ok(())
    }

    fn replace_event(&self, event: &Event, with_address: bool) -> Result<()> {
        unsafe {
            let mut wtxn: *mut ffi::MDB_txn = ptr::null_mut();
            check_lmdb!(ffi::mdb_txn_begin(self.env, ptr::null_mut(), 0, &mut wtxn));

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
            let mut rtxn: *mut ffi::MDB_txn = ptr::null_mut();
            check_lmdb!(ffi::mdb_txn_begin(
                self.env,
                ptr::null_mut(),
                ffi::MDB_RDONLY,
                &mut rtxn
            ));

            let mut queries: Vec<Query> = Vec::with_capacity(1);
            self.plan_query(filter, &mut queries, 1);
            self.execute(rtxn, queries, |existing_event| {
                if existing_event.created_at.0 < event.created_at.0 {
                    self.delete_internal(
                        wtxn,
                        u64::from_ne_bytes(existing_event.id.0[8..16].try_into().unwrap()),
                    )?;
                } else {
                    should_store = false; // newer event already exists
                }

                Ok(())
            })?;

            ffi::mdb_txn_abort(rtxn);

            if should_store {
                self.save_internal(wtxn, event)?;
            }

            check_lmdb!(ffi::mdb_txn_commit(wtxn));
        }
        Ok(())
    }

    fn query_events<F>(&self, filters: Vec<Filter>, max_limit: usize, mut cb: F) -> Result<()>
    where
        F: FnMut(&ArchivedEvent) -> Result<()>,
    {
        unsafe {
            let mut queries: Vec<Query> = Vec::with_capacity(64);

            let mut txn: *mut ffi::MDB_txn = ptr::null_mut();
            check_lmdb!(ffi::mdb_txn_begin(
                self.env,
                ptr::null_mut(),
                ffi::MDB_RDONLY,
                &mut txn
            ));

            for filter in filters {
                if filter.search.is_some() {
                    ffi::mdb_txn_abort(txn);
                    return Err(DatabaseError::InvalidFilter(
                        "search not supported".to_string(),
                    ));
                }

                // id query, just process these ids and move on
                if let Some(ids) = &filter.ids {
                    for id in ids {
                        let id_bytes = id.as_u64_lossy().to_ne_bytes();
                        let key = ffi::MDB_val {
                            mv_size: id_bytes.len(),
                            mv_data: id_bytes.as_ptr() as *mut _,
                        };
                        let mut data = ffi::MDB_val {
                            mv_size: 0,
                            mv_data: ptr::null_mut(),
                        };

                        if ffi::mdb_get(txn, self.events_by_id, &key, &mut data) == 0 {
                            let raw =
                                slice::from_raw_parts(data.mv_data as *const u8, data.mv_size);
                            let event = rkyv::access_unchecked::<ArchivedEvent>(raw);
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
                self.execute(txn, queries, |event| {
                    cb(event)?;
                    Ok(())
                })?;
            }

            ffi::mdb_txn_abort(txn);
        }
        Ok(())
    }

    fn delete_event(&self, id: &ID) -> Result<()> {
        unsafe {
            let mut txn: *mut ffi::MDB_txn = ptr::null_mut();
            check_lmdb!(ffi::mdb_txn_begin(self.env, ptr::null_mut(), 0, &mut txn));
            self.delete_internal(txn, id.as_u64_lossy())?;
            check_lmdb!(ffi::mdb_txn_commit(txn));
        }
        Ok(())
    }
}

// helper function to open a database
fn open_db(txn: *mut ffi::MDB_txn, name: &str) -> Result<ffi::MDB_dbi> {
    unsafe {
        let mut dbi: ffi::MDB_dbi = 0;
        let c_name = CString::new(name).unwrap();
        check_lmdb!(ffi::mdb_dbi_open(txn, c_name.as_ptr(), ffi::MDB_CREATE, &mut dbi));
        Ok(dbi)
    }
}

fn lmdb_error(rc: i32) -> String {
    unsafe {
        let err_str = ffi::mdb_strerror(rc);
        if err_str.is_null() {
            format!("Unknown LMDB error: {}", rc)
        } else {
            std::ffi::CStr::from_ptr(err_str)
                .to_string_lossy()
                .to_string()
        }
    }
}

#[derive(Debug)]
struct IndexKey<'a> {
    db: ffi::MDB_dbi,
    key: &'a [u8],
}

#[derive(Debug)]
struct Query {
    db: ffi::MDB_dbi,

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
