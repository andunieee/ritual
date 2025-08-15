use crate::database::{DatabaseError, EventDatabase, Result};
use crate::filter::TagQuery;
use crate::ArchivedID;
use crate::{event::ArchivedEvent, Event, Filter, ID};
use fasthash::MumHasher;
use itertools::iproduct;
use lmdb_master_sys as lmdb;
use rkyv::rancor;
use rkyv::rend::u16_le;
use std::cell::Cell;
use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::rc::Rc;

pub struct LMDBEventDatabase {
    pub path: String,

    env: *mut lmdb::MDB_env,

    // indexes
    events_by_id: lmdb::MDB_dbi,
    index_timestamp: lmdb::MDB_dbi,
    index_kind: lmdb::MDB_dbi,
    index_pubkey: lmdb::MDB_dbi,
    index_pubkey_kind: lmdb::MDB_dbi,
    index_tag: lmdb::MDB_dbi,
    index_ptag_ktag: lmdb::MDB_dbi,
}

impl Drop for LMDBEventDatabase {
    fn drop(&mut self) {
        unsafe {
            if !self.env.is_null() {
                lmdb::mdb_env_close(self.env);
            }
        }
    }
}

impl LMDBEventDatabase {
    /// initialize the database and return a new instance
    pub fn init(path: impl AsRef<Path>) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();

        // create directory if it doesn't exist
        std::fs::create_dir_all(&path_str)?;

        unsafe {
            // create environment
            let mut env: *mut lmdb::MDB_env = core::ptr::null_mut();
            check_lmdb_error(lmdb::mdb_env_create(&mut env))?;

            // set max databases
            check_lmdb_error(lmdb::mdb_env_set_maxdbs(env, 12))?;

            // set max readers
            check_lmdb_error(lmdb::mdb_env_set_maxreaders(env, 1000))?;

            // set map size
            check_lmdb_error(lmdb::mdb_env_set_mapsize(env, 1 << 34))?;

            // open environment
            let c_path = std::ffi::CString::new(path_str.clone()).unwrap();
            check_lmdb_error(lmdb::mdb_env_open(env, c_path.as_ptr(), 0, 0o644))?;

            // create databases
            let mut txn: *mut lmdb::MDB_txn = core::ptr::null_mut();
            check_lmdb_error(lmdb::mdb_txn_begin(env, core::ptr::null_mut(), 0, &mut txn))?;

            let events_by_id = open_db(txn, "events", lmdb::MDB_INTEGERKEY)?;
            let index_timestamp =
                open_db(txn, "timestamp", lmdb::MDB_DUPSORT | lmdb::MDB_DUPFIXED)?;
            let index_kind = open_db(txn, "kind", lmdb::MDB_DUPSORT | lmdb::MDB_DUPFIXED)?;
            let index_pubkey = open_db(txn, "pubkey", lmdb::MDB_DUPSORT | lmdb::MDB_DUPFIXED)?;
            let index_pubkey_kind =
                open_db(txn, "pubkey_kind", lmdb::MDB_DUPSORT | lmdb::MDB_DUPFIXED)?;
            let index_tag = open_db(txn, "tag", lmdb::MDB_DUPSORT | lmdb::MDB_DUPFIXED)?;
            let index_ptag_ktag =
                open_db(txn, "ptag_ktag", lmdb::MDB_DUPSORT | lmdb::MDB_DUPFIXED)?;

            lmdb::mdb_set_compare(txn, index_timestamp, Some(strfry_uint32_comparator));
            lmdb::mdb_set_compare(txn, index_kind, Some(strfry_uint32_comparator));
            lmdb::mdb_set_compare(txn, index_pubkey, Some(strfry_uint32_comparator));
            lmdb::mdb_set_compare(txn, index_pubkey_kind, Some(strfry_uint32_comparator));
            lmdb::mdb_set_compare(txn, index_tag, Some(strfry_uint32_comparator));
            lmdb::mdb_set_compare(txn, index_ptag_ktag, Some(strfry_uint32_comparator));

            check_lmdb_error(lmdb::mdb_txn_commit(txn))?;

            Ok(Self {
                path: path_str,
                env,
                events_by_id,
                index_timestamp,
                index_kind,
                index_pubkey,
                index_pubkey_kind,
                index_tag,
                index_ptag_ktag,
            })
        }
    }

    fn save_internal(&self, txn: *mut lmdb::MDB_txn, event: &Event) -> Result<()> {
        unsafe {
            let event_data = rkyv::to_bytes::<rancor::Error>(event)?;
            let id_u64 = event.id.as_u64_lossy();
            let id_bytes = id_u64.to_ne_bytes();

            // save raw event
            let mut key = lmdb::MDB_val {
                mv_size: id_bytes.len(),
                mv_data: id_bytes.as_ptr() as *mut _,
            };
            let mut data = lmdb::MDB_val {
                mv_size: event_data.len(),
                mv_data: event_data.as_ptr() as *mut _,
            };
            check_lmdb_error(lmdb::mdb_put(
                txn,
                self.events_by_id,
                &mut key as *mut lmdb::MDB_val,
                &mut data as *mut lmdb::MDB_val,
                0,
            ))?;

            // save indexes
            self.get_index_keys_for_event(
                &rkyv::from_bytes_unchecked::<Event, rancor::Error>(&event_data)?,
                |index_key| {
                    let mut key = lmdb::MDB_val {
                        mv_size: index_key.key.len(),
                        mv_data: index_key.key.as_ptr() as *mut _,
                    };
                    let mut data = lmdb::MDB_val {
                        mv_size: id_bytes.len(),
                        mv_data: id_bytes.as_ptr() as *mut _,
                    };

                    check_lmdb_error(lmdb::mdb_put(
                        txn,
                        index_key.db,
                        &mut key as *mut lmdb::MDB_val,
                        &mut data as *mut lmdb::MDB_val,
                        0,
                    ))?;
                    Ok(())
                },
            )?;
        }

        Ok(())
    }

    /// internal delete function
    fn delete_internal(&self, txn: *mut lmdb::MDB_txn, id: u64) -> Result<()> {
        unsafe {
            let id_bytes = id.to_ne_bytes();
            let mut key = lmdb::MDB_val {
                mv_size: id_bytes.len(),
                mv_data: id_bytes.as_ptr() as *mut _,
            };

            // get the event data to compute indexes
            let mut data = lmdb::MDB_val {
                mv_size: 0,
                mv_data: core::ptr::null_mut(),
            };
            let rc = lmdb::mdb_get(
                txn,
                self.events_by_id,
                &mut key as *mut lmdb::MDB_val,
                &mut data as *mut lmdb::MDB_val,
            );
            if rc == lmdb::MDB_NOTFOUND {
                return Err(DatabaseError::EventNotFound);
            }
            check_lmdb_error(rc)?;

            let raw = std::slice::from_raw_parts(data.mv_data as *const u8, data.mv_size);
            let event = rkyv::from_bytes_unchecked::<Event, rancor::Error>(raw)?;

            // delete all indexes
            self.get_index_keys_for_event(&event, |index_key| {
                let mut key = lmdb::MDB_val {
                    mv_size: index_key.key.len(),
                    mv_data: index_key.key.as_ptr() as *mut _,
                };
                check_lmdb_error(lmdb::mdb_del(
                    txn,
                    index_key.db,
                    &mut key as *mut lmdb::MDB_val,
                    core::ptr::null_mut(),
                ))?;
                Ok(())
            })?;

            // delete raw event
            let mut key = lmdb::MDB_val {
                mv_size: id_bytes.len(),
                mv_data: id_bytes.as_ptr() as *mut _,
            };
            check_lmdb_error(lmdb::mdb_del(
                txn,
                self.events_by_id,
                &mut key as *mut lmdb::MDB_val,
                core::ptr::null_mut(),
            ))?;
        }

        Ok(())
    }

    fn execute<F>(&self, rtxn: *mut lmdb::MDB_txn, queries: Vec<Query>, mut cb: F) -> Result<()>
    where
        F: FnMut(&ArchivedEvent) -> Result<()>,
    {
        unsafe {
            let mut cursors: Vec<Cursor> =
                Vec::with_capacity(queries.iter().fold(0, |acc, q| acc + q.sub_queries.len()));

            for query in queries {
                let rc_query = Rc::new(query);

                for (i, sub_query) in rc_query.sub_queries.iter().enumerate() {
                    let prefix = &sub_query[0..sub_query.len() - 4];

                    let mut cursor: *mut lmdb::MDB_cursor = core::ptr::null_mut();
                    check_lmdb_error(lmdb::mdb_cursor_open(rtxn, rc_query.db, &mut cursor))?;

                    // set cursor to starting point
                    let mut key = lmdb::MDB_val {
                        mv_size: sub_query.len(),
                        mv_data: sub_query.as_ptr() as *mut _,
                    };
                    let mut val = lmdb::MDB_val {
                        mv_size: 0,
                        mv_data: core::ptr::null_mut(),
                    };

                    // position cursor at or after the key
                    let o = lmdb::mdb_cursor_get(cursor, &mut key, &mut val, lmdb::MDB_SET_RANGE);

                    // if it went after, go back one
                    if o == lmdb::MDB_NOTFOUND
                        || !std::slice::from_raw_parts(key.mv_data as *const u8, key.mv_size)
                            .starts_with(prefix)
                    {
                        let o = lmdb::mdb_cursor_get(cursor, &mut key, &mut val, lmdb::MDB_PREV);
                        if o == lmdb::MDB_NOTFOUND {
                            // it's ok, just skip this cursor
                            continue;
                        } else {
                            check_lmdb_error(o)?;
                        }
                    }

                    // use this cursor
                    let mut c = Cursor {
                        i,

                        cursor,
                        query: rc_query.clone(),
                        last_read_timestamp: None,

                        pulled: VecDeque::with_capacity(64),

                        last_key: key,
                        last_val: val,

                        done: false,
                    };

                    // in the beginning, pull 16 entries from each cursor
                    c.fetch();

                    cursors.push(c);
                }
            }

            let mut collected_events: Vec<(&ArchivedEvent, Rc<Cell<usize>>)> =
                Vec::with_capacity(64);
            let mut last_sent: Option<(&ArchivedID, Rc<Cell<usize>>)> = None;

            while cursors.len() > 0 {
                collected_events.truncate(0);

                // sort such that the cursors will be the ones we'll read from as they're the less advanced
                glidesort::sort_in_vec_by_key(&mut cursors, |c| c.last_read_timestamp);

                // and any entry already pulled that has a timestamp higher than this can al ready be collected
                // (if there is no cutpoint that means we have no results to collect and our query will be ended)
                if let Some(Some(cutpoint)) = cursors.last().map(|c| c.last_read_timestamp) {
                    // reading from db and collecting events
                    for c in &mut cursors {
                        for _ in 0..c.pulled.len() {
                            if c.query.total_sent.get() >= c.query.limit {
                                c.done = true;
                                break;
                            }

                            // we'll always be collecting from the front of the vec
                            if c.pulled[0].0 < cutpoint {
                                // from this point on we stop collecting
                                break;
                            }

                            // otherwise we're still good, collect this
                            // (and some lines below we'll swap remove this index)
                            let id_bytes = c.pulled[0].1.to_ne_bytes();
                            let mut event_key = lmdb::MDB_val {
                                mv_size: id_bytes.len(),
                                mv_data: id_bytes.as_ptr() as *mut _,
                            };
                            let mut event_data = lmdb::MDB_val {
                                mv_size: 0,
                                mv_data: core::ptr::null_mut(),
                            };
                            check_lmdb_error(lmdb::mdb_get(
                                rtxn,
                                self.events_by_id,
                                &mut event_key as *mut lmdb::MDB_val,
                                &mut event_data as *mut lmdb::MDB_val,
                            ))?;
                            let raw = std::slice::from_raw_parts(
                                event_data.mv_data as *const u8,
                                event_data.mv_size,
                            );
                            let event: &ArchivedEvent = rkyv::access_unchecked(raw);

                            // remove this from pulled list as it has been collected
                            c.pulled.pop_front();

                            // check if this event passes the other filters before actually sending it
                            if let Some(extra_kinds) = &c.query.extra_kinds {
                                if !extra_kinds.contains(&event.kind.0) {
                                    continue;
                                };
                            }
                            if let Some(extra_authors) = &c.query.extra_authors {
                                if !extra_authors.contains(&event.pubkey.0) {
                                    continue;
                                };
                            }

                            let mut tags_ok = false;
                            if let Some(extra_tag) = &c.query.extra_tag {
                                let tags = &event.tags.0;
                                for tag in tags.iter() {
                                    if tag.len() >= 2 && tag[0] == extra_tag.key() {
                                        if extra_tag.values().contains(&tag[1].to_string()) {
                                            tags_ok = true;
                                        }
                                    }
                                }
                            } else {
                                tags_ok = true;
                            }
                            if !tags_ok {
                                continue;
                            }

                            // this event is ok
                            collected_events.push((event, c.query.total_sent.clone()));
                            c.query.total_sent.update(|u| u + 1);
                        }
                    }
                }

                // after deciding what events are going to the client we send them
                collected_events.sort_by_key(|(event, _)| event.created_at.0);

                // dispatch to caller, filtering out duplicates
                for (event, query_total_sent) in collected_events.iter().rev() {
                    if let Some((last_id, last_query_ref)) =
                        last_sent.replace((&event.id, query_total_sent.clone()))
                    {
                        if last_id == &event.id {
                            if last_query_ref == *query_total_sent {
                                query_total_sent.update(|u| u - 1);
                            }
                            continue;
                        }
                    }
                    cb(event)?;
                }

                // cleanup cursors that have ended
                let mut i = 0;
                for _ in 0..cursors.len() {
                    if cursors[i].done {
                        cursors.swap_remove(i);
                        continue;
                    }
                    i += 1;
                }

                // pull 16 entries from each of the top 4 cursors (as defined from the previous sort call)
                let max_len = cursors.len().max(4);
                for c in &mut cursors[max_len - 4..] {
                    c.fetch();
                }
            }

            Ok(())
        }
    }

    fn plan_query(&self, filter: Filter, queries: &mut Vec<Query>, max_limit: usize) {
        let start_ts = filter
            .until
            .map(|ts| ts.0)
            .unwrap_or(u32::MAX)
            .to_ne_bytes();
        let end_ts = filter.since.map(|ts| ts.0).unwrap_or(0);
        let mut extra_tag: Option<TagQuery> = None;
        let mut second_best: Option<TagQuery> = None;

        if let Some(mut tags) = filter.tags {
            tags.sort_unstable_by_key(|tagq| tagq.worth());
            tags.reverse();

            let tagq = tags
                .get(0)
                .expect("there must always be at least one tag if tags is present");

            if tagq.worth() > 5 {
                // use tag query as the main index
                queries.push(Query {
                    db: self.index_tag,
                    sub_queries: tagq.to_sub_queries(&start_ts),
                    end_ts,
                    limit: max_limit,
                    total_sent: Rc::new(Cell::new(0)),
                    extra_tag: tags.get(1).cloned(), // get the second tag if it exists as secondary filter
                    extra_kinds: filter
                        .kinds
                        .map(|kinds| kinds.iter().map(|kind| u16_le::from(kind.0)).collect()),
                    extra_authors: filter
                        .authors
                        .map(|authors| authors.iter().map(|author| author.0).collect()),
                });

                return;
            }

            // if there is a "K" and a "p"/"P" use that special index
            let mut k_values = Vec::new();
            let mut p_values = Vec::new();
            for tag in &tags {
                if tag.key() == "p" || tag.key() == "P" {
                    p_values.extend(tag.values());
                } else if tag.key() == "K" {
                    k_values.extend(tag.values());
                }
            }

            let mut sub_queries = Vec::with_capacity(p_values.len() * k_values.len());
            for (k_value, p_value) in iproduct!(k_values, p_values) {
                let mut key = Vec::from([0u8; 8 + 2 + 4]);
                key[8 + 2..].copy_from_slice(&start_ts);

                if let Ok(k) = k_value.parse::<u16>() {
                    key[8..8 + 2].copy_from_slice(&k.to_ne_bytes());

                    if p_value.len() == 64
                        && lowercase_hex::decode_to_slice(
                            &p_value[8 * 2..8 * 2 + 8 * 2],
                            &mut key[0..8],
                        )
                        .is_ok()
                    {
                        sub_queries.push(key);
                    }
                }
            }

            if sub_queries.len() > 0 {
                // use the best tag that isn't "p"/"P" or "k" as the extra filterer
                let best_possible_tag = tags
                    .iter()
                    .find(|tag| tag.key() != "p" && tag.key() != "P" && tag.key() != "K");

                queries.push(Query {
                    db: self.index_ptag_ktag,
                    sub_queries,
                    end_ts,
                    limit: max_limit,
                    total_sent: Rc::new(Cell::new(0)),
                    extra_tag: best_possible_tag.cloned(),
                    extra_kinds: filter
                        .kinds
                        .map(|kinds| kinds.iter().map(|kind| u16_le::from(kind.0)).collect()),
                    extra_authors: filter
                        .authors
                        .map(|authors| authors.iter().map(|author| author.0).collect()),
                });
                return;
            }

            // otherwise don't use a tag-based index
            if let Some(best_tag) = tags.get(0) {
                // only use the first tag as the extra tag filter
                extra_tag = Some(best_tag.clone());

                // also keep the second best tag so we can use it maybe eventually
                second_best = tags.get(1).map(|tagq| tagq.clone());
            }
        }

        if let (Some(authors), Some(kinds)) = (&filter.authors, &filter.kinds) {
            // kinds and authors
            // use pubkey-kind as the main index
            let mut sub_queries = Vec::with_capacity(authors.len() * kinds.len());

            for author in authors {
                for kind in kinds {
                    let mut key = Vec::from([0u8; 8 + 2 + 4]);
                    key[8 + 2..].copy_from_slice(&start_ts);

                    key[0..8].copy_from_slice(&author.as_u64_lossy().to_ne_bytes());
                    key[8..8 + 2].copy_from_slice(&kind.0.to_ne_bytes());
                    sub_queries.push(key);
                }
            }

            queries.push(Query {
                db: self.index_pubkey_kind,
                sub_queries,
                end_ts,
                limit: max_limit,
                total_sent: Rc::new(Cell::new(0)),
                extra_tag,
                extra_kinds: None,
                extra_authors: None,
            });

            return;
        }

        if let Some(authors) = filter.authors {
            // just authors
            queries.push(Query {
                db: self.index_pubkey,
                sub_queries: authors
                    .iter()
                    .map(|a| {
                        let mut key = Vec::from([0u8; 8 + 4]);
                        key[8..].copy_from_slice(&start_ts);
                        key[0..8].copy_from_slice(&a.as_u64_lossy().to_ne_bytes());
                        key
                    })
                    .collect(),
                end_ts,
                limit: max_limit,
                total_sent: Rc::new(Cell::new(0)),
                extra_tag,
                extra_kinds: None,
                extra_authors: None,
            });

            return;
        }

        if let Some(kinds) = filter.kinds {
            // just kinds
            queries.push(Query {
                db: self.index_kind,
                sub_queries: kinds
                    .iter()
                    .map(|k| {
                        let mut key = Vec::from([0u8; 2 + 4]);
                        key[2..].copy_from_slice(&start_ts);
                        key[0..2].copy_from_slice(&k.0.to_ne_bytes());
                        key
                    })
                    .collect(),
                end_ts,
                limit: max_limit,
                total_sent: Rc::new(Cell::new(0)),
                extra_tag,
                extra_kinds: None,
                extra_authors: None,
            });

            return;
        }

        // if we got here and we have an extra_tag, let's use that as our main query
        // as it's better than nothing
        if let Some(best_tagq) = &extra_tag {
            queries.push(Query {
                db: self.index_tag,
                sub_queries: best_tagq.to_sub_queries(&start_ts),
                end_ts,
                limit: max_limit,
                total_sent: Rc::new(Cell::new(0)),
                extra_tag: second_best,
                extra_kinds: None,
                extra_authors: None,
            });

            return;
        }

        // no filters, use just the created_at index
        queries.push(Query {
            db: self.index_timestamp,
            sub_queries: vec![start_ts.into()],
            end_ts,
            limit: max_limit,
            total_sent: Rc::new(Cell::new(0)),
            extra_tag: None,
            extra_kinds: None,
            extra_authors: None,
        });
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
                db: self.index_timestamp,
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
        let mut tag_key: Option<[u8; 1 + 8 + 4]> = None;
        for tag in &event.tags.0 {
            if tag.len() < 2 || tag[0].len() != 1 {
                continue;
            }

            let key = tag_key.get_or_insert_with(|| {
                let mut key = [0u8; 1 + 8 + 4];
                key[1 + 8..].copy_from_slice(ts_bytes);
                key
            });
            key[0] = tag[0].as_bytes()[0];

            if tag[1].len() == 64 {
                if lowercase_hex::decode_to_slice(&tag[1][8 * 2..8 * 2 + 8 * 2], &mut key[1..1 + 8])
                    .is_ok()
                {
                    cb(IndexKey {
                        db: self.index_tag,
                        key: key,
                    })?;
                    continue;
                }
            }

            let mut s: MumHasher = Default::default();
            tag[1].hash(&mut s);
            let hash = s.finish();
            key[1..1 + 8].copy_from_slice(hash.to_ne_bytes().as_slice());

            cb(IndexKey {
                db: self.index_tag,
                key: key,
            })?;
        }

        // by p-tag + k-tag (includes all variantions possible)
        let mut kp_key: Option<[u8; 8 + 2 + 4]> = None;
        for (k_tagname, p_tagname) in vec![("K", "p"), ("K", "P")] {
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

impl EventDatabase for LMDBEventDatabase {
    fn save_event(&self, event: &Event) -> Result<()> {
        unsafe {
            let mut txn: *mut lmdb::MDB_txn = core::ptr::null_mut();
            check_lmdb_error(lmdb::mdb_txn_begin(
                self.env,
                core::ptr::null_mut(),
                0,
                &mut txn,
            ))?;

            // check if we already have this id
            let id_bytes = event.id.as_u64_lossy().to_ne_bytes();
            let mut key = lmdb::MDB_val {
                mv_size: id_bytes.len(),
                mv_data: id_bytes.as_ptr() as *mut _,
            };
            let mut data = lmdb::MDB_val {
                mv_size: 0,
                mv_data: core::ptr::null_mut(),
            };

            if lmdb::mdb_get(
                txn,
                self.events_by_id,
                &mut key as *mut lmdb::MDB_val,
                &mut data as *mut lmdb::MDB_val,
            ) == 0
            {
                lmdb::mdb_txn_abort(txn);
                return Err(DatabaseError::DuplicateEvent);
            }

            self.save_internal(txn, event)?;
            check_lmdb_error(lmdb::mdb_txn_commit(txn))?;
        }

        Ok(())
    }

    fn replace_event(&self, event: &Event, with_address: bool) -> Result<()> {
        unsafe {
            let mut wtxn: *mut lmdb::MDB_txn = core::ptr::null_mut();
            check_lmdb_error(lmdb::mdb_txn_begin(
                self.env,
                core::ptr::null_mut(),
                0,
                &mut wtxn,
            ))?;

            // create filter to find existing events
            let mut filter = Filter::default();
            filter.kinds = Some(vec![event.kind]);
            filter.authors = Some(vec![event.pubkey]);
            filter.limit = Some(10);

            if with_address {
                filter.tags = Some(vec![TagQuery("d".to_string(), vec![event.tags.get_d()])]);
            }

            let mut should_store = true;

            // find and delete older events
            let mut queries: Vec<Query> = Vec::with_capacity(1);
            self.plan_query(filter, &mut queries, 1);
            self.execute(wtxn, queries, |existing_event| {
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

            if should_store {
                self.save_internal(wtxn, event)?;
            }

            check_lmdb_error(lmdb::mdb_txn_commit(wtxn))?;
        }
        Ok(())
    }

    fn query_events<F>(&self, filters: Vec<Filter>, max_limit: usize, mut cb: F) -> Result<()>
    where
        F: FnMut(&ArchivedEvent) -> Result<()>,
    {
        unsafe {
            let mut queries: Vec<Query> = Vec::with_capacity(64);

            let mut txn: *mut lmdb::MDB_txn = core::ptr::null_mut();
            check_lmdb_error(lmdb::mdb_txn_begin(
                self.env,
                core::ptr::null_mut(),
                lmdb::MDB_RDONLY,
                &mut txn,
            ))?;

            for filter in filters {
                if filter.search.is_some() {
                    lmdb::mdb_txn_abort(txn);
                    return Err(DatabaseError::InvalidFilter(
                        "search not supported".to_string(),
                    ));
                }

                // id query, just process these ids and move on
                if let Some(ids) = &filter.ids {
                    for id in ids {
                        let id_bytes = id.as_u64_lossy().to_ne_bytes();
                        let mut key = lmdb::MDB_val {
                            mv_size: id_bytes.len(),
                            mv_data: id_bytes.as_ptr() as *mut _,
                        };
                        let mut data = lmdb::MDB_val {
                            mv_size: 0,
                            mv_data: core::ptr::null_mut(),
                        };

                        if lmdb::mdb_get(
                            txn,
                            self.events_by_id,
                            &mut key as *mut lmdb::MDB_val,
                            &mut data as *mut lmdb::MDB_val,
                        ) == 0
                        {
                            let raw =
                                std::slice::from_raw_parts(data.mv_data as *const u8, data.mv_size);
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

            lmdb::mdb_txn_abort(txn);
        }
        Ok(())
    }

    fn delete_event(&self, id: &ID) -> Result<()> {
        unsafe {
            let mut txn: *mut lmdb::MDB_txn = core::ptr::null_mut();
            check_lmdb_error(lmdb::mdb_txn_begin(
                self.env,
                core::ptr::null_mut(),
                0,
                &mut txn,
            ))?;
            self.delete_internal(txn, id.as_u64_lossy())?;
            check_lmdb_error(lmdb::mdb_txn_commit(txn))?;
        }
        Ok(())
    }
}

// helper function to open a database
fn open_db(txn: *mut lmdb::MDB_txn, name: &str, flags: u32) -> Result<lmdb::MDB_dbi> {
    unsafe {
        let mut dbi: lmdb::MDB_dbi = 0;
        let c_name = std::ffi::CString::new(name).unwrap();
        check_lmdb_error(lmdb::mdb_dbi_open(
            txn,
            c_name.as_ptr(),
            lmdb::MDB_CREATE | flags,
            &mut dbi,
        ))?;
        Ok(dbi)
    }
}

#[derive(Debug)]
struct IndexKey<'a> {
    db: lmdb::MDB_dbi,
    key: &'a [u8],
}

#[derive(Debug)]
struct Query {
    db: lmdb::MDB_dbi,

    // this is the main index we'll use, the values are the starting points
    // the prefix should be just the initial bytes (anything besides the last 4 bytes)
    sub_queries: Vec<Vec<u8>>,

    // we'll scan each index up to this point (the last 4 bytes)
    end_ts: u32,

    // max number of results we'll return from this
    limit: usize,
    total_sent: Rc<Cell<usize>>, // total sent for this query, shared among all sub_queries

    // these extra values will be matched against after we've read an event from the database
    extra_tag: Option<TagQuery>,
    extra_kinds: Option<Vec<u16_le>>,
    extra_authors: Option<Vec<[u8; 32]>>,
}

#[derive(Debug)]
struct Cursor {
    // this index in the sub_queries list
    i: usize,

    cursor: *mut lmdb::MDB_cursor,
    query: Rc<Query>,
    last_read_timestamp: Option<u32>,

    // timestamps and ids we've pulled that were not yet collected
    pulled: VecDeque<(u32, u64)>,

    // last key-val we fetched (also the one with the lowest timestamp)
    last_key: lmdb::MDB_val,
    last_val: lmdb::MDB_val,

    // if this is true we won't read anymore and this cursor will be soon removed from the list
    done: bool,
}

impl Cursor {
    fn fetch(&mut self) {
        unsafe {
            for _ in 0..16 {
                // check if we've run out of things to read in this cursor
                let key = std::slice::from_raw_parts(
                    self.last_key.mv_data as *const u8,
                    self.last_key.mv_size,
                );

                let starting_key = &self.query.sub_queries[self.i];
                let prefix = &starting_key[0..starting_key.len() - 4];
                if !key.starts_with(prefix) {
                    // this cursor has ended
                    self.done = true;
                    break;
                }

                let timestamp = u32::from_ne_bytes(key[key.len() - 4..].try_into().unwrap());
                if self.last_key.mv_size == 0 || timestamp < self.query.end_ts {
                    // this cursor has ended
                    self.done = true;
                    break;
                }

                // if it didn't end this was a valid pulled value, add it
                let id_ref = u64::from_ne_bytes(
                    std::slice::from_raw_parts(
                        self.last_val.mv_data as *const u8,
                        self.last_val.mv_size,
                    )
                    .try_into()
                    .expect("value should be 8 bytes"),
                );

                self.pulled.push_back((timestamp, id_ref));

                // update this
                self.last_read_timestamp = Some(timestamp);

                // advance the cursor
                let o = lmdb::mdb_cursor_get(
                    self.cursor,
                    &mut self.last_key as *mut lmdb::MDB_val,
                    &mut self.last_val as *mut lmdb::MDB_val,
                    lmdb::MDB_PREV,
                );
                if o == lmdb::MDB_NOTFOUND {
                    self.done = true;
                    break;
                }
            }
        }
    }
}

fn check_lmdb_error(lmdb_code: std::os::raw::c_int) -> Result<()> {
    unsafe {
        if lmdb_code == 0 {
            Ok(())
        } else {
            let err_cstr = lmdb::mdb_strerror(lmdb_code);
            let err_str = if err_cstr.is_null() {
                format!("Unknown LMDB error: {}", lmdb_code)
            } else {
                std::ffi::CStr::from_ptr(err_cstr)
                    .to_string_lossy()
                    .to_string()
            };
            return Err(DatabaseError::LMDB(err_str));
        }
    }
}

#[no_mangle]
pub extern "C" fn mdb_cmp_memn(
    a: *const lmdb::MDB_val,
    b: *const lmdb::MDB_val,
) -> std::os::raw::c_int {
    if a.is_null() || b.is_null() {
        return 0;
    }

    let a_val = unsafe { &*a };
    let b_val = unsafe { &*b };

    if a_val.mv_data.is_null() || b_val.mv_data.is_null() {
        return 0;
    }

    let len = a_val.mv_size;
    let len_diff = (a_val.mv_size as isize) - (b_val.mv_size as isize);

    let (cmp_len, final_len_diff) = if len_diff > 0 {
        (b_val.mv_size, 1i32)
    } else {
        (len, if len_diff < 0 { -1i32 } else { 0i32 })
    };

    let diff = unsafe {
        let a_slice = std::slice::from_raw_parts(a_val.mv_data as *const u8, cmp_len);
        let b_slice = std::slice::from_raw_parts(b_val.mv_data as *const u8, cmp_len);

        // Compare bytes lexicographically
        match a_slice.cmp(b_slice) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Greater => 1,
            std::cmp::Ordering::Equal => 0,
        }
    };

    if diff != 0 {
        diff
    } else {
        final_len_diff
    }
}

#[no_mangle]
pub extern "C" fn strfry_uint32_comparator(
    a: *const lmdb::MDB_val,
    b: *const lmdb::MDB_val,
) -> std::os::raw::c_int {
    let a_val = unsafe { &*a };
    let b_val = unsafe { &*b };

    // create modified MDB_val structs for string comparison (without the last 4 bytes)
    let a2 = lmdb::MDB_val {
        mv_size: a_val.mv_size - 4,
        mv_data: a_val.mv_data,
    };
    let b2 = lmdb::MDB_val {
        mv_size: b_val.mv_size - 4,
        mv_data: b_val.mv_data,
    };

    // compare the string portions
    let string_compare = mdb_cmp_memn(&a2 as *const lmdb::MDB_val, &b2 as *const lmdb::MDB_val);
    if string_compare != 0 {
        return string_compare;
    }

    // extract and compare the native-encoded uint32 values from the last 4 bytes
    let ai = unsafe {
        let src = (a_val.mv_data as *const u8).add(a_val.mv_size - 4);
        core::ptr::read_unaligned(src as *const u32)
    };

    let bi = unsafe {
        let src = (b_val.mv_data as *const u8).add(b_val.mv_size - 4);
        core::ptr::read_unaligned(src as *const u32)
    };

    if ai < bi {
        -1
    } else if ai > bi {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{event_template::EventTemplate, Filter, Kind, SecretKey, Tags, Timestamp};
    use assertables::{assert_contains, assert_ge, assert_lt};

    #[test]
    fn test_custom_comparator() {
        let temp_dir = std::env::temp_dir().join("lmdb_test_custom_comparator");
        let _ = std::fs::remove_dir_all(&temp_dir);
        let store = LMDBEventDatabase::init(&temp_dir).expect("failed to initialize store");

        // [n, 0, 0, 0]
        for i in 0..256 {
            let event = EventTemplate {
                content: "nothing".to_string(),
                created_at: Timestamp(i),
                ..Default::default()
            }
            .finalize(&SecretKey::generate());
            store.save_event(&event).expect("failed to save event");
        }
        // [n, 0, 0, 1]
        for i in 16777216..16777472 {
            let event = EventTemplate {
                content: "nothing".to_string(),
                created_at: Timestamp(i),
                ..Default::default()
            }
            .finalize(&SecretKey::generate());
            store.save_event(&event).expect("failed to save event");
        }

        {
            let filter = Filter {
                since: Some(50u32.into()),
                until: Some(100u32.into()),
                ..Default::default()
            };
            let mut results: Vec<u32> = Vec::with_capacity(50);
            store
                .query_events(vec![filter], 100, |event| {
                    results.push(event.created_at.0.into());
                    Ok(())
                })
                .expect("failed to query events");

            assert_eq!(results.len(), 51);
        }

        {
            let filter = Filter {
                since: Some(16777266u32.into()),
                until: Some(16777316u32.into()),
                ..Default::default()
            };
            let mut results: Vec<u32> = Vec::with_capacity(50);
            store
                .query_events(vec![filter], 100, |event| {
                    results.push(event.created_at.0.into());
                    Ok(())
                })
                .expect("failed to query events");

            assert_eq!(results.len(), 51);
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_query_empty() {
        let temp_dir = std::env::temp_dir().join("lmdb_test_query_empty");
        let _ = std::fs::remove_dir_all(&temp_dir);
        let store = LMDBEventDatabase::init(&temp_dir).expect("failed to initialize store");

        // query all events (there are none)
        let filter = Filter::default();
        let mut results = 0;
        store
            .query_events(vec![filter], 100, |_| {
                results += 1;
                Ok(())
            })
            .expect("failed to query events");

        assert_eq!(results, 0);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_save_and_query_event() {
        let temp_dir = std::env::temp_dir().join("lmdb_test_save_query");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = LMDBEventDatabase::init(&temp_dir).expect("failed to initialize store");
        let event = EventTemplate {
            content: "nothing".to_string(),
            ..Default::default()
        }
        .finalize(&SecretKey::generate());

        // save the event
        store.save_event(&event).expect("failed to save event");

        // query all events
        let filter = Filter::default();
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

        let store = LMDBEventDatabase::init(&temp_dir).expect("failed to initialize store");
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

        let store = LMDBEventDatabase::init(&temp_dir).expect("failed to initialize store");
        let event = EventTemplate {
            content: "nothing".to_string(),
            ..Default::default()
        }
        .finalize(&SecretKey::generate());

        // save the event
        store.save_event(&event).expect("failed to save event");

        // verify it exists
        let filter = Filter::default();
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
    fn test_replaceable_events() {
        let temp_dir = std::env::temp_dir().join("lmdb_test_replaceable");
        let _ = std::fs::remove_dir_all(&temp_dir);
        let store = LMDBEventDatabase::init(&temp_dir).expect("failed to initialize store");
        let sk = SecretKey::generate();

        // first event
        let event1 = EventTemplate {
            kind: Kind(10001),
            created_at: Timestamp(100),
            tags: vec![vec!["d".to_string(), "test".to_string()]].into(),
            ..Default::default()
        }
        .finalize(&sk);
        store
            .replace_event(&event1, true)
            .expect("failed to replace event 1");

        // check it's there
        let mut results = Vec::new();
        store
            .query_events(vec![Filter::default()], 100, |event| {
                results.push(rkyv::deserialize::<Event, rancor::Error>(event).unwrap());
                Ok(())
            })
            .expect("failed to query events");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, event1.id);

        // second event, newer
        let event2 = EventTemplate {
            kind: Kind(10001),
            created_at: Timestamp(200),
            tags: vec![vec!["d".to_string(), "test".to_string()]].into(),
            ..Default::default()
        }
        .finalize(&sk);
        store
            .replace_event(&event2, true)
            .expect("failed to replace event 2");

        // check that event1 is gone and event2 is there
        results.clear();
        store
            .query_events(vec![Filter::default()], 100, |event| {
                results.push(rkyv::deserialize::<Event, rancor::Error>(event).unwrap());
                Ok(())
            })
            .expect("failed to query events");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, event2.id);

        // third event, older than event2 but newer than event1
        let event3 = EventTemplate {
            kind: Kind(10001),
            created_at: Timestamp(150),
            tags: vec![vec!["d".to_string(), "test".to_string()]].into(),
            ..Default::default()
        }
        .finalize(&sk);
        store
            .replace_event(&event3, true)
            .expect("failed to replace event 3");

        // check that event2 is still there
        results.clear();
        store
            .query_events(vec![Filter::default()], 100, |event| {
                results.push(rkyv::deserialize::<Event, rancor::Error>(event).unwrap());
                Ok(())
            })
            .expect("failed to query events");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, event2.id);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_filter_by_kind() {
        let temp_dir = std::env::temp_dir().join("lmdb_test_filter_kind");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = LMDBEventDatabase::init(&temp_dir).expect("failed to initialize store");

        // save events with different kinds
        for i in 0..3000 {
            let event = EventTemplate {
                content: format!("{}", i),
                created_at: Timestamp(i),
                kind: Kind(i as u16 % 50),
                ..Default::default()
            }
            .finalize(&SecretKey::generate());
            store.save_event(&event).expect("failed to save event");
        }

        let mut filter = Filter::default();
        filter.kinds = Some(vec![Kind(1)]);
        let mut results = Vec::new();
        store
            .query_events(vec![filter], 100, |event| {
                results.push(event.kind.0);
                Ok(())
            })
            .expect("failed to query events");
        assert_eq!(results.len(), 60);
        assert!(results.iter().all(|kind| *kind == 1),);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_filter_by_tag() {
        let temp_dir = std::env::temp_dir().join("lmdb_test_filter_tag");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = LMDBEventDatabase::init(&temp_dir).expect("failed to initialize store");

        // save events with different kinds
        for i in 0..300 {
            let mut templ = EventTemplate {
                content: format!("{}", i),
                created_at: Timestamp(i),
                kind: Kind(1),
                tags: Tags(vec![]),
                ..Default::default()
            };
            if i % 2 == 0 {
                templ.tags.0.push(vec!["t".to_string(), "foo".to_string()]);
            }
            if i % 3 == 0 {
                templ.tags.0.push(vec!["h".to_string(), "bar".to_string()]);
            }

            let event = templ.finalize(&SecretKey::generate());
            store.save_event(&event).expect("failed to save event");
        }

        // one
        {
            let mut results = 0;
            store
                .query_events(
                    vec![Filter {
                        tags: Some(vec![TagQuery("h".to_string(), vec!["bar".to_string()])]),
                        ..Default::default()
                    }],
                    500,
                    |event| {
                        assert_contains!(
                            event
                                .tags
                                .0
                                .iter()
                                .map(|tag| tag[1].to_string())
                                .collect::<Vec<String>>(),
                            &"bar".to_string()
                        );
                        results += 1;
                        Ok(())
                    },
                )
                .expect("failed to query events");
            assert_eq!(results, 100);
        }

        // the other
        {
            let mut results = 0;
            store
                .query_events(
                    vec![Filter {
                        tags: Some(vec![TagQuery("t".to_string(), vec!["foo".to_string()])]),
                        ..Default::default()
                    }],
                    500,
                    |event| {
                        assert_contains!(
                            event
                                .tags
                                .0
                                .iter()
                                .map(|tag| tag[1].to_string())
                                .collect::<Vec<String>>(),
                            &"foo".to_string()
                        );
                        results += 1;
                        Ok(())
                    },
                )
                .expect("failed to query events");
            assert_eq!(results, 150);
        }

        // the intersection
        {
            let mut results = 0;
            store
                .query_events(
                    vec![Filter {
                        tags: Some(vec![
                            TagQuery("t".to_string(), vec!["foo".to_string()]),
                            TagQuery("h".to_string(), vec!["bar".to_string()]),
                        ]),
                        ..Default::default()
                    }],
                    500,
                    |event| {
                        assert_contains!(
                            event
                                .tags
                                .0
                                .iter()
                                .map(|tag| tag[1].to_string())
                                .collect::<Vec<String>>(),
                            &"foo".to_string()
                        );
                        assert_contains!(
                            event
                                .tags
                                .0
                                .iter()
                                .map(|tag| tag[1].to_string())
                                .collect::<Vec<String>>(),
                            &"bar".to_string()
                        );
                        results += 1;
                        Ok(())
                    },
                )
                .expect("failed to query events");
            assert_eq!(results, 50);
        }

        // the union
        {
            let mut results = 0;
            store
                .query_events(
                    vec![
                        Filter {
                            tags: Some(vec![TagQuery("t".to_string(), vec!["foo".to_string()])]),
                            ..Default::default()
                        },
                        Filter {
                            tags: Some(vec![TagQuery("h".to_string(), vec!["bar".to_string()])]),
                            ..Default::default()
                        },
                    ],
                    500,
                    |event| {
                        assert!(
                            event
                                .tags
                                .0
                                .iter()
                                .map(|tag| tag[1].to_string())
                                .collect::<Vec<String>>()
                                .contains(&"foo".to_string())
                                || event
                                    .tags
                                    .0
                                    .iter()
                                    .map(|tag| tag[1].to_string())
                                    .collect::<Vec<String>>()
                                    .contains(&"bar".to_string())
                        );
                        results += 1;
                        Ok(())
                    },
                )
                .expect("failed to query events");
            assert_eq!(results, 187);
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_slightly_complex_query() {
        let temp_dir = std::env::temp_dir().join("lmdb_test_slightly_complex_query");
        let _ = std::fs::remove_dir_all(&temp_dir);
        let store = LMDBEventDatabase::init(&temp_dir).expect("failed to initialize store");

        // save 100 events
        for i in 0..100 {
            let mut tags = Vec::new();
            if i % 3 == 0 {
                tags.push(vec!["t".to_string(), "a".to_string()]);
            }
            if i % 4 == 0 {
                tags.push(vec!["t".to_string(), "b".to_string()]);
            }

            let event = EventTemplate {
                content: format!("{}", i),
                created_at: Timestamp(i),
                kind: Kind(1),
                tags: tags.into(),
                ..Default::default()
            }
            .finalize(&SecretKey::generate());

            store.save_event(&event).expect("failed to save event");
        }

        {
            let filters = vec![Filter {
                tags: Some(vec![TagQuery(
                    "t".to_string(),
                    vec!["a".to_string(), "b".to_string()],
                )]),
                limit: Some(20),
                ..Default::default()
            }];

            let mut total = 0;
            store
                .query_events(filters, 1000, |_| {
                    total += 1;
                    Ok(())
                })
                .expect("failed to query events");

            assert_eq!(total, 20);
        }

        {
            let filters = vec![
                Filter {
                    tags: Some(vec![TagQuery("t".to_string(), vec!["a".to_string()])]),
                    limit: Some(30),
                    ..Default::default()
                },
                Filter {
                    tags: Some(vec![TagQuery("t".to_string(), vec!["b".to_string()])]),
                    limit: Some(40),
                    ..Default::default()
                },
            ];

            let mut total = 0;
            store
                .query_events(filters, 1000, |_| {
                    total += 1;
                    Ok(())
                })
                .expect("failed to query events");

            assert_eq!(total, 45);
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_complex_query() {
        let temp_dir = std::env::temp_dir().join("lmdb_test_complex_query");
        let _ = std::fs::remove_dir_all(&temp_dir);
        let store = LMDBEventDatabase::init(&temp_dir).expect("failed to initialize store");

        let sk1 = SecretKey::generate();
        let pk1 = sk1.pubkey();
        let sk2 = SecretKey::generate();
        let pk2 = sk2.pubkey();
        let sk3 = SecretKey::generate();

        // save 5000 events
        for i in 0..5000 {
            let sk = if i % 3 == 0 {
                &sk1
            } else if i % 3 == 1 {
                &sk2
            } else {
                &sk3
            };

            let mut tags = Vec::new();
            if i % 9 == 0 {
                tags.push(vec!["t".to_string(), "hello".to_string()]);
            }
            if i % 10 == 0 {
                tags.push(vec!["t".to_string(), "world".to_string()]);
            }
            if i % 25 == 0 {
                tags.push(vec!["K".to_string(), "1".to_string()]);
                tags.push(vec!["P".to_string(), pk2.to_hex()]);
            }

            let event = EventTemplate {
                content: format!("{}", i),
                created_at: Timestamp(i),
                kind: Kind(i as u16 % 50),
                tags: tags.into(),
                ..Default::default()
            }
            .finalize(sk);
            store.save_event(&event).expect("failed to save event");
        }

        let filters = vec![
            Filter {
                limit: Some(3),
                kinds: Some(vec![Kind(1)]),
                authors: Some(vec![pk1, pk2]),
                ..Default::default()
            },
            Filter {
                limit: Some(10),
                ..Default::default()
            },
            Filter {
                tags: Some(vec![TagQuery(
                    "t".to_string(),
                    vec!["hello".to_string(), "world".to_string()],
                )]),
                limit: Some(300),
                ..Default::default()
            },
            Filter {
                tags: Some(vec![
                    TagQuery("K".to_string(), vec!["1".to_string()]),
                    TagQuery("P".to_string(), vec![pk2.to_hex()]),
                ]),
                limit: Some(50),
                ..Default::default()
            },
        ];

        let mut counts = [0, 0, 0, 0];
        let mut total = 0;
        let filters_clone = filters.clone();
        store
            .query_events(filters, 1000, |archived_event| {
                let event = rkyv::deserialize::<Event, rancor::Error>(archived_event).unwrap();
                for (i, filter) in filters_clone.iter().enumerate() {
                    if filter.matches(&event) {
                        counts[i] += 1;
                    }
                }
                total += 1;
                Ok(())
            })
            .expect("failed to query events");

        assert_ge!(counts[0], 3);
        assert_ge!(counts[1], 10);
        assert_ge!(counts[2], 300);
        assert_ge!(counts[3], 50);
        assert_lt!(total, 3 + 10 + 300 + 50);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
