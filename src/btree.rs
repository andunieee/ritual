use std::collections::BTreeMap;
use std::cell::RefCell;
use std::rc::Rc;
use std::hash::{BuildHasher, Hash, Hasher};

pub struct BTreeEventDatabase {
    pub events_by_id: Rc<RefCell<BTreeMap<Vec<u8>, Vec<u8>>>>,

    // indexes: key -> vec of id bytes
    index_timestamp: Rc<RefCell<BTreeMap<Vec<u8>, Vec<Vec<u8>>>>>,
    index_kind: Rc<RefCell<BTreeMap<Vec<u8>, Vec<Vec<u8>>>>>,
    index_pubkey: Rc<RefCell<BTreeMap<Vec<u8>, Vec<Vec<u8>>>>>,
    index_pubkey_kind: Rc<RefCell<BTreeMap<Vec<u8>, Vec<Vec<u8>>>>>,
    index_tag: Rc<RefCell<BTreeMap<Vec<u8>, Vec<Vec<u8>>>>>,
    index_ptag_ktag: Rc<RefCell<BTreeMap<Vec<u8>, Vec<Vec<u8>>>>>,
}

impl BTreeEventDatabase {
    pub fn new() -> Self {
        Self {
            events_by_id: Rc::new(RefCell::new(BTreeMap::new())),
            index_timestamp: Rc::new(RefCell::new(BTreeMap::new())),
            index_kind: Rc::new(RefCell::new(BTreeMap::new())),
            index_pubkey: Rc::new(RefCell::new(BTreeMap::new())),
            index_pubkey_kind: Rc::new(RefCell::new(BTreeMap::new())),
            index_tag: Rc::new(RefCell::new(BTreeMap::new())),
            index_ptag_ktag: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }

    fn save_internal(&self, event: &crate::Event) -> crate::database::Result<()> {
        let event_data = rkyv::to_bytes::<rkyv::rancor::Error>(event)?;
        let id_u64 = event.id.as_u64_lossy();
        let id_bytes = id_u64.to_ne_bytes();

        // save raw event
        self.events_by_id.borrow_mut().insert(id_bytes.to_vec(), event_data.to_vec());

        // save indexes
        self.get_index_keys_for_event(event, |index_key| {
            let mut index = index_key.index.borrow_mut();
            if let Some(ids) = index.get_mut(&index_key.key) {
                ids.retain(|id_vec| id_vec != &id_bytes);
                if ids.is_empty() {
                    index.remove(&index_key.key);
                }
            }
            Ok(())
        })?;

        Ok(())
    }

    fn delete_internal(&self, id: u64) -> crate::database::Result<()> {
        let id_bytes = id.to_ne_bytes();

        // get the event data to compute indexes
        let event_data = self.events_by_id.borrow().get(&id_bytes.to_vec()).ok_or(crate::database::DatabaseError::EventNotFound)?.clone();
        let event = unsafe { rkyv::from_bytes_unchecked::<crate::Event, rkyv::rancor::Error>(&event_data)? };

        // delete all indexes
        self.get_index_keys_for_event(&event, |index_key| {
            let mut index = index_key.index.borrow_mut();
            if let Some(ids) = index.get_mut(&index_key.key) {
                ids.retain(|id_vec| id_vec != &id_bytes);
                if ids.is_empty() {
                    index.remove(&index_key.key);
                }
            }
            Ok(())
        })?;

        // delete raw event
        self.events_by_id.borrow_mut().remove(&id_bytes.to_vec());

        Ok(())
    }

    fn execute<F>(
        &self,
        queries: Vec<Query>,
        mut cb: F,
    ) -> crate::database::Result<()>
    where
        F: FnMut(&crate::ArchivedEvent) -> crate::database::Result<()>,
    {
        let mut cursors: Vec<Cursor> = Vec::with_capacity(queries.iter().fold(0, |acc, q| acc + q.sub_queries.len()));

        for query in queries {
            let rc_query = Rc::new(query);

            for (i, sub_query) in rc_query.sub_queries.iter().enumerate() {
                let prefix = &sub_query[0..sub_query.len() - 4];

                // collect all matching entries upfront
                let mut pulled: Vec<(u32, u64)> = Vec::new();
                for (key, ids) in rc_query.index.borrow().range(prefix.to_vec()..) {
                    if !key.starts_with(prefix) {
                        break;
                    }
                    let timestamp = u32::from_ne_bytes(key[key.len() - 4..].try_into().unwrap());
                    if timestamp < rc_query.end_ts {
                        continue;
                    }
                    for id_vec in ids {
                        let id = u64::from_ne_bytes(id_vec.as_slice().try_into().unwrap());
                        pulled.push((timestamp, id));
                    }
                }
                // sort by timestamp desc
                pulled.sort_by(|a, b| b.0.cmp(&a.0));

                let c = Cursor {
                    i,
                    query: rc_query.clone(),
                    pulled: std::collections::VecDeque::from(pulled),
                    done: false,
                };

                cursors.push(c);
            }
        }

        let mut collected_events: Vec<(
            Vec<u8>,
            Rc<std::cell::Cell<usize>>,
        )> = Vec::with_capacity(64);
        let mut last_sent: Option<([u8; 32], Rc<std::cell::Cell<usize>>)> = None;

        while cursors.len() > 0 {
            collected_events.truncate(0);

            // sort cursors by last_read_timestamp
            glidesort::sort_in_vec_by_key(&mut cursors, |c| c.last_read_timestamp());

            // collect from cursors
            if let Some(Some(cutpoint)) = cursors.last().map(|c| c.last_read_timestamp()) {
                for c in &mut cursors {
                    for _ in 0..c.pulled.len() {
                        if c.query.total_sent.get() >= c.query.limit {
                            c.done = true;
                            break;
                        }

                        if c.pulled[0].0 < cutpoint {
                            break;
                        }

                        let id_bytes = c.pulled[0].1.to_ne_bytes();
                        let event_data = self.events_by_id.borrow().get(&id_bytes.to_vec()).unwrap().clone();
                        let event: &crate::ArchivedEvent = unsafe { rkyv::access_unchecked(&event_data) };

                        c.pulled.pop_front();

                        // check extra filters
                        if let Some(extra_kinds) = &c.query.extra_kinds {
                            if !extra_kinds.contains(&event.kind.0) {
                                continue;
                            }
                        }
                        if let Some(extra_authors) = &c.query.extra_authors {
                            if !extra_authors.contains(&event.pubkey.0) {
                                continue;
                            }
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

                        collected_events.push((event_data, c.query.total_sent.clone()));
                        c.query.total_sent.update(|u| u + 1);
                    }
                }
            }

            // sort collected by created_at desc
            collected_events.sort_by_key(|(event_data, _)| {
                let event: &crate::ArchivedEvent = unsafe { rkyv::access_unchecked(event_data) };
                std::cmp::Reverse(event.created_at.0)
            });

            // dispatch
            for (event_data, query_total_sent) in collected_events.drain(..).rev() {
                let event: &crate::ArchivedEvent = unsafe { rkyv::access_unchecked(&event_data) };
                if let Some((last_id, last_query_ref)) = last_sent.replace((event.id.0, query_total_sent.clone())) {
                    if last_id == event.id.0 {
                        if Rc::ptr_eq(&last_query_ref, &query_total_sent) {
                            query_total_sent.update(|u| u - 1);
                        }
                        continue;
                    }
                }
                cb(event)?;
            }

            // cleanup done cursors
            let mut i = 0;
            while i < cursors.len() {
                if cursors[i].done {
                    cursors.swap_remove(i);
                } else {
                    i += 1;
                }
            }
        }

        Ok(())
    }

    fn plan_query(&self, filter: crate::Filter, queries: &mut Vec<Query>, max_limit: usize) {
        let start_ts = filter.until.map(|ts| ts.0).unwrap_or(u32::MAX).to_ne_bytes();
        let end_ts = filter.since.map(|ts| ts.0).unwrap_or(0);
        let mut extra_tag: Option<crate::filter::TagQuery> = None;
        let mut second_best: Option<crate::filter::TagQuery> = None;

        if let Some(mut tags) = filter.tags {
            tags.sort_unstable_by_key(|tagq| tagq.worth());
            tags.reverse();

            let tagq = tags.get(0).expect("there must always be at least one tag if tags is present");

            if tagq.worth() > 5 {
                queries.push(Query {
                    index: self.index_tag.clone(),
                    sub_queries: tagq.to_sub_queries(&start_ts),
                    end_ts,
                    limit: max_limit,
                    total_sent: Rc::new(std::cell::Cell::new(0)),
                    extra_tag: tags.get(1).cloned(),
                    extra_kinds: filter.kinds.map(|kinds| kinds.iter().map(|kind| rkyv::rend::u16_le::from(kind.0)).collect()),
                    extra_authors: filter.authors.map(|authors| authors.iter().map(|author| author.0).collect()),
                });
                return;
            }

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
            for (k_value, p_value) in itertools::iproduct!(k_values, p_values) {
                let mut key = Vec::from([0u8; 8 + 2 + 4]);
                key[8 + 2..].copy_from_slice(&start_ts);

                if let Ok(k) = k_value.parse::<u16>() {
                    key[8..8 + 2].copy_from_slice(&k.to_ne_bytes());

                    if p_value.len() == 64 && lowercase_hex::decode_to_slice(&p_value[8 * 2..8 * 2 + 8 * 2], &mut key[0..8]).is_ok() {
                        sub_queries.push(key);
                    }
                }
            }

            if sub_queries.len() > 0 {
                let best_possible_tag = tags.iter().find(|tag| tag.key() != "p" && tag.key() != "P" && tag.key() != "K");

                queries.push(Query {
                    index: self.index_ptag_ktag.clone(),
                    sub_queries,
                    end_ts,
                    limit: max_limit,
                    total_sent: Rc::new(std::cell::Cell::new(0)),
                    extra_tag: best_possible_tag.cloned(),
                    extra_kinds: filter.kinds.map(|kinds| kinds.iter().map(|kind| rkyv::rend::u16_le::from(kind.0)).collect()),
                    extra_authors: filter.authors.map(|authors| authors.iter().map(|author| author.0).collect()),
                });
                return;
            }

            if let Some(best_tag) = tags.get(0) {
                extra_tag = Some(best_tag.clone());
                second_best = tags.get(1).map(|tagq| tagq.clone());
            }
        }

        if let (Some(authors), Some(kinds)) = (&filter.authors, &filter.kinds) {
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
                index: self.index_pubkey_kind.clone(),
                sub_queries,
                end_ts,
                limit: max_limit,
                total_sent: Rc::new(std::cell::Cell::new(0)),
                extra_tag,
                extra_kinds: None,
                extra_authors: None,
            });
            return;
        }

        if let Some(authors) = filter.authors {
            queries.push(Query {
                index: self.index_pubkey.clone(),
                sub_queries: authors.iter().map(|a| {
                    let mut key = Vec::from([0u8; 8 + 4]);
                    key[8..].copy_from_slice(&start_ts);
                    key[0..8].copy_from_slice(&a.as_u64_lossy().to_ne_bytes());
                    key
                }).collect(),
                end_ts,
                limit: max_limit,
                total_sent: Rc::new(std::cell::Cell::new(0)),
                extra_tag,
                extra_kinds: None,
                extra_authors: None,
            });
            return;
        }

        if let Some(kinds) = filter.kinds {
            queries.push(Query {
                index: self.index_kind.clone(),
                sub_queries: kinds.iter().map(|k| {
                    let mut key = Vec::from([0u8; 2 + 4]);
                    key[2..].copy_from_slice(&start_ts);
                    key[0..2].copy_from_slice(&k.0.to_ne_bytes());
                    key
                }).collect(),
                end_ts,
                limit: max_limit,
                total_sent: Rc::new(std::cell::Cell::new(0)),
                extra_tag,
                extra_kinds: None,
                extra_authors: None,
            });
            return;
        }

        if let Some(best_tagq) = &extra_tag {
            queries.push(Query {
                index: self.index_tag.clone(),
                sub_queries: best_tagq.to_sub_queries(&start_ts),
                end_ts,
                limit: max_limit,
                total_sent: Rc::new(std::cell::Cell::new(0)),
                extra_tag: second_best,
                extra_kinds: None,
                extra_authors: None,
            });
            return;
        }

        queries.push(Query {
            index: self.index_timestamp.clone(),
            sub_queries: vec![start_ts.into()],
            end_ts,
            limit: max_limit,
            total_sent: Rc::new(std::cell::Cell::new(0)),
            extra_tag: None,
            extra_kinds: None,
            extra_authors: None,
        });
    }

    fn get_index_keys_for_event<F>(&self, event: &crate::Event, mut cb: F) -> crate::database::Result<()>
    where
        F: FnMut(IndexKey) -> crate::database::Result<()>,
    {
        let ts_bytes = &event.created_at.0.to_ne_bytes();

        // by date only
        {
            cb(IndexKey {
                key: ts_bytes.to_vec(),
                index: self.index_timestamp.clone(),
            })?;
        }

        // by kind + date
        {
            let mut key = [0u8; 2 + 4];
            key[0..2].copy_from_slice(&event.kind.0.to_ne_bytes());
            key[2..].copy_from_slice(ts_bytes);
            cb(IndexKey {
                key: key.to_vec(),
                index: self.index_kind.clone(),
            })?;
        }

        // by pubkey + date
        {
            let mut key = [0u8; 8 + 4];
            key[0..8].copy_from_slice(&event.pubkey.as_u64_lossy().to_ne_bytes());
            key[8..].copy_from_slice(ts_bytes);
            cb(IndexKey {
                key: key.to_vec(),
                index: self.index_pubkey.clone(),
            })?;
        }

        // by pubkey + kind + date
        {
            let mut key = [0u8; 8 + 2 + 4];
            key[0..8].copy_from_slice(&event.pubkey.as_u64_lossy().to_ne_bytes());
            key[8..8 + 2].copy_from_slice(&event.kind.0.to_ne_bytes());
            key[8 + 2..].copy_from_slice(ts_bytes);
            cb(IndexKey {
                key: key.to_vec(),
                index: self.index_pubkey_kind.clone(),
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
                if lowercase_hex::decode_to_slice(&tag[1][8 * 2..8 * 2 + 8 * 2], &mut key[1..1 + 8]).is_ok() {
                    cb(IndexKey {
                        key: key.to_vec(),
                        index: self.index_tag.clone(),
                    })?;
                    continue;
                }
            }

            let mut s = foldhash::fast::FixedState::with_seed(crate::filter::TAG_HASHER_SEED).build_hasher();
            tag[1].hash(&mut s);
            let hash = s.finish();
            key[1..1 + 8].copy_from_slice(hash.to_ne_bytes().as_slice());

            cb(IndexKey {
                key: key.to_vec(),
                index: self.index_tag.clone(),
            })?;
        }

        // by p-tag + k-tag
        let mut kp_key: Option<[u8; 8 + 2 + 4]> = None;
        for (k_tagname, p_tagname) in vec![("K", "p"), ("K", "P")] {
            for k_tag in &event.tags.0 {
                if k_tag.len() >= 2 && k_tag[0] == k_tagname {
                    if let Ok(k) = k_tag[1].parse::<u16>() {
                        let key = kp_key.get_or_insert_with(|| {
                            let mut key = [0u8; 8 + 2 + 4];
                            key[8 + 2..].copy_from_slice(ts_bytes);
                            key
                        });

                        key[8..8 + 2].copy_from_slice(&k.to_ne_bytes());

                        for p_tag in &event.tags.0 {
                            if p_tag.len() >= 2 && p_tag[0] == p_tagname && p_tag[1].len() == 64 {
                                if lowercase_hex::decode_to_slice(&p_tag[1][8 * 2..8 * 2 + 8 * 2], &mut key[0..8]).is_ok() {
                                    cb(IndexKey {
                                        key: key.to_vec(),
                                        index: self.index_ptag_ktag.clone(),
                                    })?;
                                }
                            }
                        }
                    }
                    break;
                }
            }
        }

        Ok(())
    }
}

impl crate::database::EventDatabase for BTreeEventDatabase {
    fn save_event(&self, event: &crate::Event) -> crate::database::Result<()> {
        let id_bytes = event.id.as_u64_lossy().to_ne_bytes();

        if self.events_by_id.borrow().contains_key(&id_bytes.to_vec()) {
            return Err(crate::database::DatabaseError::DuplicateEvent);
        }

        self.save_internal(event)?;
        Ok(())
    }

    fn replace_event(&self, event: &crate::Event, with_address: bool) -> crate::database::Result<()> {
        let mut filter = crate::Filter::default();
        filter.kinds = Some(vec![event.kind]);
        filter.authors = Some(vec![event.pubkey]);
        filter.limit = Some(10);

        if with_address {
            filter.tags = Some(vec![crate::filter::TagQuery("d".to_string(), vec![event.tags.get_d()])]);
        }

        let mut should_store = true;

        let mut queries: Vec<Query> = Vec::with_capacity(1);
        self.plan_query(filter, &mut queries, 1);
        self.execute(queries, |existing_event| {
            if existing_event.created_at.0 < event.created_at.0 {
                self.delete_internal(u64::from_ne_bytes(existing_event.id.0[8..16].try_into().unwrap()))?;
            } else {
                should_store = false;
            }
            Ok(())
        })?;

        if should_store {
            self.save_internal(event)?;
        }

        Ok(())
    }

    fn query_events<F>(&self, filters: Vec<crate::Filter>, max_limit: usize, mut cb: F) -> crate::database::Result<()>
    where
        F: FnMut(&crate::ArchivedEvent) -> crate::database::Result<()>,
    {
        let mut queries: Vec<Query> = Vec::with_capacity(64);

        for filter in filters {
            if filter.search.is_some() {
                return Err(crate::database::DatabaseError::InvalidFilter("search not supported".to_string()));
            }

                    if let Some(ids) = &filter.ids {
                        for id in ids {
                            let id_bytes = id.as_u64_lossy().to_ne_bytes();
                            if let Some(event_data) = self.events_by_id.borrow().get(&id_bytes.to_vec()) {
                                let event = unsafe { rkyv::access_unchecked::<crate::ArchivedEvent>(event_data) };
                                cb(event)?;
                            }
                        }
                        continue;
                    }

            let limit = filter.limit.unwrap_or(max_limit).min(max_limit);
            if limit == 0 {
                continue;
            }

            self.plan_query(filter, &mut queries, limit);
        }

        if queries.len() > 0 {
            self.execute(queries, |event| {
                cb(event)?;
                Ok(())
            })?;
        }

        Ok(())
    }

    fn delete_event(&self, id: &crate::ID) -> crate::database::Result<()> {
        self.delete_internal(id.as_u64_lossy())?;
        Ok(())
    }
}

#[derive(Debug)]
struct IndexKey {
    key: Vec<u8>,
    index: Rc<RefCell<BTreeMap<Vec<u8>, Vec<Vec<u8>>>>>,
}

#[derive(Debug)]
struct Query {
    index: Rc<RefCell<BTreeMap<Vec<u8>, Vec<Vec<u8>>>>>,

    // this is the main index we'll use, the values are the starting points
    // the prefix should be just the initial bytes (anything besides the last 4 bytes)
    sub_queries: Vec<Vec<u8>>,

    // we'll scan each index up to this point (the last 4 bytes)
    end_ts: u32,

    // max number of results we'll return from this
    limit: usize,
    total_sent: Rc<std::cell::Cell<usize>>, // total sent for this query, shared among all sub_queries

    // these extra values will be matched against after we've read an event from the database
    extra_tag: Option<crate::filter::TagQuery>,
    extra_kinds: Option<Vec<rkyv::rend::u16_le>>,
    extra_authors: Option<Vec<[u8; 32]>>,
}

#[derive(Debug)]
struct Cursor {
    // this index in the sub_queries list
    i: usize,

    query: Rc<Query>,
    // timestamps and ids we've pulled that were not yet collected
    pulled: std::collections::VecDeque<(u32, u64)>,

    // if this is true we won't read anymore and this cursor will be soon removed from the list
    done: bool,
}

impl Cursor {
    fn last_read_timestamp(&self) -> Option<u32> {
        self.pulled.front().map(|(ts, _)| *ts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::EventDatabase;
    use crate::*;
    use assertables::{assert_contains, assert_ge, assert_lt};

    #[test]
    fn test_query_empty() {
        let store = BTreeEventDatabase::new();

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
    }

    #[test]
    fn test_save_and_query_event() {
        let store = BTreeEventDatabase::new();
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
                results.push(rkyv::deserialize::<Event, rkyv::rancor::Error>(event).unwrap());
                Ok(())
            })
            .expect("failed to query events");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, event.id);
        assert_eq!(results[0].content, event.content);
    }

    #[test]
    fn test_duplicate_event() {
        let store = BTreeEventDatabase::new();
        let event = EventTemplate {
            content: "nothing".to_string(),
            ..Default::default()
        }
        .finalize(&SecretKey::generate());

        // save the event
        store.save_event(&event).expect("failed to save event");

        // try to save the same event again
        let result = store.save_event(&event);
        assert!(matches!(
            result,
            Err(crate::database::DatabaseError::DuplicateEvent)
        ));
    }

    #[test]
    fn test_delete_event() {
        let store = BTreeEventDatabase::new();
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
    }

    #[test]
    fn test_replaceable_events() {
        let store = BTreeEventDatabase::new();
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
                results.push(rkyv::deserialize::<Event, rkyv::rancor::Error>(event).unwrap());
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
                results.push(rkyv::deserialize::<Event, rkyv::rancor::Error>(event).unwrap());
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
                results.push(rkyv::deserialize::<Event, rkyv::rancor::Error>(event).unwrap());
                Ok(())
            })
            .expect("failed to query events");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, event2.id);
    }

    #[test]
    fn test_filter_by_kind() {
        let store = BTreeEventDatabase::new();

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
    }

    #[test]
    fn test_filter_by_tag() {
        let store = BTreeEventDatabase::new();

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
    }

    #[test]
    fn test_slightly_complex_query() {
        let store = BTreeEventDatabase::new();

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
    }

    #[test]
    fn test_complex_query() {
        let store = BTreeEventDatabase::new();

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
                let event =
                    rkyv::deserialize::<Event, rkyv::rancor::Error>(archived_event).unwrap();
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
    }
}