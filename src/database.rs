use std::hash::{BuildHasher, Hash, Hasher};

pub const TAG_HASHER_SEED: u64 = 64;

pub type Result<T> = std::result::Result<T, DatabaseError>;

#[derive(thiserror::Error, Debug)]
pub enum DatabaseError {
    #[error("LMDB error: {0}")]
    LMDB(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] rkyv::rancor::Error),

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
    type ReadTxn<'t>: ReadTransaction<'t>
    where
        Self: 't;

    type WriteTxn<'t>: WriteTransaction<'t>
    where
        Self: 't;

    fn save_event(&self, event: &crate::Event) -> crate::database::Result<()> {
        let mut txn = self.begin_write_txn();

        if txn.has_event(event.id.short()) {
            return Err(DatabaseError::DuplicateEvent);
        }

        txn.save(&event)?;
        Ok(())
    }

    fn delete_event(&self, id: crate::ShortID) -> Result<()> {
        let mut txn = self.begin_write_txn();
        txn.delete(id)?;
        Ok(())
    }

    fn query_events<'t>(&self, filters: Vec<crate::Filter>) -> QueryResults<'t, Self::ReadTxn<'t>> {
        let txn = self.begin_read_txn();
        let mut results = QueryResults::new(txn);

        for filter in filters {
            if filter.search.is_some() {
                log::warn!("ignoring query with search field");
                continue;
            }

            // id query, just process these ids and that's it
            if let Some(ids) = filter.ids {
                results.ids.reserve(ids.len());
                for id in ids {
                    results.ids.push(id.short());
                }
            } else {
                plan_index_queries(&mut results.index_queries, filter);
            }
        }

        results
    }

    fn replace_event(&self, event: &crate::Event, with_address: bool) -> Result<()> {
        let mut txn = self.begin_write_txn();

        // create filter to find existing events
        let mut filter = crate::Filter {
            kinds: Some(vec![event.kind]),
            authors: Some(vec![event.pubkey.clone()]),
            limit: Some(10),
            ..Default::default()
        };

        if with_address {
            filter.tags = Some(vec![crate::filter::TagQuery(
                "d".to_string(),
                vec![event.tags.get_d()],
            )]);
        }

        let mut should_store = true;

        // find and delete older events
        let mut results = QueryResults::new(txn.clone());
        plan_index_queries(&mut results.index_queries, filter);

        for existing_event in results {
            if existing_event.created_at.0 < event.created_at.0 {
                txn.delete(existing_event.id.short())?;
            } else {
                should_store = false; // newer event already exists
            }
        }

        if should_store {
            txn.save(event)?;
        }

        Ok(())
    }

    fn begin_read_txn<'t>(&self) -> Self::ReadTxn<'t>;
    fn begin_write_txn<'t>(&self) -> Self::WriteTxn<'t>;
}

pub trait ReadTransaction<'t>: Clone {
    type Cursor: Cursor<'t>;

    fn has_event(&self, id: crate::ShortID) -> bool;
    fn get_event(&self, id: crate::ShortID) -> Result<&'t crate::ArchivedEvent>;
    fn new_cursor(&self, query: &IndexQuery) -> Self::Cursor;
}

pub trait WriteTransaction<'t>: ReadTransaction<'t> {
    fn put_event(&mut self, event: &crate::Event) -> Result<()>;
    fn del_event(&mut self, id: crate::ShortID) -> Result<()>;
    fn put_key(&mut self, index_key: IndexKey) -> Result<()>;
    fn del_key(&mut self, index_key: IndexKey) -> Result<()>;

    fn save(&mut self, event: &crate::Event) -> Result<()> {
        self.put_event(&event)?;

        get_index_keys_for_event(event, |index_key| {
            self.put_key(index_key)?;
            Ok(())
        })?;

        Ok(())
    }

    fn delete(&mut self, id: crate::ShortID) -> Result<()> {
        match self.get_event(id) {
            Ok(event) => {
                get_index_keys_for_event(
                    &rkyv::deserialize::<crate::Event, rkyv::rancor::Error>(event)
                        .expect("archived type must deserialize"),
                    |index_key| self.del_key(index_key),
                )?;
                self.del_event(id)
            }
            Err(DatabaseError::EventNotFound) => Ok(()),
            Err(err) => Err(err),
        }
    }
}

pub struct QueryResults<'t, T>
where
    T: ReadTransaction<'t>,
{
    txn: T,

    // ids are just fetched first and straightforwardly
    ids: Vec<crate::ShortID>,

    // index queries are more complex, they're fetched all at the same time and ordered dynamically
    index_queries: Vec<std::rc::Rc<IndexQuery>>,
    initialized: bool, // whether the cursors have been initialized
    cursors: Vec<(std::rc::Rc<IndexQuery>, T::Cursor)>, // in the beginning, one for each IndexQuery; these will be reordered many times.
    collectable: Vec<&'t crate::ArchivedEvent>,
    last_sent: Option<&'t crate::ArchivedID>,
}

impl<'t, T> QueryResults<'t, T>
where
    T: ReadTransaction<'t>,
{
    fn new(txn: T) -> Self {
        Self {
            txn,
            ids: Vec::new(),
            index_queries: Vec::with_capacity(12),
            collectable: Vec::with_capacity(64),
            initialized: false,
            cursors: Vec::with_capacity(12),
            last_sent: None,
        }
    }
}

pub trait Cursor<'t> {
    fn pull(&mut self);
    fn last_read_timestamp(&self) -> u32;
    fn total_pulled(&self) -> usize;
    fn set_done(&mut self);
    fn is_done(&self) -> bool;
    fn first_pulled_timestamp(&self) -> u32;
    fn pop_front_pulled_id(&mut self) -> crate::ShortID;
}

impl<'t, T> Iterator for QueryResults<'t, T>
where
    T: ReadTransaction<'t>,
{
    type Item = &'t crate::ArchivedEvent;

    fn next(&mut self) -> Option<Self::Item> {
        // first emit all ids
        while let Some(id) = self.ids.pop() {
            match self.txn.get_event(id) {
                Ok(event) => return Some(event),
                Err(DatabaseError::EventNotFound) => continue, // try the next
                Err(err) => {
                    log::warn!("get_event('{}') errored: {}", id, err);
                    return None;
                }
            }
        }

        // after those have ended start pulling results from the queries
        if self.index_queries.len() == 0 {
            return None;
        }

        if !self.initialized {
            for query in self.index_queries.iter() {
                let mut cursor = self.txn.new_cursor(&query);

                // pull some entries from every cursor
                cursor.pull();

                self.cursors.push((query.clone(), cursor));
            }
            self.initialized = true;
        }

        // if we don't have any events waiting to be yielded to the iterator, perform the fetch flow
        loop {
            if self.collectable.len() == 0 {
                if self.cursors.len() > 0 {
                    // sort such that the cursors will be the ones we'll read from as they're the less advanced
                    glidesort::sort_in_vec_by_key(&mut self.cursors, |c| c.1.last_read_timestamp());

                    // and any entry already pulled that has a timestamp higher than this can al ready be collected
                    // (if there is no cutpoint that means we have no results to collect and our query will be ended)
                    if let Some(cutpoint) = self.cursors.last().map(|c| c.1.last_read_timestamp()) {
                        // reading from db and collecting events
                        for (query, cursor) in &mut self.cursors {
                            for _ in 0..cursor.total_pulled() {
                                if let Some(limit) = query.limit
                                    && *query.total_sent.borrow() >= limit
                                {
                                    cursor.set_done();
                                    break;
                                }

                                // we'll always be collecting from the front of the vec
                                if cursor.first_pulled_timestamp() < cutpoint {
                                    // from this point on we stop collecting
                                    break;
                                }

                                // otherwise we're still good, collect this (and remove it)
                                let id = cursor.pop_front_pulled_id();
                                let event = match self.txn.get_event(id) {
                                    Err(err) => {
                                        log::warn!("failed to get event with {}: {}", id, err);
                                        continue;
                                    }
                                    Ok(event) => event,
                                };

                                // check if this event passes the other filters before actually sending it
                                if let Some(extra_kinds) = &query.extra_kinds {
                                    if !extra_kinds.contains(&event.kind.0) {
                                        continue;
                                    };
                                }
                                if let Some(extra_authors) = &query.extra_authors {
                                    if !extra_authors.contains(&event.pubkey.0) {
                                        continue;
                                    };
                                }

                                let mut tags_ok = false;
                                if let Some(extra_tag) = &query.extra_tag {
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
                                self.collectable.push(event);
                                *query.total_sent.borrow_mut() += 1;
                            }
                        }
                    }

                    // after deciding what events are going to the client we order them
                    self.collectable.sort_by_key(|event| event.created_at.0);
                }
            }

            // at this point we must have some events to dispatch, otherwise we end here
            if self.collectable.len() == 0 {
                return None;
            }

            // now we have something to dispatch, but before that let's prepare the next round:
            // cleanup cursors that have ended (cumbersome swap_remove() flow)
            let mut i = 0;
            for _ in 0..self.cursors.len() {
                if self.cursors[i].1.is_done() {
                    self.cursors.swap_remove(i);
                    continue;
                }
                i += 1;
            }

            // pull 16 entries from each of the top 4 cursors (as defined from the previous sort call)
            let max_len = self.cursors.len().max(4);
            for (_, cursor) in &mut self.cursors[max_len - 4..] {
                cursor.pull();
            }

            // dispatch next event to caller, filtering out duplicates
            while let Some(event) = self.collectable.pop() {
                if let Some(last_id) = self.last_sent.replace(&event.id) {
                    if last_id == &event.id {
                        continue;
                    }
                }

                return Some(event);
            }
        }
    }
}

pub struct IndexQuery {
    pub index: Index,
    pub key: Vec<u8>,

    // we'll scan each index up to this point (the last 4 bytes)
    pub end_ts: u32,

    // max number of results we'll return from this (if it specifies a limit)
    limit: Option<usize>,
    total_sent: std::rc::Rc<std::cell::RefCell<usize>>, // total for this filter, shared among all derived queries

    // these extra values will be matched against after we've read an event from the database
    extra_tag: Option<std::rc::Rc<crate::filter::TagQuery>>,
    extra_kinds: Option<std::rc::Rc<Vec<rkyv::rend::u16_le>>>,
    extra_authors: Option<std::rc::Rc<Vec<[u8; 32]>>>,
}

fn plan_index_queries(queries: &mut Vec<std::rc::Rc<IndexQuery>>, filter: crate::Filter) {
    let crate::Filter {
        until,
        since,
        limit,
        authors: mut authors_,
        tags: mut tags_,
        kinds: mut kinds_,

        ids: _,
        search: _,
    } = filter;

    let start_ts = until.map(|ts| ts.0).unwrap_or(u32::MAX).to_ne_bytes();
    let end_ts = since.map(|ts| ts.0).unwrap_or(0);
    let mut extra_tag: Option<std::rc::Rc<crate::filter::TagQuery>> = None;
    let mut second_best: Option<std::rc::Rc<crate::filter::TagQuery>> = None;

    let total_sent = std::rc::Rc::new(std::cell::RefCell::new(0));

    if let Some(mut tags) = tags_.take() {
        tags.sort_unstable_by_key(|tagq| tagq.worth());

        let best_tag = match tags.pop() {
            None => {
                // there must always be at least one tag if tags is present, so this is technically an error
                log::warn!("abort query with filter with Some([]) tags");
                return;
            }
            Some(tag) => tag,
        };

        if best_tag.worth() > 5 {
            // use tag query as the main index
            let second_best_tag = tags.pop().map(std::rc::Rc::new);

            plan_tag_queries(
                queries,
                &best_tag,
                &start_ts,
                end_ts,
                second_best_tag,
                kinds_.map(|kinds| {
                    std::rc::Rc::new(
                        kinds
                            .into_iter()
                            .map(|kind| rkyv::rend::u16_le::from(kind.0))
                            .collect(),
                    )
                }),
                authors_.map(|authors| {
                    std::rc::Rc::new(authors.iter().map(|author| author.0).collect())
                }),
                limit,
                total_sent,
            );

            return;
        }

        // if there is a "K" and a "p"/"P" use that special index
        {
            let mut k_values = Vec::new();
            let mut p_values = Vec::new();
            for tag in &tags {
                if tag.key() == "p" || tag.key() == "P" {
                    p_values.extend(tag.values());
                } else if tag.key() == "K" {
                    k_values.extend(tag.values());
                }
            }

            let mut used_this = false;
            let mut best_possible_tag: Option<std::rc::Rc<crate::TagQuery>> = None;
            let mut extra_kinds: Option<std::rc::Rc<Vec<rkyv::rend::u16_le>>> = None;
            let mut extra_authors: Option<std::rc::Rc<Vec<[u8; 32]>>> = None;

            for (k_value, p_value) in itertools::iproduct!(k_values, p_values) {
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
                        if best_possible_tag.is_none() {
                            best_possible_tag = tags
                                .iter()
                                .find(|tag| {
                                    tag.key() != "p" && tag.key() != "P" && tag.key() != "K"
                                })
                                .map(|t| t.to_owned())
                                .map(std::rc::Rc::new);
                        }

                        if let Some(kinds) = kinds_.take() {
                            extra_kinds = Some(std::rc::Rc::new(
                                kinds
                                    .into_iter()
                                    .map(|kind| rkyv::rend::u16_le::from(kind.0))
                                    .collect(),
                            ));
                        }

                        if let Some(authors) = authors_.take() {
                            extra_authors = Some(std::rc::Rc::new(
                                authors.into_iter().map(|author| author.0).collect(),
                            ));
                        }

                        queries.push(std::rc::Rc::new(IndexQuery {
                            index: Index::PtagKtag,
                            key,
                            end_ts,
                            extra_tag: best_possible_tag.clone(),
                            extra_kinds: extra_kinds.clone(),
                            extra_authors: extra_authors.clone(),
                            limit,
                            total_sent: total_sent.clone(),
                        }));

                        used_this = true;
                    }
                }
            }
            if used_this {
                return;
            }
        }

        // otherwise don't use a tag-based index
        // only use the first tag as the extra tag filter
        extra_tag = Some(std::rc::Rc::new(best_tag));

        // also keep the second best tag so we can use it maybe eventually
        second_best = tags.pop().map(std::rc::Rc::new);
    }

    if let (Some(authors), Some(kinds)) = (&authors_, &kinds_) {
        // kinds and authors
        // use pubkey-kind as the main index
        for author in authors {
            for kind in kinds {
                let mut key = Vec::from([0u8; 8 + 2 + 4]);
                key[8 + 2..].copy_from_slice(&start_ts);

                key[0..8].copy_from_slice(&author.short().0.to_ne_bytes());
                key[8..8 + 2].copy_from_slice(&kind.0.to_ne_bytes());

                queries.push(std::rc::Rc::new(IndexQuery {
                    index: Index::PubkeyKind,
                    key,
                    end_ts,
                    extra_tag: extra_tag.clone(),
                    extra_kinds: None,
                    extra_authors: None,

                    limit,
                    total_sent: total_sent.clone(),
                }));
            }
        }

        return;
    }

    if let Some(authors) = authors_.take() {
        // just authors
        for a in authors {
            let mut key = Vec::from([0u8; 8 + 4]);
            key[8..].copy_from_slice(&start_ts);
            key[0..8].copy_from_slice(&a.short().0.to_ne_bytes());

            queries.push(std::rc::Rc::new(IndexQuery {
                index: Index::Pubkey,
                key,
                end_ts,
                extra_tag: extra_tag.clone(),
                extra_kinds: None,
                extra_authors: None,

                limit,
                total_sent: total_sent.clone(),
            }));
        }

        return;
    }

    if let Some(kinds) = kinds_.take() {
        // just kinds
        for k in kinds {
            let mut key = Vec::from([0u8; 2 + 4]);
            key[2..].copy_from_slice(&start_ts);
            key[0..2].copy_from_slice(&k.0.to_ne_bytes());

            queries.push(std::rc::Rc::new(IndexQuery {
                index: Index::Kind,
                key,
                end_ts,
                extra_tag: extra_tag.clone(),
                extra_kinds: None,
                extra_authors: None,

                limit,
                total_sent: total_sent.clone(),
            }));
        }

        return;
    }

    // if we got here and we have an extra_tag, let's use that as our main query
    // as it's better than nothing
    if let Some(best_tagq) = &extra_tag {
        plan_tag_queries(
            queries,
            &best_tagq,
            &start_ts,
            end_ts,
            second_best,
            None,
            None,
            limit,
            total_sent,
        );
        return;
    }

    // no filters, use just the created_at index
    queries.push(std::rc::Rc::new(IndexQuery {
        index: Index::Timestamp,
        key: start_ts.into(),
        end_ts,
        extra_tag: None,
        extra_kinds: None,
        extra_authors: None,

        limit,
        total_sent,
    }));
}

fn plan_tag_queries(
    queries: &mut Vec<std::rc::Rc<IndexQuery>>,
    tq: &crate::TagQuery,
    start_ts: &[u8],
    end_ts: u32,
    extra_tag: Option<std::rc::Rc<crate::TagQuery>>,
    extra_kinds: Option<std::rc::Rc<Vec<rkyv::rend::u16_le>>>,
    extra_authors: Option<std::rc::Rc<Vec<[u8; 32]>>>,
    limit: Option<usize>,
    total_sent: std::rc::Rc<std::cell::RefCell<usize>>,
) {
    for v in &tq.1 {
        let mut key = [0u8; 1 + 8 + 4];
        key[1 + 8..].copy_from_slice(&start_ts);

        if tq.0.len() > 0 {
            key[0] = tq.0.as_bytes()[0];
        }

        let key = match lowercase_hex::decode_to_slice(v, &mut key[1..1 + 8]) {
            Ok(_) => Vec::from(&key[..]),
            Err(_) => {
                let mut s = foldhash::fast::FixedState::with_seed(TAG_HASHER_SEED).build_hasher();
                v.hash(&mut s);
                let hash = s.finish();
                key[1..1 + 8].copy_from_slice(&hash.to_ne_bytes());
                Vec::from(&key[..])
            }
        };

        queries.push(std::rc::Rc::new(IndexQuery {
            index: Index::Tag,
            key,

            end_ts,
            extra_tag: extra_tag.clone(),
            extra_kinds: extra_kinds.clone(),
            extra_authors: extra_authors.clone(),

            limit,
            total_sent: total_sent.clone(),
        }));
    }
}

#[derive(Debug)]
pub enum Index {
    Timestamp,
    Pubkey,
    PubkeyKind,
    Kind,
    Tag,
    PtagKtag,
}

#[derive(Debug)]
pub struct IndexKey<'a> {
    pub index: Index,
    pub key: &'a [u8],
}

fn get_index_keys_for_event<F>(event: &crate::Event, mut cb: F) -> crate::database::Result<()>
where
    F: FnMut(IndexKey) -> crate::database::Result<()>,
{
    // this is so the events are ordered from newer to older
    let ts_bytes = &event.created_at.invert().to_be_bytes();

    // by date only
    {
        cb(IndexKey {
            index: Index::Timestamp,
            key: ts_bytes,
        })?;
    }

    // by kind + date
    {
        let mut key = [0u8; 2 + 4];
        key[0..2].copy_from_slice(&event.kind.0.to_ne_bytes());
        key[2..].copy_from_slice(ts_bytes);
        cb(IndexKey {
            index: Index::Kind,
            key: &key,
        })?;
    }

    // by pubkey + date
    {
        let mut key = [0u8; 8 + 4];
        key[0..8].copy_from_slice(&event.pubkey.short().0.to_ne_bytes());
        key[8..].copy_from_slice(ts_bytes);
        cb(IndexKey {
            index: Index::Pubkey,
            key: &key,
        })?;
    }

    // by pubkey + kind + date
    {
        let mut key = [0u8; 8 + 2 + 4];
        key[0..8].copy_from_slice(&event.pubkey.short().0.to_ne_bytes());
        key[8..8 + 2].copy_from_slice(&event.kind.0.to_ne_bytes());
        key[8 + 2..].copy_from_slice(ts_bytes);
        cb(IndexKey {
            index: Index::PubkeyKind,
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
                    index: Index::Tag,
                    key: key,
                })?;
                continue;
            }
        }

        let mut s = foldhash::fast::FixedState::with_seed(TAG_HASHER_SEED).build_hasher();
        tag[1].hash(&mut s);
        let hash = s.finish();
        key[1..1 + 8].copy_from_slice(hash.to_ne_bytes().as_slice());

        cb(IndexKey {
            index: Index::Tag,
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
                                    index: Index::PtagKtag,
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
