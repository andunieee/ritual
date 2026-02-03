use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use crate::database::{
    Cursor, DatabaseError, EventDatabase, Index, IndexKey, ReadTransaction, Result,
    WriteTransaction,
};

/// btree-based in-memory event database
pub struct BTreeEventDatabase {
    // main event storage: shortid -> archived event bytes (using Arc to safely return references)
    events: Arc<RwLock<BTreeMap<u64, Arc<Vec<u8>>>>>,

    // indexes: binary key -> shortid
    index_timestamp: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    index_pubkey: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    index_pubkey_kind: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    index_kind: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    index_tag: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    index_ptag_ktag: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
}

impl BTreeEventDatabase {
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(BTreeMap::new())),
            index_timestamp: Arc::new(RwLock::new(BTreeMap::new())),
            index_pubkey: Arc::new(RwLock::new(BTreeMap::new())),
            index_pubkey_kind: Arc::new(RwLock::new(BTreeMap::new())),
            index_kind: Arc::new(RwLock::new(BTreeMap::new())),
            index_tag: Arc::new(RwLock::new(BTreeMap::new())),
            index_ptag_ktag: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }
}

impl Default for BTreeEventDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl EventDatabase for BTreeEventDatabase {
    type ReadTxn<'t> = BTreeReadTransaction;
    type WriteTxn<'t> = BTreeWriteTransaction;

    fn begin_read_txn<'t>(&self) -> Self::ReadTxn<'t> {
        BTreeReadTransaction {
            events: self.events.clone(),
            index_timestamp: self.index_timestamp.clone(),
            index_pubkey: self.index_pubkey.clone(),
            index_pubkey_kind: self.index_pubkey_kind.clone(),
            index_kind: self.index_kind.clone(),
            index_tag: self.index_tag.clone(),
            index_ptag_ktag: self.index_ptag_ktag.clone(),
            leaked_refs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn begin_write_txn<'t>(&self) -> Self::WriteTxn<'t> {
        BTreeWriteTransaction {
            events: self.events.clone(),
            index_timestamp: self.index_timestamp.clone(),
            index_pubkey: self.index_pubkey.clone(),
            index_pubkey_kind: self.index_pubkey_kind.clone(),
            index_kind: self.index_kind.clone(),
            index_tag: self.index_tag.clone(),
            index_ptag_ktag: self.index_ptag_ktag.clone(),
            current_event_id: Arc::new(Mutex::new(None)),
            leaked_refs: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[derive(Clone)]
pub struct BTreeReadTransaction {
    events: Arc<RwLock<BTreeMap<u64, Arc<Vec<u8>>>>>,
    index_timestamp: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    index_pubkey: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    index_pubkey_kind: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    index_kind: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    index_tag: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    index_ptag_ktag: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    // keep Arcs alive during transaction to prevent memory leaks
    leaked_refs: Arc<Mutex<Vec<Arc<Vec<u8>>>>>,
}

impl<'t> ReadTransaction<'t> for BTreeReadTransaction {
    type Cursor = BTreeCursor;

    fn has_event(&self, id: crate::ShortID) -> bool {
        self.events.read().unwrap().contains_key(&id.0)
    }

    fn get_event(&self, id: crate::ShortID) -> Result<&'t crate::ArchivedEvent> {
        // get the Arc<Vec<u8>> from the map
        let events = self.events.read().unwrap();
        let bytes_arc = events
            .get(&id.0)
            .ok_or(DatabaseError::EventNotFound)?
            .clone();
        drop(events);

        // keep the Arc alive by storing it in the transaction
        self.leaked_refs.lock().unwrap().push(bytes_arc.clone());

        // convert Arc to raw pointer to get a reference with lifetime 't
        let ptr = Arc::into_raw(bytes_arc);
        let bytes_ref = unsafe { &*ptr };

        let archived =
            unsafe { rkyv::access_unchecked::<crate::ArchivedEvent>(bytes_ref.as_slice()) };

        Ok(archived)
    }

    fn new_cursor(&self, query: &crate::database::IndexQuery) -> Self::Cursor {
        let index_map = match query.index {
            Index::Timestamp => self.index_timestamp.clone(),
            Index::Pubkey => self.index_pubkey.clone(),
            Index::PubkeyKind => self.index_pubkey_kind.clone(),
            Index::Kind => self.index_kind.clone(),
            Index::Tag => self.index_tag.clone(),
            Index::PtagKtag => self.index_ptag_ktag.clone(),
        };

        BTreeCursor {
            index_map,
            start_key: query.key.clone(),
            end_ts: query.end_ts,
            pulled_ids: Vec::new(),
            last_read_ts: u32::MAX,
            first_pulled_ts: 0,
            done: false,
            last_key: None,
        }
    }
}

pub struct BTreeWriteTransaction {
    events: Arc<RwLock<BTreeMap<u64, Arc<Vec<u8>>>>>,
    index_timestamp: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    index_pubkey: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    index_pubkey_kind: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    index_kind: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    index_tag: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    index_ptag_ktag: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    // track the current event being saved for index operations
    current_event_id: Arc<Mutex<Option<u64>>>,
    // keep Arcs alive during transaction to prevent memory leaks
    leaked_refs: Arc<Mutex<Vec<Arc<Vec<u8>>>>>,
}

impl Clone for BTreeWriteTransaction {
    fn clone(&self) -> Self {
        Self {
            events: self.events.clone(),
            index_timestamp: self.index_timestamp.clone(),
            index_pubkey: self.index_pubkey.clone(),
            index_pubkey_kind: self.index_pubkey_kind.clone(),
            index_kind: self.index_kind.clone(),
            index_tag: self.index_tag.clone(),
            index_ptag_ktag: self.index_ptag_ktag.clone(),
            current_event_id: self.current_event_id.clone(),
            leaked_refs: self.leaked_refs.clone(),
        }
    }
}

impl<'t> ReadTransaction<'t> for BTreeWriteTransaction {
    type Cursor = BTreeCursor;

    fn has_event(&self, id: crate::ShortID) -> bool {
        self.events.read().unwrap().contains_key(&id.0)
    }

    fn get_event(&self, id: crate::ShortID) -> Result<&'t crate::ArchivedEvent> {
        // get the Arc<Vec<u8>> from the map
        let events = self.events.read().unwrap();
        let bytes_arc = events
            .get(&id.0)
            .ok_or(DatabaseError::EventNotFound)?
            .clone();
        drop(events);

        // keep the Arc alive by storing it in the transaction
        self.leaked_refs.lock().unwrap().push(bytes_arc.clone());

        // convert Arc to raw pointer to get a reference with lifetime 't
        let ptr = Arc::into_raw(bytes_arc);
        let bytes_ref = unsafe { &*ptr };

        let archived =
            unsafe { rkyv::access_unchecked::<crate::ArchivedEvent>(bytes_ref.as_slice()) };

        Ok(archived)
    }

    fn new_cursor(&self, query: &crate::database::IndexQuery) -> Self::Cursor {
        let index_map = match query.index {
            Index::Timestamp => self.index_timestamp.clone(),
            Index::Pubkey => self.index_pubkey.clone(),
            Index::PubkeyKind => self.index_pubkey_kind.clone(),
            Index::Kind => self.index_kind.clone(),
            Index::Tag => self.index_tag.clone(),
            Index::PtagKtag => self.index_ptag_ktag.clone(),
        };

        BTreeCursor {
            index_map,
            start_key: query.key.clone(),
            end_ts: query.end_ts,
            pulled_ids: Vec::new(),
            last_read_ts: u32::MAX,
            first_pulled_ts: 0,
            done: false,
            last_key: None,
        }
    }
}

impl<'t> WriteTransaction<'t> for BTreeWriteTransaction {
    fn put_event(&mut self, event: &crate::Event) -> Result<()> {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(event)?;
        let short_id = event.id.short().0;

        // store the current event id for use in put_key calls
        *self.current_event_id.lock().unwrap() = Some(short_id);

        self.events
            .write()
            .unwrap()
            .insert(short_id, Arc::new(bytes.to_vec()));
        Ok(())
    }

    fn del_event(&mut self, id: crate::ShortID) -> Result<()> {
        self.events.write().unwrap().remove(&id.0);
        Ok(())
    }

    fn put_key(&mut self, index_key: IndexKey) -> Result<()> {
        let index_map = match index_key.index {
            Index::Timestamp => &self.index_timestamp,
            Index::Pubkey => &self.index_pubkey,
            Index::PubkeyKind => &self.index_pubkey_kind,
            Index::Kind => &self.index_kind,
            Index::Tag => &self.index_tag,
            Index::PtagKtag => &self.index_ptag_ktag,
        };

        // get the current event's short_id that was set in put_event
        let short_id = self.current_event_id.lock().unwrap().ok_or_else(|| {
            DatabaseError::InvalidFilter("put_key called without a current event".to_string())
        })?;

        // insert the index entry: index_key -> event_short_id
        index_map
            .write()
            .unwrap()
            .insert(index_key.key.to_vec(), short_id);
        Ok(())
    }

    fn del_key(&mut self, index_key: IndexKey) -> Result<()> {
        let index_map = match index_key.index {
            Index::Timestamp => &self.index_timestamp,
            Index::Pubkey => &self.index_pubkey,
            Index::PubkeyKind => &self.index_pubkey_kind,
            Index::Kind => &self.index_kind,
            Index::Tag => &self.index_tag,
            Index::PtagKtag => &self.index_ptag_ktag,
        };

        index_map.write().unwrap().remove(index_key.key);
        Ok(())
    }
}

pub struct BTreeCursor {
    index_map: Arc<RwLock<BTreeMap<Vec<u8>, u64>>>,
    start_key: Vec<u8>,
    end_ts: u32,
    pulled_ids: Vec<crate::ShortID>,
    last_read_ts: u32,
    first_pulled_ts: u32,
    done: bool,
    last_key: Option<Vec<u8>>,
}

impl<'t> Cursor<'t> for BTreeCursor {
    fn pull(&mut self) {
        if self.done {
            return;
        }

        let map = self.index_map.read().unwrap();
        let mut count = 0;
        const PULL_BATCH_SIZE: usize = 16;

        // determine the range to iterate
        // we need to use a different approach to avoid collecting into a Vec
        let mut keys_to_process: Vec<(Vec<u8>, u64)> = Vec::with_capacity(PULL_BATCH_SIZE);

        if let Some(ref last) = self.last_key {
            // subsequent pulls: exclude the last key we already processed
            for (key, &short_id) in map.range::<Vec<u8>, _>(..last.clone()).rev() {
                if keys_to_process.len() >= PULL_BATCH_SIZE {
                    break;
                }
                keys_to_process.push((key.clone(), short_id));
            }
        } else {
            // first pull: include the start_key
            for (key, &short_id) in map.range::<Vec<u8>, _>(..=self.start_key.clone()).rev() {
                if keys_to_process.len() >= PULL_BATCH_SIZE {
                    break;
                }
                keys_to_process.push((key.clone(), short_id));
            }
        }

        for (key, short_id) in keys_to_process {
            // extract timestamp from the key (last 4 bytes)
            let key_len = key.len();
            if key_len < 4 {
                continue;
            }

            let ts_bytes: [u8; 4] = key[key_len - 4..].try_into().unwrap();

            // timestamps are stored inverted and in big-endian
            let inverted_ts = u32::from_be_bytes(ts_bytes);
            let actual_ts = u32::MAX - inverted_ts;

            if actual_ts < self.end_ts {
                self.done = true;
                break;
            }

            self.pulled_ids.push(crate::ShortID(short_id));
            self.last_read_ts = actual_ts;

            if count == 0 {
                self.first_pulled_ts = actual_ts;
            }

            // save this key for next iteration
            self.last_key = Some(key.clone());

            count += 1;
        }

        if count < PULL_BATCH_SIZE {
            self.done = true;
        }
    }

    fn last_read_timestamp(&self) -> u32 {
        self.last_read_ts
    }

    fn total_pulled(&self) -> usize {
        self.pulled_ids.len()
    }

    fn set_done(&mut self) {
        self.done = true;
    }

    fn is_done(&self) -> bool {
        self.done
    }

    fn first_pulled_timestamp(&self) -> u32 {
        self.first_pulled_ts
    }

    fn pop_front_pulled_id(&mut self) -> crate::ShortID {
        self.pulled_ids.remove(0)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        BTreeEventDatabase, Event, EventDatabase, Filter, ID, Kind, Signature, Tags, Timestamp,
        database::ReadTransaction,
    };

    #[test]
    fn test_btree_database_basic_operations() {
        let db = BTreeEventDatabase::new();

        // create a test event with a valid public key
        let event = Event {
            id: ID::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .parse()
                .unwrap(),
            created_at: Timestamp(1234567890),
            kind: Kind(1),
            tags: Tags::default(),
            content: "test event".to_string(),
            sig: Signature::from_bytes([0u8; 64]),
        };

        // test saving and retrieving event
        db.save_event(&event).unwrap();

        let mut results = db.query_events(&mut [Filter::default()]);
        let retrieved = results.next().unwrap();
        assert_eq!(event.id, retrieved.id);

        // test has_event
        assert!(db.begin_read_txn().has_event(event.id.short()));

        // test delete
        db.delete_event(event.id.short()).unwrap();
        assert!(!db.begin_read_txn().has_event(event.id.short()));
    }

    #[test]
    fn test_btree_database_query_by_author() {
        let db = BTreeEventDatabase::new();

        let event = Event {
            id: ID::from_hex("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap(),
            pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .parse()
                .unwrap(),
            created_at: Timestamp(1234567890),
            kind: Kind(1),
            tags: Tags::default(),
            content: "test event by author".to_string(),
            sig: Signature::from_bytes([0u8; 64]),
        };

        db.save_event(&event).unwrap();

        let filter = Filter {
            authors: Some(vec![event.pubkey]),
            ..Default::default()
        };

        let mut results = db.query_events(&mut [filter]);
        let retrieved = results.next().unwrap();
        assert_eq!(event.pubkey.0, retrieved.pubkey.0);
    }

    #[test]
    fn test_btree_database_query_by_kind() {
        let db = BTreeEventDatabase::new();

        let event = Event {
            id: ID::from_hex("2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap(),
            pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .parse()
                .unwrap(),
            created_at: Timestamp(1234567890),
            kind: Kind(5),
            tags: Tags::default(),
            content: "test event with specific kind".to_string(),
            sig: Signature::from_bytes([0u8; 64]),
        };

        db.save_event(&event).unwrap();

        let filter = Filter {
            kinds: Some(vec![event.kind]),
            ..Default::default()
        };

        let mut results = db.query_events(&mut [filter]);
        let retrieved = results.next().unwrap();
        assert_eq!(event.kind.0, retrieved.kind.0);
    }
}
