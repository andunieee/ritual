use crate::{
    normalize_url,
    relay::{self, Occurrence, Relay, SubscriptionOptions},
    Event, Filter,
};
use dashmap::{DashMap, DashSet};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use thiserror::Error;
use tokio_with_wasm::alias as tokio;
use tokio::sync::{mpsc, oneshot};

#[derive(Error, Debug)]
pub enum EnsureError {
    #[error("in penalty box, {0}s remaining")]
    PenaltyBox(u32),

    #[error("URL normalization error")]
    Normalize(#[from] url::ParseError),

    #[error("failed to connect: {0}")]
    Connect(#[from] relay::ConnectError),
}

#[derive(Debug)]
pub struct Pool {
    relays: Arc<DashMap<String, Relay>>,
    penalty_box: Option<Arc<DashMap<String, (u16, u32)>>>, // (failures, remaining_seconds)
}

#[derive(Default)]
pub struct PoolOptions {
    pub penalty_box: bool,
}

pub struct PublishResult {
    pub error: Option<String>,
    pub relay_url: String,
}

pub struct DirectedFilter {
    pub filter: Filter,
    pub relay: String,
}

impl Pool {
    pub fn new(opts: PoolOptions) -> Self {
        let penalty_box = if opts.penalty_box {
            Some(Arc::new(DashMap::new()))
        } else {
            None
        };

        Self {
            relays: Arc::new(DashMap::new()),
            penalty_box,
        }
    }

    /// get an existing relay connection if it exists, do not try to open a new one
    pub fn get_relay(&self, url: &str) -> Option<Relay> {
        let normalized_url = normalize_url(url).ok()?;
        self.relays
            .get(normalized_url.as_str())
            .map(|relay| relay.clone())
    }

    /// get or create a relay connection to the given url
    pub async fn ensure_relay(&self, url: &str) -> Result<Relay, EnsureError> {
        let normalized_url = normalize_url(url)?;

        // check if relay already exists
        if let Some(relay) = self.relays.get(normalized_url.as_str()) {
            return Ok(relay.clone());
        }

        // check penalty box
        if let Some(ref penalty_box) = self.penalty_box {
            if let Some(pb) = penalty_box.get(normalized_url.as_str()) {
                let (_, remaining) = *pb;
                if remaining > 0 {
                    return Err(EnsureError::PenaltyBox(remaining));
                }
            }
        }

        // create new relay connection
        let (on_close, handle_close) = oneshot::channel::<String>();
        let nm_ = normalized_url.clone();
        let relays_map = self.relays.clone();
        tokio::spawn(async move {
            match handle_close.await {
                Ok(reason) => {
                    println!("[{}] relay connection closed: {}", nm_.as_str(), reason);

                    // the relay connection will be dropped from the map if it disconnects
                    relays_map.remove(nm_.as_str());
                }
                Err(err) => {
                    println!(
                        "got an error from the handle_close oneshot for {}: {}",
                        nm_.as_str(),
                        err
                    );
                }
            }
        });

        match Relay::connect(normalized_url.to_owned(), Some(on_close)).await {
            Ok(relay) => {
                self.relays
                    .insert(normalized_url.to_string(), relay.clone());
                Ok(relay)
            }
            Err(err) => {
                // add to penalty box
                if let Some(ref penalty_box) = self.penalty_box {
                    let (failures, _) = penalty_box
                        .get(normalized_url.as_str())
                        .map(|v| *v)
                        .unwrap_or((0u16, 0u32));
                    let new_penalty = 30 + 2u32.pow(failures as u32 + 1);
                    penalty_box.insert(normalized_url.to_string(), (failures + 1, new_penalty));
                }
                Err(EnsureError::Connect(err))
            }
        }
    }

    /// publish an event to multiple relays
    pub async fn publish_many(
        &mut self,
        urls: Vec<String>,
        event: Event,
    ) -> mpsc::UnboundedReceiver<PublishResult> {
        let (tx, rx) = mpsc::unbounded_channel();

        for url in urls {
            let tx = tx.clone();
            let event = event.clone();
            let pool = self.clone();

            tokio::spawn(async move {
                let result = match pool.ensure_relay(&url).await {
                    Ok(relay) => match relay.publish(event).await {
                        Ok(_) => PublishResult {
                            error: None,
                            relay_url: url.clone(),
                        },
                        Err(err) => PublishResult {
                            error: Some(err.to_string()),
                            relay_url: url.clone(),
                        },
                    },
                    Err(err) => PublishResult {
                        error: Some(err.to_string()),
                        relay_url: url.clone(),
                    },
                };

                let _ = tx.send(result);
            });
        }

        rx
    }

    /// subscribe to events from multiple relays, stop on EOSE, return a sorted list
    pub async fn query(
        &self,
        urls: Vec<String>,
        filter: Filter,
        subscription_options: SubscriptionOptions,
    ) -> Vec<Event> {
        let mut events = Vec::with_capacity(filter.limit.unwrap_or(500) * urls.len() / 2);

        let mut occurrences = self.subscribe(urls, filter, subscription_options).await;
        while let Some(occ) = occurrences.recv().await {
            match occ {
                Occurrence::Event(event) => {
                    events.push(event);
                }
                _ => {
                    break;
                }
            }
        }

        glidesort::sort_by_key(&mut events, |event| u32::MAX - event.created_at.0);
        events
    }

    /// subscribe to events from multiple relays, returns a channel that will receive occurrences
    pub async fn subscribe(
        &self,
        urls: Vec<String>,
        filter: Filter,
        subscription_options: SubscriptionOptions,
    ) -> mpsc::Receiver<Occurrence> {
        let (tx, rx) = mpsc::channel(256);
        let skip_ids = Arc::new(DashSet::new());
        let eose_counter = Arc::new(AtomicUsize::new(urls.len()));
        let closed_counter = Arc::new(AtomicUsize::new(urls.len()));
        let eosed = Arc::new(AtomicBool::new(false));

        for url in urls {
            let filter = filter.clone();
            let pool = self.clone();
            let opts = SubscriptionOptions {
                skip_ids: Some(skip_ids.clone()),
                ..subscription_options.clone()
            };
            let tx = tx.clone();
            let eose_counter = eose_counter.clone();
            let closed_counter = closed_counter.clone();
            let eosed = eosed.clone();

            tokio::spawn(async move {
                if let Ok(relay) = pool.ensure_relay(&url).await {
                    let mut sub = relay.subscribe(filter, opts).await;
                    while let Some(occ) = sub.recv().await {
                        match occ {
                            Occurrence::Event(event) => {
                                if tx.send(Occurrence::Event(event)).await.is_err() {
                                    // receiver dropped
                                    return;
                                }
                            }
                            Occurrence::EOSE => {
                                if eose_counter.fetch_sub(1, Ordering::SeqCst) == 1 {
                                    if !eosed.swap(true, Ordering::SeqCst) {
                                        if tx.send(Occurrence::EOSE).await.is_err() {
                                            // receiver dropped
                                            return;
                                        }
                                    }
                                }
                            }
                            Occurrence::Close(_) => break,
                        }
                    }
                }

                // if we are here, it means ensure_relay or subscribe failed or the subscription ended.
                if eose_counter.fetch_sub(1, Ordering::SeqCst) == 1 {
                    if !eosed.swap(true, Ordering::SeqCst) {
                        if tx.send(Occurrence::EOSE).await.is_err() {
                            // receiver dropped
                            return;
                        }
                    }
                }

                if closed_counter.fetch_sub(1, Ordering::SeqCst) == 1 {
                    if tx
                        .send(Occurrence::Close(crate::relay::CloseReason::Unknown))
                        .await
                        .is_err()
                    {
                        // receiver dropped
                        return;
                    }
                }
            });
        }

        drop(tx);
        rx
    }

    /// close the pool
    pub async fn close(self) {
        for relay in self.relays.iter() {
            let _ = relay.clone().close().await;
        }
        self.relays.clear(); // this has to be called as the "on_close" handler won't be triggered
    }
}

// we can clone the pool because its fields are just arcs
impl Clone for Pool {
    fn clone(&self) -> Self {
        Self {
            relays: self.relays.clone(),
            penalty_box: self.penalty_box.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::Kind;

    use super::*;

    #[tokio::test]
    async fn test_pool_subscribe_multiple() {
        let pool = Pool::new(PoolOptions::default());

        let urls = vec![
            "wss://nos.lol".to_string(),
            "wss://nostr.wine".to_string(),
            "wss://nostr.mom".to_string(),
            "wss://relay.damus.io".to_string(),
            "wss://relay.primal.net".to_string(),
        ];

        let filter = Filter {
            kinds: Some(vec![Kind(1), Kind(1111)]),
            limit: Some(5),
            ..Default::default()
        };

        let events = pool
            .query(
                urls,
                filter,
                SubscriptionOptions {
                    label: Some("test".to_string()),
                    ..Default::default()
                },
            )
            .await;

        assert!(events.len() > 10, "was {}", events.len()); // should be greater than 10 since we're reading 5 from each relay
        assert!(events.len() < 25, "was {}", events.len()); // but still we should have eliminated some duplicates so less than 25

        // ok let's be sure there are no duplicates
        let mut ids = HashSet::new();
        for event in events.iter() {
            assert!(ids.insert(event.id));
        }
    }

    #[tokio::test]
    async fn test_pool_ensure() {
        let pool = Pool::new(PoolOptions::default());

        let relay1 = pool.ensure_relay("wss://nos.lol").await.unwrap();
        let relay2 = pool.ensure_relay("wss://nos.lol").await.unwrap();

        // should return the same relay instance
        assert!(std::ptr::eq(
            relay1.sub_sender_map.as_ref() as *const _,
            relay2.sub_sender_map.as_ref() as *const _
        ));
    }
}
