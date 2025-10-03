use tokio_with_wasm::alias as tokio;

#[derive(thiserror::Error, Debug)]
pub enum EnsureError {
    #[error("URL normalization error")]
    Normalize(#[from] url::ParseError),

    #[error("failed to connect: {0}")]
    Connect(#[from] crate::relay::ConnectError),
}

#[derive(Debug)]
pub struct Pool {
    relays: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, crate::Relay>>>,
}

pub struct PublishResult {
    pub error: Option<String>,
    pub relay_url: String,
}

#[derive(Debug)]
pub enum Occurrence {
    Event(crate::Event, url::Url),
    EOSE,
    Close,
}

impl Pool {
    pub fn new() -> Self {
        Self {
            relays: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// get an existing relay connection if it exists, do not try to open a new one
    pub async fn get_relay(&self, url: &str) -> Option<crate::Relay> {
        let normalized_url = crate::normalize_url(url).ok()?;
        self.relays
            .lock()
            .await
            .get(normalized_url.as_str())
            .map(|relay| relay.clone())
    }

    /// get or create a relay connection to the given url
    pub async fn ensure_relay(&self, url: &str) -> Result<crate::Relay, EnsureError> {
        let normalized_url = crate::normalize_url(url)?;

        // check if relay already exists
        let mut relay_map = self.relays.lock().await;
        if let Some(relay) = relay_map.get(normalized_url.as_str()) {
            return Ok(relay.clone());
        }

        // create new relay connection
        let (on_close, handle_close) = tokio::sync::oneshot::channel::<String>();
        let nm_ = normalized_url.clone();
        let relay_map_on_close = self.relays.clone();
        tokio::spawn(async move {
            match handle_close.await {
                Ok(reason) => {
                    log::info!("[{}] relay connection closed: {}", nm_.as_str(), reason);

                    // the relay connection will be dropped from the map if it disconnects
                    relay_map_on_close.lock().await.remove(nm_.as_str());
                }
                Err(err) => {
                    log::info!(
                        "got an error from the handle_close oneshot for {}: {}",
                        nm_.as_str(),
                        err
                    );
                }
            }
        });

        match crate::Relay::connect(normalized_url.to_owned(), Some(on_close)).await {
            Ok(relay) => {
                relay_map.insert(normalized_url.to_string(), relay.clone());
                Ok(relay)
            }
            Err(err) => Err(EnsureError::Connect(err)),
        }
    }

    /// publish an event to multiple relays
    pub async fn publish_many(
        &mut self,
        urls: Vec<String>,
        event: crate::Event,
    ) -> tokio::sync::mpsc::UnboundedReceiver<PublishResult> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

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
        filter: crate::Filter,
        subscription_options: crate::SubscriptionOptions,
    ) -> Vec<crate::Event> {
        let mut events = Vec::with_capacity(filter.limit.unwrap_or(500) * urls.len() / 2);

        let mut occurrences = self.subscribe(urls, filter, subscription_options).await;
        while let Some(occ) = occurrences.recv().await {
            match occ {
                Occurrence::Event(event, _) => {
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
        filter: crate::Filter,
        subscription_options: crate::SubscriptionOptions,
    ) -> tokio::sync::mpsc::Receiver<Occurrence> {
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let skip_ids = std::sync::Arc::new(dashmap::DashSet::new());
        let eose_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(urls.len()));
        let closed_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(urls.len()));
        let eosed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        for url in urls {
            let filter = filter.clone();
            let pool = self.clone();
            let opts = crate::SubscriptionOptions {
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
                            crate::relay::Occurrence::Event(event) => {
                                if tx
                                    .send(Occurrence::Event(event, relay.url.clone()))
                                    .await
                                    .is_err()
                                {
                                    // receiver dropped
                                    return;
                                }
                            }
                            crate::relay::Occurrence::EOSE => {
                                if eose_counter.fetch_sub(1, std::sync::atomic::Ordering::SeqCst)
                                    == 1
                                {
                                    if !eosed.swap(true, std::sync::atomic::Ordering::SeqCst) {
                                        if tx.send(Occurrence::EOSE).await.is_err() {
                                            // receiver dropped
                                            return;
                                        }
                                    }
                                }
                            }
                            crate::relay::Occurrence::Close(_) => break,
                        }
                    }
                }

                // if we are here, it means ensure_relay or subscribe failed or the subscription ended.
                if eose_counter.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1 {
                    if !eosed.swap(true, std::sync::atomic::Ordering::SeqCst) {
                        if tx.send(Occurrence::EOSE).await.is_err() {
                            // receiver dropped
                            return;
                        }
                    }
                }

                if closed_counter.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1 {
                    if tx.send(Occurrence::Close).await.is_err() {
                        // receiver dropped
                        return;
                    }
                }
            });
        }

        drop(tx);
        rx
    }
}

// we can clone the pool because its fields are just arcs
impl Clone for Pool {
    fn clone(&self) -> Self {
        Self {
            relays: self.relays.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use std::collections::HashSet;

    #[tokio::test]
    async fn test_pool_subscribe_multiple() {
        let pool = Pool::new();

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
        let pool = Pool::new();

        let relay1 = pool.ensure_relay("wss://nos.lol").await.unwrap();
        let relay2 = pool.ensure_relay("wss://nos.lol").await.unwrap();

        // should return the same relay instance
        assert!(std::ptr::eq(
            relay1.sub_sender_map.as_ref() as *const _,
            relay2.sub_sender_map.as_ref() as *const _
        ));
    }
}
