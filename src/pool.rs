use crate::{Event, Filter, Relay, RelayEvent, Result, SubscriptionOptions};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};

/// pool manages connections to multiple relays
pub struct Pool {
    relays: Arc<DashMap<String, Arc<Mutex<Relay>>>>,
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

    /// get or create a relay connection to the given url
    pub async fn ensure_relay(&self, url: &str) -> Result<Arc<Mutex<Relay>>> {
        let normalized_url = crate::normalize::normalize_url(url)?;

        // check penalty box
        if let Some(ref penalty_box) = self.penalty_box {
            if let Some(pb) = penalty_box.get(normalized_url.as_str()) {
                let (_, remaining) = *pb;
                if remaining > 0 {
                    return Err(format!("in penalty box, {}s remaining", remaining).into());
                }
            }
        }

        // check if relay already exists
        if let Some(relay) = self.relays.get(normalized_url.as_str()) {
            return Ok(relay.clone());
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
                let r = Arc::new(Mutex::new(relay));
                self.relays.insert(normalized_url.to_string(), r.clone());
                Ok(r)
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
                Err(format!("failed to connect: {}", err).into())
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
                    Ok(relay) => match relay.lock().await.publish(event).await {
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

    /// subscribe to events from multiple relays
    pub async fn subscribe_many(
        &self,
        urls: Vec<String>,
        filter: Filter,
        label: Option<String>,
    ) -> mpsc::Receiver<RelayEvent> {
        let (tx, rx) = mpsc::channel(1);

        for url in urls {
            let tx = tx.clone();
            let filter = filter.clone();
            let pool = self.clone();
            let label = label.clone();

            tokio::spawn(async move {
                if let Ok(relay) = pool.ensure_relay(&url).await {
                    let relay = relay.lock().await;
                    if let Ok(subscription) = relay
                        .subscribe(filter, SubscriptionOptions { label: label })
                        .await
                    {
                        let mut sub = subscription.lock().await;
                        while let Some(event) = sub.events.recv().await {
                            let _ = tx
                                .send(RelayEvent {
                                    event,
                                    relay_url: relay.url.clone(),
                                })
                                .await;
                        }
                    }
                }
            });
        }

        rx
    }

    /// close the pool
    pub async fn close(self) {
        for relay in self.relays.iter() {
            let _ = relay.clone().lock().await.close().await;
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
