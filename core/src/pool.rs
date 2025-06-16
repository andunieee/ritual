use crate::{Event, Filter, Relay, RelayOptions, Result, SubscriptionOptions, RelayEvent};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

/// Pool manages connections to multiple relays
pub struct Pool {
    relays: Arc<DashMap<String, Arc<Relay>>>,
    auth_handler: Option<Box<dyn Fn(&Event) -> Result<()> + Send + Sync>>,
    event_middleware: Option<Box<dyn Fn(&RelayEvent) + Send + Sync>>,
    duplicate_middleware: Option<Box<dyn Fn(&str, &crate::ID) + Send + Sync>>,
    relay_options: RelayOptions,
    penalty_box: Option<Arc<DashMap<String, (f64, f64)>>>, // (failures, remaining_seconds)
}

/// Options for creating a pool
#[derive(Default)]
pub struct PoolOptions {
    pub auth_handler: Option<Box<dyn Fn(&Event) -> Result<()> + Send + Sync>>,
    pub penalty_box: bool,
    pub event_middleware: Option<Box<dyn Fn(&RelayEvent) + Send + Sync>>,
    pub duplicate_middleware: Option<Box<dyn Fn(&str, &crate::ID) + Send + Sync>>,
    pub relay_options: RelayOptions,
}

/// Result of publishing an event
pub struct PublishResult {
    pub error: Option<String>,
    pub relay_url: String,
    pub relay: Option<Arc<Relay>>,
}

/// Directed filter combines a filter with a specific relay URL
pub struct DirectedFilter {
    pub filter: Filter,
    pub relay: String,
}

impl Pool {
    /// Create a new pool
    pub fn new(opts: PoolOptions) -> Self {
        let penalty_box = if opts.penalty_box {
            Some(Arc::new(DashMap::new()))
        } else {
            None
        };

        Self {
            relays: Arc::new(DashMap::new()),
            auth_handler: opts.auth_handler,
            event_middleware: opts.event_middleware,
            duplicate_middleware: opts.duplicate_middleware,
            relay_options: opts.relay_options,
            penalty_box,
        }
    }

    /// Ensure a relay connection exists and is active
    pub async fn ensure_relay(&self, url: &str) -> Result<Arc<Relay>> {
        let normalized_url = crate::normalize::normalize_url(url);
        
        // Check penalty box
        if let Some(ref penalty_box) = self.penalty_box {
            if let Some((_, remaining)) = penalty_box.get(&normalized_url) {
                if *remaining > 0.0 {
                    return Err(format!("in penalty box, {}s remaining", remaining).into());
                }
            }
        }

        // Check if relay already exists and is connected
        if let Some(relay) = self.relays.get(&normalized_url) {
            if relay.is_connected() {
                return Ok(relay.clone());
            }
        }

        // Create new relay and connect
        let mut relay = Relay::new(&normalized_url, RelayOptions::default());
        
        match relay.connect().await {
            Ok(_) => {
                let relay = Arc::new(relay);
                self.relays.insert(normalized_url, relay.clone());
                Ok(relay)
            }
            Err(err) => {
                // Add to penalty box
                if let Some(ref penalty_box) = self.penalty_box {
                    let (failures, _) = penalty_box.get(&normalized_url).map(|v| *v).unwrap_or((0.0, 0.0));
                    let new_penalty = 30.0 + 2.0_f64.powf(failures + 1.0);
                    penalty_box.insert(normalized_url, (failures + 1.0, new_penalty));
                }
                Err(format!("failed to connect: {}", err).into())
            }
        }
    }

    /// Publish an event to multiple relays
    pub async fn publish_many(&self, urls: Vec<String>, event: Event) -> mpsc::UnboundedReceiver<PublishResult> {
        let (tx, rx) = mpsc::unbounded_channel();
        
        for url in urls {
            let tx = tx.clone();
            let event = event.clone();
            let pool = self.clone();
            
            tokio::spawn(async move {
                let result = match pool.ensure_relay(&url).await {
                    Ok(relay) => {
                        match relay.publish(event).await {
                            Ok(_) => PublishResult {
                                error: None,
                                relay_url: url.clone(),
                                relay: Some(relay),
                            },
                            Err(err) => PublishResult {
                                error: Some(err.to_string()),
                                relay_url: url.clone(),
                                relay: Some(relay),
                            },
                        }
                    }
                    Err(err) => PublishResult {
                        error: Some(err.to_string()),
                        relay_url: url.clone(),
                        relay: None,
                    },
                };
                
                let _ = tx.send(result);
            });
        }
        
        rx
    }

    /// Subscribe to events from multiple relays
    pub async fn subscribe_many(
        &self,
        urls: Vec<String>,
        filter: Filter,
        opts: SubscriptionOptions,
    ) -> mpsc::UnboundedReceiver<RelayEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        
        for url in urls {
            let tx = tx.clone();
            let filter = filter.clone();
            let opts = opts.clone();
            let pool = self.clone();
            
            tokio::spawn(async move {
                if let Ok(relay) = pool.ensure_relay(&url).await {
                    if let Ok(subscription) = relay.subscribe(filter, opts).await {
                        // Handle events from this subscription
                        // This is a simplified version - full implementation would handle the subscription properly
                    }
                }
            });
        }
        
        rx
    }

    /// Close the pool
    pub async fn close(&self) {
        for relay in self.relays.iter() {
            // Close each relay connection
            // This would need to be implemented properly
        }
    }
}

impl Clone for Pool {
    fn clone(&self) -> Self {
        Self {
            relays: self.relays.clone(),
            auth_handler: None, // Can't clone function pointers easily
            event_middleware: None,
            duplicate_middleware: None,
            relay_options: RelayOptions::default(),
            penalty_box: self.penalty_box.clone(),
        }
    }
}
