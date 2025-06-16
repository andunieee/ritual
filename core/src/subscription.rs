use crate::{Event, Filter, Timestamp, ID};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// Subscription options
#[derive(Clone, Default)]
pub struct SubscriptionOptions {
    /// Label for the subscription
    pub label: String,

    /// Function to check for duplicate events
    pub check_duplicate: Option<Arc<dyn Fn(&ID, &str) -> bool + Send + Sync>>,

    /// Function to check for duplicate replaceable events
    pub check_duplicate_replaceable:
        Option<Arc<dyn Fn(&ReplaceableKey, Timestamp) -> bool + Send + Sync>>,
}

/// Key for replaceable events
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReplaceableKey {
    pub pubkey: crate::PubKey,
    pub kind: crate::Kind,
    pub d_tag: String,
}

/// Subscription to a relay
pub struct Subscription {
    id: String,
    filter: Filter,

    /// Channel for receiving events
    pub events: mpsc::UnboundedReceiver<Event>,
    events_sender: mpsc::UnboundedSender<Event>,

    /// Channel that gets closed when EOSE is received
    pub end_of_stored_events: oneshot::Receiver<()>,
    eose_sender: Option<oneshot::Sender<()>>,

    /// Channel for receiving close reasons
    pub closed_reason: mpsc::UnboundedReceiver<String>,
    closed_sender: mpsc::UnboundedSender<String>,

    /// Whether the subscription is live
    live: Arc<AtomicBool>,

    /// Whether EOSE has been received
    eosed: Arc<AtomicBool>,

    /// Options
    options: SubscriptionOptions,
}

impl Subscription {
    /// Create a new subscription
    pub fn new(id: String, filter: Filter, options: SubscriptionOptions) -> Self {
        let (events_sender, events) = mpsc::unbounded_channel();
        let (eose_sender, end_of_stored_events) = oneshot::channel();
        let (closed_sender, closed_reason) = mpsc::unbounded_channel();

        Self {
            id,
            filter,
            events,
            events_sender,
            end_of_stored_events,
            eose_sender: Some(eose_sender),
            closed_reason,
            closed_sender,
            live: Arc::new(AtomicBool::new(false)),
            eosed: Arc::new(AtomicBool::new(false)),
            options,
        }
    }

    /// Get the subscription ID
    pub fn get_id(&self) -> &str {
        &self.id
    }

    /// Get the filter
    pub fn get_filter(&self) -> &Filter {
        &self.filter
    }

    /// Check if the subscription is live
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Relaxed)
    }

    /// Check if EOSE has been received
    pub fn is_eosed(&self) -> bool {
        self.eosed.load(Ordering::Relaxed)
    }

    /// Start the subscription
    pub fn start(&self) {
        self.live.store(true, Ordering::Relaxed);
    }

    /// Stop the subscription
    pub fn stop(&self) {
        self.live.store(false, Ordering::Relaxed);
    }

    /// Dispatch an event to the subscription
    pub fn dispatch_event(&self, event: Event) {
        if self.live.load(Ordering::Relaxed) {
            let _ = self.events_sender.send(event);
        }
    }

    /// Check if an event matches the subscription filter
    pub fn matches(&self, event: &Event) -> bool {
        if self.eosed.load(Ordering::Relaxed) {
            self.filter.matches_ignoring_timestamp_constraints(event)
        } else {
            self.filter.matches(event)
        }
    }
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("id", &self.id)
            .field("filter", &self.filter)
            .field("live", &self.live.load(Ordering::Relaxed))
            .field("eosed", &self.eosed.load(Ordering::Relaxed))
            .finish()
    }
}
