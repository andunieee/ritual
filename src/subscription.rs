use crate::{Event, Filter};
use tokio::sync::{mpsc, oneshot};

/// subscription to a relay
pub struct Subscription {
    id: String,
    pub(crate) filter: Filter,

    pub events: mpsc::Receiver<Event>,
    pub(crate) events_sender: mpsc::Sender<Event>,

    pub eose: oneshot::Receiver<()>,
    pub(crate) eose_sender: Option<oneshot::Sender<()>>,

    close_sender: Option<oneshot::Sender<()>>,
}

#[derive(Debug, Default)]
pub struct SubscriptionOptions {
    pub label: Option<String>,
}

impl Subscription {
    /// create a new subscription
    pub fn new(id: String, filter: Filter) -> (Self, oneshot::Receiver<()>) {
        let (events_sender, events) = mpsc::channel(1);
        let (eose_sender, eose) = oneshot::channel();
        let (close_sender, close) = oneshot::channel();

        (
            Self {
                id,
                filter,
                events,
                events_sender,
                eose,
                eose_sender: Some(eose_sender),
                close_sender: Some(close_sender),
            },
            close,
        )
    }

    /// check if EOSE has been received
    pub fn is_eosed(&self) -> bool {
        !self.eose.is_empty()
    }

    pub fn close(&mut self) -> () {
        if let Some(sender) = self.close_sender.take() {
            let _ = sender.send(());
        }
    }
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("id", &self.id)
            .field("filter", &self.filter)
            .field("eosed", &self.is_eosed())
            .finish()
    }
}
