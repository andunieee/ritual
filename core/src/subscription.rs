use crate::{Event, Filter};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReplaceableKey {
    pub pubkey: crate::PubKey,
    pub kind: crate::Kind,
    pub d_tag: String,
}

/// subscription to a relay
pub struct Subscription {
    id: String,
    pub(crate) filter: Filter,

    pub events: mpsc::Receiver<Event>,
    pub(crate) events_sender: mpsc::Sender<Event>,

    pub eose: oneshot::Receiver<()>,
    pub(crate) eose_sender: Option<oneshot::Sender<()>>,
}

impl Subscription {
    /// create a new subscription
    pub fn new(id: String, filter: Filter) -> Self {
        let (events_sender, events) = mpsc::channel(1);
        let (eose_sender, eose) = oneshot::channel();

        Self {
            id,
            filter,
            events,
            events_sender,
            eose,
            eose_sender: Some(eose_sender),
        }
    }

    /// check if EOSE has been received
    pub fn is_eosed(&self) -> bool {
        !self.eose.is_empty()
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
