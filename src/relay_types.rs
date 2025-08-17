use crate::{finalizer::Finalizer, Event, Filter, ID};
use dashmap::DashSet;
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tokio_with_wasm::alias as tokio;

#[derive(thiserror::Error, Debug)]
pub enum PublishError {
    #[error("ok=false, relay message: {0}")]
    NotOK(String),

    #[error("internal channel error, relay connection might have closed")]
    Channel,
}

#[derive(thiserror::Error, Debug)]
pub enum ConnectError {
    #[error("relay connection error")]
    Websocket,
}

#[derive(Debug)]
pub(crate) struct SubSender {
    pub(crate) ocurrences_sender: mpsc::Sender<Occurrence>,
    pub(crate) filter: Filter,
    pub(crate) auth_automatically: Option<Finalizer>,
}

#[derive(Debug)]
pub enum CloseReason {
    RelayConnectionClosedByUs,
    RelayConnectionClosedByThem(Option<String>),
    RelayConnectionError,
    ClosedByUs,
    ClosedByThemWithReason(String),
    Unknown,
}

#[derive(Default, Clone)]
pub struct SubscriptionOptions {
    pub label: Option<String>,
    pub timeout: Option<Duration>,
    pub auth_automatically: Option<Finalizer>,

    pub(crate) skip_ids: Option<Arc<DashSet<ID>>>,
}

impl std::fmt::Debug for SubscriptionOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("label", &self.label)
            .field("timeout", &self.timeout)
            .field("auth_automatically", &self.auth_automatically)
            .field("skip_ids", &self.skip_ids)
            .finish()
    }
}

#[derive(Debug)]
pub enum Occurrence {
    Event(Event),
    EOSE,
    Close(CloseReason),
}
