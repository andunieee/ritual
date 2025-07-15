use std::fmt::Debug;
use thiserror::Error;

use crate::{event_template::EventTemplate, nip46::BunkerClient, Event, SecretKey};

#[derive(Debug, Error)]
pub enum Error {
    #[error("unauthorized by user")]
    Unauthorized,

    #[error("something went wrong, we don't know what")]
    SomethingWentWrong,
}

#[derive(Debug, Clone)]
pub enum Finalizer {
    Plain(SecretKey),
    Bunker(BunkerClient),
}

impl Finalizer {
    pub async fn finalize_event(&self, evt: EventTemplate) -> Result<Event, Error> {
        match self {
            Self::Plain(sk) => Ok(evt.finalize(sk)),
            Self::Bunker(b) => b
                .finalize_event(evt)
                .await
                .map_err(|_| Error::SomethingWentWrong),
        }
    }
}
