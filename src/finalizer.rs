use crate::{event_template::EventTemplate, Event, SecretKey};

#[derive(Debug, Clone)]
pub enum Finalizer {
    SecretKey { sk: SecretKey },
}

impl Finalizer {
    pub fn finalize_event(&self, evt: EventTemplate) -> crate::Result<Event> {
        match self {
            Finalizer::SecretKey { sk } => evt.finalize(sk),
        }
    }
}
