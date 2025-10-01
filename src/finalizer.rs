#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unauthorized by user")]
    Unauthorized,

    #[error("something went wrong, we don't know what")]
    SomethingWentWrong,
}

#[derive(Debug, Clone)]
pub enum Finalizer {
    Plain(crate::SecretKey),
    Bunker(crate::bunker_client::BunkerClient),
}

impl Finalizer {
    pub async fn finalize_event(
        &self,
        evt: crate::event_template::EventTemplate,
    ) -> Result<crate::Event, Error> {
        match self {
            Self::Plain(sk) => Ok(evt.finalize(sk)),
            Self::Bunker(b) => b
                .finalize_event(evt)
                .await
                .map_err(|_| Error::SomethingWentWrong),
        }
    }
}
