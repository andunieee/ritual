use crate::helpers::{
    extract_event_id, extract_key_from_sub_id, key_from_sub_id, sub_id_from_key, SubscriptionKey,
};
use crate::{envelopes::*, Event, Filter, ID};
use dashmap::{DashMap, DashSet};
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt, TryFutureExt};
use hyper_tungstenite::tungstenite::client::IntoClientRequest;
use slotmap::{SecondaryMap, SlotMap};
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio::time::{interval, Duration};
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async_tls_with_config, MaybeTlsStream, WebSocketStream};
use url::Url;

#[derive(Error, Debug)]
pub enum RelayError {
    #[error("relay returned ok=false: {0}")]
    OKFalseWithReason(String),
    #[error("relay connection error: {0}")]
    RelayConnectionError(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("JSON error: {0}")]
    JSON(#[from] serde_json::Error),
    #[error("failed to send to {0}: {1}")]
    PublishSendError(Url, String),
    #[error("IO error")]
    IOError(#[from] tokio::sync::oneshot::error::RecvError),
    #[error("Hex error")]
    HexEncodingError(#[from] lowercase_hex::FromHexError),
}

pub type Result<T> = std::result::Result<T, RelayError>;

#[derive(Clone)]
pub struct Relay {
    pub url: Url,
    // by connection
    challenge: Arc<RwLock<Option<String>>>,
    conn_write: Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
    write_queue: mpsc::Sender<String>,

    // by subscription
    pub(crate) occurrences_sender_map:
        Arc<Mutex<SlotMap<SubscriptionKey, (mpsc::Sender<Occurrence>, Filter)>>>,
    id_skippers_map: Arc<Mutex<SecondaryMap<SubscriptionKey, Arc<DashSet<ID>>>>>,

    // by publish
    ok_callbacks: Arc<DashMap<ID, oneshot::Sender<Result<()>>>>,
}

impl Relay {
    pub async fn connect(url: Url, mut on_close: Option<oneshot::Sender<String>>) -> Result<Self> {
        let (write_sender, mut write_receiver) = mpsc::channel(1);

        // connect
        let (ws_stream, _) =
            connect_async_tls_with_config(url.as_str().into_client_request()?, None, false, None)
                .await?;
        let (conn_write, mut conn_read) = ws_stream.split();

        let relay = Self {
            url: url.clone(),
            conn_write: Arc::new(Mutex::new(conn_write)),
            occurrences_sender_map: Arc::new(Mutex::new(SlotMap::with_capacity_and_key(8))),
            id_skippers_map: Arc::new(Mutex::new(SecondaryMap::with_capacity(8))),
            challenge: Arc::new(RwLock::new(None)),
            ok_callbacks: Arc::new(DashMap::new()),
            write_queue: write_sender,
        };

        // start write queue handler
        let queue_writer = relay.conn_write.clone();
        tokio::spawn(async move {
            while let Some(text) = write_receiver.recv().await {
                let _ = queue_writer.lock().await.send(Message::text(text)).await;
            }
        });

        // start ping handler
        let ping_writer = relay.conn_write.clone();
        tokio::spawn(async move {
            let mut ping_interval = interval(Duration::from_secs(29));
            loop {
                ping_interval.tick().await;
                if let Err(err) = ping_writer
                    .lock()
                    .await
                    .send(Message::Ping(vec![].into()))
                    .await
                {
                    println!("ping failed: {}", err);
                    break;
                }
            }
        });

        // start message reader
        let pong_writer = relay.conn_write.clone();
        let id_skippers_map = relay.id_skippers_map.clone();
        let occurrences_sender_map = relay.occurrences_sender_map.clone();
        let challenge = relay.challenge.clone();
        let ok_callbacks = relay.ok_callbacks.clone();
        tokio::spawn(async move {
            let mut buf = Vec::with_capacity(500);
            loop {
                if let Some(msg) = conn_read.next().await {
                    match msg {
                        Ok(Message::Text(text)) => {
                            buf.clear();
                            buf.extend_from_slice(text.as_bytes());
                            // message will be handled below
                        }
                        Ok(Message::Ping(_)) => {
                            let _ = pong_writer
                                .lock()
                                .await
                                .send(Message::Pong(vec![].into()))
                                .await;
                            continue;
                        }
                        Ok(Message::Close(frame)) => {
                            if let Some(on_close) = on_close.take() {
                                let _ = on_close.send(
                                    frame.clone().map_or("broken close".to_string(), |c| {
                                        format!("close ({}) {}", c.code, c.reason)
                                    }),
                                );
                            }
                            for (_, (occ, _)) in occurrences_sender_map.lock().await.drain() {
                                let _ = occ
                                    .send(Occurrence::Close(
                                        CloseReason::RelayConnectionClosedByThem(frame.clone()),
                                    ))
                                    .await;
                            }
                            return;
                        }
                        Err(err) => {
                            if let Some(on_close) = on_close.take() {
                                let _ = on_close.send(format!("error: {}", err.to_string()));
                            }
                            for (_, (occ, _)) in occurrences_sender_map.lock().await.drain() {
                                let _ = occ
                                    .send(Occurrence::Close(CloseReason::RelayConnectionError))
                                    .await;
                            }
                            return;
                        }
                        _ => continue,
                    }
                }

                let message = String::from_utf8_lossy(&buf);

                match extract_key_from_sub_id(&message) {
                    None => {}
                    Some(sub_key) => {
                        if let Some(skip_ids) = id_skippers_map.lock().await.get(sub_key) {
                            if let Some(id) = extract_event_id(&message) {
                                let wasnt = skip_ids.insert(id);
                                if !wasnt {
                                    // this id was already known
                                    continue;
                                }
                            }
                        }
                    }
                }

                // parse the message
                match parse_message(&message) {
                    Ok(Envelope::InEvent(event)) => {
                        if let Some((occ, filter)) = occurrences_sender_map
                            .lock()
                            .await
                            .get(key_from_sub_id(event.subscription_id.as_str()))
                        {
                            if filter.matches(&event.event) {
                                let _ = occ.send(Occurrence::Event(event.event)).await;
                            }
                        };
                    }
                    Ok(Envelope::Eose(eose)) => {
                        let key = key_from_sub_id(eose.subscription_id.as_str());
                        let mut map = occurrences_sender_map.lock().await;
                        if let Some(occfilter) = map.get_mut(key) {
                            // since we got an EOSE our internal filter won't check for since/until anymore
                            occfilter.1.since = None;
                            occfilter.1.until = None;

                            // and we dispatch this to the listener
                            let _ = occfilter.0.send(Occurrence::EOSE).await;
                        };
                    }
                    Ok(Envelope::Ok(ok)) => match ok_callbacks.remove(&ok.event_id) {
                        Some((_, sender)) => {
                            let _ = sender.send(match ok.ok {
                                true => Ok(()),
                                false => Err(RelayError::OKFalseWithReason(ok.reason)),
                            });
                        }
                        None => {
                            println!(
                                "received OK for unknown event {}: {} - {}",
                                ok.event_id, ok.ok, ok.reason
                            );
                        }
                    },
                    Ok(Envelope::Notice(notice)) => {
                        println!("[{}] received notice: {}", url.as_str(), notice.0);
                    }
                    Ok(Envelope::Closed(closed)) => {
                        if let Some((occ, _)) = occurrences_sender_map
                            .lock()
                            .await
                            .remove(key_from_sub_id(&closed.subscription_id))
                        {
                            let _ = occ
                                .send(Occurrence::Close(CloseReason::ClosedByThemWithReason(
                                    closed.reason,
                                )))
                                .await;
                        }
                    }
                    Ok(Envelope::AuthChallenge(authc)) => {
                        let _ = challenge.write().await.insert(authc.challenge);
                    }
                    Ok(envelope) => {
                        println!(
                            "[{}] unexpected message: {}",
                            url.as_str(),
                            envelope.label()
                        );
                    }
                    Err(err) => {
                        println!("[{}] wrong message: {}", url.as_str(), err);
                    }
                }
            }
        });

        Ok(relay)
    }

    pub async fn publish(&self, event: Event) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.ok_callbacks.insert(event.id.clone(), tx);

        let envelope = OutEventEnvelope { event };
        let msg = serde_json::to_string(&envelope)?;

        self.write_queue
            .send(msg)
            .map_err(|err| RelayError::PublishSendError(self.url.clone(), err.0))
            .await?;

        rx.await?
    }

    /// subscribe to events matching a filter
    pub async fn subscribe(
        &self,
        filter: Filter,
        opts: SubscriptionOptions,
    ) -> Result<mpsc::Receiver<Occurrence>> {
        let mut reqmsg = String::new();
        let mut closemsg = String::new();
        let (occurrences_sender, occurrences) = mpsc::channel::<Occurrence>(1);

        let key = self
            .occurrences_sender_map
            .lock()
            .await
            .insert_with_key(|key| {
                // use the key here to prepare the REQ msg
                let id = sub_id_from_key(&key, &opts.label);
                reqmsg = format!(
                    "[\"REQ\",\"{}\",{}]",
                    id,
                    serde_json::to_string(&filter).unwrap()
                );
                closemsg = format!("[\"CLOSE\",\"{}\"]", id);

                // and store this tuple
                (occurrences_sender.clone(), filter)
            });

        if let Some(skip_ids) = opts.skip_ids {
            self.id_skippers_map.lock().await.insert(key, skip_ids);
        }

        let write_queue = self.write_queue.clone();
        tokio::spawn(async move {
            // when the listener stops listening from this subscription we close it automatically
            occurrences_sender.closed().await;
            let _ = write_queue.send(closemsg).await;
        });

        let _ = self
            .write_queue
            .send(reqmsg)
            .map_err(|err| {
                format!(
                    "[{}] failed to fire subscription: {}",
                    self.url.as_str(),
                    err
                )
            })
            .await;

        Ok(occurrences)
    }

    pub async fn close(self) -> () {
        for (_, (occ, _)) in self.occurrences_sender_map.lock().await.drain() {
            let _ = occ
                .send(Occurrence::Close(CloseReason::RelayConnectionClosedByUs))
                .await;
        }

        let _ = self.conn_write.lock().await.close().await;
    }
}

impl std::fmt::Display for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Filter, Kind};

    #[tokio::test]
    async fn test_subscribe() {
        let url = "wss://nos.lol".parse().unwrap();
        let relay = Relay::connect(url, None).await.unwrap();

        let filter = Filter {
            kinds: Some(vec![Kind(1)]),
            limit: Some(5),
            ..Default::default()
        };

        let mut sub = relay
            .subscribe(filter, SubscriptionOptions::default())
            .await
            .unwrap();

        let mut pre_eose_count = 0;
        while let Some(occ) = sub.recv().await {
            match occ {
                Occurrence::Event(_) => {
                    pre_eose_count += 1;
                }
                Occurrence::EOSE => {
                    break;
                }
                Occurrence::Close(_) => {
                    panic!("shouldn't close");
                }
            }
        }

        assert_eq!(pre_eose_count, 5);
    }
}

#[derive(Debug)]
pub enum CloseReason {
    RelayConnectionClosedByUs,
    RelayConnectionClosedByThem(Option<CloseFrame>),
    RelayConnectionError,
    ClosedByUs,
    ClosedByThemWithReason(String),
}

#[derive(Debug, Default)]
pub struct SubscriptionOptions {
    pub label: Option<String>,
    pub skip_ids: Option<Arc<DashSet<ID>>>,
}

#[derive(Debug)]
pub enum Occurrence {
    Event(Event),
    EOSE,
    Close(CloseReason),
}
