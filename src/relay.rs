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
    pub(crate) closers_map: Arc<Mutex<SlotMap<SubscriptionKey, oneshot::Sender<CloseReason>>>>,
    occurrences_sender_map:
        Arc<Mutex<SecondaryMap<SubscriptionKey, (mpsc::Sender<Occurrence>, Filter)>>>,
    id_skippers_map: Arc<Mutex<SecondaryMap<SubscriptionKey, Arc<DashSet<ID>>>>>,

    // by publish
    ok_callbacks: Arc<DashMap<ID, oneshot::Sender<Result<()>>>>,
}

pub enum Occurrence {
    Event(Event),
    EOSE,
    Close(CloseReason),
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
            closers_map: Arc::new(Mutex::new(SlotMap::with_capacity_and_key(8))),
            occurrences_sender_map: Arc::new(Mutex::new(SecondaryMap::with_capacity(8))),
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
                    println!("ping to failed: {}", err);
                    break;
                }
            }
        });

        // start message reader
        let pong_writer = relay.conn_write.clone();
        let closers_map = relay.closers_map.clone();
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
                            for (_, closer) in closers_map.lock().await.drain() {
                                let _ = closer
                                    .send(CloseReason::RelayConnectionClosedByThem(frame.clone()));
                            }
                            return;
                        }
                        Err(err) => {
                            if let Some(on_close) = on_close.take() {
                                let _ = on_close.send(format!("error: {}", err.to_string()));
                            }
                            for (_, closer) in closers_map.lock().await.drain() {
                                let _ = closer.send(CloseReason::RelayConnectionError);
                            }
                            return;
                        }
                        _ => continue,
                    }
                }

                let message = String::from_utf8_lossy(&buf);

                println!("got message: {}", &message);

                match extract_key_from_sub_id(&message) {
                    None => {}
                    Some(sub_key) => {
                        println!("0");
                        if let Some(id) = extract_event_id(&message) {
                            println!("00");
                            if let Some(skip_ids) = id_skippers_map.lock().await.get(sub_key) {
                                println!("000");
                                let wasnt = skip_ids.insert(id);
                                if !wasnt {
                                    // this id was already known
                                    println!("///");
                                    continue;
                                }
                                println!("1");
                            }
                            println!("1");
                        }
                        println!("1");
                    }
                }

                println!("...");

                // parse the message
                match parse_message(&message) {
                    Ok(Envelope::InEvent(event)) => {
                        if let Some((occ, filter)) = occurrences_sender_map
                            .lock()
                            .await
                            .get(key_from_sub_id(event.subscription_id.as_str()))
                        {
                            if filter.matches(&event.event) {
                                let _ = occ.send(Occurrence::Event(event.event));
                            }
                        };
                    }
                    Ok(Envelope::Eose(eose)) => {
                        let key = key_from_sub_id(eose.subscription_id.as_str());
                        let mut map = occurrences_sender_map.lock().await;
                        if let Some((occ, filter)) = map.remove(key) {
                            map.insert(
                                key,
                                (
                                    occ.clone(),
                                    Filter {
                                        since: None,
                                        until: None,
                                        ..filter.clone()
                                    },
                                ),
                            );
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
                        if let Some(sub) = closers_map
                            .lock()
                            .await
                            .remove(key_from_sub_id(&closed.subscription_id))
                        {
                            let _ = sub.send(CloseReason::ClosedWithReason(closed.reason));
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
        let (close_sender, close) = oneshot::channel();
        let key = self.closers_map.lock().await.insert(close_sender);

        let id = sub_id_from_key(&key, &opts.label);
        let msg = format!("[\"REQ\",\"{}\",{}]", id, serde_json::to_string(&filter)?);

        let (occurrences_sender, occurrences) = mpsc::channel::<Occurrence>(1);
        self.occurrences_sender_map
            .lock()
            .await
            .insert(key, (occurrences_sender, filter));

        if let Some(skip_ids) = opts.skip_ids {
            self.id_skippers_map.lock().await.insert(key, skip_ids);
        }

        let write_queue = self.write_queue.clone();
        tokio::spawn(async move {
            let _ = close.await;
            let msg = format!("[\"CLOSE\",\"{}\"]", id);
            let _ = write_queue.send(msg).await;
        });

        let _ = self
            .write_queue
            .send(msg.clone())
            .map_err(|err| format!("[{}] failed to send {}: {}", self.url.as_str(), msg, err))
            .await;

        Ok(occurrences)
    }

    pub async fn close(self) -> () {
        for (_, closer) in self.closers_map.lock().await.drain() {
            let _ = closer.send(CloseReason::RelayConnectionClosedByUs);
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
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn test_subscribe() {
        let url = "wss://nos.lol".parse().unwrap();
        let relay = Relay::connect(url, None).await.unwrap();

        let filter = Filter {
            kinds: Some(vec![Kind(1)]),
            limit: Some(5),
            ..Default::default()
        };

        let mut occ = relay
            .subscribe(filter, SubscriptionOptions::default())
            .await
            .unwrap();

        // wait for at least one event or timeout after 10 seconds
        let result = timeout(Duration::from_secs(1), occ.recv()).await;

        match result {
            Ok(Some(Occurrence::Event(event))) => {
                println!("received event from nos.lol: {}", event.id);
                assert_eq!(event.kind, Kind(1));
            }
            Err(err) => panic!("timeout waiting for events from nos.lol: {}", err),
            _ => panic!("subscription closed without receiving events"),
        }
    }
}

pub enum CloseReason {
    RelayConnectionClosedByUs,
    RelayConnectionClosedByThem(Option<CloseFrame>),
    RelayConnectionError,
    ClosedWithReason(String),
}

#[derive(Debug, Default)]
pub struct SubscriptionOptions {
    pub label: Option<String>,
    pub skip_ids: Option<Arc<DashSet<ID>>>,
}
