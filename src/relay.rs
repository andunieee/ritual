use crate::{envelopes::*, Event, Filter, Result, Subscription, SubscriptionOptions};
use dashmap::DashMap;
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt, TryFutureExt};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio::time::{interval, Duration};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use url::Url;

static SUBSCRIPTION_ID_COUNTER: AtomicI64 = AtomicI64::new(0);

pub struct Relay {
    pub url: Url,
    conn_write: Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
    subscriptions: Arc<DashMap<String, Arc<Mutex<Subscription>>>>,
    challenge: Arc<RwLock<Option<String>>>,
    // ok_callbacks: Arc<DashMap<ID, Box<dyn Fn(bool, &str) + Send + Sync>>>,
    write_queue: mpsc::Sender<String>,
}

pub trait CustomHandler {
    fn custom_handler(&self);
}

impl CustomHandler for Relay {
    fn custom_handler(&self) {}
}

impl Relay {
    pub async fn connect(url: Url, mut on_close: Option<oneshot::Sender<String>>) -> Result<Self> {
        let (write_sender, mut write_receiver) = mpsc::channel(1);

        // connect
        let (ws_stream, _) = connect_async(&url).await?;
        let (conn_write, mut conn_read) = ws_stream.split();

        let relay = Self {
            url: url.clone(),
            conn_write: Arc::new(Mutex::new(conn_write)),
            subscriptions: Arc::new(DashMap::new()),
            challenge: Arc::new(RwLock::new(None)),
            // ok_callbacks: Arc::new(DashMap::new()),
            write_queue: write_sender,
        };

        // start write queue handler
        let queue_writer = relay.conn_write.clone();
        tokio::spawn(async move {
            while let Some(req) = write_receiver.recv().await {
                let _ = queue_writer.lock().await.send(Message::Text(req)).await;
            }
        });

        // start ping handler
        let ping_writer = relay.conn_write.clone();
        tokio::spawn(async move {
            let mut ping_interval = interval(Duration::from_secs(29));
            loop {
                ping_interval.tick().await;
                if let Err(err) = ping_writer.lock().await.send(Message::Ping(vec![])).await {
                    println!("ping to failed: {}", err);
                    break;
                }
            }
        });

        // start message reader
        let pong_writer = relay.conn_write.clone();
        let subs_map = relay.subscriptions.clone();
        let challenge = relay.challenge.clone();
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
                            let _ = pong_writer.lock().await.send(Message::Pong(vec![])).await;
                            continue;
                        }
                        Ok(Message::Close(f)) => {
                            if let Some(on_close) = on_close.take() {
                                let _ = on_close.send(f.map_or("broken close".to_string(), |c| {
                                    format!("close ({}) {}", c.code, c.reason)
                                }));
                            }
                            return;
                        }
                        Err(err) => {
                            if let Some(on_close) = on_close.take() {
                                let _ = on_close.send(format!("error: {}", err.to_string()));
                            }
                            return;
                        }
                        _ => continue,
                    }
                }

                let message = String::from_utf8_lossy(&buf);

                // parse the message
                if let Ok(envelope) = parse_message(&message) {
                    match envelope {
                        Envelope::InEvent(event) => {
                            if let Some(sub) = subs_map.get(event.subscription_id.as_str()) {
                                let s = sub.lock().await;
                                if s.is_eosed()
                                    && s.filter
                                        .matches_ignoring_timestamp_constraints(&event.event)
                                {
                                    let _ = s.events_sender.send(event.event);
                                } else if s.filter.matches(&event.event) {
                                    let _ = s.events_sender.send(event.event);
                                }
                            };
                        }
                        Envelope::Eose(eose) => {
                            if let Some(sub) = subs_map.get(eose.subscription_id.as_str()) {
                                if let Some(sender) = sub.lock().await.eose_sender.take() {
                                    let _ = sender.send(());
                                }
                            };
                        }
                        Envelope::Ok(ok) => {
                            println!(
                                "received OK for event {}: {} - {}",
                                ok.event_id, ok.ok, ok.reason
                            );
                        }
                        Envelope::Notice(notice) => {
                            println!("[{}] received notice: {}", url.as_str(), notice.0);
                        }
                        Envelope::Closed(closed) => {
                            if let Some((_, sub)) = subs_map.remove(&closed.subscription_id) {
                                sub.clone().lock().await.close();
                            }
                        }
                        Envelope::AuthChallenge(authc) => {
                            let _ = challenge.write().await.insert(authc.challenge);
                        }
                        _ => {
                            println!(
                                "[{}] unexpected message: {}",
                                url.as_str(),
                                envelope.label()
                            );
                        }
                    }
                }
            }
        });

        Ok(relay)
    }

    pub async fn publish(&self, event: Event) -> Result<()> {
        let envelope = OutEventEnvelope { event };
        let msg = serde_json::to_string(&envelope)?;
        self.write_queue
            .send(msg)
            .map_err(|err| {
                format!(
                    "[{}] failed to send {}: {}",
                    self.url.as_str(),
                    serde_json::to_string(&envelope).unwrap(),
                    err
                )
            })
            .await?;
        Ok(())
    }

    /// subscribe to events matching a filter
    pub async fn subscribe(
        &self,
        filter: Filter,
        opts: SubscriptionOptions,
    ) -> Result<Arc<Mutex<Subscription>>> {
        let counter = SUBSCRIPTION_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
        let id = if let Some(label) = opts.label {
            format!("{}:{}", counter, label)
        } else {
            format!("{}", counter)
        };

        let msg = format!("[\"REQ\",\"{}\",{}]", id, serde_json::to_string(&filter)?);
        let (sub, close_notifier) = Subscription::new(id.clone(), filter);
        let subscription = Arc::new(Mutex::new(sub));
        self.subscriptions.insert(id.clone(), subscription.clone());

        let subs_map = self.subscriptions.clone();
        let write_queue = self.write_queue.clone();
        let close_id = id.clone();
        tokio::spawn(async move {
            let _ = close_notifier.await;
            if let Some(_) = subs_map.remove(&close_id) {
                let msg = format!("[\"CLOSE\",\"{}\"]", id);
                let _ = write_queue.send(msg).await;
            }
        });

        let _ = self
            .write_queue
            .send(msg.clone())
            .map_err(|err| format!("[{}] failed to send {}: {}", self.url.as_str(), msg, err))
            .await;

        Ok(subscription)
    }

    pub async fn close(&self) -> () {
        for sub in self.subscriptions.iter_mut() {
            sub.clone().lock().await.close();
        }

        self.subscriptions.clear();
        let _ = self.conn_write.lock().await.close().await;

        // (this doesn't call the "on_close" handler)
    }
}

impl std::fmt::Display for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url)
    }
}
