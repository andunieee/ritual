use crate::{envelopes::*, Event, Filter, Result, Subscription, ID};
use dashmap::DashMap;
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt, TryFutureExt};
use nonempty::NonEmpty;
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
    ok_callbacks: Arc<DashMap<ID, Box<dyn Fn(bool, &str) + Send + Sync>>>,
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
            ok_callbacks: Arc::new(DashMap::new()),
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
                                    s.events_sender.send(event.event);
                                } else if s.filter.matches(&event.event) {
                                    s.events_sender.send(event.event);
                                }
                            };
                        }
                        Envelope::Eose(eose) => {
                            if let Some(sub) = subs_map.get(eose.subscription_id.as_str()) {
                                if let Some(sender) = sub.lock().await.eose_sender.take() {
                                    sender.send(());
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
                                drop(sub)
                            }
                        }
                        Envelope::AuthChallenge(authc) => {
                            challenge.write().await.insert(authc.challenge);
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

    pub async fn write(&self, msg: String) -> Result<()> {
        self.write_queue
            .send(msg)
            .map_err(|err| format!("failed to send: {}", err));
        Ok(())
    }

    pub async fn publish(&self, event: Event) -> Result<()> {
        let envelope = OutEventEnvelope { event };
        let msg = serde_json::to_string(&envelope)?;
        self.write(msg);
        Ok(())
    }

    /// subscribe to events matching a filter
    pub async fn subscribe(
        &self,
        filters: NonEmpty<Filter>,
        opts: SubscriptionOptions,
    ) -> Result<Arc<Mutex<Subscription>>> {
        let counter = SUBSCRIPTION_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
        let id = format!("{}:{}", counter, opts.label);

        let msg = serde_json::to_string(&ReqEnvelope {
            subscription_id: id,
            filters,
        })?;

        let subscription = Arc::new(Mutex::new(Subscription::new(id.clone(), filters)));
        self.subscriptions.insert(id.clone(), subscription.clone());

        self.write(msg).await?;

        Ok(subscription)
    }

    pub fn unsubscribe(&self, sub_id: &str) -> () {
        if let Some((_, sub)) = self.subscriptions.remove(sub_id) {
            drop(sub)
        }
    }

    pub async fn close(&self) -> () {
        let _ = self.conn_write.lock().await.close().await;
    }
}

impl std::fmt::Display for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url)
    }
}
