use crate::{
    envelopes::*, normalize::normalize_url, Event, Filter, Result, Subscription,
    SubscriptionOptions, ID,
};
use dashmap::DashMap;
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, Duration};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use url::Url;

static SUBSCRIPTION_ID_COUNTER: AtomicI64 = AtomicI64::new(0);

pub struct Relay {
    pub url: String,
    conn_write: Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
    subscriptions: Arc<DashMap<i64, Arc<Subscription>>>,
    connection_error: Option<String>,
    challenge: String,
    notice_handler: Option<Box<dyn Fn(&str) + Send + Sync>>,
    custom_handler: Option<Box<dyn Fn(&str) + Send + Sync>>,
    ok_callbacks: Arc<DashMap<ID, Box<dyn Fn(bool, &str) + Send + Sync>>>,
    write_queue: mpsc::UnboundedSender<String>,
    pub assume_valid: bool,
}

#[derive(Default)]
pub struct RelayOptions {
    pub notice_handler: Option<Box<dyn Fn(&str) + Send + Sync>>,
    pub custom_handler: Option<Box<dyn Fn(&str) + Send + Sync>>,
}

impl Relay {
    pub async fn connect(url: &str, opts: RelayOptions) -> Result<Self> {
        let (write_sender, mut write_receiver) = mpsc::unbounded_channel();

        let url = normalize_url(url);
        if url.is_empty() {
            return Err(format!("invalid relay URL '{}'", url).into());
        }

        // connect
        let (ws_stream, _) = connect_async(Url::parse(&url)?).await?;
        let (conn_write, mut conn_read) = ws_stream.split();

        let relay = Self {
            url,
            conn_write: Arc::new(Mutex::new(conn_write)),
            subscriptions: Arc::new(DashMap::new()),
            connection_error: None,
            challenge: String::new(),
            notice_handler: opts.notice_handler,
            custom_handler: opts.custom_handler,
            ok_callbacks: Arc::new(DashMap::new()),
            write_queue: write_sender,
            assume_valid: false,
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
                let _ = ping_writer.lock().await.send(Message::Ping(vec![])).await;
            }
        });

        // start message reader
        tokio::spawn(async move {
            let mut buf = Vec::new();
            loop {
                if let Some(msg) = conn_read.next().await {
                    match msg {
                        Ok(Message::Text(text)) => {
                            buf.clear();
                            buf.extend_from_slice(text.as_bytes());
                        }
                        _ => {}
                    }
                }

                let message = String::from_utf8_lossy(&buf);

                // Parse the message
                if let Ok(envelope) = parse_message(&message) {
                    // Handle different envelope types
                    // This is a simplified version - full implementation would handle all envelope types
                    println!("message: {}", envelope.label())
                }
            }
        });

        Ok(relay)
    }

    pub async fn write(&self, msg: String) -> Result<()> {
        self.write_queue.send(msg).map_err(|_| "connection closed");
        Ok(())
    }

    pub async fn publish(&self, event: Event) -> Result<()> {
        let envelope = EventEnvelope {
            subscription_id: None,
            event,
        };

        let msg = serde_json::to_string(&envelope)?;
        self.write(msg);
        Ok(())
    }

    /// Subscribe to events matching a filter
    pub async fn subscribe(
        &self,
        filter: Filter,
        opts: SubscriptionOptions,
    ) -> Result<Arc<Subscription>> {
        let counter = SUBSCRIPTION_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
        let id = format!("{}:{}", counter, opts.label);

        let subscription = Arc::new(Subscription::new(id.clone(), filter.clone(), opts));
        self.subscriptions.insert(counter, subscription.clone());

        // Send REQ message
        let req_envelope = ReqEnvelope {
            subscription_id: id,
            filter,
        };

        let msg = serde_json::to_string(&req_envelope)?;
        self.write(msg).await?;

        Ok(subscription)
    }

    pub async fn close(&mut self) -> () {
        let _ = self.conn_write.lock().await.close().await;
    }
}

impl std::fmt::Display for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url)
    }
}
