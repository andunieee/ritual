use crate::{
    envelopes::Envelope,
    finalizer::Finalizer,
    helpers::{
        extract_event_id, extract_key_from_sub_id, key_from_sub_id, sub_id_from_key,
        SubscriptionKey,
    },
    Event, EventTemplate, Filter, Kind, Tags, Timestamp, ID,
};
use dashmap::{DashMap, DashSet};
use slotmap::{SecondaryMap, SlotMap};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use url::Url;

#[cfg(target_arch = "wasm32")]
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

#[derive(Debug, Clone)]
pub struct Relay {
    pub url: Url,
    // by connection
    write_queue: mpsc::Sender<String>,
    challenge: Arc<RwLock<Option<String>>>,

    // by subscription
    pub(crate) sub_sender_map: Arc<Mutex<SlotMap<SubscriptionKey, SubSender>>>,
    id_skippers_map: Arc<Mutex<SecondaryMap<SubscriptionKey, Arc<DashSet<ID>>>>>,

    // by publish
    ok_callbacks: Arc<DashMap<ID, oneshot::Sender<Result<(), String>>>>,
}

impl Relay {
    #[cfg(target_arch = "wasm32")]
    pub async fn connect(
        url: Url,
        mut on_close: Option<oneshot::Sender<String>>,
    ) -> Result<Self, ConnectError> {
        use wasm_bindgen::{closure::Closure, JsCast, JsValue};
        use web_sys::{CloseEvent, ErrorEvent, MessageEvent, WebSocket};

        // create websocket
        let (write_sender, mut write_receiver) = mpsc::channel(1);

        let relay = Self {
            url: url.clone(),
            write_queue: write_sender,
            sub_sender_map: Arc::new(Mutex::new(SlotMap::with_capacity_and_key(8))),
            id_skippers_map: Arc::new(Mutex::new(SecondaryMap::with_capacity(8))),
            challenge: Arc::new(RwLock::new(None)),
            ok_callbacks: Arc::new(DashMap::new()),
        };

        let ws = Arc::new(WebSocket::new(url.as_str()).map_err(|_| ConnectError::Websocket)?);

        // start write queue handler
        let queue_writer = ws.clone();
        tokio::spawn(async move {
            while let Some(text) = write_receiver.recv().await {
                let _ = queue_writer.send_with_str(&text);
            }
        });

        // setup message handler
        let write_queue = relay.write_queue.clone();
        let id_skippers_map = relay.id_skippers_map.clone();
        let sub_sender_map = relay.sub_sender_map.clone();
        let relay_challenge = relay.challenge.clone();
        let ok_callbacks = relay.ok_callbacks.clone();
        let relay_url = relay.url.to_string();

        let on_message = Closure::wrap(Box::new(move |e: MessageEvent| {
            if let Ok(text) = e.data().dyn_into::<js_sys::JsString>() {
                let message: String = text.into();

                log::debug!("got message from {}: {}", &relay_url, &message);

                let write_queue = write_queue.clone();
                let id_skippers_map = id_skippers_map.clone();
                let sub_sender_map = sub_sender_map.clone();
                let relay_challenge = relay_challenge.clone();
                let ok_callbacks = ok_callbacks.clone();
                let relay_url = relay_url.to_string();

                tokio::spawn(async move {
                    handle_nostr_envelope(
                        message,
                        write_queue,
                        relay_challenge,
                        sub_sender_map,
                        id_skippers_map,
                        ok_callbacks,
                        relay_url,
                    )
                    .await;
                });
            }
        }) as Box<dyn FnMut(MessageEvent)>);
        ws.set_onmessage(Some(on_message.into_js_value().unchecked_ref()));

        // setup error handler
        let on_error = Closure::once(Box::new(move |e: ErrorEvent| {
            log::info!("websocket error: {:?}", e.message());
        }) as Box<dyn FnOnce(ErrorEvent)>);
        ws.set_onerror(Some(on_error.into_js_value().unchecked_ref()));

        // setup close handler
        let sub_sender_map_close = relay.sub_sender_map.clone();
        let on_close_handler = Closure::once(Box::new(move |e: CloseEvent| {
            log::info!("websocket closed: code={} reason={}", e.code(), e.reason());

            // notify all subscriptions
            let sub_sender_map_close = sub_sender_map_close.clone();
            tokio::spawn(async move {
                for (_, sub) in sub_sender_map_close.lock().await.drain() {
                    let _ = sub.ocurrences_sender.send(Occurrence::Close(
                        CloseReason::RelayConnectionClosedByThem(None),
                    ));
                }
            });

            if let Some(on_close) = on_close.take() {
                let _ = on_close.send(format!("closed: {:?}", e.reason()));
            }
        }) as Box<dyn FnOnce(CloseEvent)>);
        ws.set_onclose(Some(on_close_handler.into_js_value().unchecked_ref()));

        // setup open handler for connection ready
        let (sender, receiver) = oneshot::channel();
        let mut opt = Some(sender);
        let on_open = Closure::once(Box::new(move |_: JsValue| {
            if let Some(sender) = opt.take() {
                let _ = sender.send(());
            }
        }) as Box<dyn FnOnce(JsValue)>);
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));

        match receiver.await {
            Ok(()) => Ok(relay),
            Err(_) => Err(ConnectError::Websocket),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect(
        url: Url,
        mut on_close: Option<oneshot::Sender<String>>,
    ) -> Result<Self, ConnectError> {
        use futures::{SinkExt, StreamExt};
        use tokio::time::interval;
        use tokio_tungstenite::{
            connect_async_tls_with_config,
            tungstenite::{client::IntoClientRequest, Message},
        };

        let (write_sender, mut write_receiver) = mpsc::channel(1);

        // connect
        let (ws_stream, _) = connect_async_tls_with_config(
            url.as_str()
                .into_client_request()
                .map_err(|_| ConnectError::Websocket)?,
            None,
            false,
            None,
        )
        .await
        .map_err(|_| ConnectError::Websocket)?;

        let (conn_write, mut conn_read) = ws_stream.split();
        let writer = Arc::new(Mutex::new(conn_write));

        let relay = Self {
            url: url.clone(),
            sub_sender_map: Arc::new(Mutex::new(SlotMap::with_capacity_and_key(8))),
            id_skippers_map: Arc::new(Mutex::new(SecondaryMap::with_capacity(8))),
            challenge: Arc::new(RwLock::new(None)),
            ok_callbacks: Arc::new(DashMap::new()),
            write_queue: write_sender,
        };

        // start write queue handler
        let queue_writer = writer.clone();
        tokio::spawn(async move {
            while let Some(text) = write_receiver.recv().await {
                let _ = queue_writer.lock().await.send(Message::text(text)).await;
            }
        });

        // start ping handler
        let ping_writer = writer.clone();
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
                    log::info!("ping failed: {}", err);
                    break;
                }
            }
        });

        // start message reader
        let pong_writer = writer.clone();
        let id_skippers_map = relay.id_skippers_map.clone();
        let sub_sender_map = relay.sub_sender_map.clone();
        let relay_challenge = relay.challenge.clone();
        let ok_callbacks = relay.ok_callbacks.clone();
        let write_queue = relay.write_queue.clone();
        let relay_url = relay.url.clone();
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
                            let close_msg = frame.clone().map_or("broken close".to_string(), |c| {
                                format!("close ({}) {}", c.code, c.reason)
                            });

                            if let Some(on_close) = on_close.take() {
                                let _ = on_close.send(close_msg.clone());
                            }
                            for (_, sub) in sub_sender_map.lock().await.drain() {
                                let _ = sub
                                    .ocurrences_sender
                                    .send(Occurrence::Close(
                                        CloseReason::RelayConnectionClosedByThem(Some(
                                            close_msg.clone(),
                                        )),
                                    ))
                                    .await;
                            }
                            return;
                        }
                        Err(err) => {
                            if let Some(on_close) = on_close.take() {
                                let _ = on_close.send(format!("error: {}", err.to_string()));
                            }
                            for (_, sub) in sub_sender_map.lock().await.drain() {
                                let _ = sub
                                    .ocurrences_sender
                                    .send(Occurrence::Close(CloseReason::RelayConnectionError))
                                    .await;
                            }
                            return;
                        }
                        _ => continue,
                    }
                }

                let message = String::from_utf8_lossy(&buf);
                handle_nostr_envelope(
                    message.to_string(),
                    write_queue.clone(),
                    relay_challenge.clone(),
                    sub_sender_map.clone(),
                    id_skippers_map.clone(),
                    ok_callbacks.clone(),
                    relay_url.to_string(),
                )
                .await;
            }
        });

        Ok(relay)
    }

    pub async fn publish(&self, event: Event) -> Result<(), PublishError> {
        let (tx, rx) = oneshot::channel();
        self.ok_callbacks.insert(event.id.clone(), tx);

        let msg = serde_json::json!(["EVENT", event]);

        let _ = self
            .write_queue
            .send(msg.to_string())
            .await
            .map_err(|_| PublishError::Channel)?;

        rx.await
            .map_err(|_| PublishError::Channel)
            .map(|r| r.map_err(|err| PublishError::NotOK(err)))
            .flatten()
    }

    /// subscribe to events matching a filter
    pub async fn subscribe(
        &self,
        filter: Filter,
        opts: SubscriptionOptions,
    ) -> mpsc::Receiver<Occurrence> {
        let mut reqmsg = String::new();
        let mut closemsg = String::new();
        let (occurrences_sender, occurrences) = mpsc::channel::<Occurrence>(1);

        let key = self.sub_sender_map.lock().await.insert_with_key(|key| {
            // use the key here to prepare the REQ msg
            let id = sub_id_from_key(&key, &opts.label);
            reqmsg = format!(
                "[\"REQ\",\"{}\",{}]",
                id,
                serde_json::to_string(&filter).unwrap()
            );
            closemsg = format!("[\"CLOSE\",\"{}\"]", id);

            // and store this tuple
            SubSender {
                ocurrences_sender: occurrences_sender.clone(),
                filter,
                auth_automatically: opts.auth_automatically,
            }
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

        let _ = self.write_queue.send(reqmsg).await.map_err(|err| {
            log::warn!(
                "[{}] failed to fire subscription: {}",
                self.url.as_str(),
                err
            )
        });

        occurrences
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let sub_sender_map = self.sub_sender_map.clone();

        tokio::spawn(async move {
            for (_, sub) in sub_sender_map.lock().await.drain() {
                let _ = sub
                    .ocurrences_sender
                    .send(Occurrence::Close(CloseReason::RelayConnectionClosedByUs))
                    .await;
            }
        });
    }
}

impl std::fmt::Display for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<relay url={}>", self.url)
    }
}

#[inline]
async fn handle_nostr_envelope(
    message: String,
    write_queue: mpsc::Sender<String>,
    relay_challenge: Arc<RwLock<Option<String>>>,
    sub_sender_map: Arc<Mutex<SlotMap<SubscriptionKey, SubSender>>>,
    id_skippers_map: Arc<Mutex<SecondaryMap<SubscriptionKey, Arc<DashSet<ID>>>>>,
    ok_callbacks: Arc<DashMap<ID, oneshot::Sender<Result<(), String>>>>,
    relay_url: String,
) {
    match extract_key_from_sub_id(&message) {
        None => {}
        Some(sub_key) => {
            if let Some(skip_ids) = id_skippers_map.lock().await.get(sub_key) {
                if let Some(id) = extract_event_id(&message) {
                    let wasnt = skip_ids.insert(id);
                    if !wasnt {
                        // this id was already known
                        return;
                    }
                }
            }
        }
    }

    // parse the message
    match serde_json::from_str::<Envelope>(&message) {
        Ok(Envelope::InEvent {
            subscription_id,
            event,
        }) => {
            if let Some(sub) = sub_sender_map
                .lock()
                .await
                .get(key_from_sub_id(subscription_id.as_str()))
            {
                if sub.filter.matches(&event) && event.verify_signature() {
                    let _ = sub.ocurrences_sender.send(Occurrence::Event(event)).await;
                } else {
                    // TODO: penalize this relay?
                }
            };
        }
        Ok(Envelope::Eose { subscription_id }) => {
            let key = key_from_sub_id(subscription_id.as_str());
            let mut map = sub_sender_map.lock().await;
            if let Some(occfilter) = map.get_mut(key) {
                // since we got an EOSE our internal filter won't check for since/until anymore
                occfilter.filter.since = None;
                occfilter.filter.until = None;

                // and we dispatch this to the listener
                let _ = occfilter.ocurrences_sender.send(Occurrence::EOSE).await;
            };
        }
        Ok(Envelope::Ok {
            event_id,
            ok,
            reason,
        }) => match ok_callbacks.remove(&event_id) {
            Some((_, sender)) => {
                let _ = sender.send(match ok {
                    true => Ok(()),
                    false => Err(reason),
                });
            }
            None => {
                log::info!(
                    "received OK for unknown event {}: {} - {}",
                    event_id,
                    ok,
                    reason
                );
            }
        },
        Ok(Envelope::Notice(notice)) => {
            log::info!("[{}] received notice: {}", relay_url.as_str(), notice);
        }
        Ok(Envelope::Closed {
            subscription_id,
            reason,
        }) => {
            let key = key_from_sub_id(&subscription_id);
            let mut ssm = sub_sender_map.lock().await;
            if let Some(sub) = ssm.get_mut(key) {
                if reason.starts_with("auth-required:") {
                    if let Some(challenge) = relay_challenge.read().await.clone() {
                        if let Some(finalizer) = sub.auth_automatically.take() {
                            // instead of ending here after a CLOSED we will perform AUTH
                            let result = finalizer.finalize_event(EventTemplate {
                                created_at: Timestamp::now(),
                                kind: Kind(22242),
                                content: "".to_string(),
                                tags: Tags(vec![
                                    vec!["relay".to_string(), relay_url.to_string()],
                                    vec!["challenge".to_string(), challenge],
                                ]),
                            });
                            if let Ok(auth_event) = result.await {
                                // send the AUTH message and wait for an OK
                                let (tx, rx) = oneshot::channel();
                                ok_callbacks.insert(auth_event.id.clone(), tx);
                                let _ = write_queue
                                    .send(
                                        serde_json::to_string(&Envelope::AuthEvent {
                                            event: auth_event,
                                        })
                                        .unwrap(),
                                    )
                                    .await;

                                if let Ok(_) = rx.await {
                                    // then restart the subscription
                                    let _ = write_queue
                                        .send(
                                            serde_json::to_string(&Envelope::Req {
                                                subscription_id: subscription_id,
                                                filters: vec![sub.filter.clone()],
                                            })
                                            .unwrap(),
                                        )
                                        .await;

                                    // and set this option to false this time to prevent an infinite
                                    // AUTH loop
                                    sub.auth_automatically = None;
                                    return;
                                }
                            };
                        }
                    }
                }
            }

            // now that we checked for that circumstance and didn't hit the `continue`
            // we can proceed to remove this subscription and issue the final `Close`
            if let Some(sub) = ssm.remove(key) {
                let _ = sub
                    .ocurrences_sender
                    .send(Occurrence::Close(CloseReason::ClosedByThemWithReason(
                        reason,
                    )))
                    .await;
            }
        }
        Ok(Envelope::AuthChallenge { challenge }) => {
            let _ = relay_challenge.write().await.insert(challenge);
        }
        Ok(envelope) => {
            log::info!("[{}] unexpected message: {}", &relay_url, envelope.label());
        }
        Err(err) => {
            log::info!("[{}] wrong message: {}", &relay_url, err);
        }
    }
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod tests {
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    async fn test_subscribe() {
        // wasm tests would go here
        // note: testing websockets in wasm requires a test server
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
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
            .await;

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
