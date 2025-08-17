use crate::helpers::{
    extract_event_id, extract_key_from_sub_id, key_from_sub_id, sub_id_from_key, SubscriptionKey,
};
use crate::relay_types::SubSender;
pub use crate::relay_types::{
    CloseReason, ConnectError, Occurrence, PublishError, SubscriptionOptions,
};
use crate::{envelopes::*, Event, EventTemplate, Filter, Kind, Tags, Timestamp, ID};
use dashmap::{DashMap, DashSet};
use slotmap::{SecondaryMap, SlotMap};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio_with_wasm::alias as tokio;
use url::Url;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use web_sys::{CloseEvent, ErrorEvent, MessageEvent, WebSocket};

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
    pub async fn connect(
        url: Url,
        mut on_close: Option<oneshot::Sender<String>>,
    ) -> Result<Self, ConnectError> {
        // create websocket
        log::info!("relay {}", url);

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
        let id_skippers_map = relay.id_skippers_map.clone();
        let sub_sender_map = relay.sub_sender_map.clone();
        let relay_challenge = relay.challenge.clone();
        let ok_callbacks = relay.ok_callbacks.clone();
        let relay_url = relay.url.to_string();
        let relay_ws = ws.clone();

        let on_message = Closure::wrap(Box::new(move |e: MessageEvent| {
            if let Ok(text) = e.data().dyn_into::<js_sys::JsString>() {
                let message: String = text.into();

                log::info!("got message from {}: {}", &relay_url, &message);

                let id_skippers_map = id_skippers_map.clone();
                let sub_sender_map = sub_sender_map.clone();
                let relay_challenge = relay_challenge.clone();
                let ok_callbacks = ok_callbacks.clone();
                let relay_url = relay_url.to_string();
                let relay_ws = relay_ws.clone();

                tokio::spawn(async move {
                    // check for duplicate events
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
                            let key = key_from_sub_id(subscription_id.as_str());
                            if let Some(sub) = sub_sender_map.lock().await.get(key) {
                                if sub.filter.matches(&event) && event.verify_signature() {
                                    let _ = sub.ocurrences_sender.send(Occurrence::Event(event));
                                }
                            }
                        }
                        Ok(Envelope::Eose { subscription_id }) => {
                            let key = key_from_sub_id(subscription_id.as_str());
                            let mut map = sub_sender_map.lock().await;
                            if let Some(occfilter) = map.get_mut(key) {
                                // since we got an EOSE our internal filter won't check for since/until anymore
                                occfilter.filter.since = None;
                                occfilter.filter.until = None;

                                // and we dispatch this to the listener
                                let _ = occfilter.ocurrences_sender.send(Occurrence::EOSE);
                            }
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
                            web_sys::console::log_1(
                                &format!("[{}] received notice: {}", &relay_url, notice).into(),
                            );
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
                                                    vec![
                                                        "relay".to_string(),
                                                        relay_url.to_string(),
                                                    ],
                                                    vec!["challenge".to_string(), challenge],
                                                ]),
                                            });
                                            if let Ok(auth_event) = result.await {
                                                // send the AUTH message and wait for an OK
                                                let (tx, rx) = oneshot::channel();
                                                ok_callbacks.insert(auth_event.id.clone(), tx);

                                                let _ = relay_ws.send_with_str(
                                                    &serde_json::to_string(&Envelope::AuthEvent {
                                                        event: auth_event,
                                                    })
                                                    .unwrap(),
                                                );

                                                if let Ok(_) = rx.await {
                                                    // then restart the subscription
                                                    let _ = relay_ws.send_with_str(
                                                        &serde_json::to_string(&Envelope::Req {
                                                            subscription_id: subscription_id,
                                                            filters: vec![sub.filter.clone()],
                                                        })
                                                        .unwrap(),
                                                    );

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
                            log::info!("[{}] wrong message: {}", &relay_url, err,);
                        }
                    }
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

    pub async fn publish(&self, event: Event) -> Result<(), PublishError> {
        let (tx, rx) = oneshot::channel();
        self.ok_callbacks.insert(event.id.clone(), tx);

        let msg = serde_json::json!(["EVENT", event]);

        self.write_queue
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

        let _ = self.write_queue.send(reqmsg).await;

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
        write!(f, "{}", self.url)
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    async fn test_subscribe() {
        // wasm tests would go here
        // note: testing websockets in wasm requires a test server
    }
}
