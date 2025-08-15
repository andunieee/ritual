use crate::finalizer::Finalizer;
use crate::helpers::{
    extract_event_id, extract_key_from_sub_id, key_from_sub_id, sub_id_from_key, SubscriptionKey,
};
use crate::{envelopes::*, Event, EventTemplate, Filter, Kind, Tags, Timestamp, ID};
use dashmap::{DashMap, DashSet};
use slotmap::{SecondaryMap, SlotMap};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::oneshot;
use tokio_with_wasm::alias as tokio;
use url::Url;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use web_sys::{CloseEvent, ErrorEvent, MessageEvent, WebSocket};

// type alias for web environment - in a real implementation, this would be a proper callback
type WebOnClose = Rc<RefCell<Option<Box<dyn FnOnce(String)>>>>;

#[derive(Error, Debug)]
pub enum PublishError {
    #[error("ok=false, relay message: {0}")]
    NotOK(String),

    #[error("internal channel error, relay connection might have closed")]
    Channel,
}

#[derive(Error, Debug)]
pub enum ConnectError {
    #[error("relay connection error")]
    Websocket,
}

#[derive(Debug)]
pub(crate) struct SubSender {
    pub(crate) ocurrences_sender: Rc<RefCell<Vec<Occurrence>>>,
    pub(crate) filter: Filter,
    pub(crate) auth_automatically: Option<Finalizer>,
}

#[derive(Debug, Clone)]
pub struct Relay {
    pub url: Url,
    ws: Rc<RefCell<Option<WebSocket>>>,
    challenge: Rc<RefCell<Option<String>>>,

    // by subscription
    pub(crate) sub_sender_map: Rc<RefCell<SlotMap<SubscriptionKey, SubSender>>>,
    id_skippers_map: Rc<RefCell<SecondaryMap<SubscriptionKey, Arc<DashSet<ID>>>>>,

    // by publish
    ok_callbacks: Rc<RefCell<DashMap<ID, Rc<RefCell<Option<Result<(), String>>>>>>>,
}

impl Relay {
    pub async fn connect(
        url: Url,
        mut on_close: Option<oneshot::Sender<String>>,
    ) -> Result<Self, ConnectError> {
        // create websocket
        let ws = WebSocket::new(url.as_str()).map_err(|_| ConnectError::Websocket)?;

        let relay = Self {
            url: url.clone(),
            ws: Rc::new(RefCell::new(Some(ws.clone()))),
            sub_sender_map: Rc::new(RefCell::new(SlotMap::with_capacity_and_key(8))),
            id_skippers_map: Rc::new(RefCell::new(SecondaryMap::with_capacity(8))),
            challenge: Rc::new(RefCell::new(None)),
            ok_callbacks: Rc::new(RefCell::new(DashMap::new())),
        };

        // setup message handler
        let id_skippers_map = relay.id_skippers_map.clone();
        let sub_sender_map = relay.sub_sender_map.clone();
        let relay_challenge = relay.challenge.clone();
        let ok_callbacks = relay.ok_callbacks.clone();
        let relay_url = Rc::new(RefCell::new(relay.url.to_string()));
        let relay_ws = relay.ws.clone();

        let on_message = Closure::wrap(Box::new(move |e: MessageEvent| {
            if let Ok(text) = e.data().dyn_into::<js_sys::JsString>() {
                let message: String = text.into();

                // check for duplicate events
                match extract_key_from_sub_id(&message) {
                    None => {}
                    Some(sub_key) => {
                        if let Some(skip_ids) = id_skippers_map.borrow().get(sub_key) {
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
                        if let Some(sub) = sub_sender_map.borrow().get(key) {
                            if sub.filter.matches(&event) && event.verify_signature() {
                                sub.ocurrences_sender
                                    .borrow_mut()
                                    .push(Occurrence::Event(event));
                            }
                        }
                    }
                    Ok(Envelope::Eose { subscription_id }) => {
                        let key = key_from_sub_id(subscription_id.as_str());
                        let mut map = sub_sender_map.borrow_mut();
                        if let Some(occfilter) = map.get_mut(key) {
                            // since we got an EOSE our internal filter won't check for since/until anymore
                            occfilter.filter.since = None;
                            occfilter.filter.until = None;

                            // and we dispatch this to the listener
                            occfilter
                                .ocurrences_sender
                                .borrow_mut()
                                .push(Occurrence::EOSE);
                        }
                    }
                    Ok(Envelope::Ok {
                        event_id,
                        ok,
                        reason,
                    }) => {
                        if let Some((_, callback)) = ok_callbacks.borrow_mut().remove(&event_id) {
                            *callback.borrow_mut() = Some(match ok {
                                true => Ok(()),
                                false => Err(reason),
                            });
                        } else {
                            web_sys::console::log_1(
                                &format!(
                                    "received OK for unknown event {}: {} - {}",
                                    event_id, ok, reason
                                )
                                .into(),
                            );
                        }
                    }
                    Ok(Envelope::Notice(notice)) => {
                        web_sys::console::log_1(
                            &format!("[{}] received notice: {}", relay_url.borrow(), notice).into(),
                        );
                    }
                    Ok(Envelope::Closed {
                        subscription_id,
                        reason,
                    }) => {
                        let key = key_from_sub_id(&subscription_id);
                        let mut ssm = sub_sender_map.borrow_mut();

                        if let Some(sub) = ssm.get_mut(key) {
                            if reason.starts_with("auth-required:") {
                                if let Some(challenge) = relay_challenge.borrow().clone() {
                                    if let Some(finalizer) = sub.auth_automatically.take() {
                                        // perform AUTH
                                        let ws = relay_ws.clone();
                                        let ok_callbacks = ok_callbacks.clone();

                                        tokio::spawn(async move {
                                            let result = finalizer.finalize_event(EventTemplate {
                                                created_at: Timestamp::now(),
                                                kind: Kind(22242),
                                                content: "".to_string(),
                                                tags: Tags(vec![
                                                    vec![
                                                        "relay".to_string(),
                                                        "".to_string(),
                                                        // relay_url.borrow().clone(),
                                                    ],
                                                    vec!["challenge".to_string(), challenge],
                                                ]),
                                            });

                                            if let Ok(auth_event) = result.await {
                                                // send AUTH message
                                                let auth_msg =
                                                    serde_json::to_string(&Envelope::AuthEvent {
                                                        event: auth_event.clone(),
                                                    })
                                                    .unwrap();

                                                if let Some(ws) = ws.borrow().as_ref() {
                                                    let _ = ws.send_with_str(&auth_msg);

                                                    // register OK callback
                                                    ok_callbacks.borrow_mut().insert(
                                                        auth_event.id.clone(),
                                                        Rc::new(RefCell::new(None)),
                                                    );

                                                    // TODO: wait for OK and restart subscription
                                                    // this would require more complex async handling in wasm
                                                }
                                            }
                                        });
                                        return;
                                    }
                                }
                            }
                        }

                        // remove subscription and send close
                        if let Some(sub) = ssm.remove(key) {
                            sub.ocurrences_sender.borrow_mut().push(Occurrence::Close(
                                CloseReason::ClosedByThemWithReason(reason),
                            ));
                        }
                    }
                    Ok(Envelope::AuthChallenge { challenge }) => {
                        *relay_challenge.borrow_mut() = Some(challenge);
                    }
                    Ok(envelope) => {
                        web_sys::console::log_1(
                            &format!(
                                "[{}] unexpected message: {}",
                                relay_url.borrow(),
                                envelope.label()
                            )
                            .into(),
                        );
                    }
                    Err(err) => {
                        web_sys::console::log_1(
                            &format!("[{}] wrong message: {}", relay_url.borrow(), err).into(),
                        );
                    }
                }
            }
        }) as Box<dyn FnMut(MessageEvent)>);
        ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

        // setup error handler
        let on_error = Closure::wrap(Box::new(move |e: ErrorEvent| {
            web_sys::console::error_1(&format!("WebSocket error: {:?}", e.message()).into());
        }) as Box<dyn FnMut(ErrorEvent)>);
        ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

        // setup close handler
        let sub_sender_map_close = relay.sub_sender_map.clone();
        let on_close_handler = Closure::wrap(Box::new(move |e: CloseEvent| {
            web_sys::console::log_1(
                &format!("WebSocket closed: code={} reason={}", e.code(), e.reason()).into(),
            );

            // notify all subscriptions
            for (_, sub) in sub_sender_map_close.borrow_mut().drain() {
                sub.ocurrences_sender.borrow_mut().push(Occurrence::Close(
                    CloseReason::RelayConnectionClosedByThem(None),
                ));
            }

            if let Some(on_close) = on_close.take() {
                let _ = on_close.send(format!("closed: {:?}", e.reason()));
            }
        }) as Box<dyn FnMut(CloseEvent)>);

        ws.set_onclose(Some(on_close_handler.as_ref().unchecked_ref()));

        // setup open handler for connection ready
        let on_open = Closure::wrap(Box::new(move |_: JsValue| {
            web_sys::console::log_1(&format!("WebSocket connected to {}", url.as_str()).into());
        }) as Box<dyn FnMut(JsValue)>);

        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));

        // wait for connection to be established
        // in web environment, we return immediately and rely on the onopen event

        Ok(relay)
    }

    pub async fn publish(&self, event: Event) -> Result<(), PublishError> {
        let callback = Rc::new(RefCell::new(None));
        self.ok_callbacks
            .borrow_mut()
            .insert(event.id.clone(), callback.clone());

        let msg = serde_json::json!(["EVENT", event]);

        if let Some(ws) = self.ws.borrow().as_ref() {
            ws.send_with_str(&msg.to_string())
                .map_err(|_| PublishError::Channel)?;
        } else {
            return Err(PublishError::Channel);
        }

        // in web environment, we need to poll for the result
        // this is a simplified version - in production you'd want proper async handling
        for _ in 0..100 {
            // poll up to 10 seconds
            if let Some(result) = callback.borrow_mut().take() {
                return result.map_err(|err| PublishError::NotOK(err));
            }
            // sleep for 100ms - this would need proper async handling in wasm
            // for now, return immediately
        }

        Err(PublishError::Channel)
    }

    /// subscribe to events matching a filter
    pub async fn subscribe(&self, filter: Filter, opts: SubscriptionOptions) -> WebReceiver {
        // in web environment, we use a custom receiver implementation
        let occurrences_sender = Rc::new(RefCell::new(Vec::new()));

        let key = self.sub_sender_map.borrow_mut().insert_with_key(|key| {
            let id = sub_id_from_key(&key, &opts.label);

            // send REQ message
            let reqmsg = format!(
                r#"["REQ","{}",{}]"#,
                id,
                serde_json::to_string(&filter).unwrap()
            );

            if let Some(ws) = self.ws.borrow().as_ref() {
                let _ = ws.send_with_str(&reqmsg);
            }

            SubSender {
                ocurrences_sender: occurrences_sender.clone(),
                filter,
                auth_automatically: opts.auth_automatically,
            }
        });

        if let Some(skip_ids) = opts.skip_ids {
            self.id_skippers_map.borrow_mut().insert(key, skip_ids);
        }

        WebReceiver {
            occurrences: occurrences_sender,
        }
    }

    pub async fn close(self) -> () {
        // notify all subscriptions
        for (_, sub) in self.sub_sender_map.borrow_mut().drain() {
            sub.ocurrences_sender
                .borrow_mut()
                .push(Occurrence::Close(CloseReason::RelayConnectionClosedByUs));
        }

        if let Some(ws) = self.ws.borrow().as_ref() {
            let _ = ws.close();
        }
    }
}

impl std::fmt::Display for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url)
    }
}

// custom receiver for web environment
pub struct WebReceiver {
    occurrences: Rc<RefCell<Vec<Occurrence>>>,
}

impl WebReceiver {
    pub async fn recv(&mut self) -> Option<Occurrence> {
        // in a real implementation, this would use proper async channels for wasm
        // for now, we just poll the vector
        if let Some(occ) = self.occurrences.borrow_mut().pop() {
            Some(occ)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub enum CloseReason {
    RelayConnectionClosedByUs,
    RelayConnectionClosedByThem(Option<()>), // simplified for web
    RelayConnectionError,
    ClosedByUs,
    ClosedByThemWithReason(String),
    Unknown,
}

#[derive(Default, Clone)]
pub struct SubscriptionOptions {
    pub label: Option<String>,
    pub timeout: Option<Duration>,

    pub on_close: Option<WebOnClose>,
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

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    async fn test_subscribe() {
        // wasm tests would go here
        // note: testing websockets in wasm requires a test server
    }
}
