//! Nostr relay server implementation using hyper
//!
//! This module provides a complete Nostr relay server implementation
//! using hyper for HTTP and WebSocket handling.

use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite;

#[derive(thiserror::Error, Debug)]
pub enum RelayError {
    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("websocket error: {0}")]
    WebSocket(#[from] hyper_tungstenite::tungstenite::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("custom relay error: {0}")]
    CustomRelay(String),
}

/// trait for custom relay implementations
pub trait CustomRelay: Send + Sync {
    fn handle_event(&mut self, _event: &crate::Event) -> std::result::Result<(), String> {
        Err("can't handle anything".to_string())
    }

    fn handle_request(
        &mut self,
        _filter: &crate::Filter,
    ) -> std::result::Result<Vec<crate::Event>, String> {
        Err("can't handle anything".to_string())
    }
}

/// main relay server
pub struct RelayInternals {
    /// relay metadata
    pub info: crate::relay_information::RelayInformationDocument,

    /// the actual relay methods
    pub custom_relay: Box<tokio::sync::Mutex<dyn CustomRelay>>,
}

#[derive(thiserror::Error, Debug)]
pub enum StartError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum ServiceError {
    #[error("websocket error")]
    WebSocket,

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("custom relay error: {0}")]
    CustomRelay(String),

    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),
}

/// start the relay server
pub async fn start(
    ri: std::sync::Arc<RelayInternals>,
    addr: std::net::SocketAddr,
) -> Result<(), StartError> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    log::info!("relay listening on {}", addr);

    async fn service(
        req: hyper::Request<hyper::body::Incoming>,
        ri: std::sync::Arc<RelayInternals>,
    ) -> std::result::Result<hyper::Response<http_body_util::Full<bytes::Bytes>>, ServiceError>
    {
        match (req.method(), req.uri().path()) {
            (&hyper::Method::GET, "/") => {
                // check if this is a websocket upgrade request
                if hyper_tungstenite::is_upgrade_request(&req) {
                    match hyper_tungstenite::upgrade(req, None) {
                        Ok((response, websocket)) => {
                            let ri = ri.clone();
                            tokio::spawn(async move {
                                match websocket.await {
                                    Ok(ws_stream) => {
                                        let (tx, mut rx) = ws_stream.split();
                                        let tx = std::sync::Arc::new(tokio::sync::Mutex::new(tx));

                                        // handle incoming messages
                                        tokio::spawn(async move {
                                            while let Some(Ok(msg)) = rx.next().await {
                                                if let tungstenite::Message::Text(msg_text) = msg {
                                                    match serde_json::from_str::<crate::envelopes::Envelope>(
                                                        msg_text.as_str(),
                                                    ) {
                                                        Ok(crate::envelopes::Envelope::Req {
                                                            subscription_id,
                                                            filters,
                                                        }) => {
                                                            let _ = handle_req_envelope(
                                                                &ri,
                                                                tx.clone(),
                                                                subscription_id,
                                                                filters,
                                                            )
                                                            .await;
                                                        }
                                                        // Ok(Envelope::CountAsk { subscription_id, filter }) => {
                                                        //     handle_count_ask(
                                                        //         &ri, tx, subscription_id, filter,
                                                        //     )
                                                        //     .await;
                                                        // }
                                                        Ok(crate::envelopes::Envelope::OutEvent {
                                                            event,
                                                        }) => {
                                                            let _ = handle_event_envelope(
                                                                &ri,
                                                                tx.clone(),
                                                                &event,
                                                            )
                                                            .await;
                                                        }
                                                        Ok(envelope) => {
                                                            let notice = serde_json::json!(["NOTICE", format!("we don't know how to handle this {}", envelope.label())]);
                                                            let _ = tx
                                                                .lock()
                                                                .await
                                                                .send(
                                                                    tungstenite::Message::text(
                                                                        notice.to_string(),
                                                                    ),
                                                                )
                                                                .await;
                                                        }
                                                        Err(err) => {
                                                            let notice = serde_json::json!(["NOTICE", format!("failed to parse message: {}", err)]);
                                                            let _ = tx
                                                                .lock()
                                                                .await
                                                                .send(
                                                                    tungstenite::Message::text(
                                                                        notice.to_string(),
                                                                    ),
                                                                )
                                                                .await;
                                                        }
                                                    }
                                                }
                                            }
                                        });
                                    }
                                    Err(e) => {
                                        log::debug!("websocket upgrade failed: {}", e);
                                    }
                                }
                            });

                            Ok::<hyper::Response<http_body_util::Full<bytes::Bytes>>, ServiceError>(
                                response,
                            )
                        }
                        Err(e) => {
                            log::debug!("websocket upgrade error: {}", e);
                            Err(ServiceError::WebSocket)
                        }
                    }
                } else {
                    // is this a metadata request?
                    if let Some(accept) = req.headers().get("accept")
                        && accept == "application/nostr+json" {
                            let info_json = match serde_json::to_string(&ri.info) {
                                Ok(json) => json,
                                Err(e) => return Err(ServiceError::Json(e)),
                            };
                            return Ok(hyper::Response::builder()
                                .status(hyper::StatusCode::OK)
                                .header("content-type", "application/nostr+json")
                                .header("access-control-allow-origin", "*")
                                .body(http_body_util::Full::new(bytes::Bytes::from(info_json)))
                                .unwrap());
                        }

                    // default response
                    Ok(hyper::Response::builder()
                        .status(hyper::StatusCode::OK)
                        .body(http_body_util::Full::new(bytes::Bytes::from(
                            "nostr relay made with ritual",
                        )))
                        .unwrap())
                }
            }
            _ => Ok(hyper::Response::builder()
                .status(hyper::StatusCode::NOT_FOUND)
                .body(http_body_util::Full::new(bytes::Bytes::from("not found")))
                .unwrap()),
        }
    }

    loop {
        let (tcp, _) = listener.accept().await?;
        let io = hyper_util::rt::TokioIo::new(tcp);
        let ri_ = ri.clone();

        tokio::task::spawn(async move {
            let http = hyper::server::conn::http1::Builder::new();
            let conn = http
                .serve_connection(
                    io,
                    hyper::service::service_fn(|req| service(req, ri_.clone())),
                )
                .with_upgrades();

            if let Err(err) = conn.await {
                log::debug!("error serving connection: {:?}", err);
            }
        });
    }
}

#[derive(thiserror::Error, Debug)]
pub enum HandleReqEnvelopeError {
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("websocket error: {0}")]
    WebSocket(#[from] hyper_tungstenite::tungstenite::Error),

    #[error("custom relay error: {0}")]
    CustomRelay(String),
}

async fn handle_req_envelope(
    ri: &std::sync::Arc<RelayInternals>,
    tx: std::sync::Arc<
        tokio::sync::Mutex<
            futures::stream::SplitSink<
                tokio_tungstenite::WebSocketStream<
                    hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>,
                >,
                tungstenite::Message,
            >,
        >,
    >,
    subscription_id: String,
    filters: Vec<crate::Filter>,
) -> Result<(), HandleReqEnvelopeError> {
    for filter in filters {
        // query events
        match ri.custom_relay.lock().await.handle_request(&filter) {
            Ok(events) => {
                for event in events {
                    let event_env = serde_json::json!(["EVENT", subscription_id, event]);
                    tx.lock()
                        .await
                        .send(tungstenite::Message::text(event_env.to_string()))
                        .await?;
                }
            }
            Err(e) => {
                let notice = serde_json::json!(["NOTICE", format!("query error: {}", e)]);
                tx.lock()
                    .await
                    .send(tungstenite::Message::text(notice.to_string()))
                    .await?;
            }
        }
    }

    // send EOSE
    let eose_json = serde_json::json!(["EOSE", subscription_id]);
    tx.lock()
        .await
        .send(tungstenite::Message::text(eose_json.to_string()))
        .await?;

    Ok(())
}

#[derive(thiserror::Error, Debug)]
pub enum HandleEventEnvelopeError {
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("websocket error: {0}")]
    WebSocket(#[from] hyper_tungstenite::tungstenite::Error),

    #[error("custom relay error: {0}")]
    CustomRelay(String),
}

async fn handle_event_envelope(
    ri: &std::sync::Arc<RelayInternals>,
    tx: std::sync::Arc<
        tokio::sync::Mutex<
            futures::stream::SplitSink<
                tokio_tungstenite::WebSocketStream<
                    hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>,
                >,
                tungstenite::Message,
            >,
        >,
    >,
    event: &crate::Event,
) -> Result<(), HandleEventEnvelopeError> {
    // check event ID
    if !event.check_id() {
        let ok_json =
            serde_json::json!(["OK", event.id, false, "invalid: id is computed incorrectly"]);
        tx.lock()
            .await
            .send(tungstenite::Message::text(ok_json.to_string()))
            .await?;
        return Ok(());
    }

    // check signature
    if !event.verify_signature() {
        let ok_json = serde_json::json!(["OK", event.id, false, "invalid: signature is invalid"]);
        tx.lock()
            .await
            .send(tungstenite::Message::text(ok_json.to_string()))
            .await?;
        return Ok(());
    }

    // possibly save event
    match ri.custom_relay.lock().await.handle_event(event) {
        Ok(()) => {
            let ok_json = serde_json::json!(["OK", event.id, true, ""]);
            tx.lock()
                .await
                .send(tungstenite::Message::text(ok_json.to_string()))
                .await?;
        }
        Err(e) => {
            let ok_json = serde_json::json!([
                "OK",
                event.id,
                false,
                crate::normalize_ok_message(&e, "error")
            ]);
            tx.lock()
                .await
                .send(tungstenite::Message::text(ok_json.to_string()))
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::Occurrence;
    use crate::relay_information::RelayInformationDocument;
    use crate::*;
    use std::{cmp::min, net::SocketAddr};
    use tokio::time::{sleep, Duration};

    struct InMemoryRelay {
        events: Vec<Event>,
    }

    impl CustomRelay for InMemoryRelay {
        fn handle_event(&mut self, event: &Event) -> std::result::Result<(), String> {
            self.events.push(event.clone());
            Ok(())
        }

        fn handle_request(&mut self, filter: &Filter) -> std::result::Result<Vec<Event>, String> {
            let mut resp = Vec::with_capacity(min(
                filter.limit.unwrap_or(500),
                filter.get_theoretical_limit(),
            ));
            for event in &self.events {
                if filter.matches(event) {
                    resp.push(event.clone());
                }
            }
            Ok(resp)
        }
    }

    struct EvenTimestampRelay {
        events: Vec<Event>,
    }

    impl CustomRelay for EvenTimestampRelay {
        fn handle_event(&mut self, event: &Event) -> std::result::Result<(), String> {
            if event.created_at.0.is_multiple_of(2) {
                self.events.push(event.clone());
                Ok(())
            } else {
                Err("only even timestamps allowed".to_string())
            }
        }

        fn handle_request(&mut self, filter: &Filter) -> std::result::Result<Vec<Event>, String> {
            let mut resp = Vec::with_capacity(min(
                filter.limit.unwrap_or(500),
                filter.get_theoretical_limit(),
            ));
            for event in &self.events {
                if filter.matches(event) {
                    resp.push(event.clone());
                }
            }
            Ok(resp)
        }
    }

    struct OddTimestampRelay {
        events: Vec<Event>,
    }

    impl CustomRelay for OddTimestampRelay {
        fn handle_event(&mut self, event: &Event) -> std::result::Result<(), String> {
            if event.created_at.0 % 2 == 1 {
                self.events.push(event.clone());
                Ok(())
            } else {
                Err("only odd timestamps allowed".to_string())
            }
        }

        fn handle_request(&mut self, filter: &Filter) -> std::result::Result<Vec<Event>, String> {
            let mut resp = Vec::with_capacity(min(
                filter.limit.unwrap_or(500),
                filter.get_theoretical_limit(),
            ));
            for event in &self.events {
                if filter.matches(event) {
                    resp.push(event.clone());
                }
            }
            Ok(resp)
        }
    }

    struct MultipleOfThreeRelay {
        events: Vec<Event>,
    }

    impl CustomRelay for MultipleOfThreeRelay {
        fn handle_event(&mut self, event: &Event) -> std::result::Result<(), String> {
            if event.created_at.0.is_multiple_of(3) {
                self.events.push(event.clone());
                Ok(())
            } else {
                Err("only timestamps that are multiples of 3 allowed".to_string())
            }
        }

        fn handle_request(&mut self, filter: &Filter) -> std::result::Result<Vec<Event>, String> {
            let mut resp = Vec::with_capacity(min(
                filter.limit.unwrap_or(500),
                filter.get_theoretical_limit(),
            ));
            for event in &self.events {
                if filter.matches(event) {
                    resp.push(event.clone());
                }
            }
            Ok(resp)
        }
    }

    #[tokio::test]
    async fn test_metadata_endpoint() {
        let addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let relay = std::sync::Arc::new(RelayInternals {
            info: RelayInformationDocument {
                name: "ksowknex".to_string(),
                ..Default::default()
            },
            custom_relay: Box::new(tokio::sync::Mutex::new(InMemoryRelay {
                events: Vec::with_capacity(1024),
            })),
        });

        // start server in background
        let server_handle = tokio::spawn(async move { start(relay, addr).await });

        // give server time to start
        sleep(Duration::from_millis(100)).await;

        // request metadata
        let client = reqwest::Client::new();
        let response = client
            .get("http://127.0.0.1:8081/")
            .header("accept", "application/nostr+json")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/nostr+json"
        );

        let info: RelayInformationDocument = response.json().await.unwrap();
        assert_eq!(info.name, "ksowknex");
        assert_eq!(info.description, "");

        // cleanup
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_relay_connect_publish_subscribe() {
        let addr: SocketAddr = "127.0.0.1:8082".parse().unwrap();
        let relay_internals = std::sync::Arc::new(RelayInternals {
            info: RelayInformationDocument {
                name: "test-relay".to_string(),
                ..Default::default()
            },
            custom_relay: Box::new(tokio::sync::Mutex::new(InMemoryRelay {
                events: Vec::with_capacity(1024),
            })),
        });

        // start server in background
        let server_handle = tokio::spawn(async move { start(relay_internals, addr).await });

        // give server time to start
        sleep(Duration::from_millis(100)).await;

        // connect to the relay
        let relay_url = "ws://127.0.0.1:8082".to_string().parse().unwrap();
        let relay = Relay::connect(relay_url, None).await.unwrap();

        // create and publish an event
        let secret_key = SecretKey::generate();
        let event_template = EventTemplate {
            created_at: Timestamp::now(),
            kind: Kind(1),
            tags: crate::Tags::default(),
            content: "hello from test".to_string(),
        };
        let event = event_template.finalize(&secret_key);
        let event_id = event.id;

        // publish the event
        relay.publish(event.clone()).await.unwrap();

        // subscribe to events
        let filter = Filter {
            kinds: Some(vec![Kind(1)]),
            limit: Some(10),
            ..Default::default()
        };

        let mut subscription = relay
            .subscribe(filter, crate::relay::SubscriptionOptions::default())
            .await;

        // wait for the event to be received
        let mut received_event = None;
        let mut got_eose = false;

        while let Some(occurrence) = subscription.recv().await {
            match occurrence {
                Occurrence::Event(evt) => {
                    if evt.id == event_id {
                        received_event = Some(evt);
                    }
                }
                Occurrence::Eose => {
                    got_eose = true;
                    break;
                }
                Occurrence::Close(_) => {
                    break;
                }
            }
        }

        // verify we received the event
        assert!(received_event.is_some());
        assert!(got_eose);
        let received = received_event.unwrap();
        assert_eq!(received.id, event_id);
        assert_eq!(received.content, "hello from test");
        assert_eq!(received.kind, Kind(1));

        // cleanup
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_pool_with_filtered_relays() {
        // start three relays with different filtering logic
        let even_addr: SocketAddr = "127.0.0.1:8083".parse().unwrap();
        let odd_addr: SocketAddr = "127.0.0.1:8084".parse().unwrap();
        let multiple_of_three_addr: SocketAddr = "127.0.0.1:8085".parse().unwrap();

        let even_relay = std::sync::Arc::new(RelayInternals {
            info: RelayInformationDocument {
                name: "even-relay".to_string(),
                ..Default::default()
            },
            custom_relay: Box::new(tokio::sync::Mutex::new(EvenTimestampRelay {
                events: Vec::with_capacity(1024),
            })),
        });

        let odd_relay = std::sync::Arc::new(RelayInternals {
            info: RelayInformationDocument {
                name: "odd-relay".to_string(),
                ..Default::default()
            },
            custom_relay: Box::new(tokio::sync::Mutex::new(OddTimestampRelay {
                events: Vec::with_capacity(1024),
            })),
        });

        let multiple_of_three_relay = std::sync::Arc::new(RelayInternals {
            info: RelayInformationDocument {
                name: "multiple-of-three-relay".to_string(),
                ..Default::default()
            },
            custom_relay: Box::new(tokio::sync::Mutex::new(MultipleOfThreeRelay {
                events: Vec::with_capacity(1024),
            })),
        });

        // start servers in background
        let even_handle = tokio::spawn(async move { start(even_relay, even_addr).await });
        let odd_handle = tokio::spawn(async move { start(odd_relay, odd_addr).await });
        let multiple_of_three_handle =
            tokio::spawn(
                async move { start(multiple_of_three_relay, multiple_of_three_addr).await },
            );

        // give servers time to start
        sleep(Duration::from_millis(200)).await;

        // create pool and relay urls
        let mut pool = Pool::new();
        let relay_urls = vec![
            "ws://127.0.0.1:8083".to_string(),
            "ws://127.0.0.1:8084".to_string(),
            "ws://127.0.0.1:8085".to_string(),
        ];

        // create events with different timestamps
        let secret_key = SecretKey::generate();
        let mut events = Vec::new();

        // create events with timestamps: 100, 101, 102, 103, 104, 105, 106, 107, 108, 109
        for i in 100..110 {
            let event_template = EventTemplate {
                created_at: Timestamp(i),
                kind: Kind(1),
                tags: crate::Tags::default(),
                content: format!("event with timestamp {}", i),
            };
            let event = event_template.finalize(&secret_key);
            events.push(event);
        }

        // publish all events to all relays
        for event in &events {
            let mut publish_results = pool.publish_many(relay_urls.clone(), event.clone()).await;

            // wait for all publish results
            let mut results = Vec::new();
            while let Some(result) = publish_results.recv().await {
                results.push(result);
            }

            // we expect 3 results (one from each relay)
            assert_eq!(results.len(), 3);
        }

        // query each relay individually
        let filter = Filter {
            kinds: Some(vec![Kind(1)]),
            limit: Some(20),
            ..Default::default()
        };

        // query even relay (should have events with timestamps: 100, 102, 104, 106, 108)
        let even_events = pool
            .query(
                vec!["ws://127.0.0.1:8083".to_string()],
                filter.clone(),
                SubscriptionOptions::default(),
            )
            .await;
        assert_eq!(even_events.len(), 5);
        for event in &even_events {
            assert_eq!(
                event.created_at.0 % 2,
                0,
                "even relay should only have events with even timestamps"
            );
        }

        // query odd relay (should have events with timestamps: 101, 103, 105, 107, 109)
        let odd_events = pool
            .query(
                vec!["ws://127.0.0.1:8084".to_string()],
                filter.clone(),
                SubscriptionOptions::default(),
            )
            .await;
        assert_eq!(odd_events.len(), 5);
        for event in &odd_events {
            assert_eq!(
                event.created_at.0 % 2,
                1,
                "odd relay should only have events with odd timestamps"
            );
        }

        // query multiple of three relay (should have events with timestamps: 102, 105, 108)
        let multiple_of_three_events = pool
            .query(
                vec!["ws://127.0.0.1:8085".to_string()],
                filter.clone(),
                SubscriptionOptions::default(),
            )
            .await;
        assert_eq!(multiple_of_three_events.len(), 3);
        for event in &multiple_of_three_events {
            assert_eq!(event.created_at.0 % 3, 0, "multiple of three relay should only have events with timestamps that are multiples of 3");
        }

        // verify specific timestamps
        let even_timestamps: Vec<u32> = even_events.iter().map(|e| e.created_at.0).collect();
        assert!(even_timestamps.contains(&100));
        assert!(even_timestamps.contains(&102));
        assert!(even_timestamps.contains(&104));
        assert!(even_timestamps.contains(&106));
        assert!(even_timestamps.contains(&108));

        let odd_timestamps: Vec<u32> = odd_events.iter().map(|e| e.created_at.0).collect();
        assert!(odd_timestamps.contains(&101));
        assert!(odd_timestamps.contains(&103));
        assert!(odd_timestamps.contains(&105));
        assert!(odd_timestamps.contains(&107));
        assert!(odd_timestamps.contains(&109));

        let multiple_of_three_timestamps: Vec<u32> = multiple_of_three_events
            .iter()
            .map(|e| e.created_at.0)
            .collect();
        assert!(multiple_of_three_timestamps.contains(&102));
        assert!(multiple_of_three_timestamps.contains(&105));
        assert!(multiple_of_three_timestamps.contains(&108));

        // cleanup
        even_handle.abort();
        odd_handle.abort();
        multiple_of_three_handle.abort();
    }
}
