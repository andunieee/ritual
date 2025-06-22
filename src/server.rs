//! Nostr relay server implementation using hyper
//!
//! This module provides a complete Nostr relay server implementation
//! using hyper for HTTP and WebSocket handling.

use crate::{
    envelopes::{parse_message, Envelope, ReqEnvelope},
    nip11::RelayInformationDocument,
};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::{body::Incoming, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::{net::SocketAddr, sync::Arc};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

#[derive(Error, Debug)]
pub enum RelayError {
    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("websocket error: {0}")]
    WebSocket(#[from] hyper_tungstenite::tungstenite::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, RelayError>;

/// main relay server
pub struct RelayInternals {
    /// relay information for NIP-11
    pub info: RelayInformationDocument,
}

fn new() -> Arc<RelayInternals> {
    Arc::new(RelayInternals {
        info: RelayInformationDocument {
            ..Default::default()
        },
    })
}

/// start the relay server
async fn start(ri: Arc<RelayInternals>, addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("relay listening on {}", addr);

    async fn service(
        req: Request<Incoming>,
        ri: Arc<RelayInternals>,
    ) -> std::result::Result<Response<Full<Bytes>>, String> {
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => {
                // check if this is a websocket upgrade request
                if hyper_tungstenite::is_upgrade_request(&req) {
                    match hyper_tungstenite::upgrade(req, None) {
                        Ok((response, websocket)) => {
                            tokio::spawn(async move {
                                match websocket.await {
                                    Ok(ws_stream) => {
                                        let (mut tx, mut rx) = ws_stream.split();

                                        // handle incoming messages
                                        tokio::spawn(async move {
                                            while let Some(Ok(msg)) = rx.next().await {
                                                match msg {
                                                    Message::Text(msg) => {
                                                        match parse_message(msg.as_str()) {
                                                            Ok(Envelope::Req(req)) => {}
                                                            Ok(Envelope::CountAsk(creq)) => {}
                                                            Ok(Envelope::OutEvent(evt)) => {}
                                                            _ => {}
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        });
                                    }
                                    Err(e) => {
                                        println!("websocket upgrade failed: {}", e);
                                    }
                                }
                            });

                            Ok::<hyper::Response<http_body_util::Full<bytes::Bytes>>, String>(
                                response,
                            )
                        }
                        Err(e) => {
                            println!("websocket upgrade error: {}", e);
                            Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Full::new(Bytes::from("websocket upgrade failed")))
                                .unwrap())
                        }
                    }
                } else {
                    // check for NIP-11 request
                    if let Some(accept) = req.headers().get("accept") {
                        if accept == "application/nostr+json" {
                            let info_json = match serde_json::to_string(&ri.info) {
                                Ok(json) => json,
                                Err(_) => "{}".to_string(),
                            };
                            return Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/nostr+json")
                                .header("access-control-allow-origin", "*")
                                .body(Full::new(Bytes::from(info_json)))
                                .unwrap());
                        }
                    }

                    // default response
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from("nostr relay")))
                        .unwrap())
                }
            }
            _ => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("not found")))
                .unwrap()),
        }
    }

    loop {
        let (tcp, _) = listener.accept().await?;
        let io = TokioIo::new(tcp);
        let ri_ = ri.clone();

        println!("loop");

        tokio::task::spawn(async move {
            let http = hyper::server::conn::http1::Builder::new();
            let conn = http
                .serve_connection(
                    io,
                    hyper::service::service_fn(|req| service(req, ri_.clone())),
                )
                .with_upgrades();

            if let Err(err) = conn.await {
                println!("error serving connection: {:?}", err);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_nip11_endpoint() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let relay = new();

        // start server in background
        let server_handle = tokio::spawn(async move { start(relay, addr).await });

        // give server time to start
        sleep(Duration::from_millis(200000)).await;

        // make NIP-11 request
        let client = reqwest::Client::new();
        let response = client
            .get("http://127.0.0.1:8080/")
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
        assert_eq!(info.name, "");
        assert_eq!(info.description, "");

        // cleanup
        server_handle.abort();
    }
}
