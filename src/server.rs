//! Nostr relay server implementation using hyper
//!
//! This module provides a complete Nostr relay server implementation
//! using hyper for HTTP and WebSocket handling.

use crate::nip11::RelayInformationDocument;
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::TcpListener;

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

impl RelayInternals {
    pub fn new() -> Self {
        RelayInternals {
            info: RelayInformationDocument {
                ..Default::default()
            },
        }
    }

    /// start the relay server
    pub async fn start(&self, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;

        let service = hyper::service::service_fn(async |req| {
            match (req.method(), req.uri().path()) {
                // (&Method::GET, "/") => {
                //     // check if this is a websocket upgrade request
                //     if hyper_tungstenite::is_upgrade_request(&req) {
                //         self.handle_websocket_upgrade(req).await
                //     } else {
                //         // check for NIP-11 request
                //         if let Some(accept) = req.headers().get("accept") {
                //             if accept == "application/nostr+json" {
                //                 return self.handle_nip11().await;
                //             }
                //         }

                //         // default response
                //         Ok(Response::builder()
                //             .status(StatusCode::OK)
                //             .body("nostr relay")
                //             .unwrap())
                //     }
                // }
                _ => {
                    let x = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body("x".to_string())
                        .unwrap();
                    let res: std::result::Result<Response<String>, String> = Ok(x);
                    res
                }
            }
        });

        loop {
            let (tcp, _) = listener.accept().await?;
            let io = TokioIo::new(tcp);

            tokio::task::spawn(async move {
                let conn = hyper::server::conn::http1::Builder::new().serve_connection(io, service);

                if let Err(err) = conn.await {
                    println!("error serving connection: {:?}", err);
                };
            });

            println!("relay listening on {}", addr);
        }
    }

    // /// handle NIP-11 information request
    // async fn handle_nip11(&self) -> Result<Response<Body>> {
    //     let info = self.info.read().await;
    //     let json = serde_json::to_string(&*info)?;

    //     Ok(Response::builder()
    //         .status(StatusCode::OK)
    //         .header("content-type", "application/nostr+json")
    //         .header("access-control-allow-origin", "*")
    //         .body(Body::from(json))
    //         .unwrap())
    // }

    // /// handle websocket upgrade
    // async fn handle_websocket_upgrade(&self, req: Request<Body>) -> Result<Response<Body>> {
    //     let (response, websocket) = hyper_tungstenite::upgrade(req, None).unwrap();

    //     // spawn task to handle the websocket connection
    //     tokio::spawn(async move {
    //         if let Err(e) = handle_websocket_connection(websocket).await {
    //             eprintln!("websocket error: {}", e);
    //         }
    //     });

    //     Ok(response)
    // }
}

impl Clone for RelayInternals {
    fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
        }
    }
}

// /// handle websocket connection
// async fn handle_websocket_connection(websocket: HyperWebsocket) -> Result<()> {
//     let mut ws_stream = websocket.await?;
//
//     ws_stream.send(Message::text("banana")).await?;
//
//     println!("websocket connection established (but not implemented yet)");
//
//     Ok(())
// }

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_nip11_endpoint() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let relay = RelayInternals::new();

        // start server in background
        let server_handle = tokio::spawn(async move { relay.start(addr).await });

        // give server time to start
        sleep(Duration::from_millis(100)).await;

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
