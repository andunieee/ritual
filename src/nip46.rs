use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::{keys::SecretKey, nip44, pool::Pool, Event, EventTemplate, Filter, Kind, Timestamp};
use crate::{PubKey, Tags};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::oneshot;
use url::Url;
use velcro::hash_map;

#[derive(Debug, Serialize)]
struct Request<'a> {
    id: String,
    method: &'a str,
    params: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Response {
    pub id: String,
    pub result: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct BunkerClient {
    serial: Arc<AtomicU64>,
    client_secret_key: SecretKey,
    pool: Pool,
    target: PubKey,
    relays: Vec<String>,
    conversation_key: [u8; 32],
    listeners: Arc<DashMap<String, oneshot::Sender<Response>>>,
    expecting_auth: Arc<DashMap<String, ()>>,
    on_auth: Arc<Option<Box<dyn Fn(String) + Send + Sync>>>,

    // memoized
    get_public_key_response: Arc<tokio::sync::Mutex<Option<PubKey>>>,
}

impl BunkerClient {
    pub fn new(
        client_secret_key: SecretKey,
        target_public_key: PubKey,
        relays: Vec<String>,
        pool: Pool,
        on_auth: Option<Box<dyn Fn(String) + Send + Sync>>,
    ) -> Self {
        let client_public_key = client_secret_key.public_key();
        let conversation_key =
            nip44::generate_conversation_key(&target_public_key, &client_secret_key);

        let bunker = Self {
            serial: Arc::new(AtomicU64::new(0)),
            client_secret_key,
            pool,
            target: target_public_key,
            relays,
            conversation_key,
            listeners: Arc::new(DashMap::new()),
            expecting_auth: Arc::new(DashMap::new()),
            on_auth: Arc::new(on_auth),
            get_public_key_response: Arc::new(tokio::sync::Mutex::new(None)),
        };

        let bunker_clone = bunker.clone();
        tokio::spawn(async move {
            let filter = Filter {
                kinds: Some(vec![Kind(24133)]),
                tags: Some(hash_map!("#p".to_string(): vec![client_public_key.to_hex()])),
                since: Some(Timestamp::now()),
                ..Default::default()
            };

            for url in bunker_clone.relays.iter() {
                let bunker_clone_2 = bunker_clone.clone();
                let url = url.clone();
                let filter = filter.clone();

                tokio::spawn(async move {
                    if let Ok(relay) = bunker_clone_2.pool.ensure_relay(&url).await {
                        if let Ok(mut sub) = relay.subscribe(filter, Default::default()).await {
                            while let Some(occ) = sub.recv().await {
                                if let crate::relay::Occurrence::Event(event) = occ {
                                    if event.kind.0 != 24133 {
                                        continue;
                                    }

                                    if let Ok(plain) = nip44::decrypt(
                                        &event.content,
                                        &bunker_clone_2.conversation_key,
                                    ) {
                                        if let Ok(resp) = serde_json::from_str::<Response>(&plain) {
                                            if resp.result.as_deref() == Some("auth_url") {
                                                if let Some(auth_url) = resp.error {
                                                    if bunker_clone_2
                                                        .expecting_auth
                                                        .remove(&resp.id)
                                                        .is_some()
                                                    {
                                                        if let Some(on_auth_fn) =
                                                            bunker_clone_2.on_auth.as_ref()
                                                        {
                                                            (on_auth_fn)(auth_url);
                                                        }
                                                    }
                                                }
                                                continue;
                                            }

                                            if let Some((_, dispatcher)) =
                                                bunker_clone_2.listeners.remove(&resp.id)
                                            {
                                                let _ = dispatcher.send(resp);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                });
            }
        });

        bunker
    }

    pub async fn connect(
        client_secret_key: SecretKey,
        bunker_url_or_nip05: &str,
        pool: Pool,
        on_auth: Option<Box<dyn Fn(String) + Send + Sync>>,
    ) -> Result<Self, String> {
        let (target_public_key, relays, secret) = if bunker_url_or_nip05.starts_with("bunker://") {
            let url = Url::parse(bunker_url_or_nip05).map_err(|e| e.to_string())?;
            let host = url.host_str().ok_or("invalid bunker host")?;
            let pk = PubKey::from_hex(host).map_err(|e| e.to_string())?;
            let relays = url
                .query_pairs()
                .filter(|(k, _)| k == "relay")
                .map(|(_, v)| v.to_string())
                .collect();
            let secret = url
                .query_pairs()
                .find(|(k, _)| k == "secret")
                .map(|(_, v)| v.to_string());
            (pk, relays, secret)
        } else {
            return Err("bla".to_string());
        };

        let bunker = Self::new(
            client_secret_key,
            target_public_key.clone(),
            relays,
            pool,
            on_auth,
        );

        let mut params = vec![target_public_key.to_hex()];
        if let Some(secret) = secret {
            params.push(secret);
        }

        bunker.rpc("connect", params, true).await?;
        Ok(bunker)
    }

    pub async fn ping(&self) -> Result<(), String> {
        self.rpc("ping", vec![], false).await?;
        Ok(())
    }

    pub async fn get_public_key(&self) -> Result<PubKey, String> {
        {
            let guard = self.get_public_key_response.lock().await;
            if let Some(pk) = *guard {
                return Ok(pk);
            }
        }

        let resp = self.rpc("get_public_key", vec![], false).await?;
        let pk = PubKey::from_hex(&resp).map_err(|e| e.to_string())?;

        {
            let mut guard = self.get_public_key_response.lock().await;
            *guard = Some(pk);
        }

        Ok(pk)
    }

    pub async fn sign_event(&self, event_template: &EventTemplate) -> Result<Event, String> {
        let event_json = json!({
            "created_at": event_template.created_at,
            "kind": event_template.kind,
            "tags": event_template.tags,
            "content": event_template.content,
        })
        .to_string();

        let resp = self.rpc("sign_event", vec![event_json], true).await?;
        let event: Event = serde_json::from_str(&resp).map_err(|e| e.to_string())?;

        if !event.verify_signature() {
            return Err("".to_string());
        }

        Ok(event)
    }

    pub async fn nip44_encrypt(
        &self,
        target_public_key: &PubKey,
        plaintext: &str,
    ) -> Result<String, String> {
        self.rpc(
            "nip44_encrypt",
            vec![target_public_key.to_hex(), plaintext.to_string()],
            true,
        )
        .await
    }

    pub async fn nip44_decrypt(
        &self,
        target_public_key: &PubKey,
        ciphertext: &str,
    ) -> Result<String, String> {
        self.rpc(
            "nip44_decrypt",
            vec![target_public_key.to_hex(), ciphertext.to_string()],
            true,
        )
        .await
    }

    pub async fn nip04_encrypt(
        &self,
        target_public_key: &PubKey,
        plaintext: &str,
    ) -> Result<String, String> {
        self.rpc(
            "nip04_encrypt",
            vec![target_public_key.to_hex(), plaintext.to_string()],
            true,
        )
        .await
    }

    pub async fn nip04_decrypt(
        &self,
        target_public_key: &PubKey,
        ciphertext: &str,
    ) -> Result<String, String> {
        self.rpc(
            "nip04_decrypt",
            vec![target_public_key.to_hex(), ciphertext.to_string()],
            true,
        )
        .await
    }

    async fn rpc(
        &self,
        method: &str,
        params: Vec<String>,
        expect_auth: bool,
    ) -> Result<String, String> {
        let id = format!("{}", self.serial.fetch_add(1, Ordering::SeqCst));
        let req = Request {
            id: id.clone(),
            method,
            params,
        };
        let req_json = serde_json::to_string(&req).map_err(|e| e.to_string())?;

        let content =
            nip44::encrypt(&req_json, &self.conversation_key, None).map_err(|e| e.to_string())?;

        let event = EventTemplate {
            content,
            created_at: Timestamp::now(),
            kind: Kind(24133),
            tags: Tags(vec![vec!["p".to_string(), self.target.to_hex()]]),
            ..Default::default()
        }
        .finalize(&self.client_secret_key)
        .map_err(|e| e.to_string())?;

        let (tx, rx) = oneshot::channel::<Response>();
        self.listeners.insert(id.clone(), tx);
        if expect_auth {
            self.expecting_auth.insert(id.clone(), ());
        }

        // publish
        let mut sent = false;
        for url in self.relays.iter() {
            if let Ok(relay) = self.pool.ensure_relay(url).await {
                if relay.publish(event.clone()).await.is_ok() {
                    sent = true;
                }
            }
        }

        if !sent {
            return Err("couldn't connect to any relay".to_string());
        }

        // wait for response
        match tokio::time::timeout(Duration::from_secs(15), rx).await {
            Ok(Ok(resp)) => {
                if let Some(err) = resp.error {
                    Err(format!("response error: {}", err))
                } else {
                    Ok(resp.result.unwrap_or_default())
                }
            }
            Ok(Err(_)) => Err("response channel closed".to_string()),
            Err(_) => {
                self.listeners.remove(&id);
                if expect_auth {
                    self.expecting_auth.remove(&id);
                }
                Err("request timed out".to_string())
            }
        }
    }
}
