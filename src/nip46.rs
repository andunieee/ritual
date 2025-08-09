use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use crate::SecretKey;
use crate::{keys, nip44, pool::Pool, Event, EventTemplate, Filter, Kind, PubKey, Tags, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::json;
use slotmap::{new_key_type, Key, KeyData, SlotMap};
use thiserror::Error;
use tokio::sync::{oneshot, Mutex};
use url::Url;

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

pub struct AuthURLHandler(Box<dyn Fn(&str) + Send + Sync>);

impl Debug for AuthURLHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fn")
    }
}

#[derive(Error, Debug)]
pub enum RPCError {
    #[error("we're not connected to any relay")]
    NoRelays(Vec<String>),

    #[error("response channel closed")]
    NoResponse,

    #[error("request timed out")]
    Timeout,

    #[error("request encryption failed: {0}")]
    Encryption(#[from] nip44::EncryptError),

    #[error("response decryption failed: {0}")]
    Decryption(#[from] nip44::DecryptError),

    #[error("bunker replied with an error: {0}")]
    Response(String),
}

#[derive(Error, Debug)]
pub enum ConnectError {
    #[error("nip-46 rpc call failed: {0}")]
    RPC(#[from] RPCError),

    #[error("bunker uri is invalid")]
    URI(#[from] url::ParseError),

    #[error("bunker uri contains an invalid public key")]
    InvalidPublicKeyHost(#[from] keys::PubKeyError),
}

#[derive(Error, Debug)]
pub enum GetPublicKeyError {
    #[error("nip-46 rpc call failed: {0}")]
    RPC(#[from] RPCError),

    #[error("got an invalid public key")]
    InvalidPublicKey(#[from] keys::PubKeyError),
}

#[derive(Error, Debug)]
pub enum FinalizeError {
    #[error("bunker gave us an invalid event")]
    InvalidEvent,

    #[error("bunker gave us an event with an invalid signature")]
    InvalidSignature,

    #[error("nip-46 rpc call failed: {0}")]
    RPC(#[from] RPCError),
}

new_key_type! { struct RequestKey ; }

#[derive(Clone, Debug)]
pub struct BunkerClient
where
    Self: Send + Sync,
{
    client_secret_key: SecretKey,
    pool: Pool,
    target: PubKey,
    relays: Vec<String>,
    conversation_key: [u8; 32],
    awaiting_responses: Arc<Mutex<SlotMap<RequestKey, oneshot::Sender<Response>>>>,
    on_auth_url: Arc<Option<AuthURLHandler>>,

    // memoized
    get_pubkey_response: Arc<tokio::sync::Mutex<Option<PubKey>>>,
}

impl BunkerClient {
    pub fn new(
        client_secret_key: SecretKey,
        target_pubkey: PubKey,
        relays: Vec<String>,
        pool: Pool,
        on_auth_url: Option<AuthURLHandler>,
    ) -> Self {
        let client_pubkey = client_secret_key.pubkey();
        let conversation_key = nip44::generate_conversation_key(&target_pubkey, &client_secret_key);

        let bunker = Self {
            client_secret_key,
            pool,
            target: target_pubkey,
            relays,
            conversation_key,
            awaiting_responses: Arc::new(Mutex::new(SlotMap::with_capacity_and_key(10))),
            on_auth_url: Arc::new(on_auth_url),
            get_pubkey_response: Arc::new(tokio::sync::Mutex::new(None)),
        };

        let pool = bunker.pool.clone();
        let relays = bunker.relays.clone();
        let on_auth_url = bunker.on_auth_url.clone();
        let awaiting_responses = bunker.awaiting_responses.clone();
        tokio::spawn(async move {
            let filter = Filter {
                kinds: Some(vec![Kind(24133)]),
                tags: Some(vec![("#p".to_string(), vec![client_pubkey.to_hex()])]),
                since: Some(Timestamp::now()),
                ..Default::default()
            };

            for url in relays.iter() {
                let url = url.clone();
                let filter = filter.clone();

                let pool = pool.clone();
                let on_auth_url = on_auth_url.clone();
                let awaiting_responses = awaiting_responses.clone();
                tokio::spawn(async move {
                    if let Ok(relay) = pool.ensure_relay(&url).await {
                        let mut sub = relay.subscribe(filter, Default::default()).await;
                        while let Some(occ) = sub.recv().await {
                            if let crate::relay::Occurrence::Event(event) = occ {
                                if event.kind.0 != 24133 {
                                    continue;
                                }

                                if let Ok(plain) = nip44::decrypt(&event.content, &conversation_key)
                                {
                                    if let Ok(resp) = serde_json::from_str::<Response>(&plain) {
                                        let rk = match lowercase_hex::decode_to_array::<&str, 8>(
                                            &resp.id,
                                        ) {
                                            Ok(bytes) => RequestKey(KeyData::from_ffi(
                                                u64::from_be_bytes(bytes),
                                            )),
                                            Err(_) => continue,
                                        };

                                        if resp.result.as_deref() == Some("auth_url") {
                                            if let Some(auth_url) = &resp.error {
                                                {
                                                    if let Some(on_auth_fn) = on_auth_url.as_ref() {
                                                        on_auth_fn.0(auth_url);
                                                    }
                                                }
                                            }
                                        }

                                        if let Some(dispatcher) =
                                            awaiting_responses.lock().await.remove(rk)
                                        {
                                            let _ = dispatcher.send(resp);
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
        on_auth_url: Option<AuthURLHandler>,
    ) -> Result<Self, ConnectError> {
        let url = Url::parse(bunker_url_or_nip05)?;
        let host = url
            .host_str()
            .ok_or(ConnectError::URI(url::ParseError::EmptyHost))?;
        let pk = PubKey::from_hex(host)?;
        let relays = url
            .query_pairs()
            .filter(|(k, _)| k == "relay")
            .map(|(_, v)| v.to_string())
            .collect();
        let secret = url
            .query_pairs()
            .find(|(k, _)| k == "secret")
            .map(|(_, v)| v.to_string());

        let mut params = vec![pk.to_hex()];
        if let Some(secret) = secret {
            params.push(secret);
        }

        let bunker = Self::new(client_secret_key, pk, relays, pool, on_auth_url);

        bunker.rpc("connect", params).await?;
        Ok(bunker)
    }

    pub async fn ping(&self) -> Result<(), RPCError> {
        self.rpc("ping", vec![]).await?;
        Ok(())
    }

    pub async fn get_public_key(&self) -> Result<PubKey, GetPublicKeyError> {
        {
            let guard = self.get_pubkey_response.lock().await;
            if let Some(pk) = *guard {
                return Ok(pk);
            }
        }

        let resp = self.rpc("get_public_key", vec![]).await?;
        let pk = PubKey::from_hex(&resp)?;

        {
            let mut guard = self.get_pubkey_response.lock().await;
            *guard = Some(pk);
        }

        Ok(pk)
    }

    pub async fn finalize_event(
        &self,
        event_template: EventTemplate,
    ) -> Result<Event, FinalizeError> {
        let event_json = json!(event_template).to_string();
        let resp = self.rpc("sign_event", vec![event_json]).await?;
        let event: Event = serde_json::from_str(&resp).map_err(|_| FinalizeError::InvalidEvent)?;

        if !event.verify_signature() {
            return Err(FinalizeError::InvalidSignature);
        }

        Ok(event)
    }

    pub async fn nip44_encrypt(
        &self,
        target_pubkey: &PubKey,
        plaintext: &str,
    ) -> Result<String, RPCError> {
        self.rpc(
            "nip44_encrypt",
            vec![target_pubkey.to_hex(), plaintext.to_string()],
        )
        .await
    }

    pub async fn nip44_decrypt(
        &self,
        target_pubkey: &PubKey,
        ciphertext: &str,
    ) -> Result<String, RPCError> {
        self.rpc(
            "nip44_decrypt",
            vec![target_pubkey.to_hex(), ciphertext.to_string()],
        )
        .await
    }

    pub async fn nip04_encrypt(
        &self,
        target_pubkey: &PubKey,
        plaintext: &str,
    ) -> Result<String, RPCError> {
        self.rpc(
            "nip04_encrypt",
            vec![target_pubkey.to_hex(), plaintext.to_string()],
        )
        .await
    }

    pub async fn nip04_decrypt(
        &self,
        target_pubkey: &PubKey,
        ciphertext: &str,
    ) -> Result<String, RPCError> {
        self.rpc(
            "nip04_decrypt",
            vec![target_pubkey.to_hex(), ciphertext.to_string()],
        )
        .await
    }

    async fn rpc(&self, method: &str, params: Vec<String>) -> Result<String, RPCError> {
        // prepare response listener
        let (tx, rx) = oneshot::channel::<Response>();
        let rk = self.awaiting_responses.lock().await.insert(tx);

        let req = Request {
            id: lowercase_hex::encode(rk.data().as_ffi().to_le_bytes()),
            method,
            params,
        };
        let req_json =
            serde_json::to_string(&req).expect("request should not fail to encode as json");
        let content = nip44::encrypt(&req_json, &self.conversation_key, None)?;

        let event = EventTemplate {
            content,
            created_at: Timestamp::now(),
            kind: Kind(24133),
            tags: Tags(vec![vec!["p".to_string(), self.target.to_hex()]]),
            ..Default::default()
        }
        .finalize(&self.client_secret_key);

        // publish
        let mut sent = false;
        for url in self.relays.iter() {
            if let Some(relay) = self.pool.get_relay(url) {
                if relay.publish(event.clone()).await.is_ok() {
                    sent = true;
                }
            }
        }

        if !sent {
            return Err(RPCError::NoRelays(self.relays.clone()));
        }

        // wait for response
        match tokio::time::timeout(Duration::from_secs(15), rx).await {
            Ok(Ok(resp)) => {
                if let Some(err) = resp.error {
                    Err(RPCError::Response(err))
                } else {
                    Ok(resp.result.unwrap_or_default())
                }
            }
            Ok(Err(_)) => {
                self.awaiting_responses.lock().await.remove(rk);
                Err(RPCError::NoResponse)
            }
            Err(_) => {
                self.awaiting_responses.lock().await.remove(rk);
                Err(RPCError::Timeout)
            }
        }
    }
}
