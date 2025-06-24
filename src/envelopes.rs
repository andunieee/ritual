use crate::{Event, Filter, ID};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EnvelopeError {
    #[error("empty message")]
    EmptyMessage,
    #[error("invalid label")]
    InvalidLabel,
    #[error("invalid {0} envelope")]
    InvalidEnvelope(String),
    #[error("unknown envelope label: {0}")]
    UnknownLabel(String),
    #[error("JSON parsing error")]
    Json(#[from] serde_json::Error),
    #[error("hex decoding error")]
    Hex(#[from] lowercase_hex::FromHexError),
    #[error("ID parsing error")]
    IdParsing(#[from] crate::types::IDError),
}

pub type Result<T> = std::result::Result<T, EnvelopeError>;

/// nostr message envelopes ("commands")
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Envelope {
    InEvent(InEventEnvelope),
    OutEvent(OutEventEnvelope),
    Req(ReqEnvelope),
    CountAsk(CountAskEnvelope),
    CountReply(CountReplyEnvelope),
    Notice(NoticeEnvelope),
    Eose(EOSEEnvelope),
    Close(CloseEnvelope),
    Closed(ClosedEnvelope),
    Ok(OKEnvelope),
    AuthChallenge(AuthChallengeEnvelope),
    AuthEvent(AuthEventEnvelope),
}

impl Envelope {
    /// get the label for this envelope type
    pub fn label(&self) -> &'static str {
        match self {
            Envelope::InEvent(_) => "EVENT",
            Envelope::OutEvent(_) => "EVENT",
            Envelope::Req(_) => "REQ",
            Envelope::CountAsk(_) => "COUNT",
            Envelope::CountReply(_) => "COUNT",
            Envelope::Notice(_) => "NOTICE",
            Envelope::Eose(_) => "EOSE",
            Envelope::Close(_) => "CLOSE",
            Envelope::Closed(_) => "CLOSED",
            Envelope::Ok(_) => "OK",
            Envelope::AuthChallenge(_) => "AUTH",
            Envelope::AuthEvent(_) => "AUTH",
        }
    }
}

/// EVENT envelope (incoming from relay)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InEventEnvelope {
    pub subscription_id: String,
    pub event: Event,
}

/// EVENT envelope (outgoing to relay)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutEventEnvelope {
    pub event: Event,
}

/// REQ envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReqEnvelope {
    pub subscription_id: String,
    pub filters: Vec<Filter>,
}

/// COUNT envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountAskEnvelope {
    pub subscription_id: String,
    pub filter: Filter,
}

/// COUNT envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountReplyEnvelope {
    pub subscription_id: String,
    pub count: u32,
    pub hyperloglog: Option<Vec<u8>>,
}

/// NOTICE envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoticeEnvelope(pub String);

/// EOSE envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EOSEEnvelope {
    pub subscription_id: String,
}

/// CLOSE envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseEnvelope {
    pub subscription_id: String,
}

/// CLOSED envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosedEnvelope {
    pub subscription_id: String,
    pub reason: String,
}

/// OK envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OKEnvelope {
    pub event_id: ID,
    pub ok: bool,
    pub reason: String,
}

/// AUTH envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEventEnvelope {
    pub event: Event,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallengeEnvelope {
    pub challenge: String,
}

/// parse a message into an envelope
pub fn parse_message(message: &str) -> Result<Envelope> {
    let mut arr: Vec<Value> = serde_json::from_str(message)?;
    if arr.is_empty() {
        return Err(EnvelopeError::EmptyMessage);
    }

    let label = arr[0].as_str().ok_or(EnvelopeError::InvalidLabel)?;

    match label {
        "EVENT" => {
            let envelope = match arr.len() {
                2 => Envelope::OutEvent(OutEventEnvelope {
                    event: serde_json::from_value(arr[1].clone())?,
                }),
                3 => Envelope::InEvent(InEventEnvelope {
                    subscription_id: arr[1]
                        .as_str()
                        .ok_or(EnvelopeError::InvalidEnvelope("EVENT".to_string()))?
                        .to_string(),
                    event: serde_json::from_value(arr[2].clone())?,
                }),
                _ => return Err(EnvelopeError::InvalidEnvelope("EVENT".to_string())),
            };
            Ok(envelope)
        }
        "REQ" => {
            if arr.len() < 3 {
                return Err(EnvelopeError::InvalidEnvelope("REQ".to_string()));
            }

            let subscription_id = arr[1]
                .as_str()
                .ok_or(EnvelopeError::InvalidEnvelope("REQ".to_string()))?
                .to_string();

            let mut filters = Vec::with_capacity(arr.len() - 2);
            for x in 2..arr.len() {
                let extraf: Filter = serde_json::from_value(arr[x].clone())?;
                filters.push(extraf);
            }
            let envelope = ReqEnvelope {
                subscription_id,
                filters,
            };
            Ok(Envelope::Req(envelope))
        }
        "COUNT" => {
            if arr.len() < 3 {
                return Err(EnvelopeError::InvalidEnvelope("COUNT".to_string()));
            }
            let subscription_id = arr[1]
                .as_str()
                .ok_or(EnvelopeError::InvalidEnvelope("COUNT".to_string()))?
                .to_string();

            let envelope: Envelope;

            if let Ok(count_result) =
                serde_json::from_value::<serde_json::Map<String, Value>>(arr[2].take())
            {
                let mut countre = CountReplyEnvelope {
                    subscription_id,
                    count: 0,
                    hyperloglog: None,
                };

                if let Some(count) = count_result.get("count") {
                    countre.count = count
                        .as_i64()
                        .ok_or(EnvelopeError::InvalidEnvelope("COUNT".to_string()))?
                        as u32;
                }
                if let Some(hll) = count_result.get("hll") {
                    if let Some(hll_str) = hll.as_str() {
                        if hll_str.len() != 512 {
                            return Err(EnvelopeError::InvalidEnvelope("COUNT".to_string()));
                        }
                        let hll = lowercase_hex::decode(hll_str).ok();
                        countre.hyperloglog = hll;
                    }
                }

                envelope = Envelope::CountReply(countre);
            } else {
                // parse as filter
                envelope = Envelope::CountAsk(CountAskEnvelope {
                    subscription_id,
                    filter: serde_json::from_value(arr[2].clone())?,
                });
            }

            Ok(envelope)
        }
        "NOTICE" => {
            if arr.len() < 2 {
                return Err(EnvelopeError::InvalidEnvelope("NOTICE".to_string()));
            }
            let envelope = NoticeEnvelope(
                arr[1]
                    .as_str()
                    .ok_or(EnvelopeError::InvalidEnvelope("NOTICE".to_string()))?
                    .to_string(),
            );
            Ok(Envelope::Notice(envelope))
        }
        "EOSE" => {
            if arr.len() < 2 {
                return Err(EnvelopeError::InvalidEnvelope("EOSE".to_string()));
            }
            let envelope = EOSEEnvelope {
                subscription_id: arr[1]
                    .as_str()
                    .ok_or(EnvelopeError::InvalidEnvelope("EOSE".to_string()))?
                    .to_string(),
            };
            Ok(Envelope::Eose(envelope))
        }
        "CLOSE" => {
            if arr.len() < 2 {
                return Err(EnvelopeError::InvalidEnvelope("CLOSE".to_string()));
            }
            let envelope = CloseEnvelope {
                subscription_id: arr[1]
                    .as_str()
                    .ok_or(EnvelopeError::InvalidEnvelope("CLOSE".to_string()))?
                    .to_string(),
            };
            Ok(Envelope::Close(envelope))
        }
        "CLOSED" => {
            if arr.len() < 3 {
                return Err(EnvelopeError::InvalidEnvelope("CLOSED".to_string()));
            }
            let envelope = ClosedEnvelope {
                subscription_id: arr[1]
                    .as_str()
                    .ok_or(EnvelopeError::InvalidEnvelope("CLOSED".to_string()))?
                    .to_string(),
                reason: arr[2]
                    .as_str()
                    .ok_or(EnvelopeError::InvalidEnvelope("CLOSED".to_string()))?
                    .to_string(),
            };
            Ok(Envelope::Closed(envelope))
        }
        "OK" => {
            if arr.len() < 4 {
                return Err(EnvelopeError::InvalidEnvelope("OK".to_string()));
            }
            let envelope = OKEnvelope {
                event_id: ID::from_hex(
                    arr[1]
                        .as_str()
                        .ok_or(EnvelopeError::InvalidEnvelope("OK".to_string()))?,
                )?,
                ok: arr[2]
                    .as_bool()
                    .ok_or(EnvelopeError::InvalidEnvelope("OK".to_string()))?,
                reason: arr[3]
                    .as_str()
                    .ok_or(EnvelopeError::InvalidEnvelope("OK".to_string()))?
                    .to_string(),
            };
            Ok(Envelope::Ok(envelope))
        }
        "AUTH" => {
            if arr.len() < 2 {
                return Err(EnvelopeError::InvalidEnvelope("AUTH".to_string()));
            }

            let envelope = if arr[1].is_object() {
                Envelope::AuthEvent(AuthEventEnvelope {
                    event: serde_json::from_value(arr[1].clone())?,
                })
            } else {
                Envelope::AuthChallenge(AuthChallengeEnvelope {
                    challenge: arr[1]
                        .as_str()
                        .ok_or(EnvelopeError::InvalidEnvelope("AUTH".to_string()))?
                        .to_string(),
                })
            };
            Ok(envelope)
        }
        _ => Err(EnvelopeError::UnknownLabel(label.to_string())),
    }
}
