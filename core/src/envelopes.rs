use crate::{Event, Filter, Result, ID};
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// nostr message envelopes ("commands")
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Envelope {
    InEvent(InEventEnvelope),
    OutEvent(OutEventEnvelope),
    Req(ReqEnvelope),
    Count(CountEnvelope),
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
            Envelope::Count(_) => "COUNT",
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
    pub filters: NonEmpty<Filter>,
}

/// COUNT envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountEnvelope {
    pub subscription_id: String,
    pub filter: Option<Filter>,
    pub count: Option<u32>,
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
    let arr: Vec<Value> = serde_json::from_str(message)?;
    if arr.is_empty() {
        return Err("empty message".into());
    }

    let label = arr[0].as_str().ok_or("invalid label")?;

    match label {
        "EVENT" => {
            let envelope = match arr.len() {
                2 => Envelope::OutEvent(OutEventEnvelope {
                    event: serde_json::from_value(arr[1].clone())?,
                }),
                3 => Envelope::InEvent(InEventEnvelope {
                    subscription_id: arr[1].as_str().unwrap_or("").to_string(),
                    event: serde_json::from_value(arr[2].clone())?,
                }),
                _ => return Err("invalid EVENT envelope".into()),
            };
            Ok(envelope)
        }
        "REQ" => {
            if arr.len() < 3 {
                return Err("invalid REQ envelope".into());
            }
            let filter: Filter = serde_json::from_value(arr[2].clone())?;
            let mut filters = Vec::with_capacity(arr.len() - 2);
            for x in 2.. {
                let extraf: Filter = serde_json::from_value(arr[x].clone())?;
                filters.push(extraf);
            }
            let envelope = ReqEnvelope {
                subscription_id: arr[1].as_str().unwrap_or("").to_string(),
                filters: filters.try_into().unwrap(),
            };
            Ok(Envelope::Req(envelope))
        }
        "COUNT" => {
            if arr.len() < 3 {
                return Err("invalid COUNT envelope".into());
            }
            let subscription_id = arr[1].as_str().unwrap_or("").to_string();

            // Try to parse as count result first
            let mut envelope = CountEnvelope {
                subscription_id,
                filter: None,
                count: None,
                hyperloglog: None,
            };

            if let Ok(count_result) =
                serde_json::from_value::<serde_json::Map<String, Value>>(arr[2].clone())
            {
                if let Some(count) = count_result.get("count") {
                    envelope.count = count.as_u64().map(|c| c as u32);
                }
                if let Some(hll) = count_result.get("hll") {
                    if let Some(hll_str) = hll.as_str() {
                        envelope.hyperloglog = hex::decode(hll_str).ok();
                    }
                }
            } else {
                // Parse as filter
                envelope.filter = Some(serde_json::from_value(arr[2].clone())?);
            }

            Ok(Envelope::Count(envelope))
        }
        "NOTICE" => {
            if arr.len() < 2 {
                return Err("invalid NOTICE envelope".into());
            }
            let envelope = NoticeEnvelope(arr[1].as_str().unwrap_or("").to_string());
            Ok(Envelope::Notice(envelope))
        }
        "EOSE" => {
            if arr.len() < 2 {
                return Err("invalid EOSE envelope".into());
            }
            let envelope = EOSEEnvelope {
                subscription_id: arr[1].as_str().unwrap_or("").to_string(),
            };
            Ok(Envelope::Eose(envelope))
        }
        "CLOSE" => {
            if arr.len() < 2 {
                return Err("invalid CLOSE envelope".into());
            }
            let envelope = CloseEnvelope {
                subscription_id: arr[1].as_str().unwrap_or("").to_string(),
            };
            Ok(Envelope::Close(envelope))
        }
        "CLOSED" => {
            if arr.len() < 3 {
                return Err("invalid CLOSED envelope".into());
            }
            let envelope = ClosedEnvelope {
                subscription_id: arr[1].as_str().unwrap_or("").to_string(),
                reason: arr[2].as_str().unwrap_or("").to_string(),
            };
            Ok(Envelope::Closed(envelope))
        }
        "OK" => {
            if arr.len() < 4 {
                return Err("invalid OK envelope".into());
            }
            let envelope = OKEnvelope {
                event_id: ID::from_hex(arr[1].as_str().unwrap_or(""))?,
                ok: arr[2].as_bool().unwrap_or(false),
                reason: arr[3].as_str().unwrap_or("").to_string(),
            };
            Ok(Envelope::Ok(envelope))
        }
        "AUTH" => {
            if arr.len() < 2 {
                return Err("invalid AUTH envelope".into());
            }

            let envelope = if arr[1].is_object() {
                Envelope::AuthEvent(AuthEventEnvelope {
                    event: serde_json::from_value(arr[1].clone())?,
                })
            } else {
                Envelope::AuthChallenge(AuthChallengeEnvelope {
                    challenge: arr[1].as_str().unwrap_or("").to_string(),
                })
            };
            Ok(envelope)
        }
        _ => Err(format!("unknown envelope label: {}", label).into()),
    }
}
