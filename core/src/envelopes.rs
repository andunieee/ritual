use crate::{Event, Filter, Result, ID};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// trait for all Nostr message envelopes
pub trait Envelope {
    fn label(&self) -> &'static str;
    fn from_json(&mut self, data: &str) -> Result<()>;
}

/// EVENT envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub subscription_id: Option<String>,
    pub event: Event,
}

impl Envelope for EventEnvelope {
    fn label(&self) -> &'static str {
        "EVENT"
    }

    fn from_json(&mut self, data: &str) -> Result<()> {
        let arr: Vec<Value> = serde_json::from_str(data)?;
        match arr.len() {
            2 => {
                self.event = serde_json::from_value(arr[1].clone())?;
            }
            3 => {
                self.subscription_id = Some(arr[1].as_str().unwrap_or("").to_string());
                self.event = serde_json::from_value(arr[2].clone())?;
            }
            _ => return Err("invalid EVENT envelope".into()),
        }
        Ok(())
    }
}

/// REQ envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReqEnvelope {
    pub subscription_id: String,
    pub filter: Filter,
}

impl Envelope for ReqEnvelope {
    fn label(&self) -> &'static str {
        "REQ"
    }

    fn from_json(&mut self, data: &str) -> Result<()> {
        let arr: Vec<Value> = serde_json::from_str(data)?;
        if arr.len() < 3 {
            return Err("invalid REQ envelope".into());
        }
        self.subscription_id = arr[1].as_str().unwrap_or("").to_string();
        self.filter = serde_json::from_value(arr[2].clone())?;
        Ok(())
    }
}

/// COUNT envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountEnvelope {
    pub subscription_id: String,
    pub filter: Option<Filter>,
    pub count: Option<u32>,
    pub hyperloglog: Option<Vec<u8>>,
}

impl Envelope for CountEnvelope {
    fn label(&self) -> &'static str {
        "COUNT"
    }

    fn from_json(&mut self, data: &str) -> Result<()> {
        let arr: Vec<Value> = serde_json::from_str(data)?;
        if arr.len() < 3 {
            return Err("invalid COUNT envelope".into());
        }
        self.subscription_id = arr[1].as_str().unwrap_or("").to_string();

        // Try to parse as count result first
        if let Ok(count_result) =
            serde_json::from_value::<serde_json::Map<String, Value>>(arr[2].clone())
        {
            if let Some(count) = count_result.get("count") {
                self.count = count.as_u64().map(|c| c as u32);
            }
            if let Some(hll) = count_result.get("hll") {
                if let Some(hll_str) = hll.as_str() {
                    self.hyperloglog = hex::decode(hll_str).ok();
                }
            }
        } else {
            // Parse as filter
            self.filter = Some(serde_json::from_value(arr[2].clone())?);
        }
        Ok(())
    }
}

/// NOTICE envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoticeEnvelope(pub String);

impl Envelope for NoticeEnvelope {
    fn label(&self) -> &'static str {
        "NOTICE"
    }

    fn from_json(&mut self, data: &str) -> Result<()> {
        let arr: Vec<Value> = serde_json::from_str(data)?;
        if arr.len() < 2 {
            return Err("invalid NOTICE envelope".into());
        }
        self.0 = arr[1].as_str().unwrap_or("").to_string();
        Ok(())
    }
}

/// EOSE envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EOSEEnvelope(pub String);

impl Envelope for EOSEEnvelope {
    fn label(&self) -> &'static str {
        "EOSE"
    }

    fn from_json(&mut self, data: &str) -> Result<()> {
        let arr: Vec<Value> = serde_json::from_str(data)?;
        if arr.len() < 2 {
            return Err("invalid EOSE envelope".into());
        }
        self.0 = arr[1].as_str().unwrap_or("").to_string();
        Ok(())
    }
}

/// CLOSE envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseEnvelope(pub String);

impl Envelope for CloseEnvelope {
    fn label(&self) -> &'static str {
        "CLOSE"
    }

    fn from_json(&mut self, data: &str) -> Result<()> {
        let arr: Vec<Value> = serde_json::from_str(data)?;
        if arr.len() < 2 {
            return Err("invalid CLOSE envelope".into());
        }
        self.0 = arr[1].as_str().unwrap_or("").to_string();
        Ok(())
    }
}

/// CLOSED envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosedEnvelope {
    pub subscription_id: String,
    pub reason: String,
}

impl Envelope for ClosedEnvelope {
    fn label(&self) -> &'static str {
        "CLOSED"
    }

    fn from_json(&mut self, data: &str) -> Result<()> {
        let arr: Vec<Value> = serde_json::from_str(data)?;
        if arr.len() < 3 {
            return Err("invalid CLOSED envelope".into());
        }
        self.subscription_id = arr[1].as_str().unwrap_or("").to_string();
        self.reason = arr[2].as_str().unwrap_or("").to_string();
        Ok(())
    }
}

/// OK envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OKEnvelope {
    pub event_id: ID,
    pub ok: bool,
    pub reason: String,
}

impl Envelope for OKEnvelope {
    fn label(&self) -> &'static str {
        "OK"
    }

    fn from_json(&mut self, data: &str) -> Result<()> {
        let arr: Vec<Value> = serde_json::from_str(data)?;
        if arr.len() < 4 {
            return Err("invalid OK envelope".into());
        }
        self.event_id = ID::from_hex(arr[1].as_str().unwrap_or(""))?;
        self.ok = arr[2].as_bool().unwrap_or(false);
        self.reason = arr[3].as_str().unwrap_or("").to_string();
        Ok(())
    }
}

/// AUTH envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEnvelope {
    pub challenge: Option<String>,
    pub event: Option<Event>,
}

impl Envelope for AuthEnvelope {
    fn label(&self) -> &'static str {
        "AUTH"
    }

    fn from_json(&mut self, data: &str) -> Result<()> {
        let arr: Vec<Value> = serde_json::from_str(data)?;
        if arr.len() < 2 {
            return Err("invalid AUTH envelope".into());
        }

        if arr[1].is_object() {
            self.event = Some(serde_json::from_value(arr[1].clone())?);
        } else {
            self.challenge = Some(arr[1].as_str().unwrap_or("").to_string());
        }
        Ok(())
    }
}

/// Parse a message into an envelope
pub fn parse_message(message: &str) -> Result<Box<dyn Envelope>> {
    let arr: Vec<Value> = serde_json::from_str(message)?;
    if arr.is_empty() {
        return Err("empty message".into());
    }

    let label = arr[0].as_str().ok_or("invalid label")?;

    match label {
        "EVENT" => {
            let mut env = EventEnvelope {
                subscription_id: None,
                event: Event::new(
                    crate::PubKey::from_bytes([0; 32]),
                    crate::Timestamp::now(),
                    0,
                    crate::Tags::new(),
                    String::new(),
                ),
            };
            env.from_json(message)?;
            Ok(Box::new(env))
        }
        "REQ" => {
            let mut env = ReqEnvelope {
                subscription_id: String::new(),
                filter: Filter::new(),
            };
            env.from_json(message)?;
            Ok(Box::new(env))
        }
        "COUNT" => {
            let mut env = CountEnvelope {
                subscription_id: String::new(),
                filter: None,
                count: None,
                hyperloglog: None,
            };
            env.from_json(message)?;
            Ok(Box::new(env))
        }
        "NOTICE" => {
            let mut env = NoticeEnvelope(String::new());
            env.from_json(message)?;
            Ok(Box::new(env))
        }
        "EOSE" => {
            let mut env = EOSEEnvelope(String::new());
            env.from_json(message)?;
            Ok(Box::new(env))
        }
        "CLOSE" => {
            let mut env = CloseEnvelope(String::new());
            env.from_json(message)?;
            Ok(Box::new(env))
        }
        "CLOSED" => {
            let mut env = ClosedEnvelope {
                subscription_id: String::new(),
                reason: String::new(),
            };
            env.from_json(message)?;
            Ok(Box::new(env))
        }
        "OK" => {
            let mut env = OKEnvelope {
                event_id: ID::from_bytes([0; 32]),
                ok: false,
                reason: String::new(),
            };
            env.from_json(message)?;
            Ok(Box::new(env))
        }
        "AUTH" => {
            let mut env = AuthEnvelope {
                challenge: None,
                event: None,
            };
            env.from_json(message)?;
            Ok(Box::new(env))
        }
        _ => Err(format!("unknown envelope label: {}", label).into()),
    }
}
