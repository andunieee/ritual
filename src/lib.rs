//! # rnostr-core
//!
//! Core Nostr protocol types and utilities.
//!
//! This library provides types and utilities for working with the Nostr protocol,
//! including events, filters, relays, and connections.

pub mod envelopes;
pub mod event;
pub mod event_template;
pub mod filter;
pub mod helpers;
pub mod keys;
pub mod nip19;
pub mod normalize;
pub mod pointers;
pub mod pool;
pub mod relay;
pub mod subscription;
pub mod tags;
pub mod timestamp;
pub mod types;
pub mod utils;

// Re-export commonly used types
pub use event::Event;
pub use filter::Filter;
pub use keys::SecretKey;
pub use nip19::{decode, encode_naddr, encode_nevent, encode_nprofile, encode_npub, encode_nsec, encode_pointer, to_pointer, DecodeResult};
pub use pointers::{EntityPointer, EventPointer, Pointer, ProfilePointer};
pub use pool::{DirectedFilter, Pool, PoolOptions, PublishResult};
pub use relay::Relay;
pub use subscription::{Subscription, SubscriptionOptions};
pub use tags::{Tag, Tags};
pub use timestamp::Timestamp;
pub use types::*;

/// Result type used throughout the library
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Event kind type
pub type Kind = u16;
