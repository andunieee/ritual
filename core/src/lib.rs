//! # rnostr-core
//! 
//! Core Nostr protocol types and utilities.
//! 
//! This library provides types and utilities for working with the Nostr protocol,
//! including events, filters, relays, and connections.

pub mod types;
pub mod event;
pub mod filter;
pub mod keys;
pub mod timestamp;
pub mod tags;
pub mod signature;
pub mod helpers;
pub mod utils;
pub mod normalize;
pub mod pointers;
pub mod subscription;
pub mod connection;
pub mod envelopes;
pub mod relay;
pub mod pool;

// Re-export commonly used types
pub use types::*;
pub use event::Event;
pub use filter::Filter;
pub use keys::{SecretKey, generate};
pub use timestamp::Timestamp;
pub use tags::{Tag, Tags};
pub use pointers::{Pointer, ProfilePointer, EventPointer, EntityPointer};
pub use subscription::{Subscription, SubscriptionOptions, ReplaceableKey};
pub use connection::Connection;
pub use relay::{Relay, RelayOptions};
pub use pool::{Pool, PoolOptions, PublishResult, DirectedFilter};

/// Result type used throughout the library
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Event kind type
pub type Kind = u16;
