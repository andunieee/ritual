//! # rnostr
//!
//! nostr types and utilities
//!
//! this library provides types and utilities for working with the Nostr protocol,
//! including events, filters, relays, and connections.

#![feature(test)]

pub mod envelopes;
pub mod event;
pub mod event_template;
pub mod filter;
pub mod helpers;
pub mod keys;
pub mod lmdb;
pub mod nip05;
pub mod nip11;
pub mod nip19;
pub mod pointers;
pub mod server;
pub mod timestamp;

// re-export commonly used types
mod normalize;
mod pool;
mod relay;
mod tags;
mod types;

pub use event::Event;
pub use event_template::EventTemplate;
pub use filter::Filter;
pub use keys::SecretKey;
pub use normalize::*;
pub use pointers::{EntityPointer, EventPointer, Pointer, ProfilePointer};
pub use pool::{DirectedFilter, Pool, PoolOptions, PublishResult};
pub use relay::Relay;
pub use tags::{Tag, Tags};
pub use timestamp::Timestamp;
pub use types::*;

/// result type used throughout the library
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
