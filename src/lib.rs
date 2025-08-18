//! # ritual
//!
//! nostr types and utilities
//!
//! this library provides types and utilities for working with the Nostr protocol,
//! including events, filters, relays, and connections.

#![feature(test)]
#![feature(new_range_api)]

pub mod bunker_client;
pub mod codes;
pub mod envelopes;
pub mod event;
pub mod event_template;
pub mod filter;
pub mod helpers;
pub mod keys;
pub mod message_encryption;
pub mod metadata;
pub mod ncryptsec1;
pub mod pointers;
pub mod timestamp;

#[cfg(not(target_arch = "wasm32"))]
pub mod addresses;
#[cfg(not(target_arch = "wasm32"))]
pub mod lmdb;
#[cfg(not(target_arch = "wasm32"))]
pub mod relay_information;
#[cfg(not(target_arch = "wasm32"))]
pub mod server;

mod database;
mod finalizer;
mod normalize;
mod pool;
mod relay;
mod tags;
mod types;

// re-export commonly used types
pub use event::Event;
pub use event_template::EventTemplate;
pub use filter::Filter;
pub use keys::{PubKey, SecretKey};
pub use metadata::Metadata;
pub use normalize::*;
pub use pointers::{AddressPointer, EventPointer, Pointer, ProfilePointer};
pub use pool::{Occurrence, Pool, PoolOptions, PublishResult};
pub use relay::{CloseReason, Relay, SubscriptionOptions};
pub use tags::{Tag, Tags};
pub use timestamp::Timestamp;
pub use types::*;
