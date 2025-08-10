//! # ritual
//!
//! nostr types and utilities
//!
//! this library provides types and utilities for working with the Nostr protocol,
//! including events, filters, relays, and connections.

#![feature(test)]
#![feature(new_range_api)]

pub mod envelopes;
pub mod event;
pub mod event_template;
pub mod filter;
pub mod helpers;
pub mod keys;
pub mod nip19;
pub mod nip44;
pub mod nip46;
pub mod nip49;
pub mod pointers;
pub mod timestamp;

#[cfg(all(not(target_arch = "wasm32"), not(target_arch = "wasm64")))]
pub mod lmdb;
#[cfg(all(not(target_arch = "wasm32"), not(target_arch = "wasm64")))]
pub mod nip05;
#[cfg(all(not(target_arch = "wasm32"), not(target_arch = "wasm64")))]
pub mod nip11;
#[cfg(all(not(target_arch = "wasm32"), not(target_arch = "wasm64")))]
pub mod server;

mod database;
mod finalizer;
mod normalize;
mod tags;
mod types;

#[cfg(all(not(target_arch = "wasm32"), not(target_arch = "wasm64")))]
mod pool;
#[cfg(all(not(target_arch = "wasm32"), not(target_arch = "wasm64")))]
mod relay;

// re-export commonly used types
pub use event::Event;
pub use event_template::EventTemplate;
pub use filter::Filter;
pub use keys::{PubKey, SecretKey};
pub use normalize::*;
pub use pointers::{AddressPointer, EventPointer, Pointer, ProfilePointer};
pub use tags::{Tag, Tags};
pub use timestamp::Timestamp;
pub use types::*;

#[cfg(all(not(target_arch = "wasm32"), not(target_arch = "wasm64")))]
pub use pool::{DirectedFilter, Pool, PoolOptions, PublishResult};
