//! yggdrasil-lite: Minimal leaf-only Yggdrasil client for embedded devices.
//!
//! This crate implements a subset of the Yggdrasil/Ironwood protocol sufficient
//! to operate as a leaf node: connecting to 2-3 peers, participating in the
//! spanning tree, and exchanging encrypted packets with any node in the network.
//!
//! Designed for `no_std` + `alloc` environments (ESP32-C6 with Embassy).
//!
//! # Usage
//!
//! ```rust,ignore
//! use yggdrasil_lite::{YggdrasilLite, LiteConfig};
//!
//! let config = LiteConfig::new(my_ed25519_seed);
//! let mut node = YggdrasilLite::new(config);
//!
//! // Add a peer after TCP+TLS+metadata handshake
//! let peer_id = node.add_peer(peer_public_key, 0);
//! node.mark_handshake_done(peer_id);
//!
//! // Feed incoming data from the peer
//! let events = node.handle_peer_data(peer_id, &raw_bytes, now_ms, &mut rng);
//!
//! // Periodic maintenance
//! let events = node.poll(now_ms, &mut rng);
//!
//! // Send encrypted data to a remote node
//! let events = node.send(&dest_key, b"hello", now_ms, &mut rng);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod wire;
pub mod crypto;
pub mod address;
pub mod bloom;
pub mod meta;
pub mod peer;
pub mod tree;
pub mod pathfinder;
pub mod session;
pub mod node;

// Re-export the main public types for convenience.
pub use node::{YggdrasilLite, LiteConfig, NodeEvent};
pub use crypto::PublicKey;
pub use peer::PeerId;
pub use wire::PeerPort;
