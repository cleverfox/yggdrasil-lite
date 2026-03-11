//! yggdrasil-lite: Minimal leaf-only Yggdrasil client for embedded devices.
//!
//! This crate implements a subset of the Yggdrasil/Ironwood protocol sufficient
//! to operate as a leaf node: connecting to 2-3 peers, participating in the
//! spanning tree, and exchanging encrypted packets with any node in the network.
//!
//! Designed for `no_std` + `alloc` environments (ESP32-C6 with Embassy).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod wire;
pub mod crypto;
pub mod address;
pub mod bloom;
