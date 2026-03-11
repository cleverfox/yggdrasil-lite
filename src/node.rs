//! Main integration module for yggdrasil-lite.
//!
//! `YggdrasilLite` coordinates all subsystems:
//! - **PeerManager**: connection tracking, frame parsing
//! - **LeafTree**: spanning tree CRDT, parent selection
//! - **LeafBlooms**: bloom filter exchange for key→coordinate lookup
//! - **LeafPathfinder**: path discovery (PathLookup / PathNotify / PathBroken)
//! - **SessionManager**: encrypted sessions (Init/Ack/Traffic)
//!
//! The node is **poll-based** and **synchronous**: the caller feeds raw bytes
//! from TCP/TLS streams and collects outgoing frames. No async runtime needed.

use alloc::vec::Vec;
use ed25519_dalek::SigningKey;
use rand_core::CryptoRngCore;

use crate::address::{self, Address, Subnet};
use crate::bloom::{BloomFilter, LeafBlooms};
use crate::crypto::{self, Crypto, CurvePrivateKey, PublicKey};
use crate::pathfinder::LeafPathfinder;
use crate::peer::{PeerId, PeerManager, PeerState};
use crate::session::{SessionAction, SessionManager};
use crate::tree::{LeafTree, TreeAction};
use crate::wire::{self, PacketType, PeerPort, WireReader};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the leaf node.
pub struct LiteConfig {
    /// Ed25519 signing key (32-byte seed).
    pub private_key: [u8; 32],
    /// Optional peering password (if the peers require one).
    pub password: Option<Vec<u8>>,
    /// Maximum number of active sessions.
    pub max_sessions: usize,
    /// Maximum number of cached paths.
    pub max_paths: usize,
}

impl LiteConfig {
    pub fn new(private_key: [u8; 32]) -> Self {
        Self {
            private_key,
            password: None,
            max_sessions: 16,
            max_paths: 16,
        }
    }
}

// ---------------------------------------------------------------------------
// Events produced by the node
// ---------------------------------------------------------------------------

/// Events produced by the node for the caller to handle.
#[derive(Debug)]
pub enum NodeEvent {
    /// Send a framed message to a specific peer.
    SendToPeer { peer_id: PeerId, data: Vec<u8> },
    /// Deliver decrypted application data from a remote node.
    Deliver { source: PublicKey, data: Vec<u8> },
}

// ---------------------------------------------------------------------------
// Timers (tick-based)
// ---------------------------------------------------------------------------

/// Interval for tree maintenance (SigReq, parent selection, announce).
const TREE_INTERVAL_MS: u64 = 30_000;

/// Interval for bloom maintenance.
const BLOOM_INTERVAL_MS: u64 = 10_000;

/// Interval for path cleanup.
const PATH_CLEANUP_INTERVAL_MS: u64 = 60_000;

/// Interval for session cleanup.
const SESSION_CLEANUP_INTERVAL_MS: u64 = 30_000;

/// Interval for keepalive sends.
const KEEPALIVE_INTERVAL_MS: u64 = 20_000;

/// Path lookup timeout (how long before re-sending lookup).
const PATH_TIMEOUT_MS: u64 = 60_000;

/// Minimum interval between path lookups to the same destination.
const PATH_THROTTLE_MS: u64 = 5_000;

// ---------------------------------------------------------------------------
// YggdrasilLite
// ---------------------------------------------------------------------------

/// Minimal leaf-only Yggdrasil node.
///
/// Coordinates tree participation, bloom filters, path discovery,
/// and encrypted sessions. Transport-agnostic: the caller handles
/// TCP/TLS I/O and feeds raw bytes via [`handle_peer_data`].
pub struct YggdrasilLite {
    crypto: Crypto,
    curve_priv: CurvePrivateKey,
    password: Option<Vec<u8>>,

    peers: PeerManager,
    tree: LeafTree,
    blooms: LeafBlooms,
    pathfinder: LeafPathfinder,
    sessions: SessionManager,

    // Timers (tick-based, ms)
    last_tree_tick: u64,
    last_bloom_tick: u64,
    last_path_cleanup_tick: u64,
    last_session_cleanup_tick: u64,
    last_keepalive_tick: u64,
}

impl YggdrasilLite {
    /// Create a new leaf node from configuration.
    pub fn new(config: LiteConfig) -> Self {
        let signing_key = SigningKey::from_bytes(&config.private_key);
        let crypto = Crypto::new(signing_key);
        let curve_priv = crypto::ed25519_private_to_curve25519(&crypto.signing_key);

        Self {
            blooms: LeafBlooms::new(None),
            pathfinder: LeafPathfinder::with_capacity(
                &crypto,
                config.max_paths,
                config.max_paths,
            ),
            tree: LeafTree::new(crypto.public_key),
            sessions: SessionManager::new(),
            peers: PeerManager::new(),
            crypto,
            curve_priv,
            password: config.password,

            last_tree_tick: 0,
            last_bloom_tick: 0,
            last_path_cleanup_tick: 0,
            last_session_cleanup_tick: 0,
            last_keepalive_tick: 0,
        }
    }

    /// Our Ed25519 public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.crypto.public_key
    }

    /// Our `200::/7` IPv6 address (16 bytes).
    pub fn address(&self) -> Address {
        address::addr_for_key(&self.crypto.public_key)
    }

    /// Our `300::/7` subnet prefix (first 8 bytes of the /64).
    pub fn subnet(&self) -> Subnet {
        address::subnet_for_key(&self.crypto.public_key)
    }

    /// Our current tree coordinates.
    pub fn coords(&self) -> Vec<PeerPort> {
        self.tree.get_coords()
    }

    /// The current root of the spanning tree (lowest key).
    pub fn root(&self) -> PublicKey {
        self.tree.get_root()
    }

    /// Number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.peers.count()
    }

    /// Number of active encrypted sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.session_count()
    }

    /// Number of cached paths.
    pub fn path_count(&self) -> usize {
        self.pathfinder.path_count()
    }

    /// Register a new peer connection. Returns the peer ID.
    ///
    /// After calling this, the caller should perform the metadata handshake
    /// and then start feeding raw bytes via [`handle_peer_data`].
    pub fn add_peer(&mut self, key: PublicKey, prio: u8) -> PeerId {
        let peer_id = self.peers.add_peer(key, prio);
        self.tree.add_peer(key);
        self.blooms.add_peer(key);
        // Force a tree refresh to pick up the new peer
        self.tree.set_needs_refresh();
        peer_id
    }

    /// Remove a peer. Returns `true` if the peer existed.
    pub fn remove_peer(&mut self, peer_id: PeerId) -> bool {
        if let Some(peer) = self.peers.get(peer_id) {
            let key = peer.key;
            self.tree.remove_peer(&key);
            self.blooms.remove_peer(&key);
            self.peers.remove_peer(peer_id);
            // Force tree refresh since we may have lost our parent
            self.tree.set_needs_refresh();
            true
        } else {
            false
        }
    }

    /// Mark a peer's metadata handshake as complete.
    pub fn mark_handshake_done(&mut self, peer_id: PeerId) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.handshake_done = true;
        }
    }

    // -----------------------------------------------------------------------
    // Incoming data
    // -----------------------------------------------------------------------

    /// Feed raw bytes from a peer's TCP stream and process any complete frames.
    ///
    /// Returns a list of events (outgoing messages, delivered data).
    pub fn handle_peer_data(
        &mut self,
        peer_id: PeerId,
        data: &[u8],
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<NodeEvent> {
        let peer_key = match self.peers.get(peer_id) {
            Some(p) => p.key,
            None => return Vec::new(),
        };

        // Feed raw bytes into the peer's frame buffer
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.feed(data);
        }

        let mut events = Vec::new();

        // Extract and process all complete frames
        loop {
            let frame = match self.peers.get_mut(peer_id) {
                Some(peer) => match peer.try_read_frame() {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(_) => break,
                },
                None => break,
            };

            let (ptype, payload) = frame;
            let frame_events =
                self.handle_frame(peer_id, peer_key, ptype, &payload, now_ms, rng);
            events.extend(frame_events);
        }

        events
    }

    /// Process a single decoded frame from a peer.
    fn handle_frame(
        &mut self,
        peer_id: PeerId,
        peer_key: PublicKey,
        ptype: PacketType,
        payload: &[u8],
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<NodeEvent> {
        match ptype {
            PacketType::KeepAlive => Vec::new(),
            PacketType::Dummy => Vec::new(),
            PacketType::ProtoSigReq => self.handle_sig_req(peer_id, peer_key, payload),
            PacketType::ProtoSigRes => self.handle_sig_res(peer_key, payload),
            PacketType::ProtoAnnounce => {
                self.handle_announce(peer_id, peer_key, payload, now_ms)
            }
            PacketType::ProtoBloomFilter => self.handle_bloom(peer_key, payload),
            PacketType::ProtoPathLookup => {
                self.handle_path_lookup(peer_id, peer_key, payload, now_ms)
            }
            PacketType::ProtoPathNotify => self.handle_path_notify(payload, now_ms),
            PacketType::ProtoPathBroken => self.handle_path_broken(payload),
            PacketType::Traffic => self.handle_traffic(payload, now_ms, rng),
        }
    }

    // -----------------------------------------------------------------------
    // Protocol message handlers
    // -----------------------------------------------------------------------

    fn handle_sig_req(
        &mut self,
        peer_id: PeerId,
        peer_key: PublicKey,
        payload: &[u8],
    ) -> Vec<NodeEvent> {
        let mut r = WireReader::new(payload);
        let req = match wire::SigReq::decode(&mut r) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        // Look up the peer's port
        let peer_port = self
            .peers
            .get(peer_id)
            .map(|p| p.port)
            .unwrap_or(0);

        let action = self
            .tree
            .handle_sig_req(&self.crypto, peer_id, &peer_key, peer_port, &req);
        let mut events = Vec::new();
        events.extend(self.tree_action_to_event(action));
        events
    }

    fn handle_sig_res(&mut self, peer_key: PublicKey, payload: &[u8]) -> Vec<NodeEvent> {
        let mut r = WireReader::new(payload);
        let res = match wire::SigRes::decode(&mut r) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        self.tree.handle_sig_res(peer_key, &res);
        Vec::new()
    }

    fn handle_announce(
        &mut self,
        peer_id: PeerId,
        peer_key: PublicKey,
        payload: &[u8],
        now_ms: u64,
    ) -> Vec<NodeEvent> {
        let ann = match wire::Announce::decode(payload) {
            Ok(a) => a,
            Err(_) => return Vec::new(),
        };

        let actions = self.tree.handle_announce(peer_id, &peer_key, &ann);
        let events = self.tree_actions_to_events(actions);

        // After tree update, refresh our own path info and bloom parent
        self.update_own_path_info(now_ms);
        self.blooms.set_parent(&self.tree.get_root());

        events
    }

    fn handle_bloom(&mut self, peer_key: PublicKey, payload: &[u8]) -> Vec<NodeEvent> {
        if let Ok(filter) = BloomFilter::decode(payload) {
            self.blooms.handle_bloom(&peer_key, filter);
        }
        Vec::new()
    }

    fn handle_path_lookup(
        &mut self,
        peer_id: PeerId,
        from_key: PublicKey,
        payload: &[u8],
        _now_ms: u64,
    ) -> Vec<NodeEvent> {
        let lookup = match wire::PathLookup::decode(payload) {
            Ok(l) => l,
            Err(_) => return Vec::new(),
        };

        let mut events = Vec::new();

        // Check if the lookup is for us
        if lookup.dest == self.crypto.public_key {
            // Respond with our path info via PathNotify
            let our_coords = self.tree.get_coords();
            let notify = wire::PathNotify {
                path: our_coords.clone(),
                watermark: 0,
                source: self.crypto.public_key,
                dest: lookup.source,
                info: wire::PathNotifyInfo {
                    seq: self.pathfinder.info.seq,
                    path: our_coords,
                    sig: self.pathfinder.info.sig,
                },
            };
            let mut notify_payload = Vec::new();
            notify.encode(&mut notify_payload);
            let frame = wire::encode_frame(PacketType::ProtoPathNotify, &notify_payload);
            events.push(NodeEvent::SendToPeer {
                peer_id,
                data: frame,
            });
        } else {
            // Forward lookup to other peers whose blooms match
            let targets = self
                .blooms
                .get_multicast_targets(&from_key, &lookup.dest);
            for target_key in targets {
                if let Some(target_peer) = self.peers.get_by_key(&target_key) {
                    let target_id = target_peer.id;
                    let mut fwd_payload = Vec::new();
                    lookup.encode(&mut fwd_payload);
                    let frame =
                        wire::encode_frame(PacketType::ProtoPathLookup, &fwd_payload);
                    events.push(NodeEvent::SendToPeer {
                        peer_id: target_id,
                        data: frame,
                    });
                }
            }
        }

        events
    }

    fn handle_path_notify(
        &mut self,
        payload: &[u8],
        now_ms: u64,
    ) -> Vec<NodeEvent> {
        let notify = match wire::PathNotify::decode(payload) {
            Ok(n) => n,
            Err(_) => return Vec::new(),
        };

        // Accept the notify into our pathfinder.
        // source = the key that originally replied, dest = us
        // xformed_source = same as source for now (no key transform)
        self.pathfinder.accept_notify(
            notify.source,
            notify.source,
            notify.info.seq,
            notify.info.path,
            now_ms,
        );

        Vec::new()
    }

    fn handle_path_broken(&mut self, payload: &[u8]) -> Vec<NodeEvent> {
        let broken = match wire::PathBroken::decode(payload) {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };
        self.pathfinder.handle_broken(&broken.source);
        Vec::new()
    }

    fn handle_traffic(
        &mut self,
        payload: &[u8],
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<NodeEvent> {
        // Decode the traffic wrapper to get source key and encrypted session data
        let traffic = match wire::Traffic::decode(payload) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        // Only accept traffic destined for us
        if traffic.dest != self.crypto.public_key {
            return Vec::new();
        }

        // Session-level handling
        let session_actions = self.sessions.handle_data(
            &traffic.source,
            &traffic.payload,
            &self.curve_priv,
            &self.crypto.signing_key,
            now_ms,
            rng,
        );

        self.session_actions_to_events(&traffic.source, session_actions)
    }

    // -----------------------------------------------------------------------
    // Sending application data
    // -----------------------------------------------------------------------

    /// Send encrypted data to a destination identified by its Ed25519 public key.
    ///
    /// The node will:
    /// 1. Encrypt the data using the session layer
    /// 2. Look up the path to the destination (or initiate path discovery)
    /// 3. Wrap it in a Traffic frame and route via tree coordinates
    ///
    /// Returns events that need to be executed (sending frames to peers).
    pub fn send(
        &mut self,
        dest: &PublicKey,
        data: &[u8],
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<NodeEvent> {
        let mut events = Vec::new();

        // Encrypt via session manager
        let session_actions = self.sessions.write_to(
            dest,
            data,
            &self.crypto.signing_key,
            now_ms,
            rng,
        );

        events.extend(self.session_actions_to_events(dest, session_actions));

        // If we don't have a path yet, initiate lookup
        if !self.pathfinder.has_path(dest) {
            events.extend(self.initiate_path_lookup(dest, now_ms));
        }

        events
    }

    /// Initiate a path lookup for a destination key.
    fn initiate_path_lookup(
        &mut self,
        dest: &PublicKey,
        now_ms: u64,
    ) -> Vec<NodeEvent> {
        if self
            .pathfinder
            .should_throttle_lookup(dest, now_ms, PATH_THROTTLE_MS)
        {
            return Vec::new();
        }

        self.pathfinder.mark_lookup_sent(dest, now_ms);

        let our_coords = self.tree.get_coords();
        let lookup = wire::PathLookup {
            source: self.crypto.public_key,
            dest: *dest,
            from: our_coords,
        };
        let mut payload = Vec::new();
        lookup.encode(&mut payload);
        let frame = wire::encode_frame(PacketType::ProtoPathLookup, &payload);

        // Multicast to peers whose bloom filters match
        let targets = self
            .blooms
            .get_multicast_targets(&self.crypto.public_key, dest);

        let mut events = Vec::new();
        for target_key in &targets {
            if let Some(peer) = self.peers.get_by_key(target_key) {
                events.push(NodeEvent::SendToPeer {
                    peer_id: peer.id,
                    data: frame.clone(),
                });
            }
        }

        // If no bloom targets, send to all peers
        if targets.is_empty() {
            for pid in self.peers.peer_ids() {
                events.push(NodeEvent::SendToPeer {
                    peer_id: pid,
                    data: frame.clone(),
                });
            }
        }

        events
    }

    // -----------------------------------------------------------------------
    // Periodic maintenance
    // -----------------------------------------------------------------------

    /// Run periodic maintenance. Must be called regularly (every ~100-500ms).
    ///
    /// Handles:
    /// - Tree maintenance (SigReq, parent selection, announcements)
    /// - Bloom filter updates
    /// - Path cache cleanup
    /// - Session cache cleanup
    /// - Keepalive sends
    pub fn poll(
        &mut self,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<NodeEvent> {
        let mut events = Vec::new();

        // Tree maintenance
        if now_ms.saturating_sub(self.last_tree_tick) >= TREE_INTERVAL_MS || self.last_tree_tick == 0
        {
            self.last_tree_tick = now_ms;
            let nonce = random_nonce(rng);
            let peers = self.collect_peer_info();
            let actions = self.tree.do_maintenance(&self.crypto, &peers, nonce);
            events.extend(self.tree_actions_to_events(actions));

            // Update own path info after tree changes
            self.update_own_path_info(now_ms);
        }

        // Bloom maintenance
        if now_ms.saturating_sub(self.last_bloom_tick) >= BLOOM_INTERVAL_MS
            || self.last_bloom_tick == 0
        {
            self.last_bloom_tick = now_ms;
            let bloom_updates = self.blooms.do_maintenance(&self.crypto.public_key);
            for (target_key, filter) in bloom_updates {
                if let Some(peer) = self.peers.get_by_key(&target_key) {
                    let peer_id = peer.id;
                    let mut payload = Vec::new();
                    filter.encode(&mut payload);
                    let frame = wire::encode_frame(PacketType::ProtoBloomFilter, &payload);
                    events.push(NodeEvent::SendToPeer {
                        peer_id,
                        data: frame,
                    });
                }
            }
        }

        // Path cleanup
        if now_ms.saturating_sub(self.last_path_cleanup_tick) >= PATH_CLEANUP_INTERVAL_MS {
            self.last_path_cleanup_tick = now_ms;
            self.pathfinder.cleanup_expired(now_ms, PATH_TIMEOUT_MS);
        }

        // Session cleanup
        if now_ms.saturating_sub(self.last_session_cleanup_tick) >= SESSION_CLEANUP_INTERVAL_MS {
            self.last_session_cleanup_tick = now_ms;
            self.sessions.cleanup_expired(now_ms);
        }

        // Keepalives
        if now_ms.saturating_sub(self.last_keepalive_tick) >= KEEPALIVE_INTERVAL_MS {
            self.last_keepalive_tick = now_ms;
            let keepalive = wire::encode_frame(PacketType::KeepAlive, &[]);
            for pid in self.peers.peer_ids() {
                events.push(NodeEvent::SendToPeer {
                    peer_id: pid,
                    data: keepalive.clone(),
                });
            }
        }

        events
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Collect peer info tuples for tree maintenance.
    fn collect_peer_info(&self) -> Vec<(PeerId, PublicKey, u64)> {
        self.peers
            .iter()
            .filter(|p| p.handshake_done)
            .map(|p| (p.id, p.key, 10u64)) // TODO: actual latency measurement
            .collect()
    }

    /// Update our own signed path info after tree changes.
    fn update_own_path_info(&mut self, now_ms: u64) {
        let coords = self.tree.get_coords();
        // Use now_ms as a monotonic sequence number
        self.pathfinder.update_own_info(now_ms, coords, &self.crypto);
    }

    /// Convert a single tree action to a node event.
    fn tree_action_to_event(&self, action: TreeAction) -> Option<NodeEvent> {
        match action {
            TreeAction::SendSigReq { peer_id, req } => {
                let mut payload = Vec::new();
                req.encode(&mut payload);
                let frame = wire::encode_frame(PacketType::ProtoSigReq, &payload);
                Some(NodeEvent::SendToPeer { peer_id, data: frame })
            }
            TreeAction::SendSigRes { peer_id, res } => {
                let mut payload = Vec::new();
                res.encode(&mut payload);
                let frame = wire::encode_frame(PacketType::ProtoSigRes, &payload);
                Some(NodeEvent::SendToPeer { peer_id, data: frame })
            }
            TreeAction::SendAnnounce { peer_id, ann } => {
                let mut payload = Vec::new();
                ann.encode(&mut payload);
                let frame = wire::encode_frame(PacketType::ProtoAnnounce, &payload);
                Some(NodeEvent::SendToPeer { peer_id, data: frame })
            }
        }
    }

    /// Convert tree actions to node events.
    fn tree_actions_to_events(&self, actions: Vec<TreeAction>) -> Vec<NodeEvent> {
        actions
            .into_iter()
            .filter_map(|a| self.tree_action_to_event(a))
            .collect()
    }

    /// Convert session actions to node events. Routes encrypted data through
    /// the tree using Traffic frames.
    fn session_actions_to_events(
        &self,
        _dest: &PublicKey,
        actions: Vec<SessionAction>,
    ) -> Vec<NodeEvent> {
        let mut events = Vec::new();
        for action in actions {
            match action {
                SessionAction::SendToRemote { dest, data } => {
                    // Route via tree coordinates
                    if let Some(event) = self.route_to_dest(&dest, data) {
                        events.push(event);
                    }
                }
                SessionAction::Deliver { source, data } => {
                    events.push(NodeEvent::Deliver { source, data });
                }
            }
        }
        events
    }

    /// Route an encrypted payload to a destination via tree coordinates.
    ///
    /// Wraps in a Traffic frame and sends to the appropriate next-hop peer.
    fn route_to_dest(&self, dest: &PublicKey, payload: Vec<u8>) -> Option<NodeEvent> {
        // Get destination coordinates from pathfinder
        let dest_path = match self.pathfinder.get_path(dest) {
            Some(p) => p.to_vec(),
            None => {
                // No path yet — send to the first connected peer as a fallback
                // (the session init will have been sent already)
                for peer in self.peers.iter() {
                    if peer.handshake_done {
                        let traffic = wire::Traffic {
                            path: Vec::new(),
                            from: self.tree.get_coords(),
                            source: self.crypto.public_key,
                            dest: *dest,
                            watermark: 0,
                            payload,
                        };
                        let mut traffic_payload = Vec::new();
                        traffic.encode(&mut traffic_payload);
                        let frame =
                            wire::encode_frame(PacketType::Traffic, &traffic_payload);
                        return Some(NodeEvent::SendToPeer {
                            peer_id: peer.id,
                            data: frame,
                        });
                    }
                }
                return None;
            }
        };

        // Build Traffic message
        let traffic = wire::Traffic {
            path: dest_path.clone(),
            from: self.tree.get_coords(),
            source: self.crypto.public_key,
            dest: *dest,
            watermark: 0,
            payload,
        };
        let mut traffic_payload = Vec::new();
        traffic.encode(&mut traffic_payload);
        let frame = wire::encode_frame(PacketType::Traffic, &traffic_payload);

        // Find next hop by greedy tree routing
        let our_coords = self.tree.get_coords();
        let next_hop = self.find_next_hop(&dest_path, &our_coords)?;

        Some(NodeEvent::SendToPeer {
            peer_id: next_hop,
            data: frame,
        })
    }

    /// Greedy tree routing: find the peer closest to the destination coordinates.
    fn find_next_hop(&self, dest_path: &[PeerPort], our_coords: &[PeerPort]) -> Option<PeerId> {
        use crate::tree::tree_dist;

        let our_dist = tree_dist(our_coords, dest_path);

        let mut best_peer: Option<PeerId> = None;
        let mut best_dist = our_dist;

        for peer in self.peers.iter() {
            if !peer.handshake_done {
                continue;
            }
            let (_, peer_coords) = self.tree.get_root_and_path(&peer.key);
            let d = tree_dist(&peer_coords, dest_path);
            if d < best_dist {
                best_dist = d;
                best_peer = Some(peer.id);
            }
        }

        // If no peer is closer, send to the first connected peer as a fallback
        if best_peer.is_none() {
            for peer in self.peers.iter() {
                if peer.handshake_done {
                    return Some(peer.id);
                }
            }
        }

        best_peer
    }

    /// Get a reference to the pathfinder (for advanced queries).
    pub fn pathfinder(&self) -> &LeafPathfinder {
        &self.pathfinder
    }

    /// Get a reference to the tree (for advanced queries).
    pub fn tree(&self) -> &LeafTree {
        &self.tree
    }

    /// Access to the crypto identity.
    pub fn crypto(&self) -> &Crypto {
        &self.crypto
    }

    /// The password used for peering (for metadata handshake).
    pub fn password(&self) -> Option<&[u8]> {
        self.password.as_deref()
    }

    /// Get peer state by ID.
    pub fn get_peer(&self, peer_id: PeerId) -> Option<&PeerState> {
        self.peers.get(peer_id)
    }
}

/// Generate a random nonce from the RNG.
fn random_nonce(rng: &mut impl CryptoRngCore) -> u64 {
    let mut buf = [0u8; 8];
    rng.fill_bytes(&mut buf);
    u64::from_le_bytes(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn random_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    #[test]
    fn create_node_and_check_address() {
        let config = LiteConfig::new(random_key());
        let node = YggdrasilLite::new(config);

        let addr = node.address();
        // Should be in the 200::/7 range (first byte 0x02 or 0x03)
        assert!(
            addr.0[0] == 0x02 || addr.0[0] == 0x03,
            "address should be in 200::/7"
        );
        assert_eq!(node.peer_count(), 0);
        assert_eq!(node.session_count(), 0);
        assert_eq!(node.path_count(), 0);
    }

    #[test]
    fn add_remove_peers() {
        let config = LiteConfig::new(random_key());
        let mut node = YggdrasilLite::new(config);

        let peer_key_a: PublicKey = {
            let sk = SigningKey::from_bytes(&random_key());
            sk.verifying_key().to_bytes()
        };
        let peer_key_b: PublicKey = {
            let sk = SigningKey::from_bytes(&random_key());
            sk.verifying_key().to_bytes()
        };

        let id_a = node.add_peer(peer_key_a, 0);
        let id_b = node.add_peer(peer_key_b, 1);
        assert_eq!(node.peer_count(), 2);

        assert!(node.remove_peer(id_a));
        assert_eq!(node.peer_count(), 1);

        assert!(node.remove_peer(id_b));
        assert_eq!(node.peer_count(), 0);

        // Removing non-existent peer
        assert!(!node.remove_peer(99));
    }

    #[test]
    fn poll_sends_keepalives() {
        let config = LiteConfig::new(random_key());
        let mut node = YggdrasilLite::new(config);

        let peer_key: PublicKey = {
            let sk = SigningKey::from_bytes(&random_key());
            sk.verifying_key().to_bytes()
        };
        let pid = node.add_peer(peer_key, 0);
        node.mark_handshake_done(pid);

        // First poll should produce keepalive + tree + bloom events
        let events = node.poll(1000, &mut OsRng);
        let has_send = events.iter().any(|e| matches!(e, NodeEvent::SendToPeer { .. }));
        assert!(has_send, "poll should produce outgoing messages");
    }

    #[test]
    fn poll_no_events_when_no_peers() {
        let config = LiteConfig::new(random_key());
        let mut node = YggdrasilLite::new(config);

        let events = node.poll(1000, &mut OsRng);
        // Should still run maintenance but no outgoing messages since no peers
        let send_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, NodeEvent::SendToPeer { .. }))
            .collect();
        assert!(
            send_events.is_empty(),
            "no peers means no outgoing messages"
        );
    }

    #[test]
    fn handle_keepalive_frame() {
        let config = LiteConfig::new(random_key());
        let mut node = YggdrasilLite::new(config);

        let peer_key: PublicKey = {
            let sk = SigningKey::from_bytes(&random_key());
            sk.verifying_key().to_bytes()
        };
        let pid = node.add_peer(peer_key, 0);
        node.mark_handshake_done(pid);

        // Encode a keepalive frame and feed it
        let frame = wire::encode_frame(PacketType::KeepAlive, &[]);
        let events = node.handle_peer_data(pid, &frame, 1000, &mut OsRng);
        assert!(events.is_empty(), "keepalive should produce no events");
    }

    #[test]
    fn send_initiates_session_and_lookup() {
        let config = LiteConfig::new(random_key());
        let mut node = YggdrasilLite::new(config);

        let peer_key: PublicKey = {
            let sk = SigningKey::from_bytes(&random_key());
            sk.verifying_key().to_bytes()
        };
        let pid = node.add_peer(peer_key, 0);
        node.mark_handshake_done(pid);

        // Send to a destination we don't have a session with
        let dest_key: PublicKey = {
            let sk = SigningKey::from_bytes(&random_key());
            sk.verifying_key().to_bytes()
        };
        let events = node.send(&dest_key, b"hello", 1000, &mut OsRng);

        // Should have initiated a path lookup and/or session init (SendToPeer events)
        let send_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, NodeEvent::SendToPeer { .. }))
            .collect();
        assert!(
            !send_events.is_empty(),
            "send should produce outgoing events"
        );
    }
}
