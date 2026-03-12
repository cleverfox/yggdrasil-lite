//! Leaf tree participation for the spanning tree CRDT.
//!
//! A leaf node participates in the spanning tree by:
//! - Receiving and validating announcements from peers (CRDT gossip)
//! - Exchanging SigReq/SigRes with peers to establish parent relationships
//! - Selecting the best parent (lowest root key, then lowest cost)
//! - Generating its own announcement
//! - Computing its tree coordinates (path from root to self)
//!
//! The leaf node never acts as transit — it only accepts traffic destined for itself.

use alloc::vec::Vec;
use crate::crypto::{Crypto, PublicKey, Sig};
use crate::wire::{self, PeerPort};
use crate::peer::PeerId;

/// Maximum stored tree entries (prevents unbounded growth on constrained devices).
const MAX_TREE_ENTRIES: usize = 64;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Stored tree state for a known node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeInfo {
    pub parent: PublicKey,
    pub seq: u64,
    pub nonce: u64,
    pub port: PeerPort,
    pub psig: Sig,
    pub sig: Sig,
}

/// Actions the tree module produces for the caller to execute.
#[derive(Debug)]
pub enum TreeAction {
    /// Send a SigReq to a peer.
    SendSigReq { peer_id: PeerId, req: wire::SigReq },
    /// Send a SigRes to a peer.
    SendSigRes { peer_id: PeerId, res: wire::SigRes },
    /// Send an Announce to a peer.
    SendAnnounce { peer_id: PeerId, ann: wire::Announce },
}

/// Pending SigRes received from a peer.
#[derive(Clone, Debug)]
struct PendingSigRes {
    key: PublicKey,
    seq: u64,
    nonce: u64,
    port: PeerPort,
    psig: Sig,
}

// ---------------------------------------------------------------------------
// Standalone helpers
// ---------------------------------------------------------------------------

/// Compute the bytes that get signed for an announcement.
///
/// Format: `key(32) || parent(32) || seq(uvarint) || nonce(uvarint) || port(uvarint)`
///
/// Both the node (`key`) and its parent sign over the same bytes.
pub fn announcement_sig_bytes(
    key: &PublicKey,
    parent: &PublicKey,
    seq: u64,
    nonce: u64,
    port: PeerPort,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 32 + 24);
    out.extend_from_slice(key);
    out.extend_from_slice(parent);
    wire::encode_uvarint(&mut out, seq);
    wire::encode_uvarint(&mut out, nonce);
    wire::encode_uvarint(&mut out, port);
    out
}

/// Verify both signatures on a wire announcement.
///
/// - `sig` must be a valid signature by `key` over the announcement bytes.
/// - `psig` must be a valid signature by `parent` over the same bytes.
/// - If `port == 0` (self-rooted), `key` must equal `parent`.
pub fn verify_announce(ann: &wire::Announce) -> bool {
    if ann.sig_res.port == 0 && ann.key != ann.parent {
        return false;
    }
    let bs = announcement_sig_bytes(
        &ann.key,
        &ann.parent,
        ann.sig_res.seq,
        ann.sig_res.nonce,
        ann.sig_res.port,
    );
    Crypto::verify(&ann.key, &bs, &ann.sig)
        && Crypto::verify(&ann.parent, &bs, &ann.sig_res.psig)
}

/// Compute tree-space distance between two coordinate paths.
///
/// Shared prefix segments cancel out (each shared hop reduces distance by 2).
pub fn tree_dist(a: &[PeerPort], b: &[PeerPort]) -> u64 {
    let end = a.len().min(b.len());
    let mut dist = (a.len() + b.len()) as u64;
    for i in 0..end {
        if a[i] == b[i] {
            dist -= 2;
        } else {
            break;
        }
    }
    dist
}

/// Convert a stored TreeInfo back to a wire Announce.
fn info_to_wire(key: &PublicKey, info: &TreeInfo) -> wire::Announce {
    wire::Announce {
        key: *key,
        parent: info.parent,
        sig_res: wire::SigRes {
            seq: info.seq,
            nonce: info.nonce,
            port: info.port,
            psig: info.psig,
        },
        sig: info.sig,
    }
}

// ---------------------------------------------------------------------------
// LeafTree
// ---------------------------------------------------------------------------

/// Leaf tree state: spanning tree participation for a leaf (non-transit) node.
///
/// Tracks announcements from peers, selects the best parent, generates our
/// own announcement, and computes our tree coordinates.
pub struct LeafTree {
    our_key: PublicKey,

    /// Tree info for known nodes (key → info). Bounded to MAX_TREE_ENTRIES.
    infos: Vec<(PublicKey, TreeInfo)>,

    /// Current SigReq parameters (same request sent to all peers).
    req_seq: u64,
    req_nonce: u64,
    has_pending_req: bool,

    /// Collected SigRes from peers.
    responses: Vec<PendingSigRes>,

    /// Per-peer-key set of node keys whose announcements we've already sent.
    /// Prevents re-sending the same announcement to the same peer.
    sent_to: Vec<(PublicKey, Vec<PublicKey>)>,

    /// Flags for parent selection state machine.
    needs_refresh: bool,
    do_root1: bool,
    do_root2: bool,
}

impl LeafTree {
    pub fn new(our_key: PublicKey) -> Self {
        Self {
            our_key,
            infos: Vec::new(),
            req_seq: 0,
            req_nonce: 0,
            has_pending_req: false,
            responses: Vec::new(),
            sent_to: Vec::new(),
            needs_refresh: false,
            do_root1: false,
            do_root2: true, // become root on first maintenance
        }
    }

    /// Our public key.
    pub fn our_key(&self) -> &PublicKey {
        &self.our_key
    }

    // -----------------------------------------------------------------------
    // Info storage (bounded Vec instead of HashMap for no_std)
    // -----------------------------------------------------------------------

    fn get_info(&self, key: &PublicKey) -> Option<&TreeInfo> {
        self.infos.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn set_info(&mut self, key: PublicKey, info: TreeInfo) {
        if let Some(entry) = self.infos.iter_mut().find(|(k, _)| *k == key) {
            entry.1 = info;
        } else {
            if self.infos.len() >= MAX_TREE_ENTRIES {
                // Evict first non-self entry
                if let Some(pos) = self.infos.iter().position(|(k, _)| *k != self.our_key) {
                    self.infos.swap_remove(pos);
                }
            }
            self.infos.push((key, info));
        }
    }

    /// Check if tree info exists for a key.
    pub fn has_info(&self, key: &PublicKey) -> bool {
        self.infos.iter().any(|(k, _)| k == key)
    }

    /// Number of stored tree entries.
    pub fn info_count(&self) -> usize {
        self.infos.len()
    }

    // -----------------------------------------------------------------------
    // Peer lifecycle
    // -----------------------------------------------------------------------

    /// Register a peer for announcement tracking.
    pub fn add_peer(&mut self, peer_key: PublicKey) {
        if !self.sent_to.iter().any(|(k, _)| *k == peer_key) {
            self.sent_to.push((peer_key, Vec::new()));
        }
    }

    /// Unregister a peer.
    pub fn remove_peer(&mut self, peer_key: &PublicKey) {
        self.sent_to.retain(|(k, _)| k != peer_key);
        self.responses.retain(|r| r.key != *peer_key);
    }

    // -----------------------------------------------------------------------
    // SigReq / SigRes
    // -----------------------------------------------------------------------

    /// Start a new SigReq cycle. Returns the request to send to all peers.
    ///
    /// `nonce` should be a random u64 (caller provides the RNG).
    pub fn new_sig_req(&mut self, nonce: u64) -> wire::SigReq {
        self.req_seq = self.get_info(&self.our_key).map_or(0, |i| i.seq) + 1;
        self.req_nonce = nonce;
        self.has_pending_req = true;
        self.responses.clear();
        wire::SigReq {
            seq: self.req_seq,
            nonce: self.req_nonce,
        }
    }

    /// Handle an incoming SigReq from a peer. Returns the SigRes to send back.
    ///
    /// We sign `peer_key || our_key || seq || nonce || peer_port`, authorizing
    /// the peer to claim us as their parent on the given port.
    pub fn handle_sig_req(
        &self,
        crypto: &Crypto,
        peer_id: PeerId,
        peer_key: &PublicKey,
        peer_port: PeerPort,
        req: &wire::SigReq,
    ) -> TreeAction {
        let bs = announcement_sig_bytes(peer_key, &self.our_key, req.seq, req.nonce, peer_port);
        let psig = crypto.sign(&bs);
        TreeAction::SendSigRes {
            peer_id,
            res: wire::SigRes {
                seq: req.seq,
                nonce: req.nonce,
                port: peer_port,
                psig,
            },
        }
    }

    /// Handle an incoming SigRes from a peer.
    ///
    /// Only accepted if it matches our pending SigReq (seq + nonce).
    /// First response per peer key is stored; duplicates are ignored.
    pub fn handle_sig_res(&mut self, peer_key: PublicKey, res: &wire::SigRes) {
        if !self.has_pending_req || res.seq != self.req_seq || res.nonce != self.req_nonce {
            return;
        }
        // Only store first response per peer key
        if self.responses.iter().any(|r| r.key == peer_key) {
            return;
        }
        self.responses.push(PendingSigRes {
            key: peer_key,
            seq: res.seq,
            nonce: res.nonce,
            port: res.port,
            psig: res.psig,
        });
    }

    // -----------------------------------------------------------------------
    // CRDT update
    // -----------------------------------------------------------------------

    /// Process a tree announcement (CRDT ordering only, no signature check).
    ///
    /// CRDT prefers: highest seq → lowest parent key → lowest nonce.
    /// Returns true if the new info was accepted and stored.
    fn update_info(
        &mut self,
        key: PublicKey,
        parent: PublicKey,
        seq: u64,
        nonce: u64,
        port: PeerPort,
        psig: Sig,
        sig: Sig,
    ) -> bool {
        if let Some(info) = self.get_info(&key) {
            // CRDT ordering — must match Go exactly
            match () {
                _ if info.seq > seq => return false,
                _ if info.seq < seq => {}
                _ if info.parent < parent => return false,
                _ if parent < info.parent => {}
                _ if nonce < info.nonce => {}
                _ => return false,
            }
        }

        // Clear sent tracking for this key (peers need the update)
        for (_, sent) in &mut self.sent_to {
            sent.retain(|k| *k != key);
        }

        self.set_info(
            key,
            TreeInfo {
                parent,
                seq,
                nonce,
                port,
                psig,
                sig,
            },
        );
        true
    }

    /// Handle an incoming announcement from a peer.
    ///
    /// Verifies signatures, applies CRDT update, and may send back our version
    /// if we reject the announcement (convergence).
    pub fn handle_announce(
        &mut self,
        peer_id: PeerId,
        peer_key: &PublicKey,
        ann: &wire::Announce,
    ) -> Vec<TreeAction> {
        if !verify_announce(ann) {
            return Vec::new();
        }

        let mut actions = Vec::new();
        let accepted = self.update_info(
            ann.key,
            ann.parent,
            ann.sig_res.seq,
            ann.sig_res.nonce,
            ann.sig_res.port,
            ann.sig_res.psig,
            ann.sig,
        );

        if accepted {
            // Mark as received from this peer
            self.mark_sent(peer_key, &ann.key);

            // If someone sent us a newer announcement about ourselves, refresh
            if ann.key == self.our_key {
                self.needs_refresh = true;
            }
        } else {
            // Send back our version if different (for convergence)
            if let Some(info) = self.get_info(&ann.key) {
                let differs = info.seq != ann.sig_res.seq
                    || info.nonce != ann.sig_res.nonce
                    || info.parent != ann.parent;
                if differs {
                    actions.push(TreeAction::SendAnnounce {
                        peer_id,
                        ann: info_to_wire(&ann.key, info),
                    });
                }
                self.mark_sent(peer_key, &ann.key);
            }
        }

        actions
    }

    /// Mark that we've sent (or received) an announcement for `node_key` to/from `peer_key`.
    fn mark_sent(&mut self, peer_key: &PublicKey, node_key: &PublicKey) {
        if let Some(entry) = self.sent_to.iter_mut().find(|(k, _)| k == peer_key) {
            if !entry.1.contains(node_key) {
                entry.1.push(*node_key);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Parent selection
    // -----------------------------------------------------------------------

    /// Become self-rooted: create a self-signed announcement.
    fn become_root(&mut self, crypto: &Crypto, nonce: u64) -> bool {
        let self_key = self.our_key;
        let seq = self.get_info(&self_key).map_or(0, |i| i.seq) + 1;
        let bs = announcement_sig_bytes(&self_key, &self_key, seq, nonce, 0);
        let psig = crypto.sign(&bs);
        // Self-signed: sig == psig
        self.update_info(self_key, self_key, seq, nonce, 0, psig, psig)
    }

    /// Use a peer's SigRes to adopt them as our parent.
    fn use_response(&mut self, crypto: &Crypto, res: &PendingSigRes) -> bool {
        let self_key = self.our_key;
        let bs = announcement_sig_bytes(&self_key, &res.key, res.seq, res.nonce, res.port);
        let sig = crypto.sign(&bs);
        self.update_info(self_key, res.key, res.seq, res.nonce, res.port, res.psig, sig)
    }

    /// Parent selection: choose the best root and parent.
    ///
    /// `peers`: slice of `(peer_id, peer_key, latency_ms)` for connected peers.
    /// `nonce`: random nonce for new SigReqs if parent changes.
    fn fix(
        &mut self,
        crypto: &Crypto,
        peers: &[(PeerId, PublicKey, u64)],
        nonce: u64,
    ) -> Vec<TreeAction> {
        let self_key = self.our_key;
        let mut best_root = self_key;
        let mut best_parent = self_key;
        let mut best_cost = u64::MAX;

        let self_info_parent = self
            .get_info(&self_key)
            .map(|i| i.parent)
            .unwrap_or(self_key);

        // 1. Check current parent (if still connected)
        let parent_connected = peers.iter().any(|(_, k, _)| *k == self_info_parent);
        if parent_connected {
            let (root, dists) = self.get_root_and_dists(&self_key);
            if root < best_root {
                let mut cost = u64::MAX;
                for &(_, ref pk, lat) in peers {
                    if *pk == self_info_parent {
                        let dist_to_root = dists
                            .iter()
                            .find(|(k, _)| *k == root)
                            .map(|(_, d)| *d)
                            .unwrap_or(u64::MAX);
                        let lat = if lat == 0 { 1 } else { lat };
                        let c = dist_to_root.saturating_mul(lat);
                        if c < cost {
                            cost = c;
                        }
                    }
                }
                best_root = root;
                best_parent = self_info_parent;
                best_cost = cost;
            }
        }

        // 2. Check all peers that responded to our SigReq
        for res in &self.responses {
            let pk = res.key;
            if self.get_info(&pk).is_none() {
                continue;
            }
            let (p_root, p_dists) = self.get_root_and_dists(&pk);
            // Skip if using this peer would create a loop
            if p_dists.iter().any(|(k, _)| *k == self_key) {
                continue;
            }

            let mut cost = u64::MAX;
            for &(_, ref peer_key, lat) in peers {
                if *peer_key == pk {
                    let dist_to_root = p_dists
                        .iter()
                        .find(|(k, _)| *k == p_root)
                        .map(|(_, d)| *d)
                        .unwrap_or(u64::MAX);
                    let lat = if lat == 0 { 1 } else { lat };
                    let c = dist_to_root.saturating_mul(lat);
                    if c < cost {
                        cost = c;
                    }
                }
            }

            if p_root < best_root {
                best_root = p_root;
                best_parent = pk;
                best_cost = cost;
            } else if p_root != best_root {
                continue;
            }

            // During refresh: require significantly better cost (2x) to switch
            // Otherwise: just pick the lower-cost candidate
            if (self.needs_refresh && cost.saturating_mul(2) < best_cost)
                || (best_parent != self_info_parent && cost < best_cost)
            {
                best_root = p_root;
                best_parent = pk;
                best_cost = cost;
            }
        }

        let mut actions = Vec::new();

        if self.needs_refresh || self.do_root1 || self.do_root2 || self_info_parent != best_parent {
            // Try to adopt the best parent
            let res = self.responses.iter().find(|r| r.key == best_parent).cloned();
            if let Some(res) = res {
                if best_root != self_key && self.use_response(crypto, &res) {
                    self.needs_refresh = false;
                    self.do_root1 = false;
                    self.do_root2 = false;
                    actions.extend(self.send_reqs(peers, nonce));
                    return actions;
                }
            }

            // No valid parent found — become root (two-phase)
            if self.do_root2 {
                self.become_root(crypto, nonce);
                self.needs_refresh = false;
                self.do_root1 = false;
                self.do_root2 = false;
                actions.extend(self.send_reqs(peers, nonce));
            } else if !self.do_root1 {
                self.do_root1 = true;
            }
        }

        actions
    }

    /// Send SigReqs to all peers (starts a new SigReq cycle).
    fn send_reqs(
        &mut self,
        peers: &[(PeerId, PublicKey, u64)],
        nonce: u64,
    ) -> Vec<TreeAction> {
        let req = self.new_sig_req(nonce);
        peers
            .iter()
            .map(|&(peer_id, _, _)| TreeAction::SendSigReq {
                peer_id,
                req: req.clone(),
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Announcement sending
    // -----------------------------------------------------------------------

    /// Send pending announcements to all peers.
    ///
    /// For each peer, sends any ancestor announcements they haven't seen yet.
    fn send_announces(&mut self, peers: &[(PeerId, PublicKey, u64)]) -> Vec<TreeAction> {
        let mut actions = Vec::new();
        let self_key = self.our_key;
        let self_anc = self.get_ancestry(&self_key);

        for &(peer_id, ref peer_key, _) in peers {
            let peer_anc = self.get_ancestry(peer_key);

            // Collect keys to send (not yet sent to this peer)
            let mut to_send = Vec::new();
            let sent = self
                .sent_to
                .iter()
                .find(|(k, _)| k == peer_key)
                .map(|(_, v)| v);

            for k in self_anc.iter().chain(peer_anc.iter()) {
                let already_sent = sent.map_or(false, |s| s.contains(k));
                if !already_sent && !to_send.contains(k) {
                    to_send.push(*k);
                }
            }

            // Generate and queue announcements
            for key in &to_send {
                if let Some(info) = self.get_info(key) {
                    actions.push(TreeAction::SendAnnounce {
                        peer_id,
                        ann: info_to_wire(key, info),
                    });
                }
            }

            // Mark as sent
            if let Some(entry) = self.sent_to.iter_mut().find(|(k, _)| k == peer_key) {
                for key in to_send {
                    if !entry.1.contains(&key) {
                        entry.1.push(key);
                    }
                }
            }
        }

        actions
    }

    // -----------------------------------------------------------------------
    // Tree traversal
    // -----------------------------------------------------------------------

    /// Walk the tree upward from `start`, recording distances.
    ///
    /// Returns `(root_key, [(node_key, hop_distance_from_start), ...])`.
    fn get_root_and_dists(&self, start: &PublicKey) -> (PublicKey, Vec<(PublicKey, u64)>) {
        let mut dists: Vec<(PublicKey, u64)> = Vec::new();
        let mut next = *start;
        let mut root = [0u8; 32];
        let mut dist = 0u64;

        loop {
            if dists.iter().any(|(k, _)| *k == next) {
                break;
            }
            if let Some(info) = self.get_info(&next) {
                root = next;
                dists.push((next, dist));
                dist += 1;
                next = info.parent;
            } else {
                break;
            }
        }

        (root, dists)
    }

    /// Get root key and coordinate path (root → dest) for a node.
    pub fn get_root_and_path(&self, dest: &PublicKey) -> (PublicKey, Vec<PeerPort>) {
        let mut ports = Vec::new();
        let mut visited = Vec::new();
        let mut root;
        let mut next = *dest;

        loop {
            if visited.contains(&next) {
                return (*dest, Vec::new()); // loop detected
            }
            if let Some(info) = self.get_info(&next) {
                root = next;
                visited.push(next);
                if next == info.parent {
                    break; // reached root (self-parented)
                }
                ports.push(info.port);
                next = info.parent;
            } else {
                return (*dest, Vec::new()); // dead end
            }
        }

        ports.reverse();
        (root, ports)
    }

    /// Our coordinates in the tree (path from root to us).
    pub fn get_coords(&self) -> Vec<PeerPort> {
        let (_, path) = self.get_root_and_path(&self.our_key);
        path
    }

    /// Current root key of our tree branch.
    pub fn get_root(&self) -> PublicKey {
        let (root, _) = self.get_root_and_path(&self.our_key);
        root
    }

    /// Our direct parent peer key (from our own TreeInfo).
    /// Returns `None` if we don't have tree info yet.
    /// Returns our own key if we are self-rooted.
    pub fn get_parent(&self) -> Option<PublicKey> {
        self.get_info(&self.our_key).map(|info| info.parent)
    }

    /// Get ancestry: list of keys from root down to `key`.
    fn get_ancestry(&self, key: &PublicKey) -> Vec<PublicKey> {
        let mut anc = Vec::new();
        let mut here = *key;
        loop {
            if anc.contains(&here) {
                break;
            }
            if let Some(info) = self.get_info(&here) {
                anc.push(here);
                if here == info.parent {
                    break; // root
                }
                here = info.parent;
            } else {
                break;
            }
        }
        anc.reverse();
        anc
    }

    // -----------------------------------------------------------------------
    // Maintenance
    // -----------------------------------------------------------------------

    /// Periodic maintenance. Call every ~1 second.
    ///
    /// Performs parent selection and sends pending announcements.
    /// `peers`: slice of `(peer_id, peer_key, latency_ms)`.
    /// `nonce`: random u64 for new SigReqs.
    pub fn do_maintenance(
        &mut self,
        crypto: &Crypto,
        peers: &[(PeerId, PublicKey, u64)],
        nonce: u64,
    ) -> Vec<TreeAction> {
        let mut actions = Vec::new();
        self.do_root2 = self.do_root2 || self.do_root1;
        actions.extend(self.fix(crypto, peers, nonce));
        actions.extend(self.send_announces(peers));
        actions
    }

    /// Mark that a refresh is needed (call when timer expires).
    pub fn set_needs_refresh(&mut self) {
        self.needs_refresh = true;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn gen_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    fn make_crypto() -> Crypto {
        Crypto::new(gen_signing_key())
    }

    fn random_nonce() -> u64 {
        OsRng.next_u64()
    }

    #[test]
    fn become_root_creates_valid_announcement() {
        let crypto = make_crypto();
        let mut tree = LeafTree::new(crypto.public_key);

        assert!(tree.become_root(&crypto, random_nonce()));
        assert!(tree.has_info(&crypto.public_key));

        let info = tree.get_info(&crypto.public_key).unwrap();
        assert_eq!(info.parent, crypto.public_key); // self-rooted
        assert_eq!(info.port, 0);
        assert_eq!(info.seq, 1);

        // Verify the announcement is valid
        let ann = info_to_wire(&crypto.public_key, info);
        assert!(verify_announce(&ann));
    }

    #[test]
    fn crdt_accepts_higher_seq() {
        let crypto = make_crypto();
        let mut tree = LeafTree::new(crypto.public_key);

        // Create initial announcement (seq=1)
        tree.become_root(&crypto, 42);

        // Create newer announcement (seq=2)
        let nonce = 100;
        let bs = announcement_sig_bytes(&crypto.public_key, &crypto.public_key, 2, nonce, 0);
        let sig = crypto.sign(&bs);
        assert!(tree.update_info(crypto.public_key, crypto.public_key, 2, nonce, 0, sig, sig));

        assert_eq!(tree.get_info(&crypto.public_key).unwrap().seq, 2);
    }

    #[test]
    fn crdt_rejects_lower_seq() {
        let crypto = make_crypto();
        let mut tree = LeafTree::new(crypto.public_key);

        // Create announcement with seq=5
        let bs = announcement_sig_bytes(&crypto.public_key, &crypto.public_key, 5, 42, 0);
        let sig = crypto.sign(&bs);
        assert!(tree.update_info(crypto.public_key, crypto.public_key, 5, 42, 0, sig, sig));

        // Try to update with seq=3 — should be rejected
        let bs2 = announcement_sig_bytes(&crypto.public_key, &crypto.public_key, 3, 99, 0);
        let sig2 = crypto.sign(&bs2);
        assert!(!tree.update_info(crypto.public_key, crypto.public_key, 3, 99, 0, sig2, sig2));

        // Seq should still be 5
        assert_eq!(tree.get_info(&crypto.public_key).unwrap().seq, 5);
    }

    #[test]
    fn crdt_same_seq_prefers_lower_parent() {
        let crypto = make_crypto();
        let mut tree = LeafTree::new(crypto.public_key);

        // Ensure parent_low < parent_high lexicographically
        let mut parent_low = [0x00; 32];
        parent_low[0] = 0x01;
        let mut parent_high = [0x00; 32];
        parent_high[0] = 0xFF;

        // Set with high parent (seq=1)
        let psig = [0xAA; 64]; // dummy sig (no verification in update_info)
        let sig = [0xBB; 64];
        assert!(tree.update_info(crypto.public_key, parent_high, 1, 10, 1, psig, sig));

        // Update with same seq but lower parent — should be accepted
        let psig2 = [0xCC; 64];
        let sig2 = [0xDD; 64];
        assert!(tree.update_info(crypto.public_key, parent_low, 1, 20, 2, psig2, sig2));

        assert_eq!(tree.get_info(&crypto.public_key).unwrap().parent, parent_low);
    }

    #[test]
    fn sig_req_res_creates_valid_announcement() {
        let crypto_a = make_crypto(); // node A (child)
        let crypto_b = make_crypto(); // node B (parent)

        let mut tree_a = LeafTree::new(crypto_a.public_key);
        let tree_b = LeafTree::new(crypto_b.public_key);

        // A sends SigReq to B
        let req = tree_a.new_sig_req(random_nonce());
        assert_eq!(req.seq, 1);

        // B responds with SigRes
        let action = tree_b.handle_sig_req(&crypto_b, 1, &crypto_a.public_key, 3, &req);
        let res = match action {
            TreeAction::SendSigRes { res, .. } => res,
            _ => panic!("expected SendSigRes"),
        };
        assert_eq!(res.port, 3);

        // A stores the response
        tree_a.handle_sig_res(crypto_b.public_key, &res);
        assert_eq!(tree_a.responses.len(), 1);

        // A uses B's response as parent
        let pending = tree_a.responses[0].clone();
        assert!(tree_a.use_response(&crypto_a, &pending));

        // Verify the resulting announcement
        let info = tree_a.get_info(&crypto_a.public_key).unwrap();
        assert_eq!(info.parent, crypto_b.public_key);
        assert_eq!(info.port, 3);

        let ann = info_to_wire(&crypto_a.public_key, info);
        assert!(verify_announce(&ann));
    }

    #[test]
    fn get_coords_simple_chain() {
        let crypto_root = make_crypto();
        let crypto_mid = make_crypto();
        let crypto_leaf = make_crypto();

        let mut tree = LeafTree::new(crypto_leaf.public_key);

        // Root (self-parented)
        let bs = announcement_sig_bytes(
            &crypto_root.public_key,
            &crypto_root.public_key,
            1, 0, 0,
        );
        let root_sig = crypto_root.sign(&bs);
        tree.update_info(
            crypto_root.public_key, crypto_root.public_key,
            1, 0, 0, root_sig, root_sig,
        );

        // Mid node (parent = root, port 2)
        let bs = announcement_sig_bytes(
            &crypto_mid.public_key,
            &crypto_root.public_key,
            1, 0, 2,
        );
        let psig = crypto_root.sign(&bs);
        let sig = crypto_mid.sign(&bs);
        tree.update_info(
            crypto_mid.public_key, crypto_root.public_key,
            1, 0, 2, psig, sig,
        );

        // Leaf node (parent = mid, port 5)
        let bs = announcement_sig_bytes(
            &crypto_leaf.public_key,
            &crypto_mid.public_key,
            1, 0, 5,
        );
        let psig = crypto_mid.sign(&bs);
        let sig = crypto_leaf.sign(&bs);
        tree.update_info(
            crypto_leaf.public_key, crypto_mid.public_key,
            1, 0, 5, psig, sig,
        );

        // Coords should be [2, 5] (root -> mid via port 2, mid -> leaf via port 5)
        let coords = tree.get_coords();
        assert_eq!(coords, vec![2, 5]);

        // Root should be the root node
        assert_eq!(tree.get_root(), crypto_root.public_key);
    }

    #[test]
    fn tree_dist_calculations() {
        // Same path: distance 0
        assert_eq!(tree_dist(&[1, 2, 3], &[1, 2, 3]), 0);

        // Completely different: sum of lengths
        assert_eq!(tree_dist(&[1, 2], &[3, 4]), 4);

        // Shared prefix: each shared hop reduces by 2
        assert_eq!(tree_dist(&[1, 2, 3], &[1, 2, 4]), 2); // 3+3 - 2*2 = 2
        assert_eq!(tree_dist(&[1, 2], &[1, 3]), 2); // 2+2 - 2 = 2

        // One is prefix of other
        assert_eq!(tree_dist(&[1, 2], &[1, 2, 3]), 1); // 2+3 - 4 = 1

        // Empty paths
        assert_eq!(tree_dist(&[], &[]), 0);
        assert_eq!(tree_dist(&[], &[1, 2]), 2);
    }

    #[test]
    fn verify_announce_rejects_bad_sig() {
        let crypto = make_crypto();

        // Valid self-rooted announcement
        let bs = announcement_sig_bytes(&crypto.public_key, &crypto.public_key, 1, 42, 0);
        let sig = crypto.sign(&bs);
        let good = wire::Announce {
            key: crypto.public_key,
            parent: crypto.public_key,
            sig_res: wire::SigRes { seq: 1, nonce: 42, port: 0, psig: sig },
            sig,
        };
        assert!(verify_announce(&good));

        // Tampered signature
        let mut bad = good.clone();
        bad.sig[0] ^= 0xFF;
        assert!(!verify_announce(&bad));

        // Port=0 but key != parent (invalid self-root)
        let other = make_crypto();
        let bad2 = wire::Announce {
            key: crypto.public_key,
            parent: other.public_key,
            sig_res: wire::SigRes { seq: 1, nonce: 42, port: 0, psig: sig },
            sig,
        };
        assert!(!verify_announce(&bad2));
    }

    #[test]
    fn maintenance_becomes_root_and_sends_reqs() {
        let crypto = make_crypto();
        let peer_crypto = make_crypto();
        let mut tree = LeafTree::new(crypto.public_key);

        tree.add_peer(peer_crypto.public_key);
        let peers = [(1u32, peer_crypto.public_key, 10u64)];

        let actions = tree.do_maintenance(&crypto, &peers, random_nonce());

        // Should become root (do_root2 = true initially)
        assert!(tree.has_info(&crypto.public_key));
        let info = tree.get_info(&crypto.public_key).unwrap();
        assert_eq!(info.parent, crypto.public_key); // self-rooted

        // Should have sent SigReq and announcements
        let has_sig_req = actions.iter().any(|a| matches!(a, TreeAction::SendSigReq { .. }));
        assert!(has_sig_req, "should send SigReq to peer");

        let has_announce = actions.iter().any(|a| matches!(a, TreeAction::SendAnnounce { .. }));
        assert!(has_announce, "should send our root announcement to peer");
    }

    #[test]
    fn parent_selection_picks_lower_root() {
        // Generate three keys and sort them so the node always has the highest key.
        // This ensures the node wants to join a peer's tree rather than self-rooting.
        let mut cryptos: Vec<Crypto> = (0..3).map(|_| make_crypto()).collect();
        cryptos.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        // cryptos[0] = lowest key (best root), cryptos[1] = middle, cryptos[2] = highest (our node)
        let lower_crypto = &cryptos[0];
        let higher_crypto = &cryptos[1];
        let node_crypto = &cryptos[2];

        let mut tree = LeafTree::new(node_crypto.public_key);

        // Add self-rooted announcements for both peers
        let bs_lo = announcement_sig_bytes(
            &lower_crypto.public_key, &lower_crypto.public_key, 1, 0, 0,
        );
        let sig_lo = lower_crypto.sign(&bs_lo);
        tree.update_info(
            lower_crypto.public_key, lower_crypto.public_key, 1, 0, 0, sig_lo, sig_lo,
        );

        let bs_hi = announcement_sig_bytes(
            &higher_crypto.public_key, &higher_crypto.public_key, 1, 0, 0,
        );
        let sig_hi = higher_crypto.sign(&bs_hi);
        tree.update_info(
            higher_crypto.public_key, higher_crypto.public_key, 1, 0, 0, sig_hi, sig_hi,
        );

        // SigReq/SigRes from both peers
        let req = tree.new_sig_req(random_nonce());

        // Higher-key peer responds
        let bs = announcement_sig_bytes(
            &node_crypto.public_key, &higher_crypto.public_key,
            req.seq, req.nonce, 1,
        );
        let psig_hi = higher_crypto.sign(&bs);
        tree.handle_sig_res(higher_crypto.public_key, &wire::SigRes {
            seq: req.seq, nonce: req.nonce, port: 1, psig: psig_hi,
        });

        // Lower-key peer responds
        let bs = announcement_sig_bytes(
            &node_crypto.public_key, &lower_crypto.public_key,
            req.seq, req.nonce, 2,
        );
        let psig_lo = lower_crypto.sign(&bs);
        tree.handle_sig_res(lower_crypto.public_key, &wire::SigRes {
            seq: req.seq, nonce: req.nonce, port: 2, psig: psig_lo,
        });

        tree.add_peer(higher_crypto.public_key);
        tree.add_peer(lower_crypto.public_key);

        // Run maintenance
        let peers = [
            (1u32, higher_crypto.public_key, 10u64),
            (2u32, lower_crypto.public_key, 10u64),
        ];
        tree.set_needs_refresh();
        let _actions = tree.do_maintenance(&node_crypto, &peers, random_nonce());

        // Should have picked peer with lower key (= lower root)
        let info = tree.get_info(&node_crypto.public_key).unwrap();
        assert_eq!(
            info.parent, lower_crypto.public_key,
            "should pick peer with lower root key"
        );
        assert_eq!(tree.get_root(), lower_crypto.public_key);
    }
}
