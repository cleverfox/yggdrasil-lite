//! Per-peer connection state for the leaf node.
//!
//! Each peer tracks:
//! - Public key and port assignment
//! - Priority and connection order
//! - Keepalive timing
//! - Frame read buffer for streaming TCP reads

use alloc::vec::Vec;
use crate::crypto::PublicKey;
use crate::wire::{self, PeerPort, PacketType, WireError};

/// Unique peer identifier within the node.
pub type PeerId = u32;

/// Maximum message size (64 KiB, matches Go).
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Per-peer connection state.
pub struct PeerState {
    pub id: PeerId,
    pub key: PublicKey,
    pub port: PeerPort,
    pub prio: u8,
    pub order: u64,
    /// Accumulates partial TCP reads until a full frame is available.
    read_buf: Vec<u8>,
    /// Whether this peer has completed the metadata handshake.
    pub handshake_done: bool,
}

impl PeerState {
    pub fn new(id: PeerId, key: PublicKey, port: PeerPort, prio: u8, order: u64) -> Self {
        Self {
            id,
            key,
            port,
            prio,
            order,
            read_buf: Vec::with_capacity(2048),
            handshake_done: false,
        }
    }

    /// Feed raw bytes from TCP into the read buffer.
    /// Returns how many bytes were consumed.
    pub fn feed(&mut self, data: &[u8]) {
        self.read_buf.extend_from_slice(data);
    }

    /// Try to extract the next complete frame from the read buffer.
    ///
    /// Returns `Some((packet_type, payload))` if a complete frame is available,
    /// or `None` if more data is needed.
    ///
    /// The payload is returned as a `Vec<u8>` to decouple it from the read buffer.
    pub fn try_read_frame(&mut self) -> Result<Option<(PacketType, Vec<u8>)>, WireError> {
        if self.read_buf.is_empty() {
            return Ok(None);
        }

        // Try to decode the uvarint length prefix
        let (frame_len, varint_bytes) = match wire::decode_uvarint(&self.read_buf) {
            Some((len, bytes)) => (len as usize, bytes),
            None => {
                // Not enough data for the length prefix yet
                if self.read_buf.len() > 10 {
                    // Uvarint can't be more than 10 bytes
                    return Err(WireError::Decode);
                }
                return Ok(None);
            }
        };

        if frame_len > MAX_MESSAGE_SIZE {
            return Err(WireError::Decode);
        }

        let total_needed = varint_bytes + frame_len;
        if self.read_buf.len() < total_needed {
            return Ok(None); // Need more data
        }

        // Extract the frame content (type byte + payload)
        let content = &self.read_buf[varint_bytes..total_needed];
        if content.is_empty() {
            // Consume the empty frame and continue
            self.read_buf.drain(..total_needed);
            return Ok(None);
        }

        let packet_type = PacketType::try_from(content[0])?;
        let payload = content[1..].to_vec();

        // Remove the consumed frame from the buffer
        self.read_buf.drain(..total_needed);

        Ok(Some((packet_type, payload)))
    }
}

/// Manages the set of active peers for a leaf node (bounded, max ~4).
pub struct PeerManager {
    next_id: PeerId,
    next_order: u64,
    peers: Vec<PeerState>,
    /// Ports in use (simple vec since we have ≤4 peers).
    used_ports: Vec<PeerPort>,
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            next_order: 0,
            peers: Vec::new(),
            used_ports: Vec::new(),
        }
    }

    /// Allocate a new peer and return its ID.
    pub fn add_peer(&mut self, key: PublicKey, prio: u8) -> PeerId {
        let id = self.next_id;
        self.next_id += 1;
        let order = self.next_order;
        self.next_order += 1;
        let port = self.alloc_port();

        let state = PeerState::new(id, key, port, prio, order);
        self.peers.push(state);
        id
    }

    /// Remove a peer by ID. Returns the peer's port if found.
    pub fn remove_peer(&mut self, id: PeerId) -> Option<PeerPort> {
        if let Some(pos) = self.peers.iter().position(|p| p.id == id) {
            let peer = self.peers.swap_remove(pos);
            if let Some(port_pos) = self.used_ports.iter().position(|&p| p == peer.port) {
                self.used_ports.swap_remove(port_pos);
            }
            Some(peer.port)
        } else {
            None
        }
    }

    /// Get a peer by ID.
    pub fn get(&self, id: PeerId) -> Option<&PeerState> {
        self.peers.iter().find(|p| p.id == id)
    }

    /// Get a mutable peer by ID.
    pub fn get_mut(&mut self, id: PeerId) -> Option<&mut PeerState> {
        self.peers.iter_mut().find(|p| p.id == id)
    }

    /// Get a peer by public key.
    pub fn get_by_key(&self, key: &PublicKey) -> Option<&PeerState> {
        self.peers.iter().find(|p| &p.key == key)
    }

    /// Iterate over all peers.
    pub fn iter(&self) -> impl Iterator<Item = &PeerState> {
        self.peers.iter()
    }

    /// Number of connected peers.
    pub fn count(&self) -> usize {
        self.peers.len()
    }

    /// Get all peer IDs.
    pub fn peer_ids(&self) -> Vec<PeerId> {
        self.peers.iter().map(|p| p.id).collect()
    }

    /// Allocate the lowest free port (starting from 1, skip 0).
    fn alloc_port(&mut self) -> PeerPort {
        let mut p: PeerPort = 1;
        while self.used_ports.contains(&p) {
            p += 1;
        }
        self.used_ports.push(p);
        p
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_manager_add_remove() {
        let mut pm = PeerManager::new();
        let id1 = pm.add_peer([1u8; 32], 0);
        let id2 = pm.add_peer([2u8; 32], 1);
        assert_eq!(pm.count(), 2);

        // Ports should be 1 and 2
        assert_eq!(pm.get(id1).unwrap().port, 1);
        assert_eq!(pm.get(id2).unwrap().port, 2);

        // Remove first peer
        let port = pm.remove_peer(id1);
        assert_eq!(port, Some(1));
        assert_eq!(pm.count(), 1);

        // New peer should reuse port 1
        let id3 = pm.add_peer([3u8; 32], 0);
        assert_eq!(pm.get(id3).unwrap().port, 1);
    }

    #[test]
    fn frame_parsing() {
        let mut peer = PeerState::new(1, [0u8; 32], 1, 0, 0);

        // Encode a keepalive frame
        let frame = wire::encode_frame(PacketType::KeepAlive, &[]);

        // Feed in two halves to test partial reads
        let mid = frame.len() / 2;
        peer.feed(&frame[..mid]);
        assert!(peer.try_read_frame().unwrap().is_none());

        peer.feed(&frame[mid..]);
        let (ptype, payload) = peer.try_read_frame().unwrap().unwrap();
        assert_eq!(ptype, PacketType::KeepAlive);
        assert!(payload.is_empty());
    }

    #[test]
    fn multiple_frames_in_buffer() {
        let mut peer = PeerState::new(1, [0u8; 32], 1, 0, 0);

        let frame1 = wire::encode_frame(PacketType::KeepAlive, &[]);
        let frame2 = wire::encode_frame(PacketType::Dummy, &[42]);

        // Feed both frames at once
        peer.feed(&frame1);
        peer.feed(&frame2);

        let (ptype1, _) = peer.try_read_frame().unwrap().unwrap();
        assert_eq!(ptype1, PacketType::KeepAlive);

        let (ptype2, payload2) = peer.try_read_frame().unwrap().unwrap();
        assert_eq!(ptype2, PacketType::Dummy);
        assert_eq!(payload2, &[42]);

        // No more frames
        assert!(peer.try_read_frame().unwrap().is_none());
    }

    #[test]
    fn announce_frame_parsing() {
        let mut peer = PeerState::new(1, [0u8; 32], 1, 0, 0);

        let ann = wire::Announce {
            key: [1u8; 32],
            parent: [2u8; 32],
            sig_res: wire::SigRes { seq: 10, nonce: 20, port: 3, psig: [0xCC; 64] },
            sig: [0xDD; 64],
        };
        let mut payload = Vec::new();
        ann.encode(&mut payload);
        let frame = wire::encode_frame(PacketType::ProtoAnnounce, &payload);

        peer.feed(&frame);
        let (ptype, data) = peer.try_read_frame().unwrap().unwrap();
        assert_eq!(ptype, PacketType::ProtoAnnounce);

        let decoded = wire::Announce::decode(&data).unwrap();
        assert_eq!(decoded.key, [1u8; 32]);
        assert_eq!(decoded.sig_res.seq, 10);
    }
}
