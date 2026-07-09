//! Bloom filter implementation compatible with Go's bits-and-blooms/bloom library.
//!
//! Uses the same hashing scheme:
//! - Murmur3 128-bit hash to generate 4 base hash values
//! - Location formula: h[i%2] + i*h[2+(((i+(i%2))%4)/2)]
//!
//! Adapted from ironwood/src/bloom.rs for no_std.

use alloc::vec::Vec;
use crate::crypto::PublicKey;
use crate::wire;

/// Bloom filter: 8192 bits, 8 hash functions.
pub const BLOOM_FILTER_BITS: usize = 8192;
pub const BLOOM_FILTER_K: usize = 8;
pub const BLOOM_FILTER_U64S: usize = BLOOM_FILTER_BITS / 64; // 128

/// A Bloom filter with fixed 8192 bits and 8 hash functions.
/// Wire-compatible with the Go bits-and-blooms/bloom library.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BloomFilter {
    bits: [u64; BLOOM_FILTER_U64S],
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl BloomFilter {
    /// Create an empty bloom filter.
    pub fn new() -> Self {
        Self {
            bits: [0u64; BLOOM_FILTER_U64S],
        }
    }

    /// Create from a raw u64 array (e.g., from wire decoding).
    pub fn from_raw(bits: [u64; BLOOM_FILTER_U64S]) -> Self {
        Self { bits }
    }

    /// Get the raw backing array (for wire encoding).
    pub fn as_raw(&self) -> &[u64; BLOOM_FILTER_U64S] {
        &self.bits
    }

    /// Add a key to the bloom filter.
    pub fn add(&mut self, key: &[u8]) {
        let h = base_hashes(key);
        for i in 0..BLOOM_FILTER_K {
            let bit = location(&h, i, BLOOM_FILTER_BITS);
            self.set_bit(bit);
        }
    }

    /// Test if a key might be in the bloom filter.
    pub fn test(&self, key: &[u8]) -> bool {
        let h = base_hashes(key);
        for i in 0..BLOOM_FILTER_K {
            let bit = location(&h, i, BLOOM_FILTER_BITS);
            if !self.get_bit(bit) {
                return false;
            }
        }
        true
    }

    /// Merge another bloom filter into this one (bitwise OR).
    pub fn merge(&mut self, other: &BloomFilter) {
        for i in 0..BLOOM_FILTER_U64S {
            self.bits[i] |= other.bits[i];
        }
    }

    /// Count the number of set bits (for diagnostics).
    pub fn count_ones(&self) -> u32 {
        self.bits.iter().map(|w| w.count_ones()).sum()
    }

    /// Encode to wire format.
    pub fn encode(&self, out: &mut Vec<u8>) {
        wire::encode_bloom(out, &self.bits);
    }

    /// Decode from wire format.
    pub fn decode(data: &[u8]) -> Result<Self, wire::WireError> {
        let bits = wire::decode_bloom(data)?;
        Ok(Self { bits })
    }

    fn set_bit(&mut self, bit: usize) {
        let idx = bit / 64;
        let offset = bit % 64;
        self.bits[idx] |= 1u64 << offset;
    }

    fn get_bit(&self, bit: usize) -> bool {
        let idx = bit / 64;
        let offset = bit % 64;
        (self.bits[idx] >> offset) & 1 == 1
    }
}

// ---------------------------------------------------------------------------
// Simplified bloom manager for leaf node (max 3 peers)
// ---------------------------------------------------------------------------

/// Per-peer bloom filter state.
#[derive(Clone)]
pub struct PeerBloomInfo {
    /// What we send to this peer.
    pub send: BloomFilter,
    /// What we received from this peer.
    pub recv: BloomFilter,
    /// Sequence counter for periodic resend.
    pub seq: u16,
    /// Whether this peer is on the spanning tree (parent or child).
    pub on_tree: bool,
    /// Do not redistribute this peer's keys to other peers: its `recv` bloom
    /// is never merged into blooms advertised to others, and lookups from
    /// other peers are never forwarded toward it. Our own lookups still use
    /// it, so marking every peer turns a transit build into a stub node.
    pub no_redistribute: bool,
}

impl PeerBloomInfo {
    pub fn new() -> Self {
        Self {
            send: BloomFilter::new(),
            recv: BloomFilter::new(),
            seq: 0,
            on_tree: false,
            no_redistribute: false,
        }
    }
}

/// Simplified bloom manager for a leaf node with bounded peers.
pub struct LeafBlooms {
    /// Peer key -> bloom info. For a leaf node, max ~3 entries.
    peers: Vec<(PublicKey, PeerBloomInfo)>,
    /// Transform function for bloom keys (subnet_for_key().get_key()).
    /// If None, use identity.
    transform: Option<fn(PublicKey) -> PublicKey>,
}

impl LeafBlooms {
    pub fn new(transform: Option<fn(PublicKey) -> PublicKey>) -> Self {
        Self {
            peers: Vec::new(),
            transform,
        }
    }

    fn x_key(&self, key: &PublicKey) -> PublicKey {
        match self.transform {
            Some(f) => f(*key),
            None => *key,
        }
    }

    fn find(&self, key: &PublicKey) -> Option<usize> {
        self.peers.iter().position(|(k, _)| k == key)
    }

    fn find_mut(&mut self, key: &PublicKey) -> Option<&mut PeerBloomInfo> {
        self.peers.iter_mut().find(|(k, _)| k == key).map(|(_, info)| info)
    }

    /// Add bloom tracking for a new peer.
    pub fn add_peer(&mut self, key: PublicKey) {
        if self.find(&key).is_none() {
            self.peers.push((key, PeerBloomInfo::new()));
        }
    }

    /// Remove bloom tracking for a disconnected peer.
    pub fn remove_peer(&mut self, key: &PublicKey) {
        if let Some(idx) = self.find(key) {
            self.peers.swap_remove(idx);
        }
    }

    /// Handle receiving a bloom filter from a peer.
    pub fn handle_bloom(&mut self, peer_key: &PublicKey, filter: BloomFilter) {
        if let Some(info) = self.find_mut(peer_key) {
            info.recv = filter;
        }
    }

    /// Update on-tree status based on tree parent.
    /// When we have a parent peer: only that peer is on-tree.
    /// When we are root (parent == our_key): all peers are children → all on-tree.
    pub fn set_parent(&mut self, parent_key: &PublicKey, our_key: &PublicKey) {
        let is_root = parent_key == our_key;
        for (k, info) in &mut self.peers {
            info.on_tree = k == parent_key || is_root;
        }
    }

    /// Update on-tree status from exact tree relationships (transit mode).
    ///
    /// `parent_key`: our current parent (our own key if we are root).
    /// `children`: peers whose announced tree parent is us.
    ///
    /// Returns `(peer_key, blank_filter)` pairs for peers that just dropped
    /// off the tree — the blank filter must be sent to them so they don't
    /// keep routing lookups toward us based on a stale advertisement.
    #[cfg(feature = "transit")]
    pub fn update_on_tree(
        &mut self,
        our_key: &PublicKey,
        parent_key: &PublicKey,
        children: &[PublicKey],
    ) -> Vec<(PublicKey, BloomFilter)> {
        let mut to_send = Vec::new();
        for (k, info) in &mut self.peers {
            let was_on = info.on_tree;
            info.on_tree = (k == parent_key && parent_key != our_key) || children.contains(k);
            if was_on && !info.on_tree {
                let blank = BloomFilter::new();
                info.send = blank.clone();
                to_send.push((*k, blank));
            }
        }
        to_send
    }

    /// Mark a peer as no-redistribute (see [`PeerBloomInfo::no_redistribute`]).
    pub fn set_no_redistribute(&mut self, key: &PublicKey, flag: bool) {
        if let Some(info) = self.find_mut(key) {
            info.no_redistribute = flag;
        }
    }

    /// Whether a peer link is currently on the spanning tree.
    pub fn is_on_tree(&self, key: &PublicKey) -> bool {
        self.find(key)
            .map_or(false, |idx| self.peers[idx].1.on_tree)
    }

    /// Compute the bloom filter to send to a given peer.
    ///
    /// Leaf builds advertise only our own key. Transit builds additionally
    /// merge the recv blooms of all on-tree peers except the target, skipping
    /// peers marked no-redistribute.
    pub fn compute_send_bloom(&self, target_key: &PublicKey, our_key: &PublicKey) -> BloomFilter {
        let _ = target_key;
        let mut b = BloomFilter::new();
        let xformed = self.x_key(our_key);
        b.add(&xformed);
        #[cfg(feature = "transit")]
        for (k, info) in &self.peers {
            if k == target_key || !info.on_tree || info.no_redistribute {
                continue;
            }
            b.merge(&info.recv);
        }
        b
    }

    /// Run periodic maintenance. Returns list of (peer_key, bloom) to send.
    pub fn do_maintenance(&mut self, our_key: &PublicKey) -> Vec<(PublicKey, BloomFilter)> {
        let mut to_send = Vec::new();
        let peer_keys: Vec<PublicKey> = self.peers.iter()
            .filter(|(_, info)| info.on_tree)
            .map(|(k, _)| *k)
            .collect();

        for k in peer_keys {
            let bloom = self.compute_send_bloom(&k, our_key);
            let info = self.find_mut(&k).unwrap();
            info.seq += 1;
            let is_new = bloom != info.send;
            if is_new || info.seq >= 3600 {
                info.send = bloom.clone();
                info.seq = 0;
                to_send.push((k, bloom));
            }
        }
        to_send
    }

    /// Find peers whose bloom filter matches a destination key.
    ///
    /// `skip_no_redistribute` must be true when forwarding a lookup received
    /// from a peer: no-redistribute peers are excluded as targets, so we never
    /// offer transit toward them. It must be false for our own lookups.
    pub fn get_multicast_targets(
        &self,
        from_key: &PublicKey,
        dest_key: &PublicKey,
        skip_no_redistribute: bool,
    ) -> Vec<PublicKey> {
        let xformed = self.x_key(dest_key);
        let mut targets = Vec::new();
        for (k, info) in &self.peers {
            if !info.on_tree || k == from_key {
                continue;
            }
            if skip_no_redistribute && info.no_redistribute {
                continue;
            }
            if info.recv.test(&xformed) {
                targets.push(*k);
            }
        }
        targets
    }
}

// ---------------------------------------------------------------------------
// Murmur3 x64_128 (inline, no_std compatible)
// ---------------------------------------------------------------------------

/// MurmurHash3 x64_128 — produces a 128-bit hash as (u64, u64).
/// Wire-compatible with the Go/C++ reference implementation and the
/// `murmur3` crate's `murmur3_x64_128(data, seed=0)`.
fn murmur3_x64_128(data: &[u8], seed: u64) -> (u64, u64) {
    const C1: u64 = 0x87c3_7b91_1142_53d5;
    const C2: u64 = 0x4cf5_ad43_2745_937f;

    let mut h1: u64 = seed;
    let mut h2: u64 = seed;
    let len = data.len();

    // Process 16-byte chunks
    let nblocks = len / 16;
    for i in 0..nblocks {
        let off = i * 16;
        let mut k1 = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let mut k2 = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());

        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1.rotate_left(27);
        h1 = h1.wrapping_add(h2);
        h1 = h1.wrapping_mul(5).wrapping_add(0x52dc_e729);

        k2 = k2.wrapping_mul(C2);
        k2 = k2.rotate_left(33);
        k2 = k2.wrapping_mul(C1);
        h2 ^= k2;
        h2 = h2.rotate_left(31);
        h2 = h2.wrapping_add(h1);
        h2 = h2.wrapping_mul(5).wrapping_add(0x3849_5ab5);
    }

    // Tail
    let tail = &data[nblocks * 16..];
    let mut k1: u64 = 0;
    let mut k2: u64 = 0;

    match tail.len() {
        15 => { k2 ^= (tail[14] as u64) << 48; k2 ^= (tail[13] as u64) << 40; k2 ^= (tail[12] as u64) << 32; k2 ^= (tail[11] as u64) << 24; k2 ^= (tail[10] as u64) << 16; k2 ^= (tail[9] as u64) << 8; k2 ^= tail[8] as u64; k2 = k2.wrapping_mul(C2); k2 = k2.rotate_left(33); k2 = k2.wrapping_mul(C1); h2 ^= k2; k1 ^= (tail[7] as u64) << 56; k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1); k1 = k1.rotate_left(31); k1 = k1.wrapping_mul(C2); h1 ^= k1; }
        14 => { k2 ^= (tail[13] as u64) << 40; k2 ^= (tail[12] as u64) << 32; k2 ^= (tail[11] as u64) << 24; k2 ^= (tail[10] as u64) << 16; k2 ^= (tail[9] as u64) << 8; k2 ^= tail[8] as u64; k2 = k2.wrapping_mul(C2); k2 = k2.rotate_left(33); k2 = k2.wrapping_mul(C1); h2 ^= k2; k1 ^= (tail[7] as u64) << 56; k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1); k1 = k1.rotate_left(31); k1 = k1.wrapping_mul(C2); h1 ^= k1; }
        13 => { k2 ^= (tail[12] as u64) << 32; k2 ^= (tail[11] as u64) << 24; k2 ^= (tail[10] as u64) << 16; k2 ^= (tail[9] as u64) << 8; k2 ^= tail[8] as u64; k2 = k2.wrapping_mul(C2); k2 = k2.rotate_left(33); k2 = k2.wrapping_mul(C1); h2 ^= k2; k1 ^= (tail[7] as u64) << 56; k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1); k1 = k1.rotate_left(31); k1 = k1.wrapping_mul(C2); h1 ^= k1; }
        12 => { k2 ^= (tail[11] as u64) << 24; k2 ^= (tail[10] as u64) << 16; k2 ^= (tail[9] as u64) << 8; k2 ^= tail[8] as u64; k2 = k2.wrapping_mul(C2); k2 = k2.rotate_left(33); k2 = k2.wrapping_mul(C1); h2 ^= k2; k1 ^= (tail[7] as u64) << 56; k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1); k1 = k1.rotate_left(31); k1 = k1.wrapping_mul(C2); h1 ^= k1; }
        11 => { k2 ^= (tail[10] as u64) << 16; k2 ^= (tail[9] as u64) << 8; k2 ^= tail[8] as u64; k2 = k2.wrapping_mul(C2); k2 = k2.rotate_left(33); k2 = k2.wrapping_mul(C1); h2 ^= k2; k1 ^= (tail[7] as u64) << 56; k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1); k1 = k1.rotate_left(31); k1 = k1.wrapping_mul(C2); h1 ^= k1; }
        10 => { k2 ^= (tail[9] as u64) << 8; k2 ^= tail[8] as u64; k2 = k2.wrapping_mul(C2); k2 = k2.rotate_left(33); k2 = k2.wrapping_mul(C1); h2 ^= k2; k1 ^= (tail[7] as u64) << 56; k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1); k1 = k1.rotate_left(31); k1 = k1.wrapping_mul(C2); h1 ^= k1; }
        9 => { k2 ^= tail[8] as u64; k2 = k2.wrapping_mul(C2); k2 = k2.rotate_left(33); k2 = k2.wrapping_mul(C1); h2 ^= k2; k1 ^= (tail[7] as u64) << 56; k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1); k1 = k1.rotate_left(31); k1 = k1.wrapping_mul(C2); h1 ^= k1; }
        8 => { k1 ^= (tail[7] as u64) << 56; k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1); k1 = k1.rotate_left(31); k1 = k1.wrapping_mul(C2); h1 ^= k1; }
        7 => { k1 ^= (tail[6] as u64) << 48; k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1); k1 = k1.rotate_left(31); k1 = k1.wrapping_mul(C2); h1 ^= k1; }
        6 => { k1 ^= (tail[5] as u64) << 40; k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1); k1 = k1.rotate_left(31); k1 = k1.wrapping_mul(C2); h1 ^= k1; }
        5 => { k1 ^= (tail[4] as u64) << 32; k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1); k1 = k1.rotate_left(31); k1 = k1.wrapping_mul(C2); h1 ^= k1; }
        4 => { k1 ^= (tail[3] as u64) << 24; k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1); k1 = k1.rotate_left(31); k1 = k1.wrapping_mul(C2); h1 ^= k1; }
        3 => { k1 ^= (tail[2] as u64) << 16; k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1); k1 = k1.rotate_left(31); k1 = k1.wrapping_mul(C2); h1 ^= k1; }
        2 => { k1 ^= (tail[1] as u64) << 8; k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1); k1 = k1.rotate_left(31); k1 = k1.wrapping_mul(C2); h1 ^= k1; }
        1 => { k1 ^= tail[0] as u64; k1 = k1.wrapping_mul(C1); k1 = k1.rotate_left(31); k1 = k1.wrapping_mul(C2); h1 ^= k1; }
        _ => {}
    }

    // Finalization
    h1 ^= len as u64;
    h2 ^= len as u64;
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    h1 = fmix64(h1);
    h2 = fmix64(h2);
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);

    (h1, h2)
}

#[inline]
fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51_afd7_ed55_8ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    k ^= k >> 33;
    k
}

/// Generate four base hash values from key data using Murmur3.
fn base_hashes(data: &[u8]) -> [u64; 4] {
    let (h1, h2) = murmur3_x64_128(data, 0);

    let mut data_with_one: Vec<u8> = Vec::with_capacity(data.len() + 1);
    data_with_one.extend_from_slice(data);
    data_with_one.push(1);

    let (h3, h4) = murmur3_x64_128(&data_with_one, 0);

    [h1, h2, h3, h4]
}

/// Calculate the ith hash location.
fn location(h: &[u64; 4], i: usize, m: usize) -> usize {
    let ii = i as u64;
    let base = h[i % 2];
    let inner = (i + (i % 2)) % 4;
    let hash_idx = 2 + (inner / 2);
    let mult = h[hash_idx];
    let loc = base.wrapping_add(ii.wrapping_mul(mult));
    (loc % m as u64) as usize
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_add_test() {
        let mut filter = BloomFilter::new();
        let key = b"hello world";
        assert!(!filter.test(key));
        filter.add(key);
        assert!(filter.test(key));
    }

    #[test]
    fn test_merge() {
        let mut filter1 = BloomFilter::new();
        let mut filter2 = BloomFilter::new();
        filter1.add(b"key1");
        filter2.add(b"key2");
        filter1.merge(&filter2);
        assert!(filter1.test(b"key1"));
        assert!(filter1.test(b"key2"));
    }

    #[test]
    fn test_encode_decode() {
        let mut filter = BloomFilter::new();
        filter.add(b"test key");
        filter.add(b"another key");

        let mut encoded = Vec::new();
        filter.encode(&mut encoded);
        let decoded = BloomFilter::decode(&encoded).unwrap();
        assert_eq!(filter, decoded);
    }

    #[test]
    fn test_known_values() {
        // Must match ironwood's test for interop verification
        let key = [42u8; 32];
        let mut filter = BloomFilter::new();
        filter.add(&key);
        let expected = hex::decode("fdbfffbfff7ffe7ffffffffcffffffff0000000000000000000000000000000020000000000000000000000000080000200000000000000000000000000080000000200000000000020000000000000000020000000000000200000000000000").unwrap();
        let expected_filter = BloomFilter::decode(&expected).unwrap();
        assert_eq!(filter, expected_filter);
    }

    #[cfg(feature = "transit")]
    #[test]
    fn transit_send_bloom_merges_on_tree_except_target_and_marked() {
        let our_key = [0u8; 32];
        let peer_a = [1u8; 32];
        let peer_b = [2u8; 32];
        let peer_c = [3u8; 32];
        let key_in_a = [0xAAu8; 32];
        let key_in_b = [0xBBu8; 32];
        let key_in_c = [0xCCu8; 32];

        let mut blooms = LeafBlooms::new(None);
        for k in [peer_a, peer_b, peer_c] {
            blooms.add_peer(k);
        }

        let mut recv = BloomFilter::new();
        recv.add(&key_in_a);
        blooms.handle_bloom(&peer_a, recv);
        let mut recv = BloomFilter::new();
        recv.add(&key_in_b);
        blooms.handle_bloom(&peer_b, recv);
        let mut recv = BloomFilter::new();
        recv.add(&key_in_c);
        blooms.handle_bloom(&peer_c, recv);

        // a = parent, b = child, c = off-tree
        blooms.update_on_tree(&our_key, &peer_a, &[peer_b]);
        blooms.set_no_redistribute(&peer_b, true);

        // Bloom for c: own key + a's recv; b excluded (no_redistribute).
        let bloom = blooms.compute_send_bloom(&peer_c, &our_key);
        assert!(bloom.test(&our_key));
        assert!(bloom.test(&key_in_a));
        assert!(!bloom.test(&key_in_b), "no_redistribute peer keys leaked");
        assert!(!bloom.test(&key_in_c), "off-tree peer keys leaked");

        // Bloom for a (the parent): b marked, c off-tree → only own key.
        let bloom = blooms.compute_send_bloom(&peer_a, &our_key);
        assert!(bloom.test(&our_key));
        assert!(!bloom.test(&key_in_a), "target's own keys echoed back");
        assert!(!bloom.test(&key_in_b));

        // Unmark b: its keys now appear in the bloom for a.
        blooms.set_no_redistribute(&peer_b, false);
        let bloom = blooms.compute_send_bloom(&peer_a, &our_key);
        assert!(bloom.test(&key_in_b));

        // Dropping b off the tree yields a blank filter to send to it.
        let blanks = blooms.update_on_tree(&our_key, &peer_a, &[]);
        assert_eq!(blanks.len(), 1);
        assert_eq!(blanks[0].0, peer_b);
        assert_eq!(blanks[0].1.count_ones(), 0);
    }

    #[test]
    fn test_false_positive_rate() {
        let mut filter = BloomFilter::new();
        for i in 0..1000u32 {
            filter.add(&i.to_be_bytes());
        }
        for i in 0..1000u32 {
            assert!(filter.test(&i.to_be_bytes()));
        }
        let mut fps = 0;
        for i in 1000..2000u32 {
            if filter.test(&i.to_be_bytes()) {
                fps += 1;
            }
        }
        let fp_rate = fps as f64 / 1000.0;
        assert!(fp_rate < 0.05, "FP rate {} too high", fp_rate);
    }
}
