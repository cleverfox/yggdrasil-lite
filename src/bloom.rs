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
}

impl PeerBloomInfo {
    pub fn new() -> Self {
        Self {
            send: BloomFilter::new(),
            recv: BloomFilter::new(),
            seq: 0,
            on_tree: false,
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

    /// Update on-tree status. For a leaf node, only the parent is on-tree.
    pub fn set_parent(&mut self, parent_key: &PublicKey) {
        for (k, info) in &mut self.peers {
            info.on_tree = k == parent_key;
        }
    }

    /// Compute the bloom filter to send to a given peer.
    /// For a leaf node: just our own key (we have no children to merge).
    pub fn compute_send_bloom(&self, _target_key: &PublicKey, our_key: &PublicKey) -> BloomFilter {
        let mut b = BloomFilter::new();
        let xformed = self.x_key(our_key);
        b.add(&xformed);
        // A leaf has no on-tree children, so no peer recv blooms to merge
        // (our parent's recv bloom would be for the opposite direction)
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
    pub fn get_multicast_targets(&self, from_key: &PublicKey, dest_key: &PublicKey) -> Vec<PublicKey> {
        let xformed = self.x_key(dest_key);
        let mut targets = Vec::new();
        for (k, info) in &self.peers {
            if !info.on_tree || k == from_key {
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
