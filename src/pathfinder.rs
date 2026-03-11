//! Path discovery and caching for the leaf node.
//!
//! Handles the path lookup protocol:
//! - **PathLookup**: multicast to peers whose bloom filters match the destination
//! - **PathNotify**: response containing signed coordinates
//! - **PathBroken**: invalidate a cached path
//!
//! Uses tick-based timing (caller provides monotonic `u64` timestamps in ms)
//! instead of `std::time::Instant` for no_std compatibility.

use alloc::vec::Vec;
use crate::crypto::{Crypto, PublicKey, Sig};
use crate::wire::{self, PeerPort};

/// Default max cached paths.
const DEFAULT_MAX_PATHS: usize = 16;

/// Default max pending rumors.
const DEFAULT_MAX_RUMORS: usize = 16;

// ---------------------------------------------------------------------------
// Our own signed path info
// ---------------------------------------------------------------------------

/// Our signed path info, advertised in PathNotify responses.
#[derive(Clone, Debug)]
pub struct OwnPathInfo {
    pub seq: u64,
    pub path: Vec<PeerPort>,
    pub sig: Sig,
}

impl OwnPathInfo {
    pub fn new() -> Self {
        Self {
            seq: 0,
            path: Vec::new(),
            sig: [0u8; 64],
        }
    }

    /// Compute the bytes that are signed: `seq(uvarint) || path(zero-terminated)`.
    pub fn bytes_for_sig(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::encode_uvarint(&mut out, self.seq);
        wire::encode_path(&mut out, &self.path);
        out
    }

    /// Sign with our private key.
    pub fn sign(&mut self, crypto: &Crypto) {
        let bytes = self.bytes_for_sig();
        self.sig = crypto.sign(&bytes);
    }

    /// Check content equality (ignoring signature).
    pub fn content_equal(&self, other: &OwnPathInfo) -> bool {
        self.seq == other.seq && self.path == other.path
    }
}

// ---------------------------------------------------------------------------
// Cached path to a destination
// ---------------------------------------------------------------------------

/// Cached path information for a known destination.
#[derive(Clone, Debug)]
struct PathEntry {
    /// Tree coordinates to the destination.
    path: Vec<PeerPort>,
    /// Sequence number from the destination's PathNotify.
    seq: u64,
    /// Tick (ms) when we last sent a lookup for this destination.
    req_tick: u64,
    /// Tick (ms) when this path was last refreshed.
    refresh_tick: u64,
    /// Whether this path is broken (awaiting new PathNotify).
    broken: bool,
}

// ---------------------------------------------------------------------------
// Pending lookup (rumor)
// ---------------------------------------------------------------------------

/// A pending lookup for a destination we don't have a path to yet.
#[derive(Clone, Debug)]
struct RumorEntry {
    /// Tick (ms) when we last sent a lookup (None = never sent).
    send_tick: Option<u64>,
    /// Tick (ms) when this rumor was created.
    created_tick: u64,
}

// ---------------------------------------------------------------------------
// LeafPathfinder
// ---------------------------------------------------------------------------

/// Path discovery and caching for a leaf node.
///
/// Bounded storage: at most `max_paths` cached paths and `max_rumors` pending lookups.
/// Uses tick-based timing for no_std compatibility.
pub struct LeafPathfinder {
    /// Our own signed path info.
    pub info: OwnPathInfo,
    /// Known paths (key → entry). Bounded.
    paths: Vec<(PublicKey, PathEntry)>,
    /// Pending lookups indexed by transformed key. Bounded.
    rumors: Vec<(PublicKey, RumorEntry)>,
    /// Capacity limits.
    max_paths: usize,
    max_rumors: usize,
}

impl LeafPathfinder {
    pub fn new(crypto: &Crypto) -> Self {
        let mut info = OwnPathInfo::new();
        info.sign(crypto);
        Self {
            info,
            paths: Vec::new(),
            rumors: Vec::new(),
            max_paths: DEFAULT_MAX_PATHS,
            max_rumors: DEFAULT_MAX_RUMORS,
        }
    }

    /// Create with custom capacity limits.
    pub fn with_capacity(crypto: &Crypto, max_paths: usize, max_rumors: usize) -> Self {
        let mut pf = Self::new(crypto);
        pf.max_paths = max_paths;
        pf.max_rumors = max_rumors;
        pf
    }

    // -----------------------------------------------------------------------
    // Path cache
    // -----------------------------------------------------------------------

    /// Get the cached path for a destination (returns None if broken).
    pub fn get_path(&self, dest: &PublicKey) -> Option<&[PeerPort]> {
        self.paths
            .iter()
            .find(|(k, _)| k == dest)
            .filter(|(_, e)| !e.broken)
            .map(|(_, e)| e.path.as_slice())
    }

    /// Check if a path exists (even if broken).
    pub fn has_path(&self, dest: &PublicKey) -> bool {
        self.paths.iter().any(|(k, _)| k == dest)
    }

    /// Number of cached paths.
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }

    /// Number of pending rumors.
    pub fn rumor_count(&self) -> usize {
        self.rumors.len()
    }

    // -----------------------------------------------------------------------
    // Lookup throttling
    // -----------------------------------------------------------------------

    /// Check if a lookup to this destination should be throttled.
    ///
    /// `now_ms`: current monotonic time in milliseconds.
    /// `throttle_ms`: minimum interval between lookups.
    pub fn should_throttle_lookup(
        &self,
        dest: &PublicKey,
        now_ms: u64,
        throttle_ms: u64,
    ) -> bool {
        self.paths
            .iter()
            .find(|(k, _)| k == dest)
            .map_or(false, |(_, e)| now_ms.saturating_sub(e.req_tick) < throttle_ms)
    }

    /// Record that we sent a lookup for this destination.
    pub fn mark_lookup_sent(&mut self, dest: &PublicKey, now_ms: u64) {
        if let Some(entry) = self.paths.iter_mut().find(|(k, _)| k == dest) {
            entry.1.req_tick = now_ms;
        }
    }

    /// Check if a rumor lookup should be throttled.
    pub fn should_throttle_rumor(
        &self,
        xformed_dest: &PublicKey,
        now_ms: u64,
        throttle_ms: u64,
    ) -> bool {
        self.rumors
            .iter()
            .find(|(k, _)| k == xformed_dest)
            .map_or(false, |(_, r)| {
                r.send_tick
                    .map_or(false, |t| now_ms.saturating_sub(t) < throttle_ms)
            })
    }

    // -----------------------------------------------------------------------
    // Rumors
    // -----------------------------------------------------------------------

    /// Get or create a rumor for a transformed destination key.
    /// Returns true if a new rumor was created.
    pub fn ensure_rumor(&mut self, xformed_dest: PublicKey, now_ms: u64) -> bool {
        if self.rumors.iter().any(|(k, _)| *k == xformed_dest) {
            return false;
        }
        // Evict oldest if at capacity
        if self.rumors.len() >= self.max_rumors {
            // Remove the oldest rumor (by created_tick)
            if let Some(pos) = self
                .rumors
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, r))| r.created_tick)
                .map(|(i, _)| i)
            {
                self.rumors.swap_remove(pos);
            }
        }
        self.rumors.push((
            xformed_dest,
            RumorEntry {
                send_tick: None,
                created_tick: now_ms,
            },
        ));
        true
    }

    /// Record that a rumor lookup was sent.
    pub fn mark_rumor_sent(&mut self, xformed_dest: &PublicKey, now_ms: u64) {
        if let Some(entry) = self.rumors.iter_mut().find(|(k, _)| k == xformed_dest) {
            entry.1.send_tick = Some(now_ms);
        }
    }

    /// Check if a rumor exists for this transformed key.
    pub fn has_rumor(&self, xformed_dest: &PublicKey) -> bool {
        self.rumors.iter().any(|(k, _)| k == xformed_dest)
    }

    // -----------------------------------------------------------------------
    // PathNotify handling
    // -----------------------------------------------------------------------

    /// Process a path notification response.
    ///
    /// `source`: the node that sent the notification (their public key).
    /// `xformed_source`: transformed key for rumor lookup.
    /// `notify_seq`: sequence number from the notification.
    /// `notify_path`: tree coordinates from the notification.
    /// `now_ms`: current monotonic time in milliseconds.
    ///
    /// Returns true if the path was accepted (new or updated).
    pub fn accept_notify(
        &mut self,
        source: PublicKey,
        xformed_source: PublicKey,
        notify_seq: u64,
        notify_path: Vec<PeerPort>,
        now_ms: u64,
    ) -> bool {
        // Check existing path
        if let Some(entry) = self.paths.iter_mut().find(|(k, _)| *k == source) {
            let info = &mut entry.1;
            if notify_seq <= info.seq {
                return false; // stale
            }
            // Storm prevention: don't update working path with same coords
            if !info.broken && info.path == notify_path {
                return false;
            }
            info.path = notify_path;
            info.seq = notify_seq;
            info.broken = false;
            info.refresh_tick = now_ms;
            return true;
        }

        // New path — must have a rumor
        if !self.rumors.iter().any(|(k, _)| *k == xformed_source) {
            return false;
        }

        // Evict oldest path if at capacity
        if self.paths.len() >= self.max_paths {
            if let Some(pos) = self
                .paths
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, e))| e.refresh_tick)
                .map(|(i, _)| i)
            {
                self.paths.swap_remove(pos);
            }
        }

        self.paths.push((
            source,
            PathEntry {
                path: notify_path,
                seq: notify_seq,
                req_tick: now_ms,
                refresh_tick: now_ms,
                broken: false,
            },
        ));

        true
    }

    // -----------------------------------------------------------------------
    // PathBroken handling
    // -----------------------------------------------------------------------

    /// Mark a path as broken (received PathBroken for this destination).
    pub fn handle_broken(&mut self, dest: &PublicKey) {
        if let Some(entry) = self.paths.iter_mut().find(|(k, _)| k == dest) {
            entry.1.broken = true;
        }
    }

    /// Reset the timeout for a destination (called when we receive traffic from them).
    pub fn reset_timeout(&mut self, key: &PublicKey, now_ms: u64) {
        if let Some(entry) = self.paths.iter_mut().find(|(k, _)| k == key) {
            if !entry.1.broken {
                entry.1.refresh_tick = now_ms;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Cleanup
    // -----------------------------------------------------------------------

    /// Clean up expired paths and rumors.
    ///
    /// `now_ms`: current monotonic time in milliseconds.
    /// `timeout_ms`: entries older than this are removed.
    pub fn cleanup_expired(&mut self, now_ms: u64, timeout_ms: u64) {
        self.paths
            .retain(|(_, e)| now_ms.saturating_sub(e.refresh_tick) < timeout_ms);
        self.rumors.retain(|(_, r)| {
            let base = r.send_tick.unwrap_or(r.created_tick);
            now_ms.saturating_sub(base) < timeout_ms
        });
    }

    // -----------------------------------------------------------------------
    // Own path info management
    // -----------------------------------------------------------------------

    /// Update our own path info if coords changed, sign if needed.
    ///
    /// `seq`: current timestamp/sequence (e.g., seconds since epoch).
    /// `path`: our current tree coordinates.
    /// `crypto`: for signing.
    ///
    /// Returns true if the info was updated.
    pub fn update_own_info(
        &mut self,
        seq: u64,
        path: Vec<PeerPort>,
        crypto: &Crypto,
    ) -> bool {
        let candidate = OwnPathInfo {
            seq,
            path,
            sig: [0u8; 64],
        };
        if self.info.content_equal(&candidate) {
            return false;
        }
        self.info.seq = candidate.seq;
        self.info.path = candidate.path;
        self.info.sign(crypto);
        true
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

    #[test]
    fn new_pathfinder() {
        let crypto = make_crypto();
        let pf = LeafPathfinder::new(&crypto);
        assert_eq!(pf.path_count(), 0);
        assert_eq!(pf.rumor_count(), 0);
    }

    #[test]
    fn own_path_info_sign_verify() {
        let crypto = make_crypto();
        let mut info = OwnPathInfo::new();
        info.seq = 42;
        info.path = vec![1, 2, 3];
        info.sign(&crypto);

        let bytes = info.bytes_for_sig();
        assert!(Crypto::verify(&crypto.public_key, &bytes, &info.sig));
    }

    #[test]
    fn accept_notify_requires_rumor() {
        let crypto = make_crypto();
        let mut pf = LeafPathfinder::new(&crypto);
        let source = [1u8; 32];
        let xformed = [1u8; 32];

        // No rumor → rejected
        assert!(!pf.accept_notify(source, xformed, 1, vec![1, 2], 1000));
        assert_eq!(pf.path_count(), 0);

        // Create rumor → accepted
        pf.ensure_rumor(xformed, 900);
        assert!(pf.accept_notify(source, xformed, 1, vec![1, 2], 1000));
        assert_eq!(pf.path_count(), 1);
        assert_eq!(pf.get_path(&source), Some(&[1u64, 2][..]));
    }

    #[test]
    fn accept_notify_rejects_stale_seq() {
        let crypto = make_crypto();
        let mut pf = LeafPathfinder::new(&crypto);
        let source = [1u8; 32];
        let xformed = [1u8; 32];

        pf.ensure_rumor(xformed, 0);
        assert!(pf.accept_notify(source, xformed, 5, vec![1, 2], 100));

        // Same seq → rejected
        assert!(!pf.accept_notify(source, xformed, 5, vec![3, 4], 200));

        // Lower seq → rejected
        assert!(!pf.accept_notify(source, xformed, 3, vec![3, 4], 300));

        // Higher seq with different path → accepted
        assert!(pf.accept_notify(source, xformed, 6, vec![3, 4], 400));
        assert_eq!(pf.get_path(&source), Some(&[3u64, 4][..]));
    }

    #[test]
    fn storm_prevention_same_coords() {
        let crypto = make_crypto();
        let mut pf = LeafPathfinder::new(&crypto);
        let source = [1u8; 32];
        let xformed = [1u8; 32];

        pf.ensure_rumor(xformed, 0);
        assert!(pf.accept_notify(source, xformed, 1, vec![1, 2], 100));

        // Same path, higher seq, NOT broken → rejected (storm prevention)
        assert!(!pf.accept_notify(source, xformed, 2, vec![1, 2], 200));

        // Mark as broken → same path now accepted
        pf.handle_broken(&source);
        assert!(pf.accept_notify(source, xformed, 3, vec![1, 2], 300));
    }

    #[test]
    fn handle_broken_and_get_path() {
        let crypto = make_crypto();
        let mut pf = LeafPathfinder::new(&crypto);
        let dest = [1u8; 32];

        pf.ensure_rumor(dest, 0);
        pf.accept_notify(dest, dest, 1, vec![1, 2], 100);

        assert!(pf.get_path(&dest).is_some());
        pf.handle_broken(&dest);
        assert!(pf.get_path(&dest).is_none()); // broken → not returned
        assert!(pf.has_path(&dest)); // but entry still exists
    }

    #[test]
    fn throttle_lookup() {
        let crypto = make_crypto();
        let mut pf = LeafPathfinder::new(&crypto);
        let dest = [1u8; 32];

        // No path → no throttle
        assert!(!pf.should_throttle_lookup(&dest, 1000, 500));

        // Create path
        pf.ensure_rumor(dest, 0);
        pf.accept_notify(dest, dest, 1, vec![1], 1000);

        // Mark lookup sent at t=1000
        pf.mark_lookup_sent(&dest, 1000);

        // At t=1200 (200ms later), throttle_ms=500 → throttled
        assert!(pf.should_throttle_lookup(&dest, 1200, 500));

        // At t=1600 (600ms later), throttle_ms=500 → not throttled
        assert!(!pf.should_throttle_lookup(&dest, 1600, 500));
    }

    #[test]
    fn throttle_rumor() {
        let crypto = make_crypto();
        let mut pf = LeafPathfinder::new(&crypto);
        let xformed = [2u8; 32];

        // No rumor → no throttle
        assert!(!pf.should_throttle_rumor(&xformed, 1000, 500));

        // Create rumor (never sent) → no throttle
        pf.ensure_rumor(xformed, 900);
        assert!(!pf.should_throttle_rumor(&xformed, 1000, 500));

        // Mark sent → throttled
        pf.mark_rumor_sent(&xformed, 1000);
        assert!(pf.should_throttle_rumor(&xformed, 1200, 500));
        assert!(!pf.should_throttle_rumor(&xformed, 1600, 500));
    }

    #[test]
    fn cleanup_expired() {
        let crypto = make_crypto();
        let mut pf = LeafPathfinder::new(&crypto);

        let dest1 = [1u8; 32];
        let dest2 = [2u8; 32];

        pf.ensure_rumor(dest1, 100);
        pf.accept_notify(dest1, dest1, 1, vec![1], 100);

        pf.ensure_rumor(dest2, 500);
        pf.accept_notify(dest2, dest2, 1, vec![2], 500);

        // At t=700, timeout=300: dest1 (refreshed at 100) expires, dest2 (at 500) survives
        pf.cleanup_expired(700, 300);
        assert_eq!(pf.path_count(), 1);
        assert!(pf.get_path(&dest2).is_some());
        assert!(pf.get_path(&dest1).is_none());
    }

    #[test]
    fn bounded_capacity() {
        let crypto = make_crypto();
        let mut pf = LeafPathfinder::with_capacity(&crypto, 3, 3);

        // Fill paths
        for i in 0..4u8 {
            let key = [i; 32];
            pf.ensure_rumor(key, i as u64 * 100);
            pf.accept_notify(key, key, 1, vec![i as u64], i as u64 * 100);
        }

        // Should be bounded to max_paths=3
        assert_eq!(pf.path_count(), 3);

        // Fill rumors
        for i in 10..14u8 {
            pf.ensure_rumor([i; 32], i as u64 * 100);
        }

        // Should be bounded to max_rumors=3
        assert_eq!(pf.rumor_count(), 3);
    }

    #[test]
    fn update_own_info() {
        let crypto = make_crypto();
        let mut pf = LeafPathfinder::new(&crypto);

        // Initial update
        assert!(pf.update_own_info(1, vec![1, 2], &crypto));
        assert_eq!(pf.info.seq, 1);
        assert_eq!(pf.info.path, vec![1, 2]);

        // Verify signature
        let bytes = pf.info.bytes_for_sig();
        assert!(Crypto::verify(&crypto.public_key, &bytes, &pf.info.sig));

        // Same content → no update
        assert!(!pf.update_own_info(1, vec![1, 2], &crypto));

        // Different content → update
        assert!(pf.update_own_info(2, vec![3, 4], &crypto));
        assert_eq!(pf.info.seq, 2);
        assert_eq!(pf.info.path, vec![3, 4]);
    }
}
