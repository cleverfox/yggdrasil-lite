//! Encrypted session state machine.
//!
//! Implements Init/Ack/Traffic handshake with 3-tier key ratcheting
//! and forward secrecy using XSalsa20-Poly1305 (NaCl box).
//!
//! Wire-compatible with ironwood's encrypted sessions.
//!
//! Adapted for no_std: RNG is passed as parameter, timing uses tick-based u64.

use alloc::vec::Vec;
use crypto_box::SalsaBox;
use rand_core::CryptoRngCore;

use crate::crypto::{
    box_open, box_open_precomputed, box_seal, box_seal_precomputed,
    ed25519_public_to_curve25519, make_salsa_box, new_box_keys, Crypto, CurvePrivateKey,
    CurvePublicKey, PublicKey, BOX_OVERHEAD,
};
use crate::wire;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Session timeout in milliseconds (60 seconds).
const SESSION_TIMEOUT_MS: u64 = 60_000;

/// Key rotation cooldown in milliseconds (60 seconds).
const ROTATION_COOLDOWN_MS: u64 = 60_000;

/// Session message types.
const SESSION_TYPE_DUMMY: u8 = 0;
const SESSION_TYPE_INIT: u8 = 1;
const SESSION_TYPE_ACK: u8 = 2;
const SESSION_TYPE_TRAFFIC: u8 = 3;

/// Minimum traffic overhead: type(1) + varint(1)*3 + box_overhead(16) + nextPub(32)
const SESSION_TRAFFIC_OVERHEAD_MIN: usize = 1 + 1 + 1 + 1 + BOX_OVERHEAD + 32;

/// Init message size: type(1) + ephemeral(32) + encrypted(sig(64)+current(32)+next(32)+keySeq(8)+seq(8)+overhead(16))
const SESSION_INIT_SIZE: usize = 1 + 32 + BOX_OVERHEAD + 64 + 32 + 32 + 8 + 8;

/// Maximum number of sessions for bounded storage.
const DEFAULT_MAX_SESSIONS: usize = 16;

/// Maximum number of pending buffers.
const DEFAULT_MAX_BUFFERS: usize = 8;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Session errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// Bad key (conversion failed).
    BadKey,
    /// Encoding error.
    Encode,
    /// Decoding error (bad format or decryption failed).
    Decode,
    /// Bad signature on init/ack message.
    BadSignature,
}

/// Action needed after receiving a traffic packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvAction {
    /// Drop the packet silently.
    Drop,
    /// Send a new init to resync.
    SendInit,
}

// ---------------------------------------------------------------------------
// SessionInit — handshake init/ack message
// ---------------------------------------------------------------------------

/// Handshake init/ack message content.
#[derive(Clone, Debug)]
pub struct SessionInit {
    pub current: CurvePublicKey,
    pub next: CurvePublicKey,
    pub key_seq: u64,
    pub seq: u64,
}

impl SessionInit {
    pub fn new(current: &CurvePublicKey, next: &CurvePublicKey, key_seq: u64, seq: u64) -> Self {
        Self {
            current: *current,
            next: *next,
            key_seq,
            seq,
        }
    }

    /// Encrypt an init message from our Ed25519 key to the recipient's Ed25519 key.
    ///
    /// Wire format: `[type(1)][ephemeral_pub(32)][encrypted_payload]`
    /// Encrypted payload: `[sig(64)][current(32)][next(32)][keySeq(8)][seq(8)]`
    pub fn encrypt(
        &self,
        our_ed_priv: &ed25519_dalek::SigningKey,
        to_ed_pub: &PublicKey,
        msg_type: u8,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, SessionError> {
        // Generate ephemeral Curve25519 keypair
        let (from_pub, from_priv) = new_box_keys(rng);

        // Convert recipient's Ed25519 public key to Curve25519
        let to_box = ed25519_public_to_curve25519(to_ed_pub).map_err(|_| SessionError::BadKey)?;

        // Build signature bytes: [fromPub][current][next][keySeq(8)][seq(8)]
        let mut sig_bytes = Vec::with_capacity(32 + 32 + 32 + 8 + 8);
        sig_bytes.extend_from_slice(&from_pub);
        sig_bytes.extend_from_slice(&self.current);
        sig_bytes.extend_from_slice(&self.next);
        sig_bytes.extend_from_slice(&self.key_seq.to_be_bytes());
        sig_bytes.extend_from_slice(&self.seq.to_be_bytes());

        // Sign with our Ed25519 key
        let sig = Crypto::sign_with_key(our_ed_priv, &sig_bytes);

        // Build payload: [sig(64)][current(32)][next(32)][keySeq(8)][seq(8)]
        let mut payload = Vec::with_capacity(64 + 32 + 32 + 8 + 8);
        payload.extend_from_slice(&sig);
        payload.extend_from_slice(&self.current);
        payload.extend_from_slice(&self.next);
        payload.extend_from_slice(&self.key_seq.to_be_bytes());
        payload.extend_from_slice(&self.seq.to_be_bytes());

        // Encrypt with ephemeral DH
        let ciphertext = box_seal(&payload, 0, &to_box, &from_priv)
            .map_err(|_| SessionError::Encode)?;

        // Assemble: [type][fromPub][ciphertext]
        let mut data = Vec::with_capacity(1 + 32 + ciphertext.len());
        data.push(msg_type);
        data.extend_from_slice(&from_pub);
        data.extend_from_slice(&ciphertext);

        Ok(data)
    }

    /// Decrypt an init/ack message.
    pub fn decrypt(
        data: &[u8],
        our_curve_priv: &CurvePrivateKey,
        from_ed_pub: &PublicKey,
    ) -> Result<Self, SessionError> {
        if data.len() != SESSION_INIT_SIZE {
            return Err(SessionError::Decode);
        }

        // Extract ephemeral public key
        let mut from_box = [0u8; 32];
        from_box.copy_from_slice(&data[1..33]);

        // Decrypt payload
        let ciphertext = &data[33..];
        let payload =
            box_open(ciphertext, 0, &from_box, our_curve_priv).map_err(|_| SessionError::Decode)?;

        if payload.len() != 64 + 32 + 32 + 8 + 8 {
            return Err(SessionError::Decode);
        }

        // Parse payload
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&payload[0..64]);
        let mut current = [0u8; 32];
        current.copy_from_slice(&payload[64..96]);
        let mut next = [0u8; 32];
        next.copy_from_slice(&payload[96..128]);
        let key_seq = u64::from_be_bytes(payload[128..136].try_into().map_err(|_| SessionError::Decode)?);
        let seq = u64::from_be_bytes(payload[136..144].try_into().map_err(|_| SessionError::Decode)?);

        // Verify signature
        let mut sig_bytes = Vec::with_capacity(32 + 32 + 32 + 8 + 8);
        sig_bytes.extend_from_slice(&from_box);
        sig_bytes.extend_from_slice(&current);
        sig_bytes.extend_from_slice(&next);
        sig_bytes.extend_from_slice(&key_seq.to_be_bytes());
        sig_bytes.extend_from_slice(&seq.to_be_bytes());

        if !Crypto::verify(from_ed_pub, &sig_bytes, &sig) {
            return Err(SessionError::BadSignature);
        }

        Ok(Self {
            current,
            next,
            key_seq,
            seq,
        })
    }
}

// ---------------------------------------------------------------------------
// SessionInfo — active session with key ratcheting
// ---------------------------------------------------------------------------

/// An active encrypted session with a remote peer.
pub struct SessionInfo {
    // Remote state
    pub seq: u64,
    pub remote_key_seq: u64,
    pub current: CurvePublicKey,
    pub next: CurvePublicKey,

    // Local key material (3-tier ratcheting)
    pub local_key_seq: u64,
    recv_priv: CurvePrivateKey,
    recv_pub: CurvePublicKey,
    recv_shared: SalsaBox,
    recv_nonce: u64,

    send_priv: CurvePrivateKey,
    send_pub: CurvePublicKey,
    send_shared: SalsaBox,
    send_nonce: u64,

    next_priv: CurvePrivateKey,
    next_pub: CurvePublicKey,

    next_send_shared: SalsaBox,
    next_send_nonce: u64,
    next_recv_shared: SalsaBox,
    next_recv_nonce: u64,

    // Timing (tick-based, ms)
    last_activity_tick: u64,
    rotated_tick: Option<u64>,
}

impl SessionInfo {
    /// Create a new session with the given remote keys.
    pub fn new(
        current: CurvePublicKey,
        next: CurvePublicKey,
        seq: u64,
        now_tick: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let (recv_pub, recv_priv) = new_box_keys(rng);
        let (send_pub, send_priv) = new_box_keys(rng);
        let (next_pub, next_priv) = new_box_keys(rng);

        let recv_shared = make_salsa_box(&current, &recv_priv);
        let send_shared = make_salsa_box(&current, &send_priv);
        let next_send_shared = make_salsa_box(&next, &send_priv);
        let next_recv_shared = make_salsa_box(&next, &recv_priv);

        Self {
            seq: seq.wrapping_sub(1),
            remote_key_seq: 0,
            current,
            next,
            local_key_seq: 0,
            recv_priv,
            recv_pub,
            recv_shared,
            recv_nonce: 0,
            send_priv,
            send_pub,
            send_shared,
            send_nonce: 0,
            next_priv,
            next_pub,
            next_send_shared,
            next_send_nonce: 0,
            next_recv_shared,
            next_recv_nonce: 0,
            last_activity_tick: now_tick,
            rotated_tick: None,
        }
    }

    /// Recompute all shared secrets after key changes.
    fn fix_shared(&mut self, recv_nonce: u64, send_nonce: u64) {
        self.recv_shared = make_salsa_box(&self.current, &self.recv_priv);
        self.send_shared = make_salsa_box(&self.current, &self.send_priv);
        self.next_send_shared = make_salsa_box(&self.next, &self.send_priv);
        self.next_recv_shared = make_salsa_box(&self.next, &self.recv_priv);
        self.next_send_nonce = 0;
        self.next_recv_nonce = 0;
        self.recv_nonce = recv_nonce;
        self.send_nonce = send_nonce;
    }

    /// Handle an init/ack update: ratchet keys forward.
    pub fn handle_update(
        &mut self,
        init: &SessionInit,
        now_tick: u64,
        rng: &mut impl CryptoRngCore,
    ) {
        self.current = init.current;
        self.next = init.next;
        self.seq = init.seq;
        self.remote_key_seq = init.key_seq;

        // Ratchet: recv = send, send = next, new next
        self.recv_pub = self.send_pub;
        self.recv_priv = self.send_priv;
        self.send_pub = self.next_pub;
        self.send_priv = self.next_priv;
        let (new_next_pub, new_next_priv) = new_box_keys(rng);
        self.next_pub = new_next_pub;
        self.next_priv = new_next_priv;
        self.local_key_seq += 1;

        self.fix_shared(0, self.send_nonce);
        self.last_activity_tick = now_tick;
    }

    /// Encrypt and produce a traffic message.
    ///
    /// Wire: `[type(1)][varint(localKeySeq)][varint(remoteKeySeq)][varint(sendNonce)][encrypted([nextPub(32)][msg])]`
    pub fn do_send(
        &mut self,
        msg: &[u8],
        now_tick: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, SessionError> {
        self.send_nonce += 1;

        if self.send_nonce == 0 {
            // Nonce overflow: ratchet
            self.recv_pub = self.send_pub;
            self.recv_priv = self.send_priv;
            self.send_pub = self.next_pub;
            self.send_priv = self.next_priv;
            let (np, nk) = new_box_keys(rng);
            self.next_pub = np;
            self.next_priv = nk;
            self.local_key_seq += 1;
            self.fix_shared(0, 0);
        }

        let mut bs = Vec::with_capacity(SESSION_TRAFFIC_OVERHEAD_MIN + msg.len());
        bs.push(SESSION_TYPE_TRAFFIC);
        wire::encode_uvarint(&mut bs, self.local_key_seq);
        wire::encode_uvarint(&mut bs, self.remote_key_seq);
        wire::encode_uvarint(&mut bs, self.send_nonce);

        // Inner: [nextPub(32)][msg]
        let mut inner = Vec::with_capacity(32 + msg.len());
        inner.extend_from_slice(&self.next_pub);
        inner.extend_from_slice(msg);

        let ciphertext = box_seal_precomputed(&inner, self.send_nonce, &self.send_shared)
            .map_err(|_| SessionError::Encode)?;
        bs.extend_from_slice(&ciphertext);

        self.last_activity_tick = now_tick;
        Ok(bs)
    }

    /// Decrypt an incoming traffic message.
    pub fn do_recv(
        &mut self,
        msg: &[u8],
        now_tick: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, RecvAction> {
        if msg.len() < SESSION_TRAFFIC_OVERHEAD_MIN || msg[0] != SESSION_TYPE_TRAFFIC {
            return Err(RecvAction::Drop);
        }

        let mut offset = 1;
        let (remote_key_seq, len) =
            wire::decode_uvarint(&msg[offset..]).ok_or(RecvAction::Drop)?;
        offset += len;
        let (local_key_seq, len) =
            wire::decode_uvarint(&msg[offset..]).ok_or(RecvAction::Drop)?;
        offset += len;
        let (nonce, len) = wire::decode_uvarint(&msg[offset..]).ok_or(RecvAction::Drop)?;
        offset += len;

        let encrypted = &msg[offset..];

        let from_current = remote_key_seq == self.remote_key_seq;
        let from_next = remote_key_seq == self.remote_key_seq + 1;
        let to_recv = local_key_seq + 1 == self.local_key_seq;
        let to_send = local_key_seq == self.local_key_seq;

        enum Case {
            CurrentToRecv,
            NextToSend,
            NextToRecv,
        }

        let case = if from_current && to_recv {
            if self.recv_nonce >= nonce {
                return Err(RecvAction::Drop);
            }
            Case::CurrentToRecv
        } else if from_next && to_send {
            if self.next_send_nonce >= nonce {
                return Err(RecvAction::Drop);
            }
            Case::NextToSend
        } else if from_next && to_recv {
            if self.next_recv_nonce >= nonce {
                return Err(RecvAction::Drop);
            }
            Case::NextToRecv
        } else {
            return Err(RecvAction::SendInit);
        };

        let shared = match case {
            Case::CurrentToRecv => &self.recv_shared,
            Case::NextToSend => &self.next_send_shared,
            Case::NextToRecv => &self.next_recv_shared,
        };

        let unboxed =
            box_open_precomputed(encrypted, nonce, shared).map_err(|_| RecvAction::SendInit)?;

        if unboxed.len() < 32 {
            return Err(RecvAction::Drop);
        }

        let mut inner_key = [0u8; 32];
        inner_key.copy_from_slice(&unboxed[..32]);
        let payload = unboxed[32..].to_vec();

        match case {
            Case::CurrentToRecv => {
                self.recv_nonce = nonce;
            }
            Case::NextToSend => {
                self.next_send_nonce = nonce;
                self.maybe_ratchet_on_recv(inner_key, nonce, now_tick, rng);
            }
            Case::NextToRecv => {
                self.next_recv_nonce = nonce;
                self.maybe_ratchet_on_recv(inner_key, nonce, now_tick, rng);
            }
        }

        self.last_activity_tick = now_tick;
        Ok(payload)
    }

    /// Possibly ratchet keys when receiving from remote's "next" key.
    fn maybe_ratchet_on_recv(
        &mut self,
        inner_key: CurvePublicKey,
        nonce: u64,
        now_tick: u64,
        rng: &mut impl CryptoRngCore,
    ) {
        let should_rotate = self
            .rotated_tick
            .map_or(true, |t| now_tick.saturating_sub(t) > ROTATION_COOLDOWN_MS);

        if should_rotate {
            self.current = self.next;
            self.next = inner_key;
            self.remote_key_seq += 1;

            self.recv_pub = self.send_pub;
            self.recv_priv = self.send_priv;
            self.send_pub = self.next_pub;
            self.send_priv = self.next_priv;
            self.local_key_seq += 1;

            let (np, nk) = new_box_keys(rng);
            self.next_pub = np;
            self.next_priv = nk;

            self.fix_shared(nonce, 0);
            self.rotated_tick = Some(now_tick);
        }
    }

    /// Check if the session has timed out.
    pub fn is_expired(&self, now_tick: u64) -> bool {
        now_tick.saturating_sub(self.last_activity_tick) > SESSION_TIMEOUT_MS
    }
}

// ---------------------------------------------------------------------------
// SessionBuffer — queued data before session is established
// ---------------------------------------------------------------------------

struct SessionBuffer {
    data: Option<Vec<u8>>,
    init: SessionInit,
    current_priv: CurvePrivateKey,
    next_priv: CurvePrivateKey,
    created_tick: u64,
}

// ---------------------------------------------------------------------------
// Actions produced by the session manager
// ---------------------------------------------------------------------------

/// Actions produced by the session manager.
#[derive(Debug)]
pub enum SessionAction {
    /// Send encrypted data to a remote peer (via traffic overlay).
    SendToRemote { dest: PublicKey, data: Vec<u8> },
    /// Deliver decrypted data to the local application.
    Deliver { source: PublicKey, data: Vec<u8> },
}

// ---------------------------------------------------------------------------
// SessionManager
// ---------------------------------------------------------------------------

/// Manages all encrypted sessions for the leaf node.
///
/// Bounded storage: at most `max_sessions` active sessions.
pub struct SessionManager {
    sessions: Vec<(PublicKey, SessionInfo)>,
    buffers: Vec<(PublicKey, SessionBuffer)>,
    max_sessions: usize,
    max_buffers: usize,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
            buffers: Vec::new(),
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_buffers: DEFAULT_MAX_BUFFERS,
        }
    }

    /// Number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Check if a session exists for a peer.
    pub fn has_session(&self, key: &PublicKey) -> bool {
        self.sessions.iter().any(|(k, _)| k == key)
    }

    fn get_session_mut(&mut self, key: &PublicKey) -> Option<&mut SessionInfo> {
        self.sessions.iter_mut().find(|(k, _)| k == key).map(|(_, s)| s)
    }

    fn insert_session(&mut self, key: PublicKey, info: SessionInfo) {
        if let Some(entry) = self.sessions.iter_mut().find(|(k, _)| *k == key) {
            entry.1 = info;
        } else {
            if self.sessions.len() >= self.max_sessions {
                // Evict least recently active
                if let Some(pos) = self
                    .sessions
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, (_, s))| s.last_activity_tick)
                    .map(|(i, _)| i)
                {
                    self.sessions.swap_remove(pos);
                }
            }
            self.sessions.push((key, info));
        }
    }

    /// Create a session from init message keys.
    fn new_session(
        &mut self,
        ed: &PublicKey,
        init: &SessionInit,
        now_tick: u64,
        rng: &mut impl CryptoRngCore,
    ) {
        let mut info = SessionInfo::new(init.current, init.next, init.seq, now_tick, rng);

        // Migrate keys from buffer if present
        if let Some(pos) = self.buffers.iter().position(|(k, _)| k == ed) {
            let (_, buf) = self.buffers.swap_remove(pos);
            info.send_pub = buf.init.current;
            info.send_priv = buf.current_priv;
            info.next_pub = buf.init.next;
            info.next_priv = buf.next_priv;
            info.fix_shared(0, 0);
        }

        self.insert_session(*ed, info);
    }

    /// Handle incoming data (dispatch by message type).
    pub fn handle_data(
        &mut self,
        from: &PublicKey,
        data: &[u8],
        our_curve_priv: &CurvePrivateKey,
        our_ed_priv: &ed25519_dalek::SigningKey,
        now_tick: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<SessionAction> {
        if data.is_empty() {
            return Vec::new();
        }
        match data[0] {
            SESSION_TYPE_DUMMY => Vec::new(),
            SESSION_TYPE_INIT => {
                match SessionInit::decrypt(data, our_curve_priv, from) {
                    Ok(init) => self.handle_init(from, &init, our_ed_priv, now_tick, rng),
                    Err(_) => Vec::new(),
                }
            }
            SESSION_TYPE_ACK => {
                match SessionInit::decrypt(data, our_curve_priv, from) {
                    Ok(ack) => self.handle_ack(from, &ack, our_ed_priv, now_tick, rng),
                    Err(_) => Vec::new(),
                }
            }
            SESSION_TYPE_TRAFFIC => self.handle_traffic(from, data, our_ed_priv, now_tick, rng),
            _ => Vec::new(),
        }
    }

    fn handle_init(
        &mut self,
        from: &PublicKey,
        init: &SessionInit,
        our_ed_priv: &ed25519_dalek::SigningKey,
        now_tick: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<SessionAction> {
        let mut actions = Vec::new();
        let had_session = self.has_session(from);

        let buffered_data = if !had_session {
            let bd = self
                .buffers
                .iter()
                .find(|(k, _)| k == from)
                .and_then(|(_, b)| b.data.clone());
            self.new_session(from, init, now_tick, rng);
            bd
        } else {
            None
        };

        if let Some(info) = self.get_session_mut(from) {
            if init.seq > info.seq {
                info.handle_update(init, now_tick, rng);
            }

            // Send ack
            let ack = SessionInit::new(&info.send_pub, &info.next_pub, info.local_key_seq, now_tick);
            if let Ok(data) = ack.encrypt(our_ed_priv, from, SESSION_TYPE_ACK, rng) {
                actions.push(SessionAction::SendToRemote {
                    dest: *from,
                    data,
                });
            }

            // Send buffered data
            if let Some(buf_data) = buffered_data {
                if let Ok(traffic) = info.do_send(&buf_data, now_tick, rng) {
                    actions.push(SessionAction::SendToRemote {
                        dest: *from,
                        data: traffic,
                    });
                }
            }
        }

        actions
    }

    fn handle_ack(
        &mut self,
        from: &PublicKey,
        ack: &SessionInit,
        _our_ed_priv: &ed25519_dalek::SigningKey,
        now_tick: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<SessionAction> {
        let mut actions = Vec::new();

        let buffered_data = if !self.has_session(from) {
            let bd = self
                .buffers
                .iter()
                .find(|(k, _)| k == from)
                .and_then(|(_, b)| b.data.clone());
            self.new_session(from, ack, now_tick, rng);
            bd
        } else {
            None
        };

        if let Some(info) = self.get_session_mut(from) {
            if ack.seq > info.seq {
                info.handle_update(ack, now_tick, rng);
            }

            if let Some(buf_data) = buffered_data {
                if let Ok(traffic) = info.do_send(&buf_data, now_tick, rng) {
                    actions.push(SessionAction::SendToRemote {
                        dest: *from,
                        data: traffic,
                    });
                }
            }
        }

        actions
    }

    fn handle_traffic(
        &mut self,
        from: &PublicKey,
        data: &[u8],
        our_ed_priv: &ed25519_dalek::SigningKey,
        now_tick: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<SessionAction> {
        let mut actions = Vec::new();

        if let Some(info) = self.get_session_mut(from) {
            match info.do_recv(data, now_tick, rng) {
                Ok(payload) => {
                    actions.push(SessionAction::Deliver {
                        source: *from,
                        data: payload,
                    });
                }
                Err(RecvAction::SendInit) => {
                    let init = SessionInit::new(
                        &info.send_pub,
                        &info.next_pub,
                        info.local_key_seq,
                        now_tick,
                    );
                    if let Ok(data) = init.encrypt(our_ed_priv, from, SESSION_TYPE_INIT, rng) {
                        actions.push(SessionAction::SendToRemote {
                            dest: *from,
                            data,
                        });
                    }
                }
                Err(RecvAction::Drop) => {}
            }
        } else {
            // Unknown sender: send ephemeral init
            let (cp, _) = new_box_keys(rng);
            let (np, _) = new_box_keys(rng);
            let init = SessionInit::new(&cp, &np, 0, now_tick);
            if let Ok(data) = init.encrypt(our_ed_priv, from, SESSION_TYPE_INIT, rng) {
                actions.push(SessionAction::SendToRemote {
                    dest: *from,
                    data,
                });
            }
        }

        actions
    }

    /// Write data to a remote peer (encrypts and sends, or buffers + init).
    pub fn write_to(
        &mut self,
        dest: &PublicKey,
        msg: &[u8],
        our_ed_priv: &ed25519_dalek::SigningKey,
        now_tick: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<SessionAction> {
        let mut actions = Vec::new();

        if let Some(info) = self.get_session_mut(dest) {
            if let Ok(traffic) = info.do_send(msg, now_tick, rng) {
                actions.push(SessionAction::SendToRemote {
                    dest: *dest,
                    data: traffic,
                });
            }
        } else {
            actions.extend(self.buffer_and_init(dest, msg, our_ed_priv, now_tick, rng));
        }

        actions
    }

    /// Buffer data and send init for a new session.
    fn buffer_and_init(
        &mut self,
        dest: &PublicKey,
        msg: &[u8],
        our_ed_priv: &ed25519_dalek::SigningKey,
        now_tick: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<SessionAction> {
        let mut actions = Vec::new();

        // Get or create buffer
        let buf_exists = self.buffers.iter().any(|(k, _)| k == dest);
        if !buf_exists {
            if self.buffers.len() >= self.max_buffers {
                // Evict oldest
                if let Some(pos) = self
                    .buffers
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, (_, b))| b.created_tick)
                    .map(|(i, _)| i)
                {
                    self.buffers.swap_remove(pos);
                }
            }
            let (current_pub, current_priv) = new_box_keys(rng);
            let (next_pub, next_priv) = new_box_keys(rng);
            self.buffers.push((
                *dest,
                SessionBuffer {
                    data: None,
                    init: SessionInit::new(&current_pub, &next_pub, 0, now_tick),
                    current_priv,
                    next_priv,
                    created_tick: now_tick,
                },
            ));
        }

        if let Some(entry) = self.buffers.iter_mut().find(|(k, _)| k == dest) {
            entry.1.data = Some(msg.to_vec());
            if let Ok(data) = entry.1.init.encrypt(our_ed_priv, dest, SESSION_TYPE_INIT, rng) {
                actions.push(SessionAction::SendToRemote {
                    dest: *dest,
                    data,
                });
            }
        }

        actions
    }

    /// Clean up expired sessions and buffers.
    pub fn cleanup_expired(&mut self, now_tick: u64) {
        self.sessions.retain(|(_, info)| !info.is_expired(now_tick));
        self.buffers
            .retain(|(_, buf)| now_tick.saturating_sub(buf.created_tick) < SESSION_TIMEOUT_MS);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519_private_to_curve25519;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn gen_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    fn make_keys() -> (SigningKey, PublicKey, CurvePrivateKey) {
        let sk = gen_signing_key();
        let pk = sk.verifying_key().to_bytes();
        let curve_priv = ed25519_private_to_curve25519(&sk);
        (sk, pk, curve_priv)
    }

    #[test]
    fn init_encrypt_decrypt() {
        let (priv_a, pub_a, _) = make_keys();
        let (_, pub_b, curve_priv_b) = make_keys();

        let (current, _) = new_box_keys(&mut OsRng);
        let (next, _) = new_box_keys(&mut OsRng);
        let init = SessionInit::new(&current, &next, 0, 1000);

        let encrypted = init
            .encrypt(&priv_a, &pub_b, SESSION_TYPE_INIT, &mut OsRng)
            .unwrap();
        assert_eq!(encrypted.len(), SESSION_INIT_SIZE);
        assert_eq!(encrypted[0], SESSION_TYPE_INIT);

        let decrypted = SessionInit::decrypt(&encrypted, &curve_priv_b, &pub_a).unwrap();
        assert_eq!(decrypted.current, current);
        assert_eq!(decrypted.next, next);
        assert_eq!(decrypted.key_seq, 0);
        assert_eq!(decrypted.seq, 1000);
    }

    #[test]
    fn session_send_recv() {
        let (priv_a, pub_a, curve_priv_a) = make_keys();
        let (priv_b, pub_b, curve_priv_b) = make_keys();

        let mut mgr_a = SessionManager::new();
        let mut mgr_b = SessionManager::new();
        let tick = 1000u64;

        // A writes to B (triggers buffer + init)
        let actions = mgr_a.write_to(&pub_b, b"hello from A", &priv_a, tick, &mut OsRng);
        assert_eq!(actions.len(), 1);

        // B receives the init
        let init_data = match &actions[0] {
            SessionAction::SendToRemote { data, .. } => data.clone(),
            _ => panic!("expected SendToRemote"),
        };
        let b_actions =
            mgr_b.handle_data(&pub_a, &init_data, &curve_priv_b, &priv_b, tick, &mut OsRng);
        assert!(!b_actions.is_empty());

        // Process B's ack on A, then A's buffered traffic on B
        for action in &b_actions {
            if let SessionAction::SendToRemote { data, .. } = action {
                let a_actions = mgr_a.handle_data(
                    &pub_b, data, &curve_priv_a, &priv_a, tick, &mut OsRng,
                );
                for a_action in &a_actions {
                    if let SessionAction::SendToRemote { data, .. } = a_action {
                        let b2 = mgr_b.handle_data(
                            &pub_a, data, &curve_priv_b, &priv_b, tick, &mut OsRng,
                        );
                        for b2_action in &b2 {
                            if let SessionAction::Deliver { source, data } = b2_action {
                                assert_eq!(*source, pub_a);
                                assert_eq!(data, b"hello from A");
                                return;
                            }
                        }
                    }
                }
            }
        }
        panic!("expected message delivery");
    }

    #[test]
    fn session_bidirectional() {
        let (priv_a, pub_a, curve_priv_a) = make_keys();
        let (priv_b, pub_b, curve_priv_b) = make_keys();

        let mut mgr_a = SessionManager::new();
        let mut mgr_b = SessionManager::new();
        let tick = 1000u64;

        // Establish: A→B init, B→A ack
        let a1 = mgr_a.write_to(&pub_b, b"msg1", &priv_a, tick, &mut OsRng);
        let init_data = match &a1[0] {
            SessionAction::SendToRemote { data, .. } => data.clone(),
            _ => panic!("expected SendToRemote"),
        };

        let b1 = mgr_b.handle_data(&pub_a, &init_data, &curve_priv_b, &priv_b, tick, &mut OsRng);
        let ack_data = match &b1[0] {
            SessionAction::SendToRemote { data, .. } => data.clone(),
            _ => panic!("expected SendToRemote"),
        };

        let a2 = mgr_a.handle_data(&pub_b, &ack_data, &curve_priv_a, &priv_a, tick, &mut OsRng);
        // Deliver buffered traffic to B
        for action in &a2 {
            if let SessionAction::SendToRemote { data, .. } = action {
                mgr_b.handle_data(&pub_a, data, &curve_priv_b, &priv_b, tick, &mut OsRng);
            }
        }

        // Now B→A should work directly
        let b_send = mgr_b.write_to(&pub_a, b"msg2", &priv_b, tick, &mut OsRng);
        for action in &b_send {
            if let SessionAction::SendToRemote { data, .. } = action {
                let recv = mgr_a.handle_data(
                    &pub_b, data, &curve_priv_a, &priv_a, tick, &mut OsRng,
                );
                for r in &recv {
                    if let SessionAction::Deliver { data, .. } = r {
                        assert_eq!(data, b"msg2");
                        return;
                    }
                }
            }
        }
        panic!("expected msg2 delivery");
    }

    #[test]
    fn session_cleanup() {
        let (priv_a, pub_a, curve_priv_a) = make_keys();
        let (priv_b, pub_b, curve_priv_b) = make_keys();

        let mut mgr_a = SessionManager::new();
        let mut mgr_b = SessionManager::new();

        // Establish session at tick=0
        let a1 = mgr_a.write_to(&pub_b, b"test", &priv_a, 0, &mut OsRng);
        let init_data = match &a1[0] {
            SessionAction::SendToRemote { data, .. } => data.clone(),
            _ => panic!(),
        };
        let b1 = mgr_b.handle_data(&pub_a, &init_data, &curve_priv_b, &priv_b, 0, &mut OsRng);
        let ack_data = match &b1[0] {
            SessionAction::SendToRemote { data, .. } => data.clone(),
            _ => panic!(),
        };
        mgr_a.handle_data(&pub_b, &ack_data, &curve_priv_a, &priv_a, 0, &mut OsRng);

        assert!(mgr_a.has_session(&pub_b));

        // Not expired at 50 seconds
        mgr_a.cleanup_expired(50_000);
        assert!(mgr_a.has_session(&pub_b));

        // Expired at 70 seconds (> 60s timeout)
        mgr_a.cleanup_expired(70_000);
        assert!(!mgr_a.has_session(&pub_b));
    }
}
