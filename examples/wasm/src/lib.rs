//! Yggdrasil leaf node running in the browser via WASM + WebSocket.
//!
//! Uses yggdrasil-lite (no_std) for the protocol and smoltcp for
//! a userspace IPv6/TCP stack.  Peers are reached via WebSocket
//! (Go Yggdrasil nodes support `wss://` listeners natively).

mod ygg_device;

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use ed25519_dalek::SigningKey;
use js_sys::Uint8Array;
use rand::rngs::OsRng;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{self, Socket as TcpSocket};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, Ipv6Address};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{MessageEvent, WebSocket};

use yggdrasil_lite::meta::Metadata;
use yggdrasil_lite::node::NodeEvent;
use yggdrasil_lite::{LiteConfig, PublicKey, YggdrasilLite};

use ygg_device::YggDevice;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Session traffic type byte (prepended to IPv6 packets inside Yggdrasil).
const TYPE_SESSION_TRAFFIC: u8 = 0x01;

/// Maximum number of TCP sockets managed by smoltcp.
// Headroom for the chat listener pool, active chats, reconnects, and one-shot
// file-transfer sockets (closed sockets aren't reclaimed, so keep this roomy).
const MAX_SOCKETS: usize = 128;

/// Number of HTTP listener sockets kept armed in parallel, so that an active
/// or stalled connection never leaves the port with nothing in LISTEN.
const HTTP_LISTENERS: usize = 4;

/// Abort an HTTP connection that opens but never completes a request within
/// this window, so a stalled client (e.g. idle `telnet`) can't tie up a slot.
const HTTP_IDLE_MS: u64 = 10_000;

/// ICMPv6
const IPPROTO_ICMPV6: u8 = 58;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

// ---------------------------------------------------------------------------
// Peer tracking
// ---------------------------------------------------------------------------

struct WsPeer {
    ws: WebSocket,
    peer_id: yggdrasil_lite::PeerId,
    /// Keep closures alive so the GC doesn't collect them.
    _onmessage: Closure<dyn FnMut(MessageEvent)>,
    _onclose: Closure<dyn FnMut()>,
    _onerror: Closure<dyn FnMut()>,
}

// ---------------------------------------------------------------------------
// Routing table entry: IPv6 address → Yggdrasil public key
// ---------------------------------------------------------------------------

struct RouteEntry {
    addr: [u8; 16],
    key: PublicKey,
}

// ---------------------------------------------------------------------------
// Ping state
// ---------------------------------------------------------------------------

struct PingState {
    dest_addr: [u8; 16],
    seq: u16,
    send_time_ms: f64,
    replied: bool,
}

// ---------------------------------------------------------------------------
// HTTP server connection slot
// ---------------------------------------------------------------------------

struct HttpConn {
    handle: SocketHandle,
    /// Accumulated request bytes for the current connection.
    req: Vec<u8>,
    /// Monotonic ms when the current connection became active (0 = idle/listening).
    active_since: u64,
}

// ---------------------------------------------------------------------------
// Inner state (shared via Rc<RefCell<_>>)
// ---------------------------------------------------------------------------

struct Inner {
    node: YggdrasilLite,
    signing_key: SigningKey,
    password: Vec<u8>,
    our_addr: [u8; 16],

    device: YggDevice,
    iface: Interface,
    sockets: SocketSet<'static>,

    peers: Vec<WsPeer>,
    routes: Vec<RouteEntry>,
    start_time: f64,

    /// Socket handles stored by user-facing index.
    tcp_handles: Vec<SocketHandle>,

    /// Pending incoming data from WebSocket onmessage callbacks.
    /// Stored as (peer_index, data).
    inbox: Vec<(usize, Vec<u8>)>,

    /// Pending ping requests (waiting for reply).
    pings: Vec<PingState>,

    /// Outbound traffic (already wrapped with TYPE_SESSION_TRAFFIC) waiting on
    /// destination key discovery. Retried from `poll()` once the key is known.
    pending_tx: Vec<([u8; 16], Vec<u8>)>,

    /// Per-destination last path-lookup time (ms), for throttling discovery.
    last_lookup: Vec<([u8; 16], u64)>,

    /// HTTP server: a pool of listener/connection slots, the port, and body.
    http_socks: Vec<HttpConn>,
    http_port: u16,
    http_body: alloc::string::String,

    /// Stats
    deliver_count: u64,
    send_count: u64,
}

impl Inner {
    /// Poll smoltcp interface (split borrow helper).
    fn poll_iface(&mut self, smol_now: SmolInstant) {
        self.iface
            .poll(smol_now, &mut self.device, &mut self.sockets);
    }

    /// Process node events: send to peers via WebSocket, deliver to smoltcp.
    fn process_events(&mut self, events: &[NodeEvent]) {
        for event in events {
            match event {
                NodeEvent::SendToPeer { peer_id, data } => {
                    self.send_count += 1;
                    if let Some(ws_peer) = self.peers.iter().find(|p| p.peer_id == *peer_id) {
                        let arr = Uint8Array::from(data.as_slice());
                        let _ = ws_peer.ws.send_with_array_buffer(&arr.buffer());
                    }
                }
                NodeEvent::Deliver { source, data } => {
                    self.deliver_count += 1;

                    log(&alloc::format!(
                        "[DELIVER] {} bytes from key={}... (type=0x{:02x})",
                        data.len(),
                        &hex_encode(source)[..16],
                        data.first().copied().unwrap_or(0),
                    ));

                    // Strip TYPE_SESSION_TRAFFIC prefix
                    if data.len() > 1 && data[0] == TYPE_SESSION_TRAFFIC {
                        let ipv6_pkt = &data[1..];

                        if ipv6_pkt.len() >= 40 {
                            // Cache source address → key mapping
                            let mut src_addr = [0u8; 16];
                            src_addr.copy_from_slice(&ipv6_pkt[8..24]);

                            let mut dst_addr = [0u8; 16];
                            dst_addr.copy_from_slice(&ipv6_pkt[24..40]);
                            let next_hdr = ipv6_pkt[6];
                            log(&alloc::format!(
                                "[RX] IPv6: {} -> {}, next_hdr={}, len={}",
                                format_ipv6(&src_addr),
                                format_ipv6(&dst_addr),
                                next_hdr,
                                ipv6_pkt.len(),
                            ));
                            if !self.routes.iter().any(|r| r.addr == src_addr) {
                                self.routes.push(RouteEntry {
                                    addr: src_addr,
                                    key: *source,
                                });
                            }

                            // Check for ICMPv6 echo reply (for ping)
                            let next_header = ipv6_pkt[6];
                            if next_header == IPPROTO_ICMPV6 && ipv6_pkt.len() >= 44 {
                                let icmp_type = ipv6_pkt[40];
                                if icmp_type == ICMPV6_ECHO_REPLY {
                                    let seq = u16::from_be_bytes([ipv6_pkt[46], ipv6_pkt[47]]);
                                    let now = now_ms_f64();
                                    if let Some(ping) = self.pings.iter_mut().find(|p| {
                                        p.seq == seq && p.dest_addr == src_addr && !p.replied
                                    }) {
                                        let rtt = now - ping.send_time_ms;
                                        ping.replied = true;
                                        log(&alloc::format!(
                                            "[PING] Reply from {} seq={} rtt={:.1}ms",
                                            format_ipv6(&src_addr),
                                            seq,
                                            rtt,
                                        ));
                                    } else {
                                        log(&alloc::format!(
                                            "[PING] Unexpected reply seq={} from {}",
                                            seq,
                                            format_ipv6(&src_addr),
                                        ));
                                    }
                                } else if icmp_type == ICMPV6_ECHO_REQUEST {
                                    log(&alloc::format!(
                                        "[PING] Echo request from {}",
                                        format_ipv6(&src_addr),
                                    ));
                                }
                            }

                            self.device.push_rx(ipv6_pkt.to_vec());
                        }
                    } else if !data.is_empty() {
                        log(&alloc::format!(
                            "[RECV] Non-traffic data ({} bytes, type=0x{:02x})",
                            data.len(),
                            data[0]
                        ));
                    }
                }
            }
        }
    }

    /// Send only SendToPeer events (no Deliver processing).
    fn send_to_peers(&self, events: &[NodeEvent]) {
        for event in events {
            if let NodeEvent::SendToPeer { peer_id, data } = event {
                if let Some(ws_peer) = self.peers.iter().find(|p| p.peer_id == *peer_id) {
                    let arr = Uint8Array::from(data.as_slice());
                    let _ = ws_peer.ws.send_with_array_buffer(&arr.buffer());
                }
            }
        }
    }

    /// Resolve a destination Yggdrasil address to a full public key.
    ///
    /// Tries, in order: a known full key in the route table, the node's
    /// pathfinder (`resolve`, populated by inbound traffic / PathNotify), and
    /// finally kicks off path discovery via `lookup` using the partial key
    /// derived from the address. Returns `None` while discovery is in flight.
    fn resolve_key(&mut self, dest: [u8; 16], now: u64) -> Option<PublicKey> {
        // 1. Known full key in the route table?
        if let Some(r) = self.routes.iter().find(|r| r.addr == dest) {
            if yggdrasil_lite::address::addr_for_key(&r.key).0 == dest {
                return Some(r.key);
            }
        }

        // 2. Learned by the pathfinder (inbound traffic or a PathNotify reply)?
        if let Some(key) = self.node.resolve(&dest) {
            if !self.routes.iter().any(|r| r.addr == dest && r.key == key) {
                self.routes.push(RouteEntry { addr: dest, key });
            }
            log(&alloc::format!(
                "[LKUP] resolved {} → key {}...",
                format_ipv6(&dest),
                &hex_encode(&key)[..16],
            ));
            return Some(key);
        }

        // 3. Kick off discovery with the partial key (throttled per dest).
        let due = self
            .last_lookup
            .iter()
            .find(|(a, _)| *a == dest)
            .map_or(true, |(_, t)| now.saturating_sub(*t) >= 1000);
        if due {
            let partial = if dest[0] == 0x03 {
                let mut p = [0u8; 8];
                p.copy_from_slice(&dest[..8]);
                yggdrasil_lite::address::Subnet(p).get_key()
            } else {
                yggdrasil_lite::address::Address(dest).get_key()
            };
            let events = self.node.lookup(&partial, now);
            self.send_to_peers(&events);
            if let Some(e) = self.last_lookup.iter_mut().find(|(a, _)| *a == dest) {
                e.1 = now;
            } else {
                self.last_lookup.push((dest, now));
            }
            log(&alloc::format!(
                "[LKUP] discovering key for {} ({} lookup frame(s))",
                format_ipv6(&dest),
                events.len(),
            ));
        }
        None
    }

    /// Send a raw IPv6 packet over Yggdrasil, resolving the destination key
    /// first. If the key isn't known yet, the packet is queued and retried
    /// from `poll()` once discovery completes.
    fn send_traffic(&mut self, dest: [u8; 16], ipv6_pkt: &[u8], now: u64) {
        let mut payload = Vec::with_capacity(1 + ipv6_pkt.len());
        payload.push(TYPE_SESSION_TRAFFIC);
        payload.extend_from_slice(ipv6_pkt);

        match self.resolve_key(dest, now) {
            Some(key) => {
                let mut rng = OsRng;
                let events = self.node.send(&key, &payload, now, &mut rng);
                self.process_events(&events);
            }
            None => {
                if self.pending_tx.len() < 64 {
                    self.pending_tx.push((dest, payload));
                }
            }
        }
    }

    /// Drive the HTTP listener pool: read requests, answer completed ones with
    /// the configured body, reclaim stalled connections, and keep every idle
    /// slot in LISTEN so the port never stops accepting.
    fn serve_http(&mut self, now: u64) {
        if self.http_socks.is_empty() {
            return;
        }
        let port = self.http_port;
        let Inner {
            ref mut sockets,
            ref mut http_socks,
            ref http_body,
            ..
        } = *self;

        for conn in http_socks.iter_mut() {
            let sock = sockets.get_mut::<TcpSocket>(conn.handle);

            // Track how long the current connection has been active.
            if sock.is_active() {
                if conn.active_since == 0 {
                    conn.active_since = now;
                }
            } else {
                conn.active_since = 0;
                conn.req.clear();
            }

            // Accumulate request bytes.
            if sock.can_recv() {
                let mut tmp = [0u8; 1024];
                if let Ok(n) = sock.recv_slice(&mut tmp) {
                    conn.req.extend_from_slice(&tmp[..n]);
                }
            }

            if sock.can_send() && conn.req.windows(4).any(|w| w == b"\r\n\r\n") {
                // Complete request → respond and close.
                let body = http_body.as_bytes();
                let resp = alloc::format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain; charset=utf-8\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.send_slice(resp.as_bytes());
                let _ = sock.send_slice(body);
                sock.close(); // initiate FIN
                conn.req.clear();
                log(&alloc::format!("[HTTP] request → 200 OK ({} bytes)", body.len()));
            } else if conn.active_since != 0
                && now.saturating_sub(conn.active_since) > HTTP_IDLE_MS
            {
                // Connected but never sent a complete request — reclaim the slot.
                sock.abort();
            }

            // Keep every idle/closed slot armed for new connections.
            if !sock.is_active() && !sock.is_listening() {
                sock.abort();
                let _ = sock.listen(port);
                conn.req.clear();
                conn.active_since = 0;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public WASM API
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub struct YggdrasilWasm {
    inner: alloc::rc::Rc<RefCell<Inner>>,
}

#[wasm_bindgen]
impl YggdrasilWasm {
    /// Create a new Yggdrasil leaf node.
    ///
    /// `seed` — optional 32-byte Ed25519 seed.  If omitted a random key is
    /// generated.
    #[wasm_bindgen(constructor)]
    pub fn new(seed: Option<Vec<u8>>) -> Self {
        let key_bytes: [u8; 32] = match seed {
            Some(s) if s.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&s);
                arr
            }
            _ => {
                let mut arr = [0u8; 32];
                getrandom::getrandom(&mut arr).expect("getrandom failed");
                arr
            }
        };

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();

        let config = LiteConfig::new(key_bytes);
        let node = YggdrasilLite::new(config);
        let our_addr = node.address();
        let our_addr_bytes = our_addr.0;

        // smoltcp interface (IP-only, no hardware address)
        let mut device = YggDevice::new();
        let mut iface_config = IfaceConfig::new(HardwareAddress::Ip);
        // Set random seed for smoltcp (used for TCP ISN, etc.)
        let mut seed_bytes = [0u8; 8];
        getrandom::getrandom(&mut seed_bytes).ok();
        iface_config.random_seed = u64::from_ne_bytes(seed_bytes);

        let mut iface = Interface::new(iface_config, &mut device, SmolInstant::from_millis(0));

        // Add our Yggdrasil /7 address
        iface.update_ip_addrs(|addrs| {
            let smol_addr = Ipv6Address::from_octets(our_addr_bytes);
            addrs
                .push(IpCidr::new(smol_addr.into(), 7))
                .expect("address push failed");
        });

        // Allocate socket storage on the heap and leak for 'static lifetime
        let storage: alloc::boxed::Box<[smoltcp::iface::SocketStorage<'static>]> =
            (0..MAX_SOCKETS)
                .map(|_| smoltcp::iface::SocketStorage::EMPTY)
                .collect::<Vec<_>>()
                .into_boxed_slice();
        let storage_ref: &'static mut [smoltcp::iface::SocketStorage<'static>] =
            alloc::boxed::Box::leak(storage);
        let sockets = SocketSet::new(storage_ref);

        let start_time = now_ms_f64();

        log(&alloc::format!(
            "[YGG] Node created.  Address: {}  PubKey: {}",
            our_addr,
            hex_encode(&public_key),
        ));

        Self {
            inner: alloc::rc::Rc::new(RefCell::new(Inner {
                node,
                signing_key,
                password: Vec::new(),
                our_addr: our_addr_bytes,
                device,
                iface,
                sockets,
                peers: Vec::new(),
                routes: Vec::new(),
                start_time,
                tcp_handles: Vec::new(),
                inbox: Vec::new(),
                pings: Vec::new(),
                pending_tx: Vec::new(),
                last_lookup: Vec::new(),
                http_socks: Vec::new(),
                http_port: 80,
                http_body: alloc::string::String::from("ACK from yggdrasil-lite in wasm"),
                deliver_count: 0,
                send_count: 0,
            })),
        }
    }

    /// Our Yggdrasil `200::/7` IPv6 address as a string.
    pub fn address(&self) -> String {
        let inner = self.inner.borrow();
        alloc::format!("{}", inner.node.address())
    }

    /// Our Ed25519 public key as a hex string.
    pub fn public_key_hex(&self) -> String {
        let inner = self.inner.borrow();
        hex_encode(inner.node.public_key())
    }

    /// Our current tree coordinates (for diagnostics).
    pub fn coords(&self) -> String {
        let inner = self.inner.borrow();
        let c = inner.node.coords();
        alloc::format!("{:?}", c)
    }

    /// Number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.inner.borrow().node.peer_count()
    }

    /// Number of active encrypted sessions.
    pub fn session_count(&self) -> usize {
        self.inner.borrow().node.session_count()
    }

    /// Number of cached paths.
    pub fn path_count(&self) -> usize {
        self.inner.borrow().node.path_count()
    }

    /// Diagnostic status string.
    pub fn status(&self) -> String {
        let inner = self.inner.borrow();
        let coords = inner.node.coords();
        let http = if inner.http_socks.is_empty() {
            alloc::string::String::from("off")
        } else {
            let listening = inner
                .http_socks
                .iter()
                .filter(|c| inner.sockets.get::<TcpSocket>(c.handle).is_listening())
                .count();
            alloc::format!("{}/{} listening", listening, inner.http_socks.len())
        };
        alloc::format!(
            "peers={} sessions={} paths={} routes={} delivered={} sent={} http={} coords={:?} root={}...",
            inner.node.peer_count(),
            inner.node.session_count(),
            inner.node.path_count(),
            inner.routes.len(),
            inner.deliver_count,
            inner.send_count,
            http,
            coords,
            &hex_encode(&inner.node.root())[..8],
        )
    }

    /// Connect to a peer via WebSocket URL (e.g. `wss://peer.example.com:443`).
    ///
    /// The metadata handshake runs automatically.  Returns a Promise that
    /// resolves when the peer is registered, or rejects on error.
    pub fn connect_peer(&self, ws_url: &str) -> js_sys::Promise {
        let inner = self.inner.clone();
        let url = alloc::string::String::from(ws_url);

        wasm_bindgen_futures::future_to_promise(async move {
            // yggdrasil-go's WSS listener requires the "ygg-ws" subprotocol and
            // closes the connection with 1008 otherwise. Servers that don't check
            // it still accept the offer, so always request it.
            let ws = WebSocket::new_with_str(&url, "ygg-ws")
                .map_err(|e| JsValue::from_str(&alloc::format!("WebSocket::new failed: {:?}", e)))?;
            ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

            // Prepare our metadata
            let (meta_bytes, peer_idx) = {
                let inner_ref = inner.borrow();
                let public_key = inner_ref.signing_key.verifying_key().to_bytes();
                let our_meta = Metadata::new(public_key, 0);
                let meta_bytes = our_meta.encode(&inner_ref.signing_key, &inner_ref.password);
                let peer_idx = inner_ref.peers.len();
                (meta_bytes, peer_idx)
            };

            // Channel to signal handshake completion
            let (resolver, resolve_rx) = futures_channel();

            // --- onopen: send our metadata ---
            let meta_for_open = meta_bytes.clone();
            let ws_for_open = ws.clone();
            let onopen = Closure::once(move || {
                let arr = Uint8Array::from(meta_for_open.as_slice());
                if let Err(e) = ws_for_open.send_with_array_buffer(&arr.buffer()) {
                    log(&alloc::format!("[WS] send metadata failed: {:?}", e));
                } else {
                    log("[WS] Metadata sent");
                }
            });
            ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
            onopen.forget();

            // --- shared accumulator for metadata handshake ---
            let meta_accum: alloc::rc::Rc<RefCell<Vec<u8>>> =
                alloc::rc::Rc::new(RefCell::new(Vec::new()));
            let handshake_done: alloc::rc::Rc<RefCell<bool>> =
                alloc::rc::Rc::new(RefCell::new(false));

            // --- onmessage ---
            let inner_msg = inner.clone();
            let meta_accum_msg = meta_accum.clone();
            let handshake_done_msg = handshake_done.clone();
            let resolver_msg = resolver.clone();
            let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
                let data = event.data();
                let buf = if let Ok(ab) = data.dyn_into::<js_sys::ArrayBuffer>() {
                    Uint8Array::new(&ab).to_vec()
                } else {
                    return;
                };

                if *handshake_done_msg.borrow() {
                    // Post-handshake: queue data for poll()
                    inner_msg.borrow_mut().inbox.push((peer_idx, buf));
                    return;
                }

                // Handshake phase: accumulate and try to decode metadata
                meta_accum_msg.borrow_mut().extend_from_slice(&buf);
                let accum = meta_accum_msg.borrow().clone();
                let password = inner_msg.borrow().password.clone();

                match Metadata::decode(&accum, &password) {
                    Ok((peer_meta, consumed)) => {
                        if !peer_meta.check() {
                            log("[WS] Incompatible protocol version");
                            return;
                        }
                        log(&alloc::format!(
                            "[WS] Peer key: {}...",
                            &hex_encode(&peer_meta.public_key)[..16]
                        ));

                        let mut inner_ref = inner_msg.borrow_mut();
                        let pid = inner_ref.node.add_peer(peer_meta.public_key, 0);
                        inner_ref.node.mark_handshake_done(pid);

                        *handshake_done_msg.borrow_mut() = true;

                        // Handle leftover bytes after metadata
                        if accum.len() > consumed {
                            let leftover = accum[consumed..].to_vec();
                            inner_ref.inbox.push((peer_idx, leftover));
                        }

                        // Signal completion
                        resolver_msg.resolve(pid);

                        log(&alloc::format!("[WS] Peer registered (id={})", pid));
                    }
                    Err(yggdrasil_lite::meta::MetaError::TooShort)
                    | Err(yggdrasil_lite::meta::MetaError::BufferTooSmall) => {
                        // Need more data
                    }
                    Err(e) => {
                        log(&alloc::format!("[WS] Metadata error: {:?}", e));
                    }
                }
            }) as Box<dyn FnMut(MessageEvent)>);

            // If the socket dies before the handshake finishes, reject the
            // pending connect promise so the UI doesn't hang on "Connecting…".
            let resolver_close = resolver.clone();
            let handshake_done_close = handshake_done.clone();
            let onclose = Closure::wrap(Box::new(move || {
                log("[WS] Connection closed");
                if !*handshake_done_close.borrow() {
                    resolver_close.reject();
                }
            }) as Box<dyn FnMut()>);

            let resolver_err = resolver.clone();
            let handshake_done_err = handshake_done.clone();
            let onerror = Closure::wrap(Box::new(move || {
                log("[WS] Connection error");
                if !*handshake_done_err.borrow() {
                    resolver_err.reject();
                }
            }) as Box<dyn FnMut()>);

            ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
            ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));
            ws.set_onerror(Some(onerror.as_ref().unchecked_ref()));

            // Wait for handshake to complete (or the socket to die first).
            let pid = resolve_rx.await.map_err(|_| {
                JsValue::from_str("WebSocket closed before handshake (wrong URL or subprotocol?)")
            })?;

            // Register the WsPeer and auto-register the peer's key as a route
            {
                let mut inner_ref = inner.borrow_mut();
                // Find the peer's public key from the node
                if let Some(peer_state) = inner_ref.node.get_peer(pid) {
                    let peer_key = peer_state.key;
                    let peer_addr = yggdrasil_lite::address::addr_for_key(&peer_key);
                    if !inner_ref.routes.iter().any(|r| r.addr == peer_addr.0) {
                        inner_ref.routes.push(RouteEntry {
                            addr: peer_addr.0,
                            key: peer_key,
                        });
                        log(&alloc::format!(
                            "[ROUTE] Auto-registered peer route: {} → key {}...",
                            peer_addr,
                            &hex_encode(&peer_key)[..16],
                        ));
                    }
                }

                inner_ref.peers.push(WsPeer {
                    ws,
                    peer_id: pid,
                    _onmessage: onmessage,
                    _onclose: onclose,
                    _onerror: onerror,
                });
            }

            Ok(JsValue::from(pid as u32))
        })
    }

    /// Register a known public key → IPv6 address mapping.
    ///
    /// Call this before ping/tcp_connect when you know the destination's
    /// real public key (hex). Without the real key, session encryption
    /// will fail because partial keys derived from addresses can't be
    /// used for X25519 DH.
    pub fn add_route(&self, pub_key_hex: &str) {
        let key = match hex_decode(pub_key_hex) {
            Some(k) if k.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&k);
                arr
            }
            _ => {
                log("[ROUTE] Invalid public key hex (need 64 hex chars)");
                return;
            }
        };

        let addr = yggdrasil_lite::address::addr_for_key(&key);
        let addr_str = alloc::format!("{}", addr);

        let mut inner = self.inner.borrow_mut();

        // Update or add route
        if let Some(route) = inner.routes.iter_mut().find(|r| r.addr == addr.0) {
            route.key = key;
            log(&alloc::format!(
                "[ROUTE] Updated route for {} → key {}...",
                addr_str,
                &pub_key_hex[..16],
            ));
        } else {
            inner.routes.push(RouteEntry {
                addr: addr.0,
                key,
            });
            log(&alloc::format!(
                "[ROUTE] Added route for {} → key {}...",
                addr_str,
                &pub_key_hex[..16],
            ));
        }
    }

    /// Derive the Yggdrasil IPv6 address for a given public key (hex).
    /// Returns the address string, or empty string on error.
    pub fn addr_for_key(&self, pub_key_hex: &str) -> String {
        match hex_decode(pub_key_hex) {
            Some(k) if k.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&k);
                let addr = yggdrasil_lite::address::addr_for_key(&arr);
                alloc::format!("{}", addr)
            }
            _ => alloc::string::String::new(),
        }
    }

    /// Send an ICMPv6 Echo Request (ping) to a destination Yggdrasil IPv6 address.
    ///
    /// IMPORTANT: For this to work, you must first register the destination's
    /// real public key via `add_route(pubkey_hex)`. Without it, the session
    /// init will be encrypted to a partial key and the destination won't be
    /// able to decrypt it.
    ///
    /// Watch the log for "[PING] Reply" messages with RTT.
    pub fn ping(&self, dest_ipv6: &str) -> u16 {
        let mut inner = self.inner.borrow_mut();
        let now = now_ms(&inner.start_time);

        let dest_bytes = parse_ipv6(dest_ipv6);

        // Sequence number
        let seq = inner.pings.len() as u16;

        // Build ICMPv6 Echo Request → IPv6 packet
        let icmp_payload = build_icmpv6_echo_request(&inner.our_addr, &dest_bytes, seq);
        let ipv6_pkt =
            build_ipv6_packet(&inner.our_addr, &dest_bytes, IPPROTO_ICMPV6, &icmp_payload);

        log(&alloc::format!(
            "[PING] echo request to {} seq={} ({} bytes)",
            dest_ipv6,
            seq,
            ipv6_pkt.len(),
        ));

        // Record ping state for RTT/timeout tracking.
        inner.pings.push(PingState {
            dest_addr: dest_bytes,
            seq,
            send_time_ms: now_ms_f64(),
            replied: false,
        });

        // Send (resolving the destination key, or queuing for discovery).
        inner.send_traffic(dest_bytes, &ipv6_pkt, now);

        log(&alloc::format!(
            "[PING] state: sessions={} paths={} pending_tx={}",
            inner.node.session_count(),
            inner.node.path_count(),
            inner.pending_tx.len(),
        ));

        seq
    }

    /// Drive the node: process queued data, run timers, poll smoltcp.
    ///
    /// Call this on a regular interval (e.g. every 100 ms via `setInterval`).
    pub fn poll(&self) {
        let mut inner = self.inner.borrow_mut();
        let now = now_ms(&inner.start_time);
        let mut rng = OsRng;

        // 1. Process queued WebSocket data
        let inbox: Vec<_> = inner.inbox.drain(..).collect();
        if !inbox.is_empty() {
            let total: usize = inbox.iter().map(|(_, d)| d.len()).sum();
            log(&alloc::format!(
                "[IN] {} msg(s), {} bytes from peer(s)",
                inbox.len(),
                total,
            ));
        }
        for (peer_idx, data) in inbox {
            let peer_id = match inner.peers.get(peer_idx) {
                Some(p) => p.peer_id,
                None => continue,
            };
            let events = inner.node.handle_peer_data(peer_id, &data, now, &mut rng);
            inner.process_events(&events);
        }

        // 2. Node maintenance (keepalives, tree, blooms, path cleanup)
        let events = inner.node.poll(now, &mut rng);
        inner.process_events(&events);

        // 3. Poll smoltcp (process inbound packets queued from Deliver events)
        let smol_now = SmolInstant::from_millis(now as i64);
        inner.poll_iface(smol_now);

        // 3b. HTTP server: answer any complete request, then re-poll so the
        //     response (and SYN-ACKs) become outbound packets.
        inner.serve_http(now);
        inner.poll_iface(smol_now);

        // 4. Drain outbound smoltcp packets -> Yggdrasil
        let tx_packets: Vec<Vec<u8>> = inner.device.drain_tx().collect();
        if !tx_packets.is_empty() {
            log(&alloc::format!(
                "[TX] smoltcp produced {} outbound packet(s)",
                tx_packets.len()
            ));
        }
        for pkt in tx_packets {
            // Extract destination IPv6 from the packet header
            if pkt.len() < 40 {
                continue;
            }
            let mut dest_addr = [0u8; 16];
            dest_addr.copy_from_slice(&pkt[24..40]);

            // Send via Yggdrasil (resolves the key or queues for discovery).
            inner.send_traffic(dest_addr, &pkt, now);
        }

        // 4b. Retry any outbound traffic whose key is now resolvable.
        if !inner.pending_tx.is_empty() {
            let pending: Vec<_> = inner.pending_tx.drain(..).collect();
            for (dest, payload) in pending {
                match inner.resolve_key(dest, now) {
                    Some(key) => {
                        let events = inner.node.send(&key, &payload, now, &mut rng);
                        inner.process_events(&events);
                    }
                    None => {
                        if inner.pending_tx.len() < 64 {
                            inner.pending_tx.push((dest, payload));
                        }
                    }
                }
            }
        }

        // 5. Second smoltcp poll to flush responses
        inner.poll_iface(smol_now);

        // 6. Check for timed-out pings (>10s)
        let now_f64 = now_ms_f64();
        for ping in &mut inner.pings {
            if !ping.replied && (now_f64 - ping.send_time_ms) > 10_000.0 {
                log(&alloc::format!(
                    "[PING] Timeout seq={} to {}",
                    ping.seq,
                    format_ipv6(&ping.dest_addr),
                ));
                ping.replied = true; // mark to stop re-reporting
            }
        }
    }

    /// Start polling on a JavaScript `setInterval` timer.
    ///
    /// Returns the interval ID (can be used with `clearInterval`).
    pub fn start_polling(&self, interval_ms: i32) -> i32 {
        let inner = self.inner.clone();
        let closure = Closure::wrap(Box::new(move || {
            let wasm = YggdrasilWasm {
                inner: inner.clone(),
            };
            wasm.poll();
        }) as Box<dyn FnMut()>);

        let window = web_sys::window().expect("no window");
        let id = window
            .set_interval_with_callback_and_timeout_and_arguments_0(
                closure.as_ref().unchecked_ref(),
                interval_ms,
            )
            .expect("setInterval failed");

        closure.forget();
        id
    }

    /// Start (or restart) a tiny HTTP server on `port` that answers every
    /// request with `body`. Idempotent — calling again updates the body and
    /// ensures the listener is armed.
    pub fn start_http_server(&self, port: u16, body: String) {
        let mut inner = self.inner.borrow_mut();
        inner.http_body = body;
        inner.http_port = port;

        // Create the listener pool once.
        if inner.http_socks.is_empty() {
            for _ in 0..HTTP_LISTENERS {
                let rx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
                let tx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
                let handle = inner.sockets.add(TcpSocket::new(rx_buf, tx_buf));
                inner.http_socks.push(HttpConn {
                    handle,
                    req: Vec::new(),
                    active_since: 0,
                });
            }
        }

        // Arm every idle slot.
        let handles: Vec<SocketHandle> = inner.http_socks.iter().map(|c| c.handle).collect();
        for h in handles {
            let sock = inner.sockets.get_mut::<TcpSocket>(h);
            if !sock.is_listening() && !sock.is_active() {
                let _ = sock.listen(port);
            }
        }
        log(&alloc::format!(
            "[HTTP] serving on port {} ({} listeners)",
            port,
            HTTP_LISTENERS
        ));
    }

    /// Update the HTTP response body returned to future requests.
    pub fn set_http_response(&self, body: String) {
        self.inner.borrow_mut().http_body = body;
    }

    /// Create a TCP socket and initiate connection to a remote Yggdrasil node.
    ///
    /// Returns a socket index for use with `tcp_send` / `tcp_recv`.
    pub fn tcp_connect(&self, dest_ipv6: &str, port: u16) -> u32 {
        let mut inner = self.inner.borrow_mut();

        let rx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
        let socket = TcpSocket::new(rx_buf, tx_buf);

        let handle = inner.sockets.add(socket);
        let idx = inner.tcp_handles.len() as u32;
        inner.tcp_handles.push(handle);

        // Parse destination IPv6
        let dest_bytes = parse_ipv6(dest_ipv6);
        let dest_smol = Ipv6Address::from_octets(dest_bytes);

        // The destination key is discovered lazily: smoltcp's SYN will hit the
        // `poll()` TX path, which calls `send_traffic` → `resolve_key`. We must
        // NOT seed a partial key here — partial and full keys map to the same
        // address, so a partial entry would masquerade as a valid full key.
        // Pre-warm discovery so the key is likely ready by the time SYN is sent.
        let now = now_ms(&inner.start_time);
        let _ = inner.resolve_key(dest_bytes, now);

        // Use a local port based on the index
        let local_port = 49152 + (idx as u16 % 16384);
        {
            let Inner {
                ref mut iface,
                ref mut sockets,
                ..
            } = *inner;
            let ctx = iface.context();
            let sock = sockets.get_mut::<TcpSocket>(handle);
            if let Err(e) = sock.connect(ctx, (dest_smol, port), local_port) {
                log(&alloc::format!("[TCP] connect error: {:?}", e));
            }
        }

        log(&alloc::format!(
            "[TCP] Connecting to [{}]:{} (handle={})",
            dest_ipv6, port, idx
        ));

        idx
    }

    /// Create a listening TCP socket on the given port.
    ///
    /// Returns a socket index.
    pub fn tcp_listen(&self, port: u16) -> u32 {
        let mut inner = self.inner.borrow_mut();

        let rx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
        let socket = TcpSocket::new(rx_buf, tx_buf);

        let handle = inner.sockets.add(socket);
        let idx = inner.tcp_handles.len() as u32;
        inner.tcp_handles.push(handle);

        let sock = inner.sockets.get_mut::<TcpSocket>(handle);
        if let Err(e) = sock.listen(port) {
            log(&alloc::format!("[TCP] listen error: {:?}", e));
        }

        log(&alloc::format!("[TCP] Listening on port {} (handle={})", port, idx));

        idx
    }

    /// Send data on a TCP socket.
    pub fn tcp_send(&self, index: u32, data: &[u8]) -> usize {
        let mut inner = self.inner.borrow_mut();
        let handle = match inner.tcp_handles.get(index as usize) {
            Some(h) => *h,
            None => return 0,
        };
        let sock = inner.sockets.get_mut::<TcpSocket>(handle);
        match sock.send_slice(data) {
            Ok(n) => n,
            Err(e) => {
                log(&alloc::format!("[TCP] send error: {:?}", e));
                0
            }
        }
    }

    /// Receive data from a TCP socket.  Returns `None` if no data available.
    pub fn tcp_recv(&self, index: u32) -> Option<Vec<u8>> {
        let mut inner = self.inner.borrow_mut();
        let handle = match inner.tcp_handles.get(index as usize) {
            Some(h) => *h,
            None => return None,
        };
        let sock = inner.sockets.get_mut::<TcpSocket>(handle);
        if !sock.can_recv() {
            return None;
        }
        let mut buf = vec![0u8; 4096];
        match sock.recv_slice(&mut buf) {
            Ok(n) if n > 0 => {
                buf.truncate(n);
                Some(buf)
            }
            _ => None,
        }
    }

    /// Check if a TCP socket is connected / established.
    pub fn tcp_is_active(&self, index: u32) -> bool {
        let inner = self.inner.borrow();
        let handle = match inner.tcp_handles.get(index as usize) {
            Some(h) => *h,
            None => return false,
        };
        let sock = inner.sockets.get::<TcpSocket>(handle);
        sock.is_active()
    }

    /// TCP socket state as a string (for diagnostics).
    pub fn tcp_state(&self, index: u32) -> String {
        let inner = self.inner.borrow();
        let handle = match inner.tcp_handles.get(index as usize) {
            Some(h) => *h,
            None => return alloc::string::String::from("invalid"),
        };
        let sock = inner.sockets.get::<TcpSocket>(handle);
        alloc::format!("{}", sock.state())
    }

    /// Remote peer's IPv6 address for this socket, or empty if not connected.
    ///
    /// Useful on the listening side to learn who dialed in: once an accepted
    /// socket leaves `LISTEN`, the remote endpoint is populated.
    pub fn tcp_remote(&self, index: u32) -> String {
        let inner = self.inner.borrow();
        let handle = match inner.tcp_handles.get(index as usize) {
            Some(h) => *h,
            None => return alloc::string::String::new(),
        };
        let sock = inner.sockets.get::<TcpSocket>(handle);
        match sock.remote_endpoint() {
            Some(ep) => alloc::format!("{}", ep.addr),
            None => alloc::string::String::new(),
        }
    }

    /// Gracefully close a TCP socket (sends FIN once the send buffer drains).
    /// Used by one-shot file transfers: the sender closes after the last byte,
    /// which the receiver sees as end-of-file.
    pub fn tcp_close(&self, index: u32) {
        let mut inner = self.inner.borrow_mut();
        let handle = match inner.tcp_handles.get(index as usize) {
            Some(h) => *h,
            None => return,
        };
        let sock = inner.sockets.get_mut::<TcpSocket>(handle);
        sock.close();
    }
}

// ---------------------------------------------------------------------------
// ICMPv6 helpers
// ---------------------------------------------------------------------------

/// Build ICMPv6 Echo Request payload (type + code + checksum + id + seq + data).
fn build_icmpv6_echo_request(src: &[u8; 16], dst: &[u8; 16], seq: u16) -> Vec<u8> {
    let id: u16 = 0x5947; // "YG"
    let data = b"yggdrasil-wasm-ping";

    let mut icmp = Vec::with_capacity(8 + data.len());
    icmp.push(ICMPV6_ECHO_REQUEST); // type
    icmp.push(0);                    // code
    icmp.extend_from_slice(&[0, 0]); // checksum placeholder
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(data);

    // Compute checksum
    let cksum = icmpv6_checksum(src, dst, &icmp);
    icmp[2] = (cksum >> 8) as u8;
    icmp[3] = (cksum & 0xFF) as u8;

    icmp
}

/// Build a minimal IPv6 packet.
fn build_ipv6_packet(src: &[u8; 16], dst: &[u8; 16], next_header: u8, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(40 + payload.len());
    // Version(6) + Traffic Class + Flow Label
    pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    // Payload length
    pkt.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    // Next header
    pkt.push(next_header);
    // Hop limit
    pkt.push(64);
    // Source
    pkt.extend_from_slice(src);
    // Destination
    pkt.extend_from_slice(dst);
    // Payload
    pkt.extend_from_slice(payload);
    pkt
}

/// Compute ICMPv6 checksum with IPv6 pseudo-header.
fn icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], icmp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
    }
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
    }
    let icmp_len = icmp_data.len() as u32;
    sum += (icmp_len >> 16) as u32;
    sum += (icmp_len & 0xFFFF) as u32;
    sum += IPPROTO_ICMPV6 as u32;
    let mut i = 0;
    while i + 1 < icmp_data.len() {
        if i == 2 {
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([icmp_data[i], icmp_data[i + 1]]) as u32;
        i += 2;
    }
    if i < icmp_data.len() {
        sum += (icmp_data[i] as u32) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_ms_f64() -> f64 {
    web_sys::window()
        .expect("no window")
        .performance()
        .expect("no performance")
        .now()
}

fn now_ms(start: &f64) -> u64 {
    (now_ms_f64() - start) as u64
}

fn log(msg: &str) {
    web_sys::console::log_1(&JsValue::from_str(msg));
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut result = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        result.push(byte);
    }
    Some(result)
}

fn hex_encode(bytes: &[u8]) -> alloc::string::String {
    let mut s = alloc::string::String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn format_ipv6(addr: &[u8; 16]) -> alloc::string::String {
    alloc::format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        u16::from_be_bytes([addr[0], addr[1]]),
        u16::from_be_bytes([addr[2], addr[3]]),
        u16::from_be_bytes([addr[4], addr[5]]),
        u16::from_be_bytes([addr[6], addr[7]]),
        u16::from_be_bytes([addr[8], addr[9]]),
        u16::from_be_bytes([addr[10], addr[11]]),
        u16::from_be_bytes([addr[12], addr[13]]),
        u16::from_be_bytes([addr[14], addr[15]]),
    )
}

/// Minimal IPv6 address parser (handles `200:abcd::1` style).
fn parse_ipv6(s: &str) -> [u8; 16] {
    let mut result = [0u8; 16];
    let parts: Vec<&str> = s.split("::").collect();

    match parts.len() {
        1 => {
            let groups: Vec<&str> = parts[0].split(':').collect();
            for (i, g) in groups.iter().enumerate() {
                if i >= 8 {
                    break;
                }
                let val = u16::from_str_radix(g, 16).unwrap_or(0);
                result[i * 2] = (val >> 8) as u8;
                result[i * 2 + 1] = val as u8;
            }
        }
        2 => {
            let left: Vec<&str> = if parts[0].is_empty() {
                Vec::new()
            } else {
                parts[0].split(':').collect()
            };
            let right: Vec<&str> = if parts[1].is_empty() {
                Vec::new()
            } else {
                parts[1].split(':').collect()
            };

            for (i, g) in left.iter().enumerate() {
                let val = u16::from_str_radix(g, 16).unwrap_or(0);
                result[i * 2] = (val >> 8) as u8;
                result[i * 2 + 1] = val as u8;
            }

            let right_start = 8 - right.len();
            for (i, g) in right.iter().enumerate() {
                let val = u16::from_str_radix(g, 16).unwrap_or(0);
                let idx = right_start + i;
                result[idx * 2] = (val >> 8) as u8;
                result[idx * 2 + 1] = val as u8;
            }
        }
        _ => {}
    }

    result
}

/// Simple one-shot channel for the handshake completion signal.
type ChannelResult = alloc::rc::Rc<RefCell<Option<Result<yggdrasil_lite::PeerId, ()>>>>;
type ChannelWaker = alloc::rc::Rc<RefCell<Option<core::task::Waker>>>;

/// Settles the handshake future. `resolve` on success, `reject` if the socket
/// dies before the handshake completes (so the awaiting promise rejects instead
/// of hanging forever). The first settle wins; later calls are ignored.
#[derive(Clone)]
struct Resolver {
    result: ChannelResult,
    waker: ChannelWaker,
}

impl Resolver {
    fn settle(&self, v: Result<yggdrasil_lite::PeerId, ()>) {
        {
            let mut r = self.result.borrow_mut();
            if r.is_some() {
                return; // already settled
            }
            *r = Some(v);
        }
        if let Some(w) = self.waker.borrow_mut().take() {
            w.wake();
        }
    }
    fn resolve(&self, pid: yggdrasil_lite::PeerId) {
        self.settle(Ok(pid));
    }
    fn reject(&self) {
        self.settle(Err(()));
    }
}

fn futures_channel() -> (Resolver, FutureChannel) {
    let result: ChannelResult = alloc::rc::Rc::new(RefCell::new(None));
    let waker: ChannelWaker = alloc::rc::Rc::new(RefCell::new(None));
    let resolver = Resolver {
        result: result.clone(),
        waker: waker.clone(),
    };
    (resolver, FutureChannel { result, waker })
}

struct FutureChannel {
    result: ChannelResult,
    waker: ChannelWaker,
}

impl core::future::Future for FutureChannel {
    type Output = Result<yggdrasil_lite::PeerId, ()>;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if let Some(v) = self.result.borrow_mut().take() {
            core::task::Poll::Ready(v)
        } else {
            *self.waker.borrow_mut() = Some(cx.waker().clone());
            core::task::Poll::Pending
        }
    }
}
