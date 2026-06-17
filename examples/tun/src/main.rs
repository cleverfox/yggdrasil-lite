//! yggdrasil-lite ⇄ OS TUN bridge for Linux and macOS.
//!
//! Connects to one or more yggdrasil-ng / yggstack peers over TCP+TLS, joins
//! the Yggdrasil overlay as a leaf node, and bridges the overlay to a real
//! kernel TUN interface. The OS networking stack does all the TCP/IP work —
//! this example only shuttles raw IPv6 packets between the TUN device and the
//! Yggdrasil node:
//!
//! ```text
//!   kernel socket ──▶ TUN (ygg0/utunN) ──▶ this bridge ──▶ Yggdrasil overlay
//!   kernel socket ◀── TUN              ◀── this bridge ◀── Yggdrasil overlay
//! ```
//!
//! Unlike the `lite_node` example (which runs a userspace TCP stack and never
//! touches the kernel routing table), this binds the overlay to the host, so
//! ordinary tools work over Yggdrasil:
//!
//! ```sh
//! ping6 <some-yggdrasil-address>
//! curl -6 "http://[<some-yggdrasil-address>]:80/"
//! ssh <some-yggdrasil-address>
//! ```
//!
//! # Usage
//!
//! Requires root (to create the TUN device and add a route):
//!
//! ```sh
//! sudo cargo run -p yggdrasil-tun -- 127.0.0.1:2020
//! sudo cargo run -p yggdrasil-tun -- 127.0.0.1:2020 --seed <64-hex> --tun ygg0
//! ```
//!
//! The bridge prints its own `200::/7` address on startup. Outbound packets to
//! an unknown destination trigger a path lookup using the partial key derived
//! from the destination address; once the destination replies with its full
//! key, queued packets are sent.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, TcpStream};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use tun::AbstractDevice;
use rand::rngs::OsRng;
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConnection, DigitallySignedStruct, Error as TlsError, SignatureScheme};

use yggdrasil_lite::address::{addr_for_key, Address, Subnet};
use yggdrasil_lite::crypto::PublicKey;
use yggdrasil_lite::meta::Metadata;
use yggdrasil_lite::node::{LiteConfig, NodeEvent, YggdrasilLite};
use yggdrasil_lite::peer::PeerId;

// ============================================================================
// Constants
// ============================================================================

/// Session type byte prepended to IPv6 packets (matches yggdrasil core.rs).
const TYPE_SESSION_TRAFFIC: u8 = 0x01;

/// Default TUN interface name on Linux (macOS auto-assigns `utunN`).
#[cfg(target_os = "linux")]
const DEFAULT_TUN_NAME: &str = "ygg0";

/// Interface MTU. Conservative default that comfortably fits inside a single
/// peer link's framing; the overlay itself can carry larger packets.
const DEFAULT_MTU: u16 = 1400;

/// Minimum interval between path lookups for the same destination.
const LOOKUP_INTERVAL_MS: u64 = 1_000;

/// Max packets queued per destination while its key is being discovered.
const MAX_PENDING_PER_DEST: usize = 16;

// ============================================================================
// Per-peer connection state
// ============================================================================

struct PeerConn {
    addr: String,
    tcp: TcpStream,
    tls: ClientConnection,
    tls_read_buf: Vec<u8>,
}

/// Write framed data to a specific peer's TLS stream.
fn send_to_peer(peers: &mut HashMap<PeerId, PeerConn>, peer_id: PeerId, data: &[u8]) {
    if let Some(pc) = peers.get_mut(&peer_id) {
        let _ = pc.tls.writer().write_all(data);
        while pc.tls.wants_write() {
            match pc.tls.write_tls(&mut pc.tcp) {
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }
}

/// Dispatch node events: forward `SendToPeer` frames to the right peer.
/// (`Deliver` events are handled separately in the main loop.)
fn dispatch_send_events(events: &[NodeEvent], peers: &mut HashMap<PeerId, PeerConn>) {
    for ev in events {
        if let NodeEvent::SendToPeer { peer_id, data } = ev {
            send_to_peer(peers, *peer_id, data);
        }
    }
}

// ============================================================================
// TLS support (accept all server certs — auth is via Yggdrasil metadata)
// ============================================================================

#[derive(Debug)]
struct AcceptAllVerifier;

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

fn create_tls_client_config() -> rustls::ClientConfig {
    use rustls::version::TLS13;
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13])
        .expect("TLS config")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![];
    config
}

/// Drive the TLS handshake to completion (blocking).
fn complete_tls_handshake(tls: &mut ClientConnection, tcp: &mut TcpStream) -> io::Result<()> {
    while tls.is_handshaking() {
        if tls.wants_write() {
            tls.write_tls(tcp)?;
        }
        if tls.wants_read() {
            tls.read_tls(tcp)?;
            tls.process_new_packets()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        }
    }
    Ok(())
}

/// Connect to a single peer: TCP, TLS, and the Yggdrasil metadata handshake.
/// Registers the peer with the node and returns the live connection.
fn connect_peer(
    peer_addr: &str,
    tls_config: Arc<rustls::ClientConfig>,
    meta_bytes: &[u8],
    password: &[u8],
    node: &mut YggdrasilLite,
) -> Result<(PeerId, PeerConn), Box<dyn std::error::Error>> {
    eprintln!("[CONN] Connecting to {}...", peer_addr);
    let mut tcp = TcpStream::connect(peer_addr)?;
    tcp.set_nodelay(true)?;
    eprintln!("[CONN] TCP connected to {}", peer_addr);

    let server_name =
        ServerName::try_from("yggdrasil").map_err(|e| format!("invalid server name: {}", e))?;
    let mut tls = ClientConnection::new(tls_config, server_name)?;
    complete_tls_handshake(&mut tls, &mut tcp)?;
    eprintln!("[CONN] TLS handshake complete");

    // Send our metadata.
    tls.writer().write_all(meta_bytes)?;
    while tls.wants_write() {
        tls.write_tls(&mut tcp)?;
    }
    eprintln!("[META] Sent metadata ({} bytes)", meta_bytes.len());

    // Read and decode peer metadata.
    let mut meta_accum = Vec::new();
    let peer_id = loop {
        if tls.wants_read() {
            tls.read_tls(&mut tcp)?;
            tls.process_new_packets()
                .map_err(|e| format!("TLS error: {}", e))?;
        }
        let mut tmp = vec![0u8; 512];
        match tls.reader().read(&mut tmp) {
            Ok(0) => continue,
            Ok(n) => {
                meta_accum.extend_from_slice(&tmp[..n]);
                match Metadata::decode(&meta_accum, password) {
                    Ok((peer_meta, consumed)) => {
                        if !peer_meta.check() {
                            return Err("Incompatible protocol version".into());
                        }
                        eprintln!(
                            "[META] Peer key: {}…",
                            &hex::encode(peer_meta.public_key)[..16]
                        );
                        let pid = node.add_peer(peer_meta.public_key, 0);
                        node.mark_handshake_done(pid);
                        eprintln!("[META] Peer {} registered (id={})", peer_addr, pid);

                        // Feed any leftover bytes that arrived after the metadata.
                        if meta_accum.len() > consumed {
                            let leftover = meta_accum[consumed..].to_vec();
                            let events = node.handle_peer_data(pid, &leftover, 0, &mut OsRng);
                            for ev in &events {
                                if let NodeEvent::SendToPeer { data, .. } = ev {
                                    let _ = tls.writer().write_all(data);
                                }
                            }
                            while tls.wants_write() {
                                let _ = tls.write_tls(&mut tcp);
                            }
                        }
                        break pid;
                    }
                    Err(yggdrasil_lite::meta::MetaError::TooShort)
                    | Err(yggdrasil_lite::meta::MetaError::BufferTooSmall) => continue,
                    Err(e) => return Err(format!("Metadata decode error: {:?}", e).into()),
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if tls.wants_read() {
                    tls.read_tls(&mut tcp)?;
                    tls.process_new_packets()
                        .map_err(|e| format!("TLS error: {}", e))?;
                }
            }
            Err(e) => return Err(e.into()),
        }
    };

    // Drain any remaining buffered protocol bytes from the handshake.
    {
        let mut drain_buf = vec![0u8; 65536];
        loop {
            match tls.reader().read(&mut drain_buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let events = node.handle_peer_data(peer_id, &drain_buf[..n], 0, &mut OsRng);
                    for ev in &events {
                        if let NodeEvent::SendToPeer { data, .. } = ev {
                            let _ = tls.writer().write_all(data);
                        }
                    }
                }
            }
        }
    }

    // Non-blocking for the event loop.
    tcp.set_nonblocking(true)?;

    Ok((
        peer_id,
        PeerConn {
            addr: peer_addr.to_string(),
            tcp,
            tls,
            tls_read_buf: vec![0u8; 65536],
        },
    ))
}

// ============================================================================
// TUN setup
// ============================================================================

/// Run a privileged setup command, logging it. Errors are surfaced.
fn run(cmd: &str, args: &[&str]) -> io::Result<()> {
    eprintln!("[TUN]  $ {} {}", cmd, args.join(" "));
    let status = std::process::Command::new(cmd).args(args).status()?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("`{}` exited with {}", cmd, status),
        ));
    }
    Ok(())
}

/// Assign our overlay address and route `200::/7` to the TUN interface.
/// `200::/7` is added with prefix length 7 so the whole Yggdrasil range is
/// on-link via this interface.
#[allow(unused_variables)]
fn configure_interface(name: &str, addr: &Ipv6Addr) -> io::Result<()> {
    let addr_str = addr.to_string();
    #[cfg(target_os = "linux")]
    {
        run("ip", &["link", "set", "dev", name, "up"])?;
        run(
            "ip",
            &["-6", "addr", "add", &format!("{}/7", addr_str), "dev", name],
        )?;
        // /7 on-link already covers 200::/7; add an explicit route to be safe.
        let _ = run("ip", &["-6", "route", "add", "200::/7", "dev", name]);
    }
    #[cfg(target_os = "macos")]
    {
        run(
            "ifconfig",
            &[name, "inet6", &addr_str, "prefixlen", "7", "up"],
        )?;
        let _ = run(
            "route",
            &["-q", "-n", "add", "-inet6", "200::/7", "-interface", name],
        );
    }
    Ok(())
}

// ============================================================================
// Packet helpers
// ============================================================================

/// Extract the 16-byte destination address from a raw IPv6 packet.
fn ipv6_dst(pkt: &[u8]) -> Option<[u8; 16]> {
    if pkt.len() < 40 || (pkt[0] >> 4) != 6 {
        return None;
    }
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&pkt[24..40]);
    Some(dst)
}

/// Reconstruct a (partial) public key from a Yggdrasil destination address,
/// suitable for a path lookup. Handles both `/128` node addresses (`0x02`)
/// and `/64` subnets (`0x03`).
fn key_for_dst(dst: &[u8; 16]) -> Option<PublicKey> {
    match dst[0] {
        0x02 => Some(Address(*dst).get_key()),
        0x03 => {
            let mut prefix = [0u8; 8];
            prefix.copy_from_slice(&dst[..8]);
            Some(Subnet(prefix).get_key())
        }
        _ => None,
    }
}

/// Wrap a raw IPv6 packet as a Yggdrasil session-traffic payload.
fn wrap_traffic(pkt: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + pkt.len());
    payload.push(TYPE_SESSION_TRAFFIC);
    payload.extend_from_slice(pkt);
    payload
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // ── Parse CLI: <peer:port>... [--seed <hex>] [--tun <name>] [--mtu <n>] ──
    let mut peer_addrs: Vec<String> = Vec::new();
    let mut seed_hex: Option<String> = None;
    let mut tun_name: Option<String> = None;
    let mut mtu: u16 = DEFAULT_MTU;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                seed_hex = args.get(i + 1).cloned();
                i += 2;
            }
            "--tun" => {
                tun_name = args.get(i + 1).cloned();
                i += 2;
            }
            "--mtu" => {
                mtu = args
                    .get(i + 1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(DEFAULT_MTU);
                i += 2;
            }
            other if !other.starts_with("--") => {
                peer_addrs.push(other.to_string());
                i += 1;
            }
            other => {
                eprintln!("Unknown option: {}", other);
                i += 1;
            }
        }
    }

    if peer_addrs.is_empty() {
        eprintln!(
            "Usage: sudo {} <peer1:port> [<peer2:port> ...] [--seed <hex>] [--tun <name>] [--mtu <n>]",
            args[0]
        );
        eprintln!();
        eprintln!("Bridges the Yggdrasil overlay to a kernel TUN interface (needs root).");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --seed <hex>  32-byte Ed25519 seed (64 hex chars). Random if omitted.");
        eprintln!("  --tun <name>  TUN interface name (Linux: ygg0; macOS: utunN).");
        eprintln!("  --mtu <n>     Interface MTU (default {}).", DEFAULT_MTU);
        std::process::exit(1);
    }

    // ── Key material ─────────────────────────────────────────────────────
    let mut seed = [0u8; 32];
    if let Some(hex_str) = &seed_hex {
        let bytes = hex::decode(hex_str).expect("invalid hex seed");
        assert_eq!(bytes.len(), 32, "seed must be 32 bytes (64 hex chars)");
        seed.copy_from_slice(&bytes);
        eprintln!("[KEY] Using provided seed");
    } else {
        OsRng.fill_bytes(&mut seed);
        eprintln!("[KEY] Generated random seed");
    }
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key: PublicKey = signing_key.verifying_key().to_bytes();

    // ── Create the node ──────────────────────────────────────────────────
    let config = LiteConfig::new(seed);
    let mut node = YggdrasilLite::new(config);
    let our_addr = node.address();
    let our_ipv6 = Ipv6Addr::from(our_addr.0);

    // ── Create + configure the TUN interface ─────────────────────────────
    let mut tun_config = tun::configure();
    tun_config.mtu(mtu).up();
    if let Some(name) = &tun_name {
        tun_config.tun_name(name);
    }
    #[cfg(target_os = "macos")]
    {
        // We assign the address and route ourselves below.
        tun_config.platform_config(|p| {
            p.enable_routing(false);
        });
    }
    #[cfg(target_os = "linux")]
    if tun_name.is_none() {
        tun_config.tun_name(DEFAULT_TUN_NAME);
    }

    let device = match tun::create(&tun_config) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[TUN]  Failed to create TUN device: {}", e);
            eprintln!("[TUN]  This example needs root. Try: sudo {} ...", args[0]);
            std::process::exit(1);
        }
    };
    let iface_name = device
        .tun_name()
        .unwrap_or_else(|_| tun_name.clone().unwrap_or_default());

    configure_interface(&iface_name, &our_ipv6)?;

    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  yggdrasil-lite ⇄ TUN bridge                                  ");
    eprintln!("╠══════════════════════════════════════════════════════════════╣");
    eprintln!("║  Public key: {}…", &hex::encode(public_key)[..16]);
    eprintln!("║  IPv6:       {}", our_ipv6);
    eprintln!("║  Interface:  {} (mtu {})", iface_name, mtu);
    for (i, addr) in peer_addrs.iter().enumerate() {
        eprintln!("║  Peer {}:     {}", i, addr);
    }
    eprintln!("╚══════════════════════════════════════════════════════════════╝");

    // ── Connect to all peers ─────────────────────────────────────────────
    let tls_config = Arc::new(create_tls_client_config());
    let password: &[u8] = b"";
    let our_meta = Metadata::new(public_key, 0);
    let meta_bytes = our_meta.encode(&signing_key, password);

    let mut peers: HashMap<PeerId, PeerConn> = HashMap::new();
    for peer_addr in &peer_addrs {
        match connect_peer(peer_addr, tls_config.clone(), &meta_bytes, password, &mut node) {
            Ok((pid, pc)) => {
                peers.insert(pid, pc);
            }
            Err(e) => eprintln!("[CONN] Failed to connect to {}: {}", peer_addr, e),
        }
    }
    if peers.is_empty() {
        return Err("No peers connected".into());
    }

    // ── Spawn the TUN reader thread (blocking reads → channel) ───────────
    // The reader and writer share the same fd; reads block in the thread while
    // the main loop writes from the other half.
    let (mut tun_reader, mut tun_writer) = device.split();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        loop {
            match tun_reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break; // main loop gone
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });

    // ── Initial poll: announce ourselves to peers ────────────────────────
    let events = node.poll(0, &mut OsRng);
    dispatch_send_events(&events, &mut peers);
    for pc in peers.values_mut() {
        while pc.tls.wants_write() {
            if pc.tls.write_tls(&mut pc.tcp).is_err() {
                break;
            }
        }
    }

    eprintln!();
    eprintln!("[INFO] Bridge is up. Try from this host:");
    eprintln!("         ping6 <a-yggdrasil-address>");
    eprintln!();

    // ── Event loop ───────────────────────────────────────────────────────
    // Pending outbound packets keyed by destination, awaiting key discovery.
    let mut pending: HashMap<Ipv6Addr, (Vec<Vec<u8>>, u64)> = HashMap::new();
    let start = Instant::now();
    let mut last_poll: u64 = 0;
    let mut last_status: u64 = 0;
    let mut disconnected: Vec<PeerId> = Vec::new();

    loop {
        let now_ms = start.elapsed().as_millis() as u64;
        let mut did_work = false;

        // ── 1. Read + decrypt from all peers ─────────────────────────────
        disconnected.clear();
        let peer_ids: Vec<PeerId> = peers.keys().copied().collect();
        let mut peer_data: Vec<(PeerId, Vec<u8>)> = Vec::new();

        for &pid in &peer_ids {
            let pc = peers.get_mut(&pid).unwrap();
            match pc.tls.read_tls(&mut pc.tcp) {
                Ok(0) => {
                    eprintln!("[CONN] Peer {} disconnected (EOF)", pc.addr);
                    disconnected.push(pid);
                    continue;
                }
                Ok(_) => {
                    if let Err(e) = pc.tls.process_new_packets() {
                        eprintln!("[TLS] Peer {} error: {}", pc.addr, e);
                        disconnected.push(pid);
                        continue;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    eprintln!("[CONN] Peer {} read error: {}", pc.addr, e);
                    disconnected.push(pid);
                    continue;
                }
            }

            let mut accum = Vec::new();
            loop {
                match pc.tls.reader().read(&mut pc.tls_read_buf) {
                    Ok(0) => break,
                    Ok(n) => accum.extend_from_slice(&pc.tls_read_buf[..n]),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
            if !accum.is_empty() {
                peer_data.push((pid, accum));
            }
        }

        // ── 2. Feed peer data to the node; route events ──────────────────
        for (pid, data) in &peer_data {
            let events = node.handle_peer_data(*pid, data, now_ms, &mut OsRng);
            for ev in &events {
                match ev {
                    NodeEvent::SendToPeer { peer_id, data } => {
                        send_to_peer(&mut peers, *peer_id, data);
                    }
                    NodeEvent::Deliver { source, data } => {
                        if data.len() > 1 && data[0] == TYPE_SESSION_TRAFFIC {
                            let ipv6_packet = &data[1..];
                            // Write the decrypted IPv6 packet to the kernel.
                            if let Err(e) = tun_writer.write_all(ipv6_packet) {
                                eprintln!("[TUN]  write error: {}", e);
                            }
                            let src = Ipv6Addr::from(addr_for_key(source).0);
                            eprintln!("[RECV] {} bytes from {}", ipv6_packet.len(), src);
                        }
                    }
                }
            }
            did_work = true;
        }

        // Remove disconnected peers.
        for pid in &disconnected {
            node.remove_peer(*pid);
            if let Some(pc) = peers.remove(pid) {
                eprintln!("[CONN] Removed peer {} (id={})", pc.addr, pid);
            }
        }
        if peers.is_empty() {
            eprintln!("[CONN] All peers disconnected, exiting");
            break;
        }

        // ── 3. Read outbound packets from the TUN ────────────────────────
        while let Ok(pkt) = rx.try_recv() {
            did_work = true;
            let dst = match ipv6_dst(&pkt) {
                Some(d) => d,
                None => continue,
            };
            // Only Yggdrasil-range destinations (200::/7).
            if dst[0] != 0x02 && dst[0] != 0x03 {
                continue;
            }
            let dst_ip = Ipv6Addr::from(dst);

            if let Some(dest_key) = node.resolve(&dst) {
                let events = node.send(&dest_key, &wrap_traffic(&pkt), now_ms, &mut OsRng);
                dispatch_send_events(&events, &mut peers);
            } else {
                // Queue the packet and (re)issue a path lookup.
                let entry = pending.entry(dst_ip).or_insert_with(|| (Vec::new(), 0));
                if entry.0.len() < MAX_PENDING_PER_DEST {
                    entry.0.push(pkt);
                }
                if now_ms.saturating_sub(entry.1) >= LOOKUP_INTERVAL_MS {
                    entry.1 = now_ms;
                    if let Some(partial) = key_for_dst(&dst) {
                        eprintln!("[LKUP] resolving {} …", dst_ip);
                        let events = node.lookup(&partial, now_ms);
                        dispatch_send_events(&events, &mut peers);
                    }
                }
            }
        }

        // ── 4. Flush any pending packets whose key we now know ───────────
        if !pending.is_empty() {
            let resolved: Vec<Ipv6Addr> = pending
                .keys()
                .filter(|ip| node.resolve(&ip.octets()).is_some())
                .copied()
                .collect();
            for ip in resolved {
                let dest_key = node.resolve(&ip.octets()).unwrap();
                if let Some((queued, _)) = pending.remove(&ip) {
                    eprintln!(
                        "[LKUP] resolved {} → sending {} queued packet(s)",
                        ip,
                        queued.len()
                    );
                    for pkt in queued {
                        let events = node.send(&dest_key, &wrap_traffic(&pkt), now_ms, &mut OsRng);
                        dispatch_send_events(&events, &mut peers);
                    }
                    did_work = true;
                }
            }
        }

        // ── 5. Periodic node maintenance ─────────────────────────────────
        if now_ms.saturating_sub(last_poll) >= 100 {
            last_poll = now_ms;
            let events = node.poll(now_ms, &mut OsRng);
            if !events.is_empty() {
                dispatch_send_events(&events, &mut peers);
                did_work = true;
            }
        }

        // ── 6. Flush all peers' TLS write buffers ────────────────────────
        for pc in peers.values_mut() {
            while pc.tls.wants_write() {
                match pc.tls.write_tls(&mut pc.tcp) {
                    Ok(_) => {}
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        eprintln!("[TLS] Peer {} write error: {}", pc.addr, e);
                        break;
                    }
                }
            }
        }

        // ── 7. Status ────────────────────────────────────────────────────
        if now_ms.saturating_sub(last_status) >= 30_000 {
            last_status = now_ms;
            eprintln!(
                "[STAT] uptime={}s peers={} sessions={} paths={} pending={}",
                now_ms / 1000,
                node.peer_count(),
                node.session_count(),
                node.path_count(),
                pending.len(),
            );
        }

        if !did_work {
            thread::sleep(Duration::from_millis(5));
        }
    }

    Ok(())
}
