//! yggdrasil-lite integration test: connects to a yggdrasil-ng node and
//! serves a tiny HTTP "Hello, World!" endpoint on the Yggdrasil overlay.
//!
//! # Usage
//!
//! 1. Start a yggdrasil-ng node:
//!    ```sh
//!    cargo run -p yggdrasil -- --config yggdrasil.conf --loglevel debug
//!    ```
//!    Note the TLS listen address from the logs.
//!
//! 2. Run this example (connecting to the yggdrasil-ng node):
//!    ```sh
//!    cargo run --example lite_node -p yggdrasil-lite -- 127.0.0.1:<port>
//!    ```
//!    It will print its Yggdrasil IPv6 address.
//!
//! 3. From the yggdrasil-ng machine, test with curl:
//!    ```sh
//!    curl -6 --max-time 30 http://[<lite_ipv6>]:80/hello
//!    ```
//!
//! The lite node handles IPv6/TCP in userspace (no TUN required), making it
//! runnable on the same machine as the full node without routing conflicts.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConnection, DigitallySignedStruct, Error as TlsError, SignatureScheme};

use yggdrasil_lite::address::addr_for_key;
use yggdrasil_lite::crypto::PublicKey;
use yggdrasil_lite::meta::Metadata;
use yggdrasil_lite::node::{LiteConfig, NodeEvent, YggdrasilLite};

// ============================================================================
// Constants
// ============================================================================

/// Session type byte prepended to IPv6 packets (matches yggdrasil core.rs).
const TYPE_SESSION_TRAFFIC: u8 = 0x01;

/// HTTP response body.
const HTTP_BODY: &[u8] = b"Hello, World!\n";

#[cfg(not(feature = "smoltcp"))]
mod minitcp_consts {
    /// TCP flags.
    pub const TCP_FIN: u8 = 0x01;
    pub const TCP_SYN: u8 = 0x02;
    pub const TCP_RST: u8 = 0x04;
    pub const TCP_PSH: u8 = 0x08;
    pub const TCP_ACK: u8 = 0x10;
}
#[cfg(not(feature = "smoltcp"))]
use minitcp_consts::*;

/// Our HTTP listen port.
const HTTP_PORT: u16 = 80;

// ============================================================================
// TLS support (accept all server certificates — auth is via Yggdrasil metadata)
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
    let mut config =
        rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&TLS13])
            .expect("TLS config")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
            .with_no_client_auth();
    config.alpn_protocols = vec![];
    config
}

/// Drive the TLS handshake to completion (blocking).
fn complete_tls_handshake(
    tls: &mut ClientConnection,
    tcp: &mut TcpStream,
) -> io::Result<()> {
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

// ============================================================================
// Minimal userspace IPv6 + TCP stack (just enough for one HTTP req/res)
// ============================================================================

#[cfg(not(feature = "smoltcp"))]
/// Parsed IPv6 header (always 40 bytes, no extensions supported).
#[allow(dead_code)]
struct Ipv6Header {
    src: [u8; 16],
    dst: [u8; 16],
    payload_len: u16,
    next_header: u8,
    hop_limit: u8,
}

#[cfg(not(feature = "smoltcp"))]
/// Parsed TCP header.
#[allow(dead_code)]
struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    data_offset: u8, // in 32-bit words
    flags: u8,
    window: u16,
}

#[cfg(not(feature = "smoltcp"))]
fn parse_ipv6(data: &[u8]) -> Option<(Ipv6Header, &[u8])> {
    if data.len() < 40 {
        return None;
    }
    let version = data[0] >> 4;
    if version != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&data[8..24]);
    dst.copy_from_slice(&data[24..40]);
    let payload_end = 40 + payload_len as usize;
    if data.len() < payload_end {
        return None;
    }
    Some((
        Ipv6Header {
            src,
            dst,
            payload_len,
            next_header,
            hop_limit,
        },
        &data[40..payload_end],
    ))
}

#[cfg(not(feature = "smoltcp"))]
fn parse_tcp(data: &[u8]) -> Option<(TcpHeader, &[u8])> {
    if data.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = data[12] >> 4;
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    let header_len = (data_offset as usize) * 4;
    if data.len() < header_len {
        return None;
    }
    Some((
        TcpHeader {
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            flags,
            window,
        },
        &data[header_len..],
    ))
}

#[cfg(not(feature = "smoltcp"))]
/// Compute TCP checksum with IPv6 pseudo-header.
fn tcp_checksum_ipv6(src: &[u8; 16], dst: &[u8; 16], tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // Pseudo-header: src addr
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
    }
    // Pseudo-header: dst addr
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
    }
    // Pseudo-header: TCP length (u32 BE)
    let tcp_len = tcp_segment.len() as u32;
    sum += (tcp_len >> 16) as u32;
    sum += (tcp_len & 0xFFFF) as u32;
    // Pseudo-header: next header = 6 (TCP)
    sum += 6u32;
    // TCP segment (skip checksum field at offset 16-17)
    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        // Skip the checksum field itself (bytes 16-17)
        if i == 16 {
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }
    // Fold carries
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(not(feature = "smoltcp"))]
/// Build an IPv6+TCP response packet.
fn build_ipv6_tcp(
    src_addr: &[u8; 16],
    dst_addr: &[u8; 16],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    tcp_options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let tcp_header_len = 20 + tcp_options.len();
    // Pad to 4-byte boundary
    let tcp_header_padded = (tcp_header_len + 3) & !3;
    let tcp_data_offset = (tcp_header_padded / 4) as u8;
    let tcp_segment_len = tcp_header_padded + payload.len();

    // Build TCP segment (with checksum placeholder)
    let mut tcp_seg = Vec::with_capacity(tcp_segment_len);
    tcp_seg.extend_from_slice(&src_port.to_be_bytes());
    tcp_seg.extend_from_slice(&dst_port.to_be_bytes());
    tcp_seg.extend_from_slice(&seq.to_be_bytes());
    tcp_seg.extend_from_slice(&ack.to_be_bytes());
    tcp_seg.push(tcp_data_offset << 4);
    tcp_seg.push(flags);
    tcp_seg.extend_from_slice(&65535u16.to_be_bytes()); // window
    tcp_seg.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    tcp_seg.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
    tcp_seg.extend_from_slice(tcp_options);
    // Pad to 4-byte boundary with NOP (kind=1)
    while tcp_seg.len() < 20 + tcp_header_padded - 20 + 20 {
        // Hmm, this is wrong. Let me recalculate.
        break;
    }
    // Pad TCP header to tcp_header_padded length
    while tcp_seg.len() < tcp_header_padded {
        tcp_seg.push(0); // NOP padding
    }
    tcp_seg.extend_from_slice(payload);

    // Compute checksum
    let cksum = tcp_checksum_ipv6(src_addr, dst_addr, &tcp_seg);
    tcp_seg[16] = (cksum >> 8) as u8;
    tcp_seg[17] = (cksum & 0xFF) as u8;

    // Build IPv6 header + TCP segment
    let mut pkt = Vec::with_capacity(40 + tcp_seg.len());
    // Version=6, traffic class=0, flow label=0
    pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    // Payload length
    pkt.extend_from_slice(&(tcp_seg.len() as u16).to_be_bytes());
    // Next header = TCP(6), hop limit = 64
    pkt.push(6);
    pkt.push(64);
    pkt.extend_from_slice(src_addr);
    pkt.extend_from_slice(dst_addr);
    pkt.extend_from_slice(&tcp_seg);

    pkt
}

// ============================================================================
// Mini TCP connection state machine
// ============================================================================

#[cfg(not(feature = "smoltcp"))]
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum TcpState {
    Listen,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    Closed,
}

#[cfg(not(feature = "smoltcp"))]
struct MiniTcp {
    our_addr: [u8; 16],
    state: TcpState,
    // Connection 4-tuple
    remote_addr: [u8; 16],
    remote_port: u16,
    local_port: u16,
    // Sequence numbers
    our_seq: u32,
    their_seq: u32, // next expected from them (= our ACK value)
    // Buffered HTTP request
    http_buf: Vec<u8>,
}

#[cfg(not(feature = "smoltcp"))]
impl MiniTcp {
    fn new(our_addr: [u8; 16], listen_port: u16) -> Self {
        let mut isn = [0u8; 4];
        OsRng.fill_bytes(&mut isn);
        Self {
            our_addr,
            state: TcpState::Listen,
            remote_addr: [0; 16],
            remote_port: 0,
            local_port: listen_port,
            our_seq: u32::from_be_bytes(isn),
            their_seq: 0,
            http_buf: Vec::new(),
        }
    }

    /// Process an incoming IPv6 packet. Returns response packets (if any).
    fn handle_packet(&mut self, ipv6_packet: &[u8]) -> Vec<Vec<u8>> {
        let mut responses = Vec::new();

        let (ip, tcp_data) = match parse_ipv6(ipv6_packet) {
            Some(v) => v,
            None => return responses,
        };

        // Only handle TCP
        if ip.next_header != 6 {
            return responses;
        }

        let (tcp, payload) = match parse_tcp(tcp_data) {
            Some(v) => v,
            None => return responses,
        };

        // Only accept packets to our listen port
        if tcp.dst_port != self.local_port {
            return responses;
        }

        match self.state {
            TcpState::Listen => {
                if tcp.flags & TCP_SYN != 0 && tcp.flags & TCP_ACK == 0 {
                    // SYN received → send SYN+ACK
                    self.remote_addr = ip.src;
                    self.remote_port = tcp.src_port;
                    self.their_seq = tcp.seq.wrapping_add(1); // SYN consumes 1

                    // MSS option: kind=2, len=4, MSS=1440
                    let mss_opt = [0x02, 0x04, 0x05, 0xA0];

                    let pkt = build_ipv6_tcp(
                        &self.our_addr,
                        &self.remote_addr,
                        self.local_port,
                        self.remote_port,
                        self.our_seq,
                        self.their_seq,
                        TCP_SYN | TCP_ACK,
                        &mss_opt,
                        &[],
                    );
                    self.our_seq = self.our_seq.wrapping_add(1); // SYN consumes 1
                    self.state = TcpState::SynReceived;
                    // SYN → SYN+ACK
                    responses.push(pkt);
                }
            }

            TcpState::SynReceived => {
                if tcp.flags & TCP_ACK != 0 && tcp.flags & TCP_SYN == 0 {
                    self.state = TcpState::Established;
                    // Connection established

                    // There might be data with this ACK
                    if !payload.is_empty() {
                        self.http_buf.extend_from_slice(payload);
                        self.their_seq = self.their_seq.wrapping_add(payload.len() as u32);
                        // Check if HTTP request is complete
                        if let Some(resp_pkts) = self.try_respond_http() {
                            responses.extend(resp_pkts);
                        }
                    }
                }
            }

            TcpState::Established => {
                if tcp.flags & TCP_RST != 0 {
                    // RST received
                    self.reset();
                    return responses;
                }

                if !payload.is_empty() {
                    self.http_buf.extend_from_slice(payload);
                    self.their_seq = self.their_seq.wrapping_add(payload.len() as u32);

                    // Send ACK for received data
                    let ack_pkt = build_ipv6_tcp(
                        &self.our_addr,
                        &self.remote_addr,
                        self.local_port,
                        self.remote_port,
                        self.our_seq,
                        self.their_seq,
                        TCP_ACK,
                        &[],
                        &[],
                    );
                    responses.push(ack_pkt);

                    // Check if HTTP request is complete
                    if let Some(resp_pkts) = self.try_respond_http() {
                        responses.extend(resp_pkts);
                    }
                }

                // Handle FIN from client
                if tcp.flags & TCP_FIN != 0 {
                    self.their_seq = self.their_seq.wrapping_add(1); // FIN consumes 1
                    let ack_pkt = build_ipv6_tcp(
                        &self.our_addr,
                        &self.remote_addr,
                        self.local_port,
                        self.remote_port,
                        self.our_seq,
                        self.their_seq,
                        TCP_ACK,
                        &[],
                        &[],
                    );
                    responses.push(ack_pkt);
                    // Client FIN
                    self.reset();
                }
            }

            TcpState::FinWait1 => {
                // We sent FIN, waiting for ACK
                if tcp.flags & TCP_ACK != 0 {
                    if tcp.flags & TCP_FIN != 0 {
                        // Simultaneous close: ACK+FIN
                        self.their_seq = self.their_seq.wrapping_add(1);
                        let ack_pkt = build_ipv6_tcp(
                            &self.our_addr,
                            &self.remote_addr,
                            self.local_port,
                            self.remote_port,
                            self.our_seq,
                            self.their_seq,
                            TCP_ACK,
                            &[],
                            &[],
                        );
                        responses.push(ack_pkt);
                        // FIN+ACK received
                        self.reset();
                    } else {
                        self.state = TcpState::FinWait2;
                    }
                }
            }

            TcpState::FinWait2 => {
                if tcp.flags & TCP_FIN != 0 {
                    self.their_seq = self.their_seq.wrapping_add(1);
                    let ack_pkt = build_ipv6_tcp(
                        &self.our_addr,
                        &self.remote_addr,
                        self.local_port,
                        self.remote_port,
                        self.our_seq,
                        self.their_seq,
                        TCP_ACK,
                        &[],
                        &[],
                    );
                    responses.push(ack_pkt);
                    // FIN received
                    self.reset();
                }
            }

            TcpState::Closed => {}
        }

        responses
    }

    /// Check if the buffered HTTP request is complete and send a response.
    fn try_respond_http(&mut self) -> Option<Vec<Vec<u8>>> {
        // HTTP request ends with \r\n\r\n
        let req = String::from_utf8_lossy(&self.http_buf);
        if !req.contains("\r\n\r\n") {
            return None;
        }

        // Log the request line
        if let Some(line) = req.lines().next() {
            eprintln!("[HTTP] {}", line);
        }

        // Build HTTP response
        let http_response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            HTTP_BODY.len()
        );
        let mut response_data = http_response.into_bytes();
        response_data.extend_from_slice(HTTP_BODY);

        // Send response with PSH+ACK+FIN
        let pkt = build_ipv6_tcp(
            &self.our_addr,
            &self.remote_addr,
            self.local_port,
            self.remote_port,
            self.our_seq,
            self.their_seq,
            TCP_PSH | TCP_ACK | TCP_FIN,
            &[],
            &response_data,
        );
        self.our_seq = self.our_seq.wrapping_add(response_data.len() as u32 + 1); // data + FIN
        self.state = TcpState::FinWait1;
        eprintln!("[HTTP] Sent {} bytes response", response_data.len());

        Some(vec![pkt])
    }

    /// Reset the connection state to listen for a new connection.
    fn reset(&mut self) {
        self.state = TcpState::Listen;
        self.remote_addr = [0; 16];
        self.remote_port = 0;
        self.http_buf.clear();
        let mut isn = [0u8; 4];
        OsRng.fill_bytes(&mut isn);
        self.our_seq = u32::from_be_bytes(isn);
        self.their_seq = 0;
    }
}

// ============================================================================
// Address helpers
// ============================================================================

fn format_ipv6(addr: &[u8; 16]) -> Ipv6Addr {
    Ipv6Addr::from(*addr)
}

fn bytes_to_ipv6(addr: &[u8; 16]) -> Ipv6Addr {
    Ipv6Addr::from(*addr)
}

/// Extract destination IPv6 from a raw IPv6 packet and look up the public key.
fn get_dest_key_from_ipv6(pkt: &[u8], map: &HashMap<Ipv6Addr, PublicKey>) -> Option<PublicKey> {
    if pkt.len() < 40 {
        return None;
    }
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&pkt[24..40]);
    let dst_ipv6 = Ipv6Addr::from(dst);
    map.get(&dst_ipv6).copied()
}

// ============================================================================
// smoltcp Device implementation
// ============================================================================

#[cfg(feature = "smoltcp")]
mod ygg_device {
    use std::collections::VecDeque;

    use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
    use smoltcp::time::Instant as SmolInstant;

    pub struct YggDevice {
        rx_queue: VecDeque<Vec<u8>>,
        tx_queue: VecDeque<Vec<u8>>,
    }

    impl YggDevice {
        pub fn new() -> Self {
            Self {
                rx_queue: VecDeque::new(),
                tx_queue: VecDeque::new(),
            }
        }

        /// Enqueue an inbound IPv6 packet (from Yggdrasil Deliver event).
        pub fn push_rx(&mut self, pkt: Vec<u8>) {
            self.rx_queue.push_back(pkt);
        }

        /// Drain all outbound packets (to send via Yggdrasil).
        pub fn drain_tx(&mut self) -> impl Iterator<Item = Vec<u8>> + '_ {
            self.tx_queue.drain(..)
        }
    }

    pub struct YggRxToken(Vec<u8>);

    impl RxToken for YggRxToken {
        fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
            f(&self.0)
        }
    }

    pub struct YggTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

    impl<'a> TxToken for YggTxToken<'a> {
        fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
            let mut buf = vec![0u8; len];
            let r = f(&mut buf);
            self.0.push_back(buf);
            r
        }
    }

    impl Device for YggDevice {
        type RxToken<'a> = YggRxToken;
        type TxToken<'a> = YggTxToken<'a>;

        fn receive(
            &mut self,
            _timestamp: SmolInstant,
        ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            let data = self.rx_queue.pop_front()?;
            Some((YggRxToken(data), YggTxToken(&mut self.tx_queue)))
        }

        fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
            Some(YggTxToken(&mut self.tx_queue))
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut caps = DeviceCapabilities::default();
            caps.max_transmission_unit = 65535;
            caps.medium = Medium::Ip;
            caps
        }
    }
}

#[cfg(feature = "smoltcp")]
use ygg_device::YggDevice;

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <peer_addr:port> [--seed <hex_seed>]", args[0]);
        eprintln!();
        eprintln!("Connects to a yggdrasil-ng node and serves HTTP on the overlay.");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --seed <hex>  Use a specific 32-byte Ed25519 seed (64 hex chars)");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  {} 127.0.0.1:12345", args[0]);
        eprintln!("  {} 127.0.0.1:12345 --seed abcdef0123...", args[0]);
        std::process::exit(1);
    }
    let peer_addr = &args[1];

    // ── Generate or load Ed25519 keypair ─────────────────────────────────
    let mut seed = [0u8; 32];
    if let Some(pos) = args.iter().position(|a| a == "--seed") {
        if let Some(hex_str) = args.get(pos + 1) {
            let bytes = hex::decode(hex_str).expect("invalid hex seed");
            assert_eq!(bytes.len(), 32, "seed must be 32 bytes (64 hex chars)");
            seed.copy_from_slice(&bytes);
            eprintln!("[KEY] Using provided seed");
        } else {
            eprintln!("--seed requires a hex argument");
            std::process::exit(1);
        }
    } else {
        OsRng.fill_bytes(&mut seed);
        eprintln!("[KEY] Generated random seed");
    }
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key: PublicKey = signing_key.verifying_key().to_bytes();

    // ── Create yggdrasil-lite node ───────────────────────────────────────
    let config = LiteConfig::new(seed);
    let mut node = YggdrasilLite::new(config);
    let our_addr = node.address();

    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  yggdrasil-lite integration test                            ║");
    eprintln!("╠══════════════════════════════════════════════════════════════╣");
    eprintln!("║  Public key: {}…", &hex::encode(&public_key)[..16]);
    eprintln!("║  IPv6:       {}", format_ipv6(&our_addr.0));
    eprintln!("║  Peer:       {}", peer_addr);
    eprintln!("╚══════════════════════════════════════════════════════════════╝");

    // ── TCP connect ──────────────────────────────────────────────────────
    let mut tcp = TcpStream::connect(peer_addr)?;
    tcp.set_nodelay(true)?;
    eprintln!("[CONN] TCP connected to {}", peer_addr);

    // ── TLS handshake ────────────────────────────────────────────────────
    let tls_config = create_tls_client_config();
    let server_name = ServerName::try_from("yggdrasil")
        .map_err(|e| format!("invalid server name: {}", e))?;
    let mut tls = ClientConnection::new(Arc::new(tls_config), server_name)?;
    complete_tls_handshake(&mut tls, &mut tcp)?;
    eprintln!("[CONN] TLS handshake complete");

    // ── Metadata handshake ───────────────────────────────────────────────
    let password: &[u8] = b"";
    let our_meta = Metadata::new(public_key, 0);
    let meta_bytes = our_meta.encode(&signing_key, password);

    // Send our metadata
    tls.writer().write_all(&meta_bytes)?;
    while tls.wants_write() {
        tls.write_tls(&mut tcp)?;
    }
    eprintln!("[META] Sent metadata ({} bytes)", meta_bytes.len());

    // Read peer metadata
    let peer_id;
    let mut meta_accum = Vec::new();
    loop {
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
                // Try to decode
                match Metadata::decode(&meta_accum, password) {
                    Ok((peer_meta, consumed)) => {
                        if !peer_meta.check() {
                            return Err("Incompatible protocol version".into());
                        }
                        eprintln!(
                            "[META] Peer key: {}…",
                            &hex::encode(&peer_meta.public_key)[..16]
                        );

                        // Register peer with yggdrasil-lite
                        let pid = node.add_peer(peer_meta.public_key, 0);
                        node.mark_handshake_done(pid);
                        peer_id = pid;
                        eprintln!("[META] Peer registered (id={})", pid);

                        // Any leftover bytes after metadata go into the frame buffer
                        if meta_accum.len() > consumed {
                            let leftover = meta_accum[consumed..].to_vec();
                            let events = node.handle_peer_data(
                                pid,
                                &leftover,
                                0,
                                &mut OsRng,
                            );
                            // Process events (just writes for now)
                            for ev in &events {
                                if let NodeEvent::SendToPeer { data, .. } = ev {
                                    let _ = tls.writer().write_all(data);
                                }
                            }
                            while tls.wants_write() {
                                let _ = tls.write_tls(&mut tcp);
                            }
                        }
                        break;
                    }
                    Err(yggdrasil_lite::meta::MetaError::TooShort)
                    | Err(yggdrasil_lite::meta::MetaError::BufferTooSmall) => {
                        // Need more data
                        continue;
                    }
                    Err(e) => return Err(format!("Metadata decode error: {:?}", e).into()),
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Read more TLS data
                if tls.wants_read() {
                    tls.read_tls(&mut tcp)?;
                    tls.process_new_packets()
                        .map_err(|e| format!("TLS error: {}", e))?;
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    // ── Switch to non-blocking for the event loop ────────────────────────
    tcp.set_nonblocking(true)?;

    // IPv6 → PublicKey routing table (built from received packets)
    let mut addr_to_key: HashMap<Ipv6Addr, PublicKey> = HashMap::new();

    // ── Drain any TLS-buffered data from the metadata handshake ──────────
    // The TLS reader may have decrypted ironwood frames that arrived alongside
    // the metadata.  Process them now so we reply promptly.
    {
        let mut drain_buf = vec![0u8; 65536];
        loop {
            match tls.reader().read(&mut drain_buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let events =
                        node.handle_peer_data(peer_id, &drain_buf[..n], 0, &mut OsRng);
                    for ev in &events {
                        if let NodeEvent::SendToPeer { data, .. } = ev {
                            let _ = tls.writer().write_all(data);
                        }
                    }
                }
            }
        }
    }

    // ── Run initial poll immediately so we send SigReq + Bloom + KeepAlive
    {
        let events = node.poll(0, &mut OsRng);
        for ev in &events {
            if let NodeEvent::SendToPeer { data, .. } = ev {
                let _ = tls.writer().write_all(data);
            }
        }
    }

    // ── Flush everything written so far ──────────────────────────────────
    while tls.wants_write() {
        match tls.write_tls(&mut tcp) {
            Ok(_) => {}
            Err(_) => break,
        }
    }

    eprintln!();
    eprintln!("[HTTP] Listening on [{}]:{}", format_ipv6(&our_addr.0), HTTP_PORT);
    eprintln!("[INFO] From the yggdrasil-ng host, run:");
    eprintln!("         curl -6 --max-time 30 http://[{}]:{}/hello", format_ipv6(&our_addr.0), HTTP_PORT);
    eprintln!();

    // ── Event loop ───────────────────────────────────────────────────────

    #[cfg(not(feature = "smoltcp"))]
    {
        let mut mini_tcp = MiniTcp::new(our_addr.0, HTTP_PORT);
        let start = Instant::now();
        let mut last_poll: u64 = 0;
        let mut last_status: u64 = 0;
        let mut tls_read_buf = vec![0u8; 65536];

        loop {
            let now_ms = start.elapsed().as_millis() as u64;
            let mut did_work = false;

            // ── 1. Read new TLS records from TCP
            match tls.read_tls(&mut tcp) {
                Ok(0) => {
                    eprintln!("[CONN] Peer disconnected (EOF)");
                    break;
                }
                Ok(_n) => {
                    match tls.process_new_packets() {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("[TLS] Error: {}", e);
                            break;
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    eprintln!("[CONN] Read error: {}", e);
                    break;
                }
            }

            // ── 2. Consume decrypted data from TLS reader
            loop {
                match tls.reader().read(&mut tls_read_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let events = node.handle_peer_data(
                            peer_id,
                            &tls_read_buf[..n],
                            now_ms,
                            &mut OsRng,
                        );
                        process_events(
                            &events,
                            &mut tls,
                            &mut tcp,
                            &mut mini_tcp,
                            &mut addr_to_key,
                            &mut node,
                            now_ms,
                        );
                        did_work = true;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }

            // ── 3. Periodic node poll
            if now_ms.saturating_sub(last_poll) >= 100 {
                last_poll = now_ms;
                let events = node.poll(now_ms, &mut OsRng);
                if !events.is_empty() {
                    for ev in &events {
                        if let NodeEvent::SendToPeer { data, .. } = ev {
                            let _ = tls.writer().write_all(data);
                        }
                    }
                    did_work = true;
                }
            }

            // ── 4. Flush TLS write buffer
            while tls.wants_write() {
                match tls.write_tls(&mut tcp) {
                    Ok(_) => {}
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        eprintln!("[TLS] Write error: {}", e);
                        break;
                    }
                }
            }

            // ── 5. Status output
            if now_ms.saturating_sub(last_status) >= 30_000 {
                last_status = now_ms;
                eprintln!(
                    "[STATUS] uptime={}s peers={} sessions={} paths={} routes={}",
                    now_ms / 1000,
                    node.peer_count(),
                    node.session_count(),
                    node.path_count(),
                    addr_to_key.len(),
                );
            }

            if !did_work {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    #[cfg(feature = "smoltcp")]
    {
        use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet, SocketStorage};
        use smoltcp::socket::tcp;
        use smoltcp::time::Instant as SmolInstant;
        use smoltcp::wire::{HardwareAddress, IpCidr, Ipv6Address};

        let mut device = YggDevice::new();

        // Configure smoltcp interface
        let mut config = IfaceConfig::new(HardwareAddress::Ip);
        config.random_seed = rand::random();

        let mut iface = Interface::new(config, &mut device, SmolInstant::now());

        // Set our Yggdrasil IPv6 address with /7 prefix
        let local_ip = Ipv6Address::from(our_addr.0);
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(local_ip.into(), 7)).unwrap();
        });

        // Create TCP socket with 4KB buffers
        let tcp_rx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
        let tcp_tx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
        let tcp_socket = tcp::Socket::new(tcp_rx_buf, tcp_tx_buf);

        let mut socket_storage = [SocketStorage::EMPTY];
        let mut sockets = SocketSet::new(&mut socket_storage[..]);
        let tcp_handle = sockets.add(tcp_socket);

        // Start listening
        sockets
            .get_mut::<tcp::Socket>(tcp_handle)
            .listen(HTTP_PORT)
            .unwrap();
        eprintln!("[SMOL] TCP listening on port {}", HTTP_PORT);

        let start = Instant::now();
        let mut last_poll: u64 = 0;
        let mut last_status: u64 = 0;
        let mut tls_read_buf = vec![0u8; 65536];
        let mut http_buf: Vec<u8> = Vec::new();

        loop {
            let now_ms = start.elapsed().as_millis() as u64;
            let smol_now = SmolInstant::now();
            let mut did_work = false;

            // ── 1. Read new TLS records from TCP
            match tls.read_tls(&mut tcp) {
                Ok(0) => {
                    eprintln!("[CONN] Peer disconnected (EOF)");
                    break;
                }
                Ok(_n) => {
                    match tls.process_new_packets() {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("[TLS] Error: {}", e);
                            break;
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    eprintln!("[CONN] Read error: {}", e);
                    break;
                }
            }

            // ── 2. Consume decrypted data → route events
            loop {
                match tls.reader().read(&mut tls_read_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let events = node.handle_peer_data(
                            peer_id,
                            &tls_read_buf[..n],
                            now_ms,
                            &mut OsRng,
                        );
                        for event in &events {
                            match event {
                                NodeEvent::SendToPeer { data, .. } => {
                                    let _ = tls.writer().write_all(data);
                                    while tls.wants_write() {
                                        match tls.write_tls(&mut tcp) {
                                            Ok(_) => {}
                                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                                            Err(_) => break,
                                        }
                                    }
                                }
                                NodeEvent::Deliver { source, data } => {
                                    if data.len() > 1 && data[0] == TYPE_SESSION_TRAFFIC {
                                        let ipv6_packet = &data[1..];

                                        // Record source key → IPv6 mapping
                                        let source_addr = addr_for_key(source);
                                        let source_ipv6 = bytes_to_ipv6(&source_addr.0);
                                        addr_to_key.insert(source_ipv6, *source);

                                        eprintln!(
                                            "[RECV] {} bytes from {}",
                                            ipv6_packet.len(),
                                            source_ipv6
                                        );

                                        // Feed to smoltcp — ICMPv6 handled automatically
                                        device.push_rx(ipv6_packet.to_vec());
                                    } else if !data.is_empty() {
                                        eprintln!(
                                            "[RECV] Non-traffic data ({} bytes, type=0x{:02x})",
                                            data.len(),
                                            data[0]
                                        );
                                    }
                                }
                            }
                        }
                        did_work = true;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }

            // ── 3. smoltcp poll (processes rx, generates tx)
            iface.poll(smol_now, &mut device, &mut sockets);

            // ── 4. Drain outbound packets → send via Yggdrasil
            for pkt in device.drain_tx() {
                if let Some(dest_key) = get_dest_key_from_ipv6(&pkt, &addr_to_key) {
                    let mut payload = Vec::with_capacity(1 + pkt.len());
                    payload.push(TYPE_SESSION_TRAFFIC);
                    payload.extend_from_slice(&pkt);

                    let send_events = node.send(&dest_key, &payload, now_ms, &mut OsRng);
                    for sev in &send_events {
                        if let NodeEvent::SendToPeer { data, .. } = sev {
                            let _ = tls.writer().write_all(data);
                            while tls.wants_write() {
                                match tls.write_tls(&mut tcp) {
                                    Ok(_) => {}
                                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                    did_work = true;
                }
            }

            // ── 5. HTTP serving on TCP socket
            {
                let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);

                // Read incoming data
                if socket.can_recv() {
                    let mut tmp = [0u8; 1024];
                    if let Ok(n) = socket.recv_slice(&mut tmp) {
                        if n > 0 {
                            http_buf.extend_from_slice(&tmp[..n]);
                        }
                    }
                }

                // Check if HTTP request is complete
                if http_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let req = String::from_utf8_lossy(&http_buf);
                    if let Some(line) = req.lines().next() {
                        eprintln!("[HTTP] {}", line);
                    }

                    let response = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: text/plain\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\
                         \r\n",
                        HTTP_BODY.len()
                    );
                    let _ = socket.send_slice(response.as_bytes());
                    let _ = socket.send_slice(HTTP_BODY);
                    socket.close(); // initiate FIN
                    http_buf.clear();
                    eprintln!("[HTTP] Sent response");
                    did_work = true;
                }

                // Re-listen when connection fully closed
                if !socket.is_active() && !socket.is_listening() {
                    socket.abort();
                    let _ = socket.listen(HTTP_PORT);
                }
            }

            // ── 6. Second smoltcp poll (flushes TCP responses)
            iface.poll(smol_now, &mut device, &mut sockets);

            // Drain tx again after second poll
            for pkt in device.drain_tx() {
                if let Some(dest_key) = get_dest_key_from_ipv6(&pkt, &addr_to_key) {
                    let mut payload = Vec::with_capacity(1 + pkt.len());
                    payload.push(TYPE_SESSION_TRAFFIC);
                    payload.extend_from_slice(&pkt);

                    let send_events = node.send(&dest_key, &payload, now_ms, &mut OsRng);
                    for sev in &send_events {
                        if let NodeEvent::SendToPeer { data, .. } = sev {
                            let _ = tls.writer().write_all(data);
                            while tls.wants_write() {
                                match tls.write_tls(&mut tcp) {
                                    Ok(_) => {}
                                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                    did_work = true;
                }
            }

            // ── 7. Periodic node poll
            if now_ms.saturating_sub(last_poll) >= 100 {
                last_poll = now_ms;
                let events = node.poll(now_ms, &mut OsRng);
                if !events.is_empty() {
                    for ev in &events {
                        if let NodeEvent::SendToPeer { data, .. } = ev {
                            let _ = tls.writer().write_all(data);
                        }
                    }
                    did_work = true;
                }
            }

            // ── 8. Flush TLS write buffer
            while tls.wants_write() {
                match tls.write_tls(&mut tcp) {
                    Ok(_) => {}
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        eprintln!("[TLS] Write error: {}", e);
                        break;
                    }
                }
            }

            // ── 9. Status output
            if now_ms.saturating_sub(last_status) >= 30_000 {
                last_status = now_ms;
                eprintln!(
                    "[STATUS] uptime={}s peers={} sessions={} paths={} routes={}",
                    now_ms / 1000,
                    node.peer_count(),
                    node.session_count(),
                    node.path_count(),
                    addr_to_key.len(),
                );
            }

            if !did_work {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    Ok(())
}

#[cfg(not(feature = "smoltcp"))]
/// Process node events: send frames to TLS, deliver IPv6 packets to mini TCP.
fn process_events(
    events: &[NodeEvent],
    tls: &mut ClientConnection,
    tcp: &mut TcpStream,
    mini_tcp: &mut MiniTcp,
    addr_to_key: &mut HashMap<Ipv6Addr, PublicKey>,
    node: &mut YggdrasilLite,
    now_ms: u64,
) {
    for event in events {
        match event {
            NodeEvent::SendToPeer { data, .. } => {
                let _ = tls.writer().write_all(data);
                while tls.wants_write() {
                    match tls.write_tls(tcp) {
                        Ok(_) => {}
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            }
            NodeEvent::Deliver { source, data } => {
                // Strip TYPE_SESSION_TRAFFIC prefix
                if data.len() > 1 && data[0] == TYPE_SESSION_TRAFFIC {
                    let ipv6_packet = &data[1..];

                    // Record source key → IPv6 mapping
                    let source_addr = addr_for_key(source);
                    let source_ipv6 = bytes_to_ipv6(&source_addr.0);
                    addr_to_key.insert(source_ipv6, *source);

                    eprintln!(
                        "[RECV] {} bytes from {}",
                        ipv6_packet.len(),
                        source_ipv6
                    );

                    // Feed to mini TCP stack
                    let responses = mini_tcp.handle_packet(ipv6_packet);
                    for resp_pkt in responses {
                        if let Some(dest_key) =
                            get_dest_key_from_ipv6(&resp_pkt, addr_to_key)
                        {
                            // Prepend TYPE_SESSION_TRAFFIC and send
                            let mut payload = Vec::with_capacity(1 + resp_pkt.len());
                            payload.push(TYPE_SESSION_TRAFFIC);
                            payload.extend_from_slice(&resp_pkt);

                            let send_events =
                                node.send(&dest_key, &payload, now_ms, &mut OsRng);
                            // Handle send events (write to TLS)
                            for sev in &send_events {
                                if let NodeEvent::SendToPeer { data, .. } = sev {
                                    let _ = tls.writer().write_all(data);
                                    while tls.wants_write() {
                                        match tls.write_tls(tcp) {
                                            Ok(_) => {}
                                            Err(ref e)
                                                if e.kind() == io::ErrorKind::WouldBlock =>
                                            {
                                                break
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if !data.is_empty() {
                    eprintln!(
                        "[RECV] Non-traffic data ({} bytes, type=0x{:02x})",
                        data.len(),
                        data[0]
                    );
                }
            }
        }
    }
}
