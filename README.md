# yggdrasil-lite

Minimal leaf-only [Yggdrasil](https://yggdrasil-network.github.io/) client for embedded devices.

Implements the Yggdrasil/Ironwood protocol subset needed to operate as a **leaf node**: connect to peers, join the spanning tree, discover paths via bloom filters, and exchange end-to-end encrypted packets with any node in the network. No transit routing, no TUN interface, no admin API.

Designed for `no_std` + `alloc` environments (ESP32-C6 with Embassy), but also builds with `std` for desktop testing.

## Features

- Spanning tree participation (announce, SigReq/SigRes, parent selection)
- Bloom filter routing (advertise own key, respond to PathLookup)
- Path discovery (PathLookup / PathNotify / PathBroken)
- End-to-end encrypted sessions (XSalsa20-Poly1305 with key ratcheting)
- Metadata handshake compatible with yggdrasil-go and yggdrasil-ng
- IPv6 address derivation from Ed25519 public key (`200::/7`)
- Poll-based, synchronous API — no async runtime dependency
- ~2500 lines of Rust, 73 unit tests

## Architecture

```
Application
    │
    ▼
YggdrasilLite          ◄── poll-based node coordinator
├── tree.rs            ◄── spanning tree CRDT (parent selection, announces)
├── bloom.rs           ◄── bloom filter exchange (key advertisement)
├── pathfinder.rs      ◄── path cache (PathLookup/PathNotify/PathBroken)
├── session.rs         ◄── encrypted sessions (Init/Ack/Traffic + ratcheting)
├── wire.rs            ◄── frame encoding/decoding (uvarint, TLV, paths)
├── meta.rs            ◄── metadata handshake (version, key, BLAKE2b sig)
├── crypto.rs          ◄── Ed25519, X25519, XSalsa20-Poly1305
├── address.rs         ◄── IPv6 address derivation from ed25519 key
└── peer.rs            ◄── per-peer connection state
```

## Usage

```rust
use yggdrasil_lite::{YggdrasilLite, LiteConfig, NodeEvent};

// Create a node with an Ed25519 seed
let config = LiteConfig::new(my_ed25519_seed);
let mut node = YggdrasilLite::new(config);

// After TCP+TLS connection and metadata handshake with a peer:
let peer_id = node.add_peer(peer_public_key, 0);
node.mark_handshake_done(peer_id);

// Main loop
loop {
    // Feed incoming data from the peer's TLS stream
    let events = node.handle_peer_data(peer_id, &incoming_bytes, now_ms, &mut rng);
    handle_events(&events, &mut tls_writer);

    // Periodic maintenance (~every 100ms)
    let events = node.poll(now_ms, &mut rng);
    handle_events(&events, &mut tls_writer);

    // Send encrypted data to a remote Yggdrasil node
    let events = node.send(&dest_public_key, b"hello", now_ms, &mut rng);
    handle_events(&events, &mut tls_writer);
}

fn handle_events(events: &[NodeEvent], writer: &mut impl std::io::Write) {
    for event in events {
        match event {
            NodeEvent::SendToPeer { data, .. } => {
                writer.write_all(data).unwrap();
            }
            NodeEvent::Deliver { source, data } => {
                // Decrypted application data from a remote node
                println!("Received {} bytes from {:?}", data.len(), &source[..4]);
            }
        }
    }
}
```

## API Overview

### `LiteConfig`

| Field | Type | Description |
|-------|------|-------------|
| `private_key` | `[u8; 32]` | Ed25519 signing key seed |
| `password` | `Option<Vec<u8>>` | Peering password (if peers require one) |
| `max_sessions` | `usize` | Max concurrent encrypted sessions (default: 16) |
| `max_paths` | `usize` | Max cached path entries (default: 16) |

### `YggdrasilLite`

| Method | Description |
|--------|-------------|
| `new(config)` | Create a new node |
| `public_key()` | Our Ed25519 public key |
| `address()` | Our Yggdrasil IPv6 address (`200::/7`) |
| `subnet()` | Our `/64` subnet (`300::/7`) |
| `coords()` | Current tree coordinates |
| `add_peer(key, priority)` | Register a peer after TLS+metadata handshake |
| `remove_peer(peer_id)` | Remove a disconnected peer |
| `mark_handshake_done(peer_id)` | Mark peer as fully connected |
| `handle_peer_data(peer_id, data, now_ms, rng)` | Process incoming wire data from a peer |
| `poll(now_ms, rng)` | Periodic maintenance (tree, bloom, keepalive, cleanup) |
| `send(dest_key, data, now_ms, rng)` | Send encrypted data to a destination |

### `NodeEvent`

| Variant | Description |
|---------|-------------|
| `SendToPeer { peer_id, data }` | Write `data` to the peer's TLS stream |
| `Deliver { source, data }` | Decrypted application data from `source` |

### Metadata Handshake

The caller is responsible for TCP+TLS connection setup. After TLS, exchange metadata using `meta::Metadata`:

```rust
use yggdrasil_lite::meta::Metadata;

// Encode and send our metadata
let meta = Metadata::new(node.public_key().clone(), 0);
let encoded = meta.encode(&signing_key, password);
tls_writer.write_all(&encoded)?;

// Read and decode peer metadata
let (peer_meta, consumed) = Metadata::decode(&received_bytes, password)?;
assert!(peer_meta.check()); // verify protocol compatibility
```

## Transport

yggdrasil-lite is transport-agnostic. It operates on framed byte streams — the caller provides TCP+TLS and feeds raw bytes in/out. This makes it usable with:

- **Desktop**: `std::net::TcpStream` + `rustls`
- **Embassy**: `embassy-net::TcpSocket` + `embedded-tls`
- **Any other runtime** that provides a byte stream

## Examples

### Desktop: `lite_node`

A complete desktop integration test node with TLS, metadata handshake, and a userspace TCP/HTTP server running on the Yggdrasil overlay.

```sh
# 1. Start a yggdrasil-ng node
cargo run -p yggdrasil -- --config yggdrasil.conf --loglevel debug
# Note the TLS listen address (e.g. tls://0.0.0.0:2020)

# 2. Run the lite node
cargo run --example lite_node -p yggdrasil-lite -- 127.0.0.1:2020

# 3. Test from the yggdrasil-ng host
curl -6 --max-time 30 "http://[<lite_ipv6>]:80/hello"
```

### ESP32-C6: Yggdrasil TCP-UART Bridge

A firmware for ESP32-C6 (tested on **ESP32-C6-WROOM-1**) that bridges TCP connections over the Yggdrasil mesh to a hardware UART. The device connects to WiFi, establishes a TLS connection to Yggdrasil peers, and listens for TCP and ICMPv6 on its overlay IPv6 address.

See [`examples/esp32c6/`](examples/esp32c6/) for the full project. Quick start:

```sh
cd examples/esp32c6

# Edit .cargo/config.toml with your WiFi and peer settings
# Then build and flash:
cargo run --release
```

On boot the device prints its Yggdrasil IPv6 address. You can then connect to it from anywhere on the mesh:

```sh
# Ping over Yggdrasil (via yggstack SOCKS5 proxy)
ping6 -x 127.0.0.1:1080 <esp-ipv6>

# TCP to UART bridge
nc -X 5 -x 127.0.0.1:1080 <esp-ipv6> 2000
```

A web UI is available at `http://192.168.4.1` (connect to the `YggBridge` AP) for configuring WiFi credentials and Yggdrasil peer addresses.

## End-to-End Test

An automated E2E test verifies the full stack: yggstack → yggdrasil-ng → lite_node → HTTP.

```sh
YGGSTACK_BIN=/path/to/yggstack bash tests/e2e.sh
```

The test starts a yggstack node with a SOCKS5 proxy, connects a lite_node to it, and verifies HTTP reachability over the Yggdrasil overlay via curl.

## Building

```sh
# Desktop (std) — tests and examples
cargo test
cargo run --example lite_node -- 127.0.0.1:12345

# ESP32-C6 (no_std) — requires nightly toolchain
cd examples/esp32c6
cargo build --release
```

## License

MPL-2.0
