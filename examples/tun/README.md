# yggdrasil-lite ⇄ TUN bridge (Linux / macOS)

Bridges the Yggdrasil overlay to a real **kernel TUN interface**, so the host's
own networking stack can reach the mesh. Unlike the [`lite_node`](../lite_node.rs)
example — which runs a *userspace* TCP stack and only answers HTTP — this binds
the overlay to the OS, so ordinary tools work over Yggdrasil:

```sh
ping6 <a-yggdrasil-address>
curl -6 "http://[<a-yggdrasil-address>]:80/"
ssh <a-yggdrasil-address>
```

```text
  kernel socket ──▶ TUN (ygg0/utunN) ──▶ this bridge ──▶ Yggdrasil overlay
  kernel socket ◀── TUN              ◀── this bridge ◀── Yggdrasil overlay
```

The bridge does **no** TCP/IP itself: it copies raw IPv6 packets between the TUN
device and the `yggdrasil-lite` node. The kernel handles TCP, ICMPv6, etc.

## How it works

1. Connect to peers over TCP+TLS and perform the Yggdrasil metadata handshake
   (same as `lite_node`).
2. Create a TUN interface, assign our `200::/7` overlay address, and route
   `200::/7` to it.
3. **Inbound**: a `NodeEvent::Deliver` carries a decrypted IPv6 packet → write it
   to the TUN device.
4. **Outbound**: a packet read from the TUN device is destined for some
   `200::/7` address. We need the destination's *full* Ed25519 key to encrypt
   a session:
   - `node.resolve(dst)` returns the full key if a path is already known
     (learned from inbound traffic or a previous lookup).
   - Otherwise we derive the **partial** key from the address
     (`Address::get_key()`), call `node.lookup(partial, ..)` to start path
     discovery, and queue the packet. The destination replies with its full key
     in a `PathNotify`; once `resolve` succeeds, queued packets are sent.

This uses two small `yggdrasil-lite` APIs added for address-initiated traffic:
`YggdrasilLite::lookup()` and `YggdrasilLite::resolve()`.

## Usage

Creating a TUN device and editing routes requires **root**:

```sh
# Build (no root needed)
cargo build --release -p yggdrasil-tun

# Run against a yggdrasil-ng / yggstack TLS peer
sudo ./target/release/yggdrasil-tun 127.0.0.1:2020

# With a fixed identity and interface name
sudo ./target/release/yggdrasil-tun 127.0.0.1:2020 --seed <64-hex> --tun ygg0
```

Options:

| Flag | Description |
|------|-------------|
| `--seed <hex>` | 32-byte Ed25519 seed (64 hex chars). Random if omitted. |
| `--tun <name>` | Interface name. Linux defaults to `ygg0`; macOS auto-assigns `utunN` (a name, if given, must be `utunN`). |
| `--mtu <n>` | Interface MTU (default `1400`). |

On startup it prints its own overlay address. From this host you can then reach
any node on the mesh, and other nodes can reach this host's overlay address.

## Platform notes

- **Linux**: creates `ygg0` (configurable), assigns the address with `ip -6
  addr add … /7`, and adds a `200::/7` route.
- **macOS**: opens a `utunN` device; assigns the address with
  `ifconfig … inet6 … prefixlen 7` and adds a `200::/7` route. The 4-byte utun
  protocol header is handled by the `tun` crate transparently.

## Requirements

- A reachable Yggdrasil TLS peer (e.g. `yggdrasil-ng` or `yggstack`).
- Root privileges to create the TUN device and modify routes.
