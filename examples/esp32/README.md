# ESP32 Yggdrasil TCP-UART Bridge

Firmware for ESP32 family that bridges TCP connections over the Yggdrasil mesh network to a hardware UART. The device connects to WiFi, establishes a TLS connection to a Yggdrasil peer, and listens for incoming TCP on its Yggdrasil IPv6 address. Any data received over TCP is forwarded to UART TX, and UART RX data is sent back over TCP.

Supports **ESP32-C6** (RISC-V) and **ESP32** (Xtensa) via Cargo features.

## Features

- Connects to Yggdrasil network via TLS (up to 3 configurable peers)
- Generates Ed25519 key on first boot, persists in flash for stable IPv6 address
- Bidirectional TCP-UART bridge on the Yggdrasil overlay
- WiFi AP+STA mode (configure via AP at `192.168.4.1`)
- Web UI for Yggdrasil peer and WiFi configuration
- Console boot banner with IPv6 address and port

## Supported Hardware

| Chip | Architecture | UART Pins | Heap |
|------|-------------|-----------|------|
| ESP32-C6 | RISC-V | TX: GPIO19, RX: GPIO20 | 96 KB |
| ESP32 | Xtensa | TX: GPIO17, RX: GPIO16 | 64 KB |

UART baud rate: 115200

## Configuration

Edit `.cargo/config.toml` to set compile-time defaults:

```toml
[env]
WIFI_SSID = "YourSSID"
WIFI_PASSWORD = "YourPassword"
YGG_PEER1 = "1.2.3.4:12345"
YGG_PEER2 = ""
YGG_PEER3 = ""
YGG_LISTEN_PORT = "2000"
```

These defaults are used on first boot. After that, settings saved via the web UI take precedence and are stored in flash.

## Build & Flash

### ESP32-C6 (RISC-V)

```sh
cd examples/esp32
cargo run --release --target riscv32imac-unknown-none-elf --features esp32c6
```

### ESP32 (Xtensa)

Requires the [esp Rust toolchain](https://github.com/esp-rs/rust-build):

```sh
cd examples/esp32
cargo +esp run --release --target xtensa-esp32-none-elf --features esp32 --no-default-features
```

Both commands build and flash via `espflash`. The serial monitor starts automatically after flashing.

## Quick Test

1. **Start a yggdrasil-ng node** on your LAN:

   ```sh
   cargo run -p yggdrasil -- --config yggdrasil.conf --loglevel debug
   ```

   Note the TLS listen address from the logs (e.g. `tls://0.0.0.0:2020`).

2. **Configure the ESP32** with the peer address in `.cargo/config.toml`:

   ```toml
   YGG_PEER1 = "192.168.1.100:2020"
   ```

3. **Flash and boot**. The console will show:

   ```
   =============================================
     Yggdrasil TCP-UART Bridge
   =============================================
     IPv6:  200:abcd:1234:5678:...
     Port:  2000
     Key:   ab12cd34ef56...
     Peer1: 192.168.1.100:2020
   =============================================
   ```

4. **Connect via yggstack SOCKS5 proxy**:

   ```sh
   yggstack --useconffile /tmp/yggstack.conf --socks 127.0.0.1:1080
   ```

   Then connect to the ESP32's Yggdrasil address:

   ```sh
   # TCP connection to UART bridge
   nc -X 5 -x 127.0.0.1:1080 200:abcd:1234:5678:... 2000
   ```

   Anything you type will be sent to the ESP32's UART TX pin, and anything received on UART RX will appear in your terminal.

## Web UI

Connect to the ESP32's AP network (`YggBridge`) and open `http://192.168.4.1` in a browser. The dashboard shows:

- Yggdrasil IPv6 address and port
- WiFi STA IP address
- UART connection status
- Editable peer addresses (up to 3)
- WiFi SSID/password configuration

Settings are saved to flash. Reboot the device after changing configuration.

## API Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/` | GET | HTML dashboard |
| `/api/status` | GET | JSON status |
| `/api/wifi` | POST | Set WiFi credentials (form: `ssid=...&password=...`) |
| `/api/ygg/peers` | POST | Set peers (form: `peer1=...&peer2=...&peer3=...`) |

## TCP Stack: MiniTcpUart vs smoltcp

By default the firmware uses `MiniTcpUart` — a minimal hand-rolled TCP state machine (~200 lines) with manual ICMPv6 echo reply handling. An optional `smoltcp` feature replaces it with the [smoltcp](https://github.com/smoltcp-rs/smoltcp) TCP/IP stack.

```sh
# ESP32-C6: default build (MiniTcpUart)
cargo run --release --target riscv32imac-unknown-none-elf --features esp32c6

# ESP32-C6: build with smoltcp
cargo run --release --target riscv32imac-unknown-none-elf --features esp32c6,smoltcp

# ESP32: default build (MiniTcpUart)
cargo +esp run --release --target xtensa-esp32-none-elf --features esp32 --no-default-features

# ESP32: build with smoltcp
cargo +esp run --release --target xtensa-esp32-none-elf --features esp32,smoltcp --no-default-features
```

### MiniTcpUart (default)

- Single TCP connection, basic 3-way handshake and teardown
- Manual ICMPv6 echo reply (ping)
- No congestion control or TCP windowing
- ~0 KB heap overhead (all state on stack)
- Good enough for a single UART bridge session

### smoltcp (`--features smoltcp`)

- Full TCP implementation (windowing, retransmission, congestion control)
- Automatic ICMPv6 handling (echo, unreachable, etc.)
- Proper socket state machine with re-listen after close
- ~4 KB extra heap (2 x 1 KB socket buffers + interface state)
- Requires 96 KB heap (vs 72 KB for MiniTcpUart)
- More robust under packet loss or misbehaving peers

Enable smoltcp if you need reliable TCP behavior or plan to extend the firmware beyond simple UART bridging. Stick with the default if heap is tight or you only need a single clean connection.

## Flash Layout (NVS)

| Offset | Size | Contents |
|--------|------|----------|
| 0 | 128 | WiFi config (SSID + password) |
| 128 | 64 | Yggdrasil Ed25519 seed (32 bytes) |
| 256 | 256 | Yggdrasil peers (3 slots, IPv4/IPv6) |

The Ed25519 key is generated once on first boot. Erasing flash will generate a new key and change the device's Yggdrasil IPv6 address.
