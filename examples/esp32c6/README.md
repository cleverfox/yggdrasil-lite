# ESP32-C6 Yggdrasil TCP-UART Bridge

Firmware for ESP32-C6 that bridges TCP connections over the Yggdrasil mesh network to a hardware UART. The device connects to WiFi, establishes a TLS connection to a Yggdrasil peer, and listens for incoming TCP on its Yggdrasil IPv6 address. Any data received over TCP is forwarded to UART TX, and UART RX data is sent back over TCP.

## Features

- Connects to Yggdrasil network via TLS (up to 3 configurable peers)
- Generates Ed25519 key on first boot, persists in flash for stable IPv6 address
- Bidirectional TCP-UART bridge on the Yggdrasil overlay
- WiFi AP+STA mode (configure via AP at `192.168.4.1`)
- Web UI for Yggdrasil peer and WiFi configuration
- Console boot banner with IPv6 address and port

## Hardware

- **Board**: Any ESP32-C6 development board
- **UART**: TX on GPIO19, RX on GPIO20 (115200 baud)

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

```sh
cd examples/esp32c6
cargo run --release
```

This builds the firmware and flashes it via `espflash`. The serial monitor starts automatically after flashing.

## Quick Test

1. **Start a yggdrasil-ng node** on your LAN:

   ```sh
   cargo run -p yggdrasil -- --config yggdrasil.conf --loglevel debug
   ```

   Note the TLS listen address from the logs (e.g. `tls://0.0.0.0:2020`).

2. **Configure the ESP32-C6** with the peer address in `.cargo/config.toml`:

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

## Flash Layout (NVS)

| Offset | Size | Contents |
|--------|------|----------|
| 0 | 128 | WiFi config (SSID + password) |
| 128 | 64 | Yggdrasil Ed25519 seed (32 bytes) |
| 256 | 256 | Yggdrasil peers (3 slots, IPv4/IPv6) |

The Ed25519 key is generated once on first boot. Erasing flash will generate a new key and change the device's Yggdrasil IPv6 address.
