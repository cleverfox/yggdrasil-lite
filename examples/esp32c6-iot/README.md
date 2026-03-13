# ESP32-C6 Yggdrasil IoT Demo

Firmware for ESP32-C6 that provides a telnet CLI with temperature sensing, RGB LED control, and ICMPv6 ping — all reachable over the Yggdrasil encrypted mesh network. No cloud, no port forwarding, no NAT traversal required.

## Features

- **Telnet CLI** on port 23 (up to 3 simultaneous clients)
- **DS18B20** temperature sensor (one-wire on GPIO4)
- **WS2812** RGB LED control (RMT on GPIO8)
- **ICMPv6 ping** over Yggdrasil mesh
- Connects to Yggdrasil network via TLS (up to 3 configurable peers)
- Generates Ed25519 key on first boot, persists in flash for stable IPv6 address
- WiFi AP+STA mode (configure via AP at `192.168.4.1`)
- Web UI for Yggdrasil peer and WiFi configuration

## Hardware

- **Board**: Any ESP32-C6 development board
- **WS2812 LED**: GPIO8 (built into many dev boards)
- **DS18B20**: GPIO4 (one-wire, uses internal pull-up)

## Telnet Commands

```
> help
Commands:
  help              Show this help
  temp              Read temperature
  led <r> <g> <b>   Set LED color (0-255)
  ping <ipv6>       Ping over Yggdrasil
  uptime            Show system uptime
  w                 Show connected sessions
  status            Show node status
```

Example session:

```
$ nc 200:abcd:ef01:2345::1 23
Yggdrasil ESP32-C6 IoT CLI
Type 'help' for commands.
> temp
Temperature: 23.4 C
> led 0 255 128
LED set: (0, 255, 128)
> ping 201:abcd:ef01:2345::2
PING 201:abcd:ef01:2345::2 ...
Reply from 201:abcd:ef01:2345::2: seq=1 time=42ms
Reply from 201:abcd:ef01:2345::2: seq=2 time=38ms
Reply from 201:abcd:ef01:2345::2: seq=3 time=41ms
Reply from 201:abcd:ef01:2345::2: seq=4 time=39ms
> uptime
up 1h 4m 7s
> w
up 1h 4m 7s, 2 users
SLOT  FROM                                      CONNECTED
0     200:abcd:ef01:2345::2:54321               1h 2m 30s
1     200:1111:2222:3333::1:12345               0m 45s
> status
Uptime: 3847s
IPv6: 200:abcd:ef01:2345::1
Peers: 1  Sessions: 1  Paths: 3
Temperature: 23.4 C
LED: (0, 255, 128)
```

## Configuration

Edit `.cargo/config.toml` to set compile-time defaults:

```toml
[env]
WIFI_SSID = "YourSSID"
WIFI_PASSWORD = "YourPassword"
YGG_PEER1 = "1.2.3.4:12345"
YGG_PEER2 = ""
YGG_PEER3 = ""
```

These defaults are used on first boot. After that, settings saved via the web UI take precedence and are stored in flash.

## Build & Flash

```sh
cd examples/esp32c6-iot
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
     Yggdrasil IoT Demo
   =============================================
     IPv6:  200:abcd:1234:5678:...
     Telnet: port 23
     Key:   ab12cd34ef56...
     Peer1: 192.168.1.100:2020
   =============================================
   ```

4. **Connect via telnet** from any machine on the Yggdrasil network:

   ```sh
   telnet 200:abcd:1234:5678:... 23
   ```

   Or via yggstack SOCKS5 proxy:

   ```sh
   nc -X 5 -x 127.0.0.1:1080 200:abcd:1234:5678:... 23
   ```

## Resource Usage

| Resource | Usage |
|----------|-------|
| Heap | ~100 KB (of 320 KB available) |
| Sockets | 3 TCP (telnet) + 1 ICMP (ping) |
| Drivers | WS2812 via RMT, DS18B20 bit-bang (no external crates) |

## Architecture

The firmware uses a single-task poll-based event loop:

1. Read TLS data from Yggdrasil peer
2. smoltcp poll (processes inbound packets)
3. Drain outbound packets to Yggdrasil
4. DS18B20 temperature state machine (start conversion every 5s, read 750ms later)
4b. ICMPv6 ping state machine (send 4 echo requests, 1s interval, 5s timeout)
5. Telnet CLI (per-client recv/parse/execute/respond)
6. Second smoltcp poll (flush TCP responses)
7. Yggdrasil node poll (100ms)
8. TLS flush

All sensor drivers are written from scratch — the WS2812 driver is 55 lines using the RMT peripheral, the DS18B20 driver is ~170 lines of bit-banged one-wire. No external sensor crates required.

## Web UI

Connect to the ESP32's AP network (`YggBridge`) and open `http://192.168.4.1` in a browser. The dashboard shows:

- Yggdrasil IPv6 address and telnet port
- WiFi STA IP address
- Telnet connection status
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
