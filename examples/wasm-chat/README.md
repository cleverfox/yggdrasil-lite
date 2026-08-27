# Yggdrasil P2P Chat (WASM)

A peer-to-peer chat that runs entirely in the browser on top of the
`yggdrasil-lite` WASM node. Each browser tab is its own Yggdrasil overlay node:
it joins the mesh over a WebSocket bridge, listens for chats on overlay TCP port
**2451**, and can dial other nodes by their Yggdrasil IPv6 address.

This example ships **no Rust crate of its own** — it reuses the `yggdrasil_wasm`
crate from [`../wasm`](../wasm) and only adds a different web front-end. All the
chat logic (framing, handshake, tabs) lives in `www/app.js`.

## Build

```bash
./build.sh          # runs wasm-pack on ../wasm, output to www/pkg/
```

Requires [`wasm-pack`](https://rustwasm.github.io/wasm-pack/).

## Run

```bash
cd www && python3 -m http.server 8081
# open http://localhost:8081
```

To chat you need two nodes on the **same** overlay. Open the page in two separate
browser profiles (or two machines) so each gets its own persisted identity.

1. In each page, set your **nickname** and click **Connect** (the WebSocket peer
   field defaults to `wss://ygg.cleverfox.org/yws`). Wait until *Peers* ≥ 1.
2. Copy one page's **Your address** value.
3. Paste it into the other page's **Start a chat** field and click **Start chat**.
4. Once the handshake completes, both pages open a tab titled with the other
   peer's nickname. Type away.

## UI behaviour

- The **Join the overlay** panel hides automatically once you're connected and
  reappears if the WebSocket link drops, so you can reconnect.
- Each chat tab shows an iOS/macOS-style **unread badge** counting messages that
  arrived while it wasn't the selected tab; selecting the tab clears it.
- A **ding** plays on every incoming message. Tick **mute sound** (top-right of
  the *Chats* panel) to silence it; the setting is persisted.

## Autochat ("chat with me" page)

To publish a page where anyone who opens it is immediately put into a chat with
*you*, set a fixed peer address. Either edit `AUTOCHAT` near the top of `app.js`:

```js
const AUTOCHAT = '200:abcd::1';   // your Yggdrasil address
```

…or pass it per-visit in the URL: `index.html?autochat=200:abcd::1`. On load the
page auto-joins the overlay (using the configured peer URL) and dials that
address. The **Start a chat** panel stays visible so visitors can also reach
other peers.

## Identity persistence

A random 32-byte Ed25519 seed is generated on first load and stored in
`localStorage` (`ygg-chat-seed`), so your Yggdrasil address stays the same across
reloads. Clear site data to get a new identity. Your nickname and last-used peer
URL are persisted too.

## Protocol (PoC, unencrypted at the app layer)

Newline-delimited JSON over a TCP stream on port 2451. The dialer is the client.

```
client → server : {"k":"YGG_CHAT_HELLO","nick":"Joe","ver":"0.1"}
server → client : {"k":"YGG_CHAT_HELLO","nick":"Robert","ver":"0.1"}
either direction : {"k":"MSG","text":"Hello, Joe, how are you?"}
```

After the HELLO exchange the connection is established and either side may send
`MSG` frames. Unknown message kinds are ignored for forward-compatibility.

> This is a proof-of-concept: there is no application-layer encryption (the
> Yggdrasil overlay link itself is encrypted), no message history, and no
> authentication of nicknames.
