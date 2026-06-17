# yggdrasil-lite in the browser (WASM)

Runs a full **Yggdrasil leaf node inside a web page**. `yggdrasil-lite` (the
`no_std` protocol core) plus [smoltcp](https://github.com/smoltcp-rs/smoltcp)
(a userspace IPv6/TCP stack) are compiled to WebAssembly; the only thing the
browser provides is a **WebSocket** to a peer. From there the page joins the
mesh and can ping, serve HTTP, and open TCP connections over the overlay — all
client-side, no native code.

## What it demonstrates

- **WebSocket transport** — peers are reached via `ws://`/`wss://` (Go and
  Rust Yggdrasil nodes support WebSocket listeners).
- **Tree participation** — joins the spanning tree and obtains coordinates.
- **Automatic key discovery** — give it any `200::/7` address and it derives the
  partial key, issues a path lookup, learns the destination's full key from the
  PathNotify reply (`lookup`/`resolve`), then opens an encrypted session. No
  need to know the peer's public key up front.
- **Ping** — sends ICMPv6 echo requests and shows the reply RTT.
- **HTTP server** — a tiny server on port 80 (smoltcp), answering every request
  with a configurable body. Reachable from anywhere on the mesh.
- **TCP client** — connect/send/recv to a remote overlay `[addr]:port`.

## Build

Requires [`wasm-pack`](https://drager.github.io/wasm-pack/).

```sh
cd examples/wasm
./build.sh          # wasm-pack build --target web --out-dir www/pkg
cd www && python3 -m http.server 8080
# open http://localhost:8080
```

## Connecting from a browser: the WebSocket caveat

A browser will only open `wss://` to a peer with a **browser-trusted TLS
certificate**. Yggdrasil's own `wss://` listener uses a self-signed cert, which
browsers reject — so front the peer's plain `ws://` listener with nginx
terminating TLS with a real (e.g. Let's Encrypt) or `mkcert`-generated cert.

Two things bite here, both handled at the proxy:

```nginx
location / {
    proxy_pass http://127.0.0.1:15014;   # the node's plain ws:// listener
    proxy_http_version 1.1;
    proxy_set_header Upgrade    $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host       $host;
    proxy_set_header Origin     "";        # Go ws libs reject cross-origin; strip it
    proxy_buffering off;                   # forward frames immediately
}
```

(`$connection_upgrade` comes from the usual `map $http_upgrade … { default upgrade; '' close; }`.)
Then connect the page to `wss://your-host/`.

See **[wss_howto.md](wss_howto.md)** for a complete, copy-pasteable setup:
running a yggdrasil-ng node with a `ws://` listener, the full nginx config, and
obtaining the certificate with acme.sh.

## Test

1. **Connect** — enter the `wss://` URL and click *Connect*. Within ~1 s
   `node.status()` should show non-empty `coords=[…]` (tree joined). Tip:
   `peers=1 sessions=… paths=… http=4/4 listening coords=[…]`.
2. **Ping** — paste any reachable overlay address (e.g. another node's
   `200:…`/`201:…`) and click *Ping*. The Result field shows
   `Reply from … seq=… rtt=…ms`. The destination key is discovered
   automatically.
3. **HTTP server** — it auto-starts on port 80 with the body in the input box
   (default `ACK from yggdrasil-lite in wasm`); *Update Response* changes it.
   From any host on the mesh:
   ```sh
   curl -6 "http://[<the-node-address-shown-in-the-page>]:80/"
   # → ACK from yggdrasil-lite in wasm
   ```
4. **TCP** — connect to a remote `[addr]:port` and send/recv bytes.

> Each page reload generates a **new random identity**, so the node's address
> changes — always use the address currently shown in the page.

## Log

The page mirrors the node's console log. Tick **verbose** to include the
per-poll chatter (`[IN] …`, `[PING] state: …`); unchecked it keeps just the
useful events (connect, key resolution, ping replies, HTTP requests, errors).

## Notes / limitations

- Leaf-only: no transit routing (same scope as `yggdrasil-lite` itself).
- After connecting, there can be a short delay before the node is reachable
  **inbound** while its key advertisement propagates through the network's
  bloom filters.
- Identity is ephemeral (random per load); there's no key persistence.
