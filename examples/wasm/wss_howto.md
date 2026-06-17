# Setting up a `wss://` peer for the WASM node

The browser example can only join the mesh through a peer that exposes a
**`wss://` WebSocket listener with a browser-trusted TLS certificate**.
Yggdrasil's own `wss://` listener uses a self-signed cert that browsers reject,
so the recommended setup is:

```
browser (wss://ygg.example.com/yws)
        │  TLS, trusted cert
        ▼
      nginx  ──proxy ws upgrade──▶  yggdrasil-ng  ws://127.0.0.1:15014
```

nginx terminates TLS with a real certificate and reverse-proxies the WebSocket
upgrade to the node's plain `ws://` listener on loopback.

## 1. Run a yggdrasil-ng node with a `ws://` listener

Use yggdrasil-ng (the Rust implementation) from the transports branch, which
supports `ws://`/`wss://` listeners:

<https://github.com/cleverfox/yggdrasil-ng/tree/cf/transportsv2>

```sh
# Prerequisites on a fresh Ubuntu: a C toolchain + rustup
sudo apt-get install -y build-essential pkg-config
# install rustup if needed: curl https://sh.rustup.rs -sSf | sh -s -- -y

git clone -b cf/transportsv2 https://github.com/cleverfox/yggdrasil-ng
cd yggdrasil-ng
cargo build --release -p yggdrasil   # binary: target/release/yggdrasil
```

Generate a config. **Note the `=`** — `--genconf` takes its filename as an
attached argument; a space-separated path is misparsed (the binary falls back
to admin-client mode and errors with "Failed to connect to admin socket"):

```sh
./target/release/yggdrasil --genconf=$HOME/yggdrasil.toml
```

In the generated `yggdrasil.toml`, set the upstream peer and replace the
default listener with a plain `ws://` listener bound to loopback (nginx will be
the only thing reaching it):

```toml
# was: peers = []
peers  = ["tls://kursk.cleverfox.org:15015"]   # your upstream peer(s)

# was: listen = ["tcp://0.0.0.0:0"]
listen = ["ws://127.0.0.1:15014"]              # local plain-ws for nginx → browser
```

(The private key lives in this file, so the node keeps a stable address across
restarts.) Run it under systemd so it survives reboots/crashes — it needs root
for the TUN device:

```sh
sudo tee /etc/systemd/system/yggdrasil-ng.service >/dev/null <<EOF
[Unit]
Description=Yggdrasil-NG (wss peer)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$HOME/yggdrasil-ng/target/release/yggdrasil --config $HOME/yggdrasil.toml
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now yggdrasil-ng
journalctl -u yggdrasil-ng -f   # expect "Listening on ws://127.0.0.1:15014" + "Connected outbound"
```

The node accepts the WebSocket handshake on any path (so nginx may mount it
under any location), binary-framed, no auth beyond the Yggdrasil metadata
handshake.

## 2. nginx in front to terminate TLS

Save this as `/etc/nginx/sites-available/ygg-wss.conf` (it's symlinked into
`sites-enabled` in step 3, after the cert exists):

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    access_log /var/log/nginx-access-1443.log;

    ssl_certificate     /etc/nginx/certs/ygg.example.com.pem;
    ssl_certificate_key /etc/nginx/certs/ygg.example.com.key;
    ssl_session_timeout 5m;
    ssl_prefer_server_ciphers on;

    charset utf-8;
    server_name ygg.example.com;

    # WebSocket upgrade → the node's plain ws:// listener
    location /yws {
        proxy_pass http://127.0.0.1:15014/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # For ACME HTTP-01 certificate issuance/renewal
    location /.well-known/acme-challenge {
        root /var/www/html;
    }
}
```

The WASM page then connects to **`wss://ygg.example.com/yws`**.

> **Origin note:** yggdrasil-ng (Rust) does not enforce a WebSocket `Origin`
> check, so the config above works as-is. If you instead front a **Go**-based
> node (upstream `yggdrasil-go` / `yggstack`), its WebSocket library rejects
> cross-origin requests with `403 ... Origin is not authorized for Host` —
> add `proxy_set_header Origin "";` to the `location /yws` block to strip it.

Enable this vhost only **after** the certificate exists (step 3), or `nginx -t`
will fail on the missing files. The ACME HTTP-01 challenge below needs only
port 80, which the default Ubuntu nginx site already serves from `/var/www/html`.

## 3. Obtain the certificate with acme.sh

Get the cert first, then enable the 443 vhost above and reload.
[acme.sh](https://github.com/acmesh-official/acme.sh) runs as your normal user,
so make the challenge dir and a cert dir writable by it (nginx, as root, still
reads them):

```sh
sudo apt-get install -y socat   # acme.sh dependency
curl https://get.acme.sh | sh -s email=you@example.com

# Challenge webroot + a user-writable cert dir nginx will point at
sudo mkdir -p /var/www/html/.well-known/acme-challenge /etc/nginx/certs
sudo chown -R "$USER" /var/www/html/.well-known /etc/nginx/certs

# Issue via Let's Encrypt (acme.sh defaults to ZeroSSL, which needs extra setup)
~/.acme.sh/acme.sh --issue -d ygg.example.com -w /var/www/html --server letsencrypt

# Install (note --ecc: acme.sh issues ECC certs by default) and reload via sudo,
# so unattended renewals (which run as your user) can reload nginx.
~/.acme.sh/acme.sh --install-cert -d ygg.example.com --ecc \
    --key-file       /etc/nginx/certs/ygg.example.com.key \
    --fullchain-file /etc/nginx/certs/ygg.example.com.pem \
    --reloadcmd      "sudo systemctl reload nginx"

sudo ln -sf /etc/nginx/sites-available/ygg-wss.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

acme.sh installs a cron entry and auto-renews (re-running `--install-cert`'s
`reloadcmd`), so the cert stays valid without further action. (Passwordless
sudo for `systemctl reload nginx` keeps the renewal reload unattended.)

## Alternative: yggstack-ng

If you don't want a full node with a TUN interface, **yggstack-ng** (userspace
Yggdrasil + SOCKS, same transports branch) can serve the `ws://` listener
instead of yggdrasil-ng — front it with the identical nginx config:

<https://github.com/cleverfox/yggstack-ng/>

## Verify

Before opening the browser, confirm the upgrade works end-to-end (expect
`HTTP/1.1 101 Switching Protocols`):

```sh
curl -i --http1.1 -k \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: $(head -c16 /dev/urandom | base64)" \
  https://ygg.example.com/yws
```

Then point the WASM page (see [README.md](README.md)) at
`wss://ygg.example.com/yws`.
