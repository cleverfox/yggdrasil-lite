import init, { YggdrasilWasm } from './pkg/yggdrasil_wasm.js';

const logEl = document.getElementById('log');
const nodeAddr = document.getElementById('node-addr');
const nodeKey = document.getElementById('node-key');
const nodeCoords = document.getElementById('node-coords');
const nodePeers = document.getElementById('node-peers');
const nodeSessions = document.getElementById('node-sessions');
const nodePaths = document.getElementById('node-paths');
const nodeStatus = document.getElementById('node-status');
const tcpState = document.getElementById('tcp-state');
const pingResult = document.getElementById('ping-result');
const verboseLog = document.getElementById('verbose-log');

// Noisy per-poll chatter, hidden unless "verbose" is checked.
function isVerboseOnly(msg) {
    return msg.includes('[IN]') || msg.includes('[PING] state:');
}

function appendLog(msg) {
    // Surface ping outcomes in the dedicated result field.
    const reply = msg.match(/\[PING\] (Reply from .+|Timeout .+)/);
    if (reply) pingResult.textContent = reply[1];

    if (!verboseLog.checked && isVerboseOnly(msg)) return;

    const entry = document.createElement('div');
    entry.className = 'log-entry';
    const ts = new Date().toISOString().slice(11, 23);
    entry.textContent = `[${ts}] ${msg}`;
    logEl.appendChild(entry);
    logEl.scrollTop = logEl.scrollHeight;
    // Keep log from growing unbounded
    while (logEl.children.length > 500) {
        logEl.removeChild(logEl.firstChild);
    }
}

// Intercept console.log to capture Rust-side logs
const origLog = console.log;
console.log = (...args) => {
    origLog(...args);
    appendLog(args.map(a => String(a)).join(' '));
};

let node = null;
let tcpHandle = null;
let pollId = null;

async function main() {
    appendLog('Loading WASM module...');
    await init();
    appendLog('WASM loaded.');

    node = new YggdrasilWasm();
    nodeAddr.textContent = node.address();
    nodeKey.textContent = node.public_key_hex();
    appendLog(`Node created: ${node.address()}`);

    // Start polling at 100ms interval
    pollId = node.start_polling(100);
    appendLog('Polling started (100ms interval)');

    // Auto-start the HTTP server so the node is always reachable on port 80.
    node.start_http_server(80, document.getElementById('http-body').value);
    document.getElementById('http-url').textContent = `http://[${node.address()}]:80/`;
    appendLog('HTTP server listening on port 80');

    // Update stats periodically
    setInterval(() => {
        if (!node) return;
        nodeCoords.textContent = node.coords();
        nodePeers.textContent = node.peer_count();
        nodeSessions.textContent = node.session_count();
        nodePaths.textContent = node.path_count();
        nodeStatus.textContent = node.status();
        if (tcpHandle !== null) {
            tcpState.textContent = node.tcp_state(tcpHandle);
        }
    }, 1000);
}

// Connect to peer
document.getElementById('btn-connect').addEventListener('click', async () => {
    const url = document.getElementById('peer-url').value.trim();
    if (!url) return;
    appendLog(`Connecting to ${url}...`);
    document.getElementById('btn-connect').disabled = true;
    try {
        const peerId = await node.connect_peer(url);
        appendLog(`Peer connected (id=${peerId})`);
    } catch (e) {
        appendLog(`Connection failed: ${e}`);
    }
    document.getElementById('btn-connect').disabled = false;
});

// Ping
document.getElementById('btn-ping').addEventListener('click', () => {
    const dest = document.getElementById('ping-dest').value.trim();
    if (!dest) return;
    pingResult.textContent = 'pinging...';
    node.ping(dest);
});

document.getElementById('btn-ping5').addEventListener('click', () => {
    const dest = document.getElementById('ping-dest').value.trim();
    if (!dest) return;
    pingResult.textContent = 'pinging...';
    let count = 0;
    const interval = setInterval(() => {
        node.ping(dest);
        count++;
        if (count >= 5) clearInterval(interval);
    }, 1000);
});

// HTTP server
document.getElementById('btn-http-start').addEventListener('click', () => {
    const body = document.getElementById('http-body').value;
    node.start_http_server(80, body);
    document.getElementById('http-url').textContent = `http://[${node.address()}]:80/`;
    appendLog('HTTP server started on port 80');
});

document.getElementById('btn-http-update').addEventListener('click', () => {
    node.set_http_response(document.getElementById('http-body').value);
    appendLog('HTTP response updated');
});

// TCP connect
document.getElementById('btn-tcp-connect').addEventListener('click', () => {
    const dest = document.getElementById('tcp-dest').value.trim();
    if (!dest) return;
    const [addr, portStr] = dest.split(/:(?=\d+$)/);
    const port = parseInt(portStr || '80', 10);
    appendLog(`TCP connecting to [${addr}]:${port}...`);
    tcpHandle = node.tcp_connect(addr, port);
    appendLog(`TCP socket created (handle=${tcpHandle})`);

    // Poll for incoming TCP data
    setInterval(() => {
        if (tcpHandle === null) return;
        const data = node.tcp_recv(tcpHandle);
        if (data) {
            const text = new TextDecoder().decode(data);
            appendLog(`TCP recv (${data.length}B): ${text.slice(0, 200)}`);
        }
    }, 200);
});

// TCP send
document.getElementById('btn-tcp-send').addEventListener('click', () => {
    if (tcpHandle === null) {
        appendLog('No TCP connection');
        return;
    }
    const text = document.getElementById('tcp-data').value;
    const data = new TextEncoder().encode(text);
    const sent = node.tcp_send(tcpHandle, data);
    appendLog(`TCP sent ${sent} bytes`);
});

main().catch(e => appendLog(`Error: ${e}`));
