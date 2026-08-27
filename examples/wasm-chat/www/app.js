import init, { YggdrasilWasm } from './pkg/yggdrasil_wasm.js';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const CHAT_PORT = 2451;          // overlay TCP port we listen on / dial
const POOL_SIZE = 4;             // concurrent inbound listeners
const PROTO_VER = '0.1';
const DEFAULT_PEER = 'wss://asia.deinfra.org/yws';

const KEEPALIVE_MS = 30000;      // send a PING on every ready chat this often
const ALIVE_TIMEOUT_MS = 70000;  // no frame for this long → mark the tab dead
const ACK_MS = 5000;             // send a cumulative ACK this often if new msgs arrived
const FILE_CHUNK = 4096;         // bytes pushed to the file socket per pump (tx buffer size)

let nextFilePort = 20000;        // ephemeral ports for one-shot file transfers
function allocFilePort() {
    nextFilePort = nextFilePort >= 60000 ? 20001 : nextFilePort + 1;
    return nextFilePort;
}

// Autochat: set a peer's Yggdrasil IPv6 address here to make a "chat with me"
// page — on load it auto-joins the overlay and dials that peer. Leave empty to
// disable. Can also be set per-visit via the URL: ?autochat=200:abcd::1
const AUTOCHAT = '';

const LS_SEED = 'ygg-chat-seed'; // hex-encoded 32-byte Ed25519 seed
const LS_NICK = 'ygg-chat-nick';
const LS_PEER = 'ygg-chat-peer';
const LS_MUTE = 'ygg-chat-mute';
const LS_AUTOCONNECT = 'ygg-chat-autoconnect';
const LS_ALLOWFILES = 'ygg-chat-allowfiles';

// TCP states (smoltcp Display strings) that mean "no longer usable".
const DEAD_STATES = new Set([
    'CLOSED', 'TIME-WAIT', 'LAST-ACK', 'CLOSING', 'FIN-WAIT-1', 'FIN-WAIT-2',
]);

const enc = new TextEncoder();

// ---------------------------------------------------------------------------
// DOM
// ---------------------------------------------------------------------------
const logEl = document.getElementById('log');
const nodeAddrEl = document.getElementById('node-addr');
const nodePeersEl = document.getElementById('node-peers');
const nickInput = document.getElementById('nick');
const peerInput = document.getElementById('peer-url');
const dialInput = document.getElementById('dial-addr');
const dialBtn = document.getElementById('btn-dial');
const tabsEl = document.getElementById('tabs');
const panesEl = document.getElementById('panes');
const emptyEl = document.getElementById('empty');
const joinPanel = document.getElementById('join-panel');
const muteCheckbox = document.getElementById('mute');
const debugCheckbox = document.getElementById('debug-log');
const autoconnectCheckbox = document.getElementById('autoconnect');
const allowFilesCheckbox = document.getElementById('allow-files');
const chatLinkEl = document.getElementById('chat-link');
const copyLinkBtn = document.getElementById('btn-copy-link');

// High-frequency, low-value telemetry from the WASM node — hidden unless the
// "debug" checkbox is ticked.
function isDebugOnly(msg) {
    return /\[(IN|TX|LKUP)\]/.test(msg);
}

function appendLog(msg) {
    if (isDebugOnly(msg) && !(debugCheckbox && debugCheckbox.checked)) return;
    // Only stick to the bottom when the user is already there; otherwise leave
    // their scroll position alone so they can read back through history.
    const atBottom = logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight < 8;
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    const ts = new Date().toISOString().slice(11, 23);
    entry.textContent = `[${ts}] ${msg}`;
    logEl.appendChild(entry);
    while (logEl.children.length > 500) logEl.removeChild(logEl.firstChild);
    if (atBottom) logEl.scrollTop = logEl.scrollHeight;
}

// Capture Rust-side logs (the WASM module logs via console.log). The WASM node
// owns the WebSocket, so its close/error log line is our only signal that the
// overlay link dropped — watch for it to re-show the Join panel.
const origLog = console.log;
console.log = (...args) => {
    origLog(...args);
    const msg = args.map(a => String(a)).join(' ');
    appendLog(msg);
    if (msg.includes('[WS] Connection closed') || msg.includes('[WS] Connection error')) {
        setOverlay(false);
    }
};

// ---------------------------------------------------------------------------
// localStorage helpers
// ---------------------------------------------------------------------------
function bytesToHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
    if (typeof hex !== 'string' || hex.length !== 64 || /[^0-9a-fA-F]/.test(hex)) return null;
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
}

// Load (or generate + persist) our stable identity seed.
function loadSeed() {
    let seed = hexToBytes(localStorage.getItem(LS_SEED));
    if (!seed) {
        seed = new Uint8Array(32);
        crypto.getRandomValues(seed);
        localStorage.setItem(LS_SEED, bytesToHex(seed));
        appendLog('Generated new identity seed (stored in localStorage).');
    } else {
        appendLog('Loaded identity seed from localStorage.');
    }
    return seed;
}

function myNick() {
    return (nickInput.value.trim() || 'anon');
}

// Make sure we have a nickname before auto-connecting. If the field is empty,
// ask the visitor for their name (looping until non-empty). Returns the name,
// or null if the visitor dismissed the prompt.
function ensureNick() {
    let nick = nickInput.value.trim();
    while (!nick) {
        const entered = window.prompt('Enter your name to start chatting:', '');
        if (entered === null) return null;   // dismissed
        nick = entered.trim();
    }
    nickInput.value = nick;
    localStorage.setItem(LS_NICK, nick);
    return nick;
}

// Where to autochat, in priority order:
//   1. URL fragment   #chat=<addr>   (shareable "chat with me" link)
//   2. URL query      ?autochat=<addr>
//   3. the AUTOCHAT constant in this file
// The fragment overrides the others so a generated link always wins.
function autochatTarget() {
    const fromHash = new URLSearchParams(location.hash.replace(/^#/, '')).get('chat');
    const fromQuery = new URLSearchParams(location.search).get('autochat');
    return (fromHash || fromQuery || AUTOCHAT || '').trim();
}

// A shareable link that puts visitors straight into a chat with this node.
function myChatLink() {
    return `${location.origin}${location.pathname}#chat=${node.address()}`;
}

// ---------------------------------------------------------------------------
// Chat sessions
// ---------------------------------------------------------------------------
let node = null;
let listeners = [];      // socket indices currently in LISTEN
const sessions = [];     // all chat sessions (active + closed)
let tabSeq = 0;
let activeSession = null;
let overlayConnected = false;

function newSession(idx, role) {
    return {
        id: ++tabSeq,
        idx,                       // smoltcp socket index
        role,                      // 'out' (we dialed) | 'in' (we accepted)
        state: role === 'out' ? 'connecting' : 'await-hello',
        nick: null,
        peerAddr: '',
        rxBuf: '',
        sentHello: false,
        unread: 0,
        lastSeen: 0,
        outQueue: [],              // {text, statusEl} not yet handed to the socket
        outSeq: 0,                 // last outbound MSG sequence number
        pending: new Map(),        // seq -> {text, statusEl} awaiting ACK
        recvMaxSeq: 0,             // highest inbound MSG seq seen
        ackSent: 0,                // highest seq we have ACKed back
        fileSends: new Map(),      // seq -> outbound file transfer state
        fileRecvs: new Map(),      // seq -> inbound file transfer state
        dec: new TextDecoder('utf-8'),
        tabEl: null, paneEl: null, msglistEl: null, inputEl: null, sendBtn: null, badgeEl: null, aliveEl: null,
    };
}

function normalizeAddr(a) {
    return (a || '').trim().toLowerCase();
}

// One chat per peer address: find an existing session for this address (open,
// closed, or still connecting) so reconnects reuse its tab and history.
function findChat(addr) {
    const key = normalizeAddr(addr);
    if (!key) return null;
    return sessions.find(s => normalizeAddr(s.peerAddr) === key) || null;
}

// Adopt a fresh socket into an existing chat: reset the per-connection state but
// keep the tab, pane, message history, and unread count.
function rebindSession(s, idx, role) {
    s.idx = idx;
    s.role = role;
    s.state = role === 'out' ? 'connecting' : 'await-hello';
    s.nick = null;                       // re-learned from the new handshake
    s.rxBuf = '';
    s.dec = new TextDecoder('utf-8');
    s.sentHello = false;
    s.lastSeen = 0;
    // Unacked messages were never confirmed delivered: requeue them (ahead of
    // anything typed while offline) so they go out again on the new connection.
    if (s.pending.size) {
        s.outQueue = [...s.pending.values(), ...s.outQueue];
        s.pending.clear();
    }
    if (s.tabEl) s.tabEl.classList.remove('closed');
    if (s.inputEl) s.inputEl.disabled = false;
    if (s.sendBtn) s.sendBtn.disabled = false;
    updateAlive(s);
    sysMsg(s, 'reconnecting…');
}

// Reopen a dead/stale chat to its known peer address (used when the user sends
// a message to a disconnected peer). No-op if a connect is already in flight or
// the link is still live.
function ensureConnected(s) {
    if (s.state === 'connecting' || s.state === 'await-hello') return;  // in progress
    if (isLive(s)) return;                                              // still healthy
    if (!s.peerAddr) { sysMsg(s, 'cannot reconnect: peer address unknown'); return; }
    if (!overlayConnected) { sysMsg(s, 'not on the overlay — connect first'); return; }
    const idx = node.tcp_connect(s.peerAddr, CHAT_PORT);
    appendLog(`Reopening chat with ${s.peerAddr} (idx=${idx})...`);
    rebindSession(s, idx, 'out');
}

// Send one MSG with a fresh sequence number and keep it pending until ACKed.
function sendMsg(s, item) {
    const seq = ++s.outSeq;
    s.pending.set(seq, item);
    send(s, { k: 'MSG', seq, text: item.text });
}

// Mark every pending message up to `ackSeq` as delivered (cumulative ACK).
function markDelivered(s, ackSeq) {
    for (const [seq, item] of s.pending) {
        if (seq <= ackSeq) {
            if (item.statusEl) {
                item.statusEl.textContent = '✓';
                item.statusEl.classList.add('delivered');
            }
            s.pending.delete(seq);
        }
    }
}

// Send any messages that were queued while the chat was disconnected.
function flushQueue(s) {
    if (!s.outQueue.length) return;
    const q = s.outQueue;
    s.outQueue = [];
    for (const item of q) sendMsg(s, item);
    appendLog(`Flushed ${q.length} queued message(s) to ${s.nick}`);
}

// ---------------------------------------------------------------------------
// File transfer
//
// Control frames ride the chat connection; the bytes go over a fresh one-shot
// TCP connection to a recipient-chosen ephemeral port:
//   sender → FILE{seq,name,size,content-type}
//   recv   → FILE_ACCEPT{orig_seq,port}  (opens a listener)  | FILE_REJECT{orig_seq}
//   sender connects to that port, streams the bytes, closes
//   recv   → FILE_ACK{orig_seq} (length matched) | FILE_NACK{orig_seq,reason}
// ---------------------------------------------------------------------------
function humanSize(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function appendFileLine(s, label, isMe) {
    if (!s.msglistEl) return null;
    const div = document.createElement('div');
    div.className = 'msg file' + (isMe ? ' me' : '');
    const who = document.createElement('span');
    who.className = 'who';
    who.textContent = (isMe ? myNick() : (s.nick || 'peer')) + ': ';
    div.appendChild(who);
    div.appendChild(document.createTextNode(label));
    const status = document.createElement('span');
    status.className = 'status';
    div.appendChild(status);
    s.msglistEl.appendChild(div);
    s.msglistEl.scrollTop = s.msglistEl.scrollHeight;
    return div;
}

function fileStatus(div, text) {
    if (!div) return;
    const st = div.querySelector('.status');
    if (st) st.textContent = ' — ' + text;
}

function offerDownload(div, name, blob) {
    if (!div) return;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.textContent = `⬇ ${name}`;
    a.className = 'dl';
    div.appendChild(document.createTextNode(' '));
    div.appendChild(a);
}

// Sender: offer a file on the chat channel, then stream it once accepted.
async function startFileSend(s, file) {
    if (!isLive(s)) { sysMsg(s, 'cannot send file: not connected'); return; }
    const bytes = new Uint8Array(await file.arrayBuffer());
    const seq = ++s.outSeq;
    const type = file.type || 'application/octet-stream';
    const lineEl = appendFileLine(s, `📎 ${file.name} (${humanSize(bytes.length)})`, true);
    s.fileSends.set(seq, {
        name: file.name, size: bytes.length, type, bytes,
        sent: 0, sockIdx: null, state: 'offered', lineEl,
    });
    fileStatus(lineEl, 'offered…');
    send(s, { seq, k: 'FILE', name: file.name, size: bytes.length, 'content-type': type });
}

// Recipient: finalize an inbound transfer once the full payload arrived.
function finalizeRecv(s, seq, fr) {
    node.tcp_close(fr.listenerIdx);
    if (fr.received === fr.size) {
        const blob = new Blob(fr.chunks, { type: fr.type || 'application/octet-stream' });
        offerDownload(fr.lineEl, fr.name, blob);
        fileStatus(fr.lineEl, 'received');
        send(s, { k: 'FILE_ACK', orig_seq: seq });
        playDing();
        appendLog(`File received: ${fr.name} (${fr.received} B)`);
    } else {
        send(s, { k: 'FILE_NACK', orig_seq: seq, reason: 'size mismatch' });
        fileStatus(fr.lineEl, `✗ size mismatch (${fr.received}/${fr.size})`);
    }
    s.fileRecvs.delete(seq);
}

// Drive in-flight transfers for one chat (called every tick).
function pumpFiles(s) {
    for (const [seq, fs] of s.fileSends) {
        if (fs.state !== 'sending' || fs.sockIdx == null) continue;
        const st = node.tcp_state(fs.sockIdx);
        if (st === 'ESTABLISHED' || st === 'CLOSE-WAIT') {
            while (fs.sent < fs.bytes.length) {
                const end = Math.min(fs.sent + FILE_CHUNK, fs.bytes.length);
                const n = node.tcp_send(fs.sockIdx, fs.bytes.subarray(fs.sent, end));
                if (n <= 0) break;            // tx buffer full → resume next tick
                fs.sent += n;
            }
            const pct = Math.floor((fs.sent / Math.max(1, fs.bytes.length)) * 100);
            fileStatus(fs.lineEl, fs.sent >= fs.bytes.length ? 'sent, awaiting confirmation…' : `sending ${pct}%`);
            if (fs.sent >= fs.bytes.length) {
                node.tcp_close(fs.sockIdx);   // FIN → recipient sees EOF
                fs.state = 'sent';
            }
        } else if (DEAD_STATES.has(st)) {
            fileStatus(fs.lineEl, '✗ connection failed');
            s.fileSends.delete(seq);
        }
    }

    for (const [seq, fr] of s.fileRecvs) {
        if (fr.state === 'listening' && node.tcp_is_active(fr.listenerIdx)) {
            fr.state = 'receiving';
        }
        if (fr.state !== 'receiving') continue;
        for (;;) {
            const data = node.tcp_recv(fr.listenerIdx);
            if (!data) break;
            fr.chunks.push(data);
            fr.received += data.length;
        }
        if (fr.received >= fr.size) {
            finalizeRecv(s, seq, fr);
        } else {
            const pct = Math.floor((fr.received / Math.max(1, fr.size)) * 100);
            fileStatus(fr.lineEl, `receiving ${pct}%`);
            const st = node.tcp_state(fr.listenerIdx);
            if (DEAD_STATES.has(st) || st === 'CLOSE-WAIT') {
                node.tcp_close(fr.listenerIdx);
                send(s, { k: 'FILE_NACK', orig_seq: seq, reason: 'size mismatch' });
                fileStatus(fr.lineEl, `✗ truncated (${fr.received}/${fr.size})`);
                s.fileRecvs.delete(seq);
            }
        }
    }
}

// Attach a new connection to its chat: reuse the existing session for this
// address if there is one, otherwise create a fresh session/tab.
function attachConnection(idx, role, addr) {
    const existing = findChat(addr);
    if (existing) {
        rebindSession(existing, idx, role);
        appendLog(`Reusing chat with ${addr || '?'} (idx=${idx}, ${role})`);
        return existing;
    }
    const s = newSession(idx, role);
    s.peerAddr = addr;
    sessions.push(s);
    return s;
}

// --- Overlay connection state: hide the Join panel while connected ----------
function setOverlay(up) {
    const was = overlayConnected;
    overlayConnected = up;
    if (joinPanel) joinPanel.style.display = up ? 'none' : '';
    // "Start a chat" only works once we're peered into the overlay.
    if (dialBtn) dialBtn.disabled = !up;
    if (dialInput) dialInput.disabled = !up;
    if (!up && was) appendLog('Overlay link down — reconnect from the Join panel.');
}

// --- Incoming-message sound -------------------------------------------------
let audioCtx = null;
function isMuted() {
    return muteCheckbox && muteCheckbox.checked;
}
function playDing() {
    if (isMuted()) return;
    try {
        if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        if (audioCtx.state === 'suspended') audioCtx.resume();
        const now = audioCtx.currentTime;
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(880, now);          // a short two-note "ding"
        osc.frequency.setValueAtTime(1320, now + 0.08);
        gain.gain.setValueAtTime(0.0001, now);
        gain.gain.exponentialRampToValueAtTime(0.25, now + 0.01);
        gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.35);
        osc.connect(gain).connect(audioCtx.destination);
        osc.start(now);
        osc.stop(now + 0.36);
    } catch (e) {
        appendLog(`ding failed: ${e}`);
    }
}

function updateBadge(s) {
    if (!s.badgeEl) return;
    if (s.unread > 0) {
        s.badgeEl.textContent = s.unread > 99 ? '99+' : String(s.unread);
        s.badgeEl.classList.add('has-unread');
    } else {
        s.badgeEl.classList.remove('has-unread');
    }
}

// A chat is "live" when it's ready and keepalives are still arriving.
function isLive(s) {
    return s.state === 'ready' && (Date.now() - s.lastSeen) < ALIVE_TIMEOUT_MS;
}

// Liveness dot: green while keepalives/messages keep arriving, red once they
// stop for longer than ALIVE_TIMEOUT_MS (or after the chat closes).
function updateAlive(s) {
    if (!s.aliveEl) return;
    const live = isLive(s);
    s.aliveEl.classList.toggle('up', live);
    s.aliveEl.classList.toggle('down', !live);
    s.aliveEl.title = live ? 'peer alive' : 'no keepalive from peer';
}

function armListeners() {
    while (listeners.length < POOL_SIZE) {
        listeners.push(node.tcp_listen(CHAT_PORT));
    }
}

function send(s, obj) {
    const bytes = enc.encode(JSON.stringify(obj) + '\n');
    const n = node.tcp_send(s.idx, bytes);
    if (n < bytes.length) appendLog(`warn: partial send ${n}/${bytes.length} (idx=${s.idx})`);
}

function sendHello(s) {
    send(s, { k: 'YGG_CHAT_HELLO', nick: myNick(), ver: PROTO_VER });
    s.sentHello = true;
}

function handleFrame(s, obj) {
    s.lastSeen = Date.now();   // any frame proves the peer is alive
    if (obj.k === 'YGG_CHAT_HELLO') {
        if (s.nick !== null) return;               // ignore duplicate HELLO
        s.nick = (typeof obj.nick === 'string' && obj.nick) ? obj.nick : '(anon)';
        // Server replies to the client's HELLO.
        if (s.role === 'in' && !s.sentHello) sendHello(s);
        s.state = 'ready';
        openTab(s);
        if (s.titleEl) s.titleEl.textContent = s.nick;   // refresh on reconnect
        updateAlive(s);
        const where = s.peerAddr ? ` (${s.peerAddr})` : '';
        sysMsg(s, `handshake complete — chatting with ${s.nick}${where}`);
        appendLog(`Chat ready with "${s.nick}"${where} (idx=${s.idx}, ${s.role})`);
        flushQueue(s);
    } else if (obj.k === 'MSG') {
        if (s.state !== 'ready') return;
        if (typeof obj.seq === 'number' && obj.seq > s.recvMaxSeq) s.recvMaxSeq = obj.seq;
        appendMessage(s, s.nick, String(obj.text ?? ''), false);
        playDing();
        if (s !== activeSession) {
            s.unread++;
            updateBadge(s);
        }
    } else if (obj.k === 'ACK') {
        // Peer confirms receipt up to obj.seq → show delivery checks.
        if (typeof obj.seq === 'number') markDelivered(s, obj.seq);
    } else if (obj.k === 'FILE') {
        // Inbound file offer.
        if (typeof obj.seq === 'number' && obj.seq > s.recvMaxSeq) s.recvMaxSeq = obj.seq;
        const name = String(obj.name ?? 'file');
        const size = Number(obj.size) || 0;
        const type = String(obj['content-type'] ?? 'application/octet-stream');
        if (!allowFilesCheckbox.checked) {
            send(s, { k: 'FILE_REJECT', orig_seq: obj.seq });
            const lineEl = appendFileLine(s, `📎 ${name} (${humanSize(size)})`, false);
            fileStatus(lineEl, 'declined (files disabled)');
        } else {
            const port = allocFilePort();
            const listenerIdx = node.tcp_listen(port);
            const lineEl = appendFileLine(s, `📎 ${name} (${humanSize(size)})`, false);
            fileStatus(lineEl, 'receiving…');
            s.fileRecvs.set(obj.seq, { name, size, type, port, listenerIdx, chunks: [], received: 0, state: 'listening', lineEl });
            send(s, { k: 'FILE_ACCEPT', orig_seq: obj.seq, port });
        }
    } else if (obj.k === 'FILE_ACCEPT') {
        const fs = s.fileSends.get(obj.orig_seq);
        if (fs && fs.state === 'offered') {
            fs.sockIdx = node.tcp_connect(s.peerAddr, obj.port);
            fs.state = 'sending';
            fileStatus(fs.lineEl, 'connecting…');
        }
    } else if (obj.k === 'FILE_REJECT') {
        const fs = s.fileSends.get(obj.orig_seq);
        if (fs) { fileStatus(fs.lineEl, '✗ rejected by peer'); s.fileSends.delete(obj.orig_seq); }
    } else if (obj.k === 'FILE_ACK') {
        const fs = s.fileSends.get(obj.orig_seq);
        if (fs) { fileStatus(fs.lineEl, '✓ delivered'); s.fileSends.delete(obj.orig_seq); }
    } else if (obj.k === 'FILE_NACK') {
        const fs = s.fileSends.get(obj.orig_seq);
        if (fs) { fileStatus(fs.lineEl, `✗ ${obj.reason || 'failed'}`); s.fileSends.delete(obj.orig_seq); }
    } else if (obj.k === 'PING') {
        // Keepalive — liveness already refreshed above; nothing to display.
        updateAlive(s);
    }
    // Unknown kinds are ignored for forward-compatibility.
}

function processFrames(s) {
    let nl;
    while ((nl = s.rxBuf.indexOf('\n')) >= 0) {
        const line = s.rxBuf.slice(0, nl).trim();
        s.rxBuf = s.rxBuf.slice(nl + 1);
        if (!line) continue;
        let obj;
        try { obj = JSON.parse(line); } catch (e) { appendLog(`bad frame (idx=${s.idx}): ${line}`); continue; }
        handleFrame(s, obj);
    }
}

function driveSession(s) {
    // Outbound: once the connection is established, open with our HELLO.
    if (s.role === 'out' && !s.sentHello && node.tcp_state(s.idx) === 'ESTABLISHED') {
        sendHello(s);
        s.state = 'await-hello';
    }

    // Drain everything available into the per-session decode buffer.
    let got = false;
    for (;;) {
        const data = node.tcp_recv(s.idx);
        if (!data) break;
        got = true;
        s.rxBuf += s.dec.decode(data, { stream: true });
    }
    processFrames(s);

    // Close detection.
    const st = node.tcp_state(s.idx);
    if (DEAD_STATES.has(st) || (st === 'CLOSE-WAIT' && !got)) {
        closeSession(s, 'peer disconnected');
    }
}

function closeSession(s, reason) {
    if (s.state === 'closed') return;
    s.state = 'closed';
    if (s.tabEl) s.tabEl.classList.add('closed');
    // Input stays enabled: sending a message reopens the connection.
    updateAlive(s);
    sysMsg(s, reason);
    appendLog(`Chat closed (idx=${s.idx}): ${reason}`);
}

// ---------------------------------------------------------------------------
// Tab / pane UI
// ---------------------------------------------------------------------------
function selectTab(s) {
    activeSession = s;
    for (const o of sessions) {
        if (o.tabEl) o.tabEl.classList.toggle('active', o === s);
        if (o.paneEl) o.paneEl.classList.toggle('active', o === s);
    }
    s.unread = 0;
    updateBadge(s);
    if (s.inputEl && s.state !== 'closed') s.inputEl.focus();
}

function openTab(s) {
    if (s.tabEl) { selectTab(s); return; }   // already open
    if (emptyEl && emptyEl.parentNode) emptyEl.remove();

    // Tab button
    const tab = document.createElement('div');
    tab.className = 'tab';
    if (s.peerAddr) tab.title = s.peerAddr;
    const dot = document.createElement('span');
    dot.className = 'alive-dot';
    tab.appendChild(dot);
    const title = document.createElement('span');
    title.textContent = s.nick || `peer ${s.id}`;
    tab.appendChild(title);
    const badge = document.createElement('span');
    badge.className = 'badge';
    tab.appendChild(badge);
    tab.addEventListener('click', () => selectTab(s));
    tabsEl.appendChild(tab);
    s.badgeEl = badge;
    s.aliveEl = dot;
    updateAlive(s);

    // Pane
    const pane = document.createElement('div');
    pane.className = 'pane';

    const msglist = document.createElement('div');
    msglist.className = 'msglist';
    pane.appendChild(msglist);

    const sendrow = document.createElement('div');
    sendrow.className = 'sendrow';
    const input = document.createElement('input');
    input.type = 'text';
    input.placeholder = 'Type a message and press Enter';
    const btn = document.createElement('button');
    btn.textContent = 'Send';
    const attachBtn = document.createElement('button');
    attachBtn.textContent = '📎';
    attachBtn.title = 'Send a file';
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.style.display = 'none';
    attachBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => {
        if (fileInput.files && fileInput.files[0]) startFileSend(s, fileInput.files[0]);
        fileInput.value = '';
    });
    sendrow.appendChild(input);
    sendrow.appendChild(btn);
    sendrow.appendChild(attachBtn);
    sendrow.appendChild(fileInput);
    pane.appendChild(sendrow);
    panesEl.appendChild(pane);

    s.tabEl = tab; s.titleEl = title; s.paneEl = pane;
    s.msglistEl = msglist; s.inputEl = input; s.sendBtn = btn;

    const doSend = () => {
        const text = input.value;
        if (!text) return;
        input.value = '';
        const div = appendMessage(s, myNick(), text, true);   // optimistic local echo
        const item = { text, statusEl: div ? div.querySelector('.status') : null };
        if (isLive(s)) {
            sendMsg(s, item);
        } else {
            // Disconnected/stale (or still connecting): queue and reopen the link.
            s.outQueue.push(item);
            ensureConnected(s);
        }
    };
    btn.addEventListener('click', doSend);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') doSend(); });

    selectTab(s);
}

function appendMessage(s, who, text, isMe) {
    if (!s.msglistEl) return null;
    const div = document.createElement('div');
    div.className = 'msg' + (isMe ? ' me' : '');
    const whoSpan = document.createElement('span');
    whoSpan.className = 'who';
    whoSpan.textContent = who + ': ';
    div.appendChild(whoSpan);
    div.appendChild(document.createTextNode(text));
    if (isMe) {
        const status = document.createElement('span');
        status.className = 'status';   // filled with ✓ once the peer ACKs
        div.appendChild(status);
    }
    s.msglistEl.appendChild(div);
    s.msglistEl.scrollTop = s.msglistEl.scrollHeight;
    return div;
}

function sysMsg(s, text) {
    if (!s.msglistEl) { appendLog(text); return; }
    const div = document.createElement('div');
    div.className = 'msg sys';
    div.textContent = `— ${text} —`;
    s.msglistEl.appendChild(div);
    s.msglistEl.scrollTop = s.msglistEl.scrollHeight;
}

// ---------------------------------------------------------------------------
// Poll loop
// ---------------------------------------------------------------------------
function tick() {
    if (!node) return;

    // Detect listeners that have accepted an inbound connection.
    for (let i = listeners.length - 1; i >= 0; i--) {
        const idx = listeners[i];
        if (node.tcp_is_active(idx)) {
            listeners.splice(i, 1);
            const addr = node.tcp_remote(idx);
            appendLog(`Inbound connection from ${addr || '?'} (idx=${idx})`);
            attachConnection(idx, 'in', addr);
        }
    }
    armListeners();

    for (const s of sessions) {
        if (s.state !== 'closed') driveSession(s);
        pumpFiles(s);   // file sockets are independent of the chat connection
    }
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------
// Join the overlay via a WebSocket bridge. Resolves true on success.
async function connectOverlay(url) {
    if (!url) return false;
    if (!node) { appendLog('Node not ready yet.'); return false; }
    localStorage.setItem(LS_PEER, url);
    const btn = document.getElementById('btn-connect');
    btn.disabled = true;
    appendLog(`Connecting to overlay via ${url}...`);
    let ok = false;
    try {
        const pid = await node.connect_peer(url);
        appendLog(`Joined overlay (peer id=${pid}).`);
        setOverlay(true);
        ok = true;
    } catch (e) {
        appendLog(`Connection failed: ${e}`);
    }
    btn.disabled = false;
    return ok;
}

// Dial a peer's Yggdrasil IPv6 address and open an outbound chat session.
function dialPeer(addr) {
    addr = (addr || '').trim();
    if (!addr) return;
    if (!node) { appendLog('Node not ready yet.'); return; }
    const idx = node.tcp_connect(addr, CHAT_PORT);
    appendLog(`Dialing [${addr}]:${CHAT_PORT} (idx=${idx})...`);
    attachConnection(idx, 'out', addr);
}

async function main() {
    appendLog('Loading WASM module...');
    await init();
    appendLog('WASM loaded.');

    // Restore UI persistence.
    nickInput.value = localStorage.getItem(LS_NICK) || '';
    peerInput.value = localStorage.getItem(LS_PEER) || DEFAULT_PEER;
    muteCheckbox.checked = localStorage.getItem(LS_MUTE) === '1';
    autoconnectCheckbox.checked = localStorage.getItem(LS_AUTOCONNECT) !== '0';   // default on
    allowFilesCheckbox.checked = localStorage.getItem(LS_ALLOWFILES) !== '0';     // default on
    nickInput.addEventListener('change', () => localStorage.setItem(LS_NICK, nickInput.value.trim()));
    muteCheckbox.addEventListener('change', () => localStorage.setItem(LS_MUTE, muteCheckbox.checked ? '1' : '0'));
    autoconnectCheckbox.addEventListener('change', () => localStorage.setItem(LS_AUTOCONNECT, autoconnectCheckbox.checked ? '1' : '0'));
    allowFilesCheckbox.addEventListener('change', () => localStorage.setItem(LS_ALLOWFILES, allowFilesCheckbox.checked ? '1' : '0'));

    setOverlay(false);           // Join panel visible until we connect

    // Stable identity from localStorage.
    node = new YggdrasilWasm(loadSeed());
    nodeAddrEl.textContent = node.address();
    chatLinkEl.textContent = myChatLink();
    appendLog(`Node ready: ${node.address()}`);

    node.start_polling(100);     // drives the WASM node internals
    armListeners();              // open the inbound chat listener pool
    appendLog(`Listening for chats on overlay port ${CHAT_PORT}.`);

    setInterval(tick, 150);      // chat protocol loop
    setInterval(() => { nodePeersEl.textContent = node.peer_count(); }, 1000);

    // Send keepalives on every ready chat.
    setInterval(() => {
        for (const s of sessions) {
            if (s.state === 'ready') send(s, { k: 'PING' });
        }
    }, KEEPALIVE_MS);

    // Refresh the liveness dots (turns red once keepalives stop arriving).
    setInterval(() => {
        for (const s of sessions) updateAlive(s);
    }, 2000);

    // Acknowledge received messages so the sender can show delivery checks.
    setInterval(() => {
        for (const s of sessions) {
            if (s.state === 'ready' && s.recvMaxSeq > s.ackSent) {
                send(s, { k: 'ACK', seq: s.recvMaxSeq });
                s.ackSent = s.recvMaxSeq;
            }
        }
    }, ACK_MS);

    // Autochat: a "chat with me" page — auto-join, then dial the target peer
    // (from the #chat= link, the ?autochat= query, or the AUTOCHAT constant).
    const autochatAddr = autochatTarget();
    if (autochatAddr) {
        appendLog(`Autochat enabled → ${autochatAddr}`);
        const nick = ensureNick();
        if (!nick) {
            appendLog('No name entered — autochat cancelled. Set a nickname and connect manually.');
        } else {
            const joined = await connectOverlay(peerInput.value.trim());
            if (joined) dialPeer(autochatAddr);
        }
    } else if (autoconnectCheckbox.checked) {
        // Fresh visitor with no autochat target: join the default node anyway.
        connectOverlay(peerInput.value.trim());
    }
}

document.getElementById('btn-connect').addEventListener('click', () => {
    connectOverlay(peerInput.value.trim());
});

copyLinkBtn.addEventListener('click', async () => {
    if (!node) { appendLog('Node not ready yet.'); return; }
    const link = myChatLink();
    try {
        await navigator.clipboard.writeText(link);
        appendLog('Chat link copied to clipboard.');
    } catch (e) {
        appendLog(`Copy failed — here is your chat link: ${link}`);
    }
});

document.getElementById('btn-dial').addEventListener('click', () => {
    dialPeer(dialInput.value);
});

main().catch(e => appendLog(`Error: ${e}`));
