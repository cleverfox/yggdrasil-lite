//! Telnet CLI — line-oriented command parser for the IoT demo.
//!
//! Accumulates bytes until CR/LF, parses commands, formats responses.
//! No heap allocation — all buffers are on the stack.

const CMD_BUF_SIZE: usize = 128;

pub const WELCOME: &[u8] = b"Yggdrasil ESP32-C6 IoT CLI\r\nType 'help' for commands.\r\n> ";
pub const PROMPT: &[u8] = b"> ";

pub enum Command {
    Help,
    Temp,
    Led { r: u8, g: u8, b: u8 },
    Status,
    Uptime,
    Who,
    Ping { addr: smoltcp::wire::Ipv6Address },
    Unknown,
}

pub struct TelnetCli {
    buf: [u8; CMD_BUF_SIZE],
    len: usize,
    /// True if we're in the middle of skipping a telnet IAC sequence.
    iac_skip: u8,
}

impl TelnetCli {
    pub const fn new() -> Self {
        Self {
            buf: [0u8; CMD_BUF_SIZE],
            len: 0,
            iac_skip: 0,
        }
    }

    /// Feed received bytes. Returns a parsed command when a complete line is received.
    pub fn feed(&mut self, data: &[u8]) -> Option<Command> {
        for &b in data {
            // Skip telnet IAC sequences: FF xx [yy]
            if self.iac_skip > 0 {
                self.iac_skip -= 1;
                continue;
            }
            if b == 0xFF {
                self.iac_skip = 2; // skip the next 2 bytes (command + option)
                continue;
            }

            // End of line → parse
            if b == b'\n' || b == b'\r' {
                if self.len > 0 {
                    let cmd = self.parse();
                    self.len = 0;
                    return Some(cmd);
                }
                continue;
            }

            // Backspace
            if b == 0x7F || b == 0x08 {
                if self.len > 0 {
                    self.len -= 1;
                }
                continue;
            }

            // Accumulate printable bytes
            if self.len < CMD_BUF_SIZE {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
        None
    }

    fn parse(&self) -> Command {
        let line = core::str::from_utf8(&self.buf[..self.len]).unwrap_or("");
        let line = line.trim();

        if line.eq_ignore_ascii_case("help") {
            Command::Help
        } else if line.eq_ignore_ascii_case("temp") {
            Command::Temp
        } else if line.eq_ignore_ascii_case("status") {
            Command::Status
        } else if line.eq_ignore_ascii_case("uptime") {
            Command::Uptime
        } else if line.eq_ignore_ascii_case("w") {
            Command::Who
        } else if line.len() > 4 && line[..4].eq_ignore_ascii_case("led ") {
            match parse_led_args(&line[4..]) {
                Some((r, g, b)) => Command::Led { r, g, b },
                None => Command::Unknown,
            }
        } else if line.len() > 5 && line[..5].eq_ignore_ascii_case("ping ") {
            match parse_ping_addr(&line[5..]) {
                Some(addr) => Command::Ping { addr },
                None => Command::Unknown,
            }
        } else {
            Command::Unknown
        }
    }
}

fn parse_led_args(args: &str) -> Option<(u8, u8, u8)> {
    let mut iter = args.split_whitespace();
    let r: u8 = iter.next()?.parse().ok()?;
    let g: u8 = iter.next()?.parse().ok()?;
    let b: u8 = iter.next()?.parse().ok()?;
    Some((r, g, b))
}

fn parse_ping_addr(args: &str) -> Option<smoltcp::wire::Ipv6Address> {
    let s = args.trim();
    // Parse IPv6 address via core::net then convert to smoltcp
    let addr: core::net::Ipv6Addr = s.parse().ok()?;
    Some(smoltcp::wire::Ipv6Address::from(addr.octets()))
}

// ── Response formatters ────────────────────────────────────────────────

pub fn fmt_help(buf: &mut [u8]) -> usize {
    let msg = b"Commands:\r\n\
                \x20 help              Show this help\r\n\
                \x20 temp              Read temperature\r\n\
                \x20 led <r> <g> <b>   Set LED color (0-255)\r\n\
                \x20 ping <ipv6>       Ping over Yggdrasil\r\n\
                \x20 uptime            Show system uptime\r\n\
                \x20 w                 Show connected sessions\r\n\
                \x20 status            Show node status\r\n";
    let n = msg.len().min(buf.len());
    buf[..n].copy_from_slice(&msg[..n]);
    n
}

pub fn fmt_unknown(buf: &mut [u8]) -> usize {
    let msg = b"Unknown command. Type 'help'.\r\n";
    let n = msg.len().min(buf.len());
    buf[..n].copy_from_slice(&msg[..n]);
    n
}

pub fn fmt_temp(buf: &mut [u8], reading: Option<crate::onewire::TempReading>) -> usize {
    match reading {
        Some(r) => {
            let mut pos = 0;
            let prefix = b"Temperature: ";
            let n = prefix.len().min(buf.len());
            buf[..n].copy_from_slice(&prefix[..n]);
            pos += n;
            pos += r.format(&mut buf[pos..]);
            let suffix = b" C\r\n";
            let n = suffix.len().min(buf.len().saturating_sub(pos));
            buf[pos..pos + n].copy_from_slice(&suffix[..n]);
            pos += n;
            pos
        }
        None => {
            let msg = b"Temperature: no reading yet\r\n";
            let n = msg.len().min(buf.len());
            buf[..n].copy_from_slice(&msg[..n]);
            n
        }
    }
}

pub fn fmt_led_ok(buf: &mut [u8], r: u8, g: u8, b: u8) -> usize {
    // "LED: (R, G, B)\r\n"
    let mut pos = 0;
    let prefix = b"LED set: (";
    let n = prefix.len().min(buf.len());
    buf[..n].copy_from_slice(&prefix[..n]);
    pos += n;
    pos += fmt_u8(&mut buf[pos..], r);
    if pos < buf.len() {
        buf[pos] = b',';
        pos += 1;
    }
    if pos < buf.len() {
        buf[pos] = b' ';
        pos += 1;
    }
    pos += fmt_u8(&mut buf[pos..], g);
    if pos < buf.len() {
        buf[pos] = b',';
        pos += 1;
    }
    if pos < buf.len() {
        buf[pos] = b' ';
        pos += 1;
    }
    pos += fmt_u8(&mut buf[pos..], b);
    let suffix = b")\r\n";
    let n = suffix.len().min(buf.len().saturating_sub(pos));
    buf[pos..pos + n].copy_from_slice(&suffix[..n]);
    pos += n;
    pos
}

#[allow(dead_code)]
pub fn fmt_led_none(buf: &mut [u8]) -> usize {
    let msg = b"LED: not available\r\n";
    let n = msg.len().min(buf.len());
    buf[..n].copy_from_slice(&msg[..n]);
    n
}

pub fn fmt_ping_start(buf: &mut [u8], addr: &smoltcp::wire::Ipv6Address) -> usize {
    let mut pos = 0;
    let prefix = b"PING ";
    let n = prefix.len().min(buf.len());
    buf[..n].copy_from_slice(&prefix[..n]);
    pos += n;
    pos += fmt_ipv6(&mut buf[pos..], addr);
    let suffix = b" ...\r\n";
    let n = suffix.len().min(buf.len().saturating_sub(pos));
    buf[pos..pos + n].copy_from_slice(&suffix[..n]);
    pos += n;
    pos
}

pub fn fmt_ping_reply(
    buf: &mut [u8],
    addr: &smoltcp::wire::Ipv6Address,
    seq: u16,
    rtt_ms: u32,
) -> usize {
    let mut pos = 0;
    let prefix = b"Reply from ";
    let n = prefix.len().min(buf.len());
    buf[..n].copy_from_slice(&prefix[..n]);
    pos += n;
    pos += fmt_ipv6(&mut buf[pos..], addr);
    let mid = b": seq=";
    let n = mid.len().min(buf.len().saturating_sub(pos));
    buf[pos..pos + n].copy_from_slice(&mid[..n]);
    pos += n;
    pos += fmt_u32(&mut buf[pos..], seq as u32);
    let mid2 = b" time=";
    let n = mid2.len().min(buf.len().saturating_sub(pos));
    buf[pos..pos + n].copy_from_slice(&mid2[..n]);
    pos += n;
    pos += fmt_u32(&mut buf[pos..], rtt_ms);
    let suffix = b"ms\r\n";
    let n = suffix.len().min(buf.len().saturating_sub(pos));
    buf[pos..pos + n].copy_from_slice(&suffix[..n]);
    pos += n;
    pos
}

pub fn fmt_ping_timeout(buf: &mut [u8], seq: u16) -> usize {
    let mut pos = 0;
    let prefix = b"Request timeout for seq ";
    let n = prefix.len().min(buf.len());
    buf[..n].copy_from_slice(&prefix[..n]);
    pos += n;
    pos += fmt_u32(&mut buf[pos..], seq as u32);
    let suffix = b"\r\n";
    let n = suffix.len().min(buf.len().saturating_sub(pos));
    buf[pos..pos + n].copy_from_slice(&suffix[..n]);
    pos += n;
    pos
}

pub fn fmt_ping_busy(buf: &mut [u8]) -> usize {
    let msg = b"Ping already in progress.\r\n";
    let n = msg.len().min(buf.len());
    buf[..n].copy_from_slice(&msg[..n]);
    n
}

/// Format uptime as "up Xd Xh Xm Xs\r\n"
pub fn fmt_uptime(buf: &mut [u8], uptime_secs: u32) -> usize {
    let mut pos = 0;
    let prefix = b"up ";
    let n = prefix.len().min(buf.len());
    buf[..n].copy_from_slice(&prefix[..n]);
    pos += n;
    pos += fmt_duration(&mut buf[pos..], uptime_secs);
    let suffix = b"\r\n";
    let n = suffix.len().min(buf.len().saturating_sub(pos));
    buf[pos..pos + n].copy_from_slice(&suffix[..n]);
    pos += n;
    pos
}

/// Info about a single connected telnet session, passed to `fmt_who`.
pub struct SessionInfo {
    pub slot: u8,
    pub addr: smoltcp::wire::Ipv6Address,
    pub port: u16,
    pub connected_secs: u32,
}

/// Format "w" output: header + one line per session.
pub fn fmt_who(buf: &mut [u8], uptime_secs: u32, sessions: &[SessionInfo]) -> usize {
    let mut pos = 0;

    // Header line: uptime + user count
    let pre = b"up ";
    let n = pre.len().min(buf.len());
    buf[..n].copy_from_slice(&pre[..n]);
    pos += n;
    pos += fmt_duration(&mut buf[pos..], uptime_secs);
    let mid = b", ";
    let n = mid.len().min(buf.len().saturating_sub(pos));
    buf[pos..pos + n].copy_from_slice(&mid[..n]);
    pos += n;
    pos += fmt_u32(&mut buf[pos..], sessions.len() as u32);
    let suf = if sessions.len() == 1 {
        &b" user\r\n"[..]
    } else {
        &b" users\r\n"[..]
    };
    let n = suf.len().min(buf.len().saturating_sub(pos));
    buf[pos..pos + n].copy_from_slice(&suf[..n]);
    pos += n;

    // Column header (SLOT=4+2pad, FROM=max48, CONNECTED)
    //                "SLOT  FROM                                                CONNECTED\r\n"
    let hdr = b"SLOT  FROM                                        CONNECTED\r\n";
    let n = hdr.len().min(buf.len().saturating_sub(pos));
    buf[pos..pos + n].copy_from_slice(&hdr[..n]);
    pos += n;

    // One line per session
    for s in sessions {
        // Slot number — pad to 6 chars ("SLOT  ")
        let slot_start = pos;
        pos += fmt_u32(&mut buf[pos..], s.slot as u32);
        let slot_len = pos - slot_start;
        let slot_pad = 6usize
            .saturating_sub(slot_len)
            .min(buf.len().saturating_sub(pos));
        for i in 0..slot_pad {
            buf[pos + i] = b' ';
        }
        pos += slot_pad;

        // Remote address:port — pad to 48 chars (max IPv6=39 + ':' + port=5 = 45, +3 gap)
        let addr_start = pos;
        pos += fmt_ipv6(&mut buf[pos..], &s.addr);
        if pos < buf.len() {
            buf[pos] = b'.';
            pos += 1;
        }
        pos += fmt_u32(&mut buf[pos..], s.port as u32);
        let addr_len = pos - addr_start;
        let pad_to: usize = 48;
        let addr_pad = pad_to
            .saturating_sub(addr_len)
            .max(2)
            .min(buf.len().saturating_sub(pos));
        for i in 0..addr_pad {
            buf[pos + i] = b' ';
        }
        pos += addr_pad;

        // Connected duration
        pos += fmt_duration(&mut buf[pos..], s.connected_secs);
        let crlf = b"\r\n";
        let n = crlf.len().min(buf.len().saturating_sub(pos));
        buf[pos..pos + n].copy_from_slice(&crlf[..n]);
        pos += n;
    }

    pos
}

/// Format seconds as "Xd Xh Xm Xs" (omitting zero leading components).
fn fmt_duration(buf: &mut [u8], total_secs: u32) -> usize {
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    let mut pos = 0;
    let mut started = false;

    if days > 0 {
        pos += fmt_u32(&mut buf[pos..], days);
        if pos < buf.len() {
            buf[pos] = b'd';
            pos += 1;
        }
        if pos < buf.len() {
            buf[pos] = b' ';
            pos += 1;
        }
        started = true;
    }
    if hours > 0 || started {
        pos += fmt_u32(&mut buf[pos..], hours);
        if pos < buf.len() {
            buf[pos] = b'h';
            pos += 1;
        }
        if pos < buf.len() {
            buf[pos] = b' ';
            pos += 1;
        }
        started = true;
    }
    if mins > 0 || started {
        pos += fmt_u32(&mut buf[pos..], mins);
        if pos < buf.len() {
            buf[pos] = b'm';
            pos += 1;
        }
        if pos < buf.len() {
            buf[pos] = b' ';
            pos += 1;
        }
    }
    pos += fmt_u32(&mut buf[pos..], secs);
    if pos < buf.len() {
        buf[pos] = b's';
        pos += 1;
    }

    pos
}

/// Format an IPv6 address into a byte buffer, return bytes written.
pub fn fmt_ipv6(buf: &mut [u8], addr: &smoltcp::wire::Ipv6Address) -> usize {
    // Use smoltcp's Display impl via a small stack formatter
    use core::fmt::Write;
    struct BufW<'a> {
        buf: &'a mut [u8],
        pos: usize,
    }
    impl<'a> Write for BufW<'a> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let n = bytes.len().min(self.buf.len().saturating_sub(self.pos));
            self.buf[self.pos..self.pos + n].copy_from_slice(&bytes[..n]);
            self.pos += n;
            Ok(())
        }
    }
    let mut w = BufW { buf, pos: 0 };
    let _ = write!(w, "{}", addr);
    w.pos
}

/// Format a u8 as decimal into buf, return bytes written.
fn fmt_u8(buf: &mut [u8], val: u8) -> usize {
    let mut digits = [0u8; 3];
    let mut n = val;
    let mut len = 0;
    if n == 0 {
        digits[0] = b'0';
        len = 1;
    } else {
        while n > 0 {
            digits[len] = b'0' + (n % 10);
            n /= 10;
            len += 1;
        }
        digits[..len].reverse();
    }
    let w = len.min(buf.len());
    buf[..w].copy_from_slice(&digits[..w]);
    w
}

/// Format a u32 as decimal into buf, return bytes written.
pub fn fmt_u32(buf: &mut [u8], val: u32) -> usize {
    let mut digits = [0u8; 10];
    let mut n = val;
    let mut len = 0;
    if n == 0 {
        digits[0] = b'0';
        len = 1;
    } else {
        while n > 0 {
            digits[len] = b'0' + (n % 10) as u8;
            n /= 10;
            len += 1;
        }
        digits[..len].reverse();
    }
    let w = len.min(buf.len());
    buf[..w].copy_from_slice(&digits[..w]);
    w
}
