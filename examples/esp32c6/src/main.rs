//! ESP32-C6 Yggdrasil TCP-UART Bridge
//!
//! Boots → connects to WiFi → establishes TLS connections to up to 3 Yggdrasil
//! peers → listens for TCP on the Yggdrasil overlay → bridges TCP↔UART.
//!
//! Web UI on AP (192.168.4.1) and STA for configuration.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::net::Ipv4Addr;
use core::sync::atomic::{AtomicBool, Ordering};

use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_net::{
    IpListenEndpoint, Ipv4Cidr, Runner, StackResources, StaticConfigV4, tcp::TcpSocket,
};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_sync::pipe::Pipe;
use embassy_time::{Duration, Timer};
use embedded_io_async::Write as AsyncWrite;
use embedded_storage::{ReadStorage, Storage};
use esp_alloc as _;
use esp_backtrace as _;
use esp_bootloader_esp_idf::partitions;
use esp_hal::{
    clock::CpuClock,
    interrupt::software::SoftwareInterruptControl,
    rng::Rng,
    timer::timg::TimerGroup,
    uart::{self, Uart},
};
use esp_hal_dhcp_server::simple_leaser::SimpleDhcpLeaser;
use esp_hal_dhcp_server::structs::DhcpServerConfig;
use esp_println::println;
use esp_radio::wifi::{
    ModeConfig, WifiController, WifiDevice, WifiEvent, ap::AccessPointConfig, sta::StationConfig,
};
use esp_storage::FlashStorage;
use heapless::String;

use ed25519_dalek::SigningKey;
use rand_core::RngCore;
use yggdrasil_lite::address::addr_for_key;
use yggdrasil_lite::crypto::PublicKey;
use yggdrasil_lite::meta::Metadata;
use yggdrasil_lite::node::{LiteConfig, NodeEvent, YggdrasilLite};

esp_bootloader_esp_idf::esp_app_desc!();

// ============================================================================
// Constants
// ============================================================================

const UART_BAUD_RATE: u32 = 115200;
const HTTP_PORT: u16 = 80;

// AP configuration
const AP_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 1);
const DHCP_POOL_START: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 10);
const DHCP_POOL_END: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 100);

// Compile-time defaults
const DEFAULT_WIFI_SSID: &str = env!("WIFI_SSID");
const DEFAULT_WIFI_PASSWORD: &str = env!("WIFI_PASSWORD");
const DEFAULT_YGG_PEER1: &str = env!("YGG_PEER1");
const DEFAULT_YGG_PEER2: &str = env!("YGG_PEER2");
const DEFAULT_YGG_PEER3: &str = env!("YGG_PEER3");
const DEFAULT_YGG_LISTEN_PORT: &str = env!("YGG_LISTEN_PORT");

// Config magic numbers
const WIFI_CONFIG_MAGIC: u32 = 0xC0F1_6001;
const YGG_KEY_MAGIC: u32 = 0xD1CE_ED01;
const YGG_PEERS_MAGIC: u32 = 0xD1CE_ED02;

// NVS offsets
const WIFI_CONFIG_OFFSET: u32 = 0;
const YGG_KEY_OFFSET: u32 = 128;
const YGG_PEERS_OFFSET: u32 = 256; // 256 bytes for 3 peers

/// Session type byte prepended to IPv6 packets.
const TYPE_SESSION_TRAFFIC: u8 = 0x01;

#[cfg(not(feature = "smoltcp"))]
mod minitcp_consts {
    /// TCP flags
    pub const TCP_FIN: u8 = 0x01;
    pub const TCP_SYN: u8 = 0x02;
    pub const TCP_RST: u8 = 0x04;
    pub const TCP_PSH: u8 = 0x08;
    pub const TCP_ACK: u8 = 0x10;

    /// ICMPv6
    pub const IPPROTO_ICMPV6: u8 = 58;
    pub const ICMPV6_ECHO_REQUEST: u8 = 128;
    pub const ICMPV6_ECHO_REPLY: u8 = 129;
}
#[cfg(not(feature = "smoltcp"))]
use minitcp_consts::*;

// ============================================================================
// Global State
// ============================================================================

/// Pipes for bidirectional TCP-UART communication
static TCP_TO_UART: Pipe<CriticalSectionRawMutex, 512> = Pipe::new();
static UART_TO_TCP: Pipe<CriticalSectionRawMutex, 512> = Pipe::new();

static WIFI_CONFIG: Mutex<CriticalSectionRawMutex, WifiConfig> = Mutex::new(WifiConfig::new());
static STA_IP: Mutex<CriticalSectionRawMutex, Option<Ipv4Addr>> = Mutex::new(None);
static WIFI_CONNECTED: AtomicBool = AtomicBool::new(false);
static UART_CONNECTED: AtomicBool = AtomicBool::new(false);

/// Yggdrasil IPv6 address (set once on boot)
static YGG_IPV6: Mutex<CriticalSectionRawMutex, [u8; 16]> = Mutex::new([0u8; 16]);

/// Yggdrasil peers config (shared between main and web server)
static YGG_PEERS: Mutex<CriticalSectionRawMutex, YggPeersConfig> =
    Mutex::new(YggPeersConfig::new());

/// Yggdrasil listen port
static YGG_PORT: Mutex<CriticalSectionRawMutex, u16> = Mutex::new(2000);

// ============================================================================
// Flash Configuration Structures
// ============================================================================

#[repr(C, align(4))]
#[derive(Clone, Copy)]
struct WifiConfig {
    magic: u32,
    ssid: [u8; 32],
    ssid_len: u8,
    password: [u8; 64],
    password_len: u8,
    _padding: [u8; 2],
}

impl WifiConfig {
    const fn new() -> Self {
        Self {
            magic: 0,
            ssid: [0; 32],
            ssid_len: 0,
            password: [0; 64],
            password_len: 0,
            _padding: [0; 2],
        }
    }

    fn is_valid(&self) -> bool {
        self.magic == WIFI_CONFIG_MAGIC && self.ssid_len > 0
    }

    fn ssid_str(&self) -> &str {
        if self.ssid_len == 0 {
            ""
        } else {
            unsafe { core::str::from_utf8_unchecked(&self.ssid[..self.ssid_len as usize]) }
        }
    }

    fn password_str(&self) -> &str {
        if self.password_len == 0 {
            ""
        } else {
            unsafe { core::str::from_utf8_unchecked(&self.password[..self.password_len as usize]) }
        }
    }

    fn set_credentials(&mut self, ssid: &str, password: &str) {
        self.magic = WIFI_CONFIG_MAGIC;
        self.ssid_len = ssid.len().min(32) as u8;
        self.ssid[..self.ssid_len as usize]
            .copy_from_slice(&ssid.as_bytes()[..self.ssid_len as usize]);
        self.password_len = password.len().min(64) as u8;
        self.password[..self.password_len as usize]
            .copy_from_slice(&password.as_bytes()[..self.password_len as usize]);
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        let config = unsafe { core::ptr::read(bytes.as_ptr() as *const Self) };
        if config.is_valid() {
            Some(config)
        } else {
            None
        }
    }
}

/// Ed25519 seed stored in flash for stable Yggdrasil address.
#[repr(C, align(4))]
#[derive(Clone, Copy)]
struct YggKeyConfig {
    magic: u32,
    seed: [u8; 32],
    _padding: [u8; 28], // pad to 64 bytes
}

impl YggKeyConfig {
    const fn new() -> Self {
        Self {
            magic: 0,
            seed: [0; 32],
            _padding: [0; 28],
        }
    }

    fn is_valid(&self) -> bool {
        self.magic == YGG_KEY_MAGIC
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        let config = unsafe { core::ptr::read(bytes.as_ptr() as *const Self) };
        if config.is_valid() {
            Some(config)
        } else {
            None
        }
    }
}

/// A single peer address entry (80 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct PeerEntry {
    addr: [u8; 72], // e.g. "1.2.3.4:12345" or "[2001:db8::1]:12345"
    addr_len: u8,
    _pad: [u8; 7],
}

impl PeerEntry {
    const fn new() -> Self {
        Self {
            addr: [0; 72],
            addr_len: 0,
            _pad: [0; 7],
        }
    }

    fn is_empty(&self) -> bool {
        self.addr_len == 0
    }

    fn as_str(&self) -> &str {
        if self.addr_len == 0 {
            ""
        } else {
            unsafe { core::str::from_utf8_unchecked(&self.addr[..self.addr_len as usize]) }
        }
    }

    fn set(&mut self, addr: &str) {
        self.addr_len = addr.len().min(72) as u8;
        self.addr[..self.addr_len as usize]
            .copy_from_slice(&addr.as_bytes()[..self.addr_len as usize]);
    }
}

/// Yggdrasil peers configuration (256 bytes total).
#[repr(C, align(4))]
#[derive(Clone, Copy)]
struct YggPeersConfig {
    magic: u32,
    count: u8,
    _pad: [u8; 3],
    peers: [PeerEntry; 3], // 3 × 80 = 240 bytes
}

impl YggPeersConfig {
    const fn new() -> Self {
        Self {
            magic: 0,
            count: 0,
            _pad: [0; 3],
            peers: [PeerEntry::new(), PeerEntry::new(), PeerEntry::new()],
        }
    }

    fn is_valid(&self) -> bool {
        self.magic == YGG_PEERS_MAGIC
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        let config = unsafe { core::ptr::read(bytes.as_ptr() as *const Self) };
        if config.is_valid() {
            Some(config)
        } else {
            None
        }
    }

    fn set_peers(&mut self, addrs: &[&str]) {
        self.magic = YGG_PEERS_MAGIC;
        self.count = 0;
        for (i, addr) in addrs.iter().enumerate().take(3) {
            if !addr.is_empty() {
                self.peers[i].set(addr);
                self.count += 1;
            }
        }
    }
}

// ============================================================================
// Flash Load/Save
// ============================================================================

macro_rules! mk_static {
    ($t:ty,$val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit().write(($val));
        x
    }};
}

fn load_wifi_config(flash: &mut FlashStorage) -> Option<WifiConfig> {
    let mut pt_mem = [0u8; partitions::PARTITION_TABLE_MAX_LEN];
    let pt = partitions::read_partition_table(flash, &mut pt_mem).ok()?;
    let nvs = pt
        .find_partition(partitions::PartitionType::Data(
            partitions::DataPartitionSubType::Nvs,
        ))
        .ok()??;
    let mut nvs_partition = nvs.as_embedded_storage(flash);
    let mut buf = [0u8; 128];
    nvs_partition.read(WIFI_CONFIG_OFFSET, &mut buf).ok()?;
    WifiConfig::from_bytes(&buf)
}

fn save_wifi_config(flash: &mut FlashStorage, config: &WifiConfig) -> Result<(), ()> {
    let mut pt_mem = [0u8; partitions::PARTITION_TABLE_MAX_LEN];
    let pt = partitions::read_partition_table(flash, &mut pt_mem).map_err(|_| ())?;
    let nvs = pt
        .find_partition(partitions::PartitionType::Data(
            partitions::DataPartitionSubType::Nvs,
        ))
        .map_err(|_| ())?
        .ok_or(())?;
    let mut nvs_partition = nvs.as_embedded_storage(flash);
    let config_bytes = config.as_bytes();
    let mut aligned = [0u8; 128];
    aligned[..config_bytes.len()].copy_from_slice(config_bytes);
    nvs_partition.write(WIFI_CONFIG_OFFSET, &aligned).map_err(|_| ())?;
    Ok(())
}

fn load_ygg_key(flash: &mut FlashStorage) -> Option<YggKeyConfig> {
    let mut pt_mem = [0u8; partitions::PARTITION_TABLE_MAX_LEN];
    let pt = partitions::read_partition_table(flash, &mut pt_mem).ok()?;
    let nvs = pt
        .find_partition(partitions::PartitionType::Data(
            partitions::DataPartitionSubType::Nvs,
        ))
        .ok()??;
    let mut nvs_partition = nvs.as_embedded_storage(flash);
    let mut buf = [0u8; 64];
    nvs_partition.read(YGG_KEY_OFFSET, &mut buf).ok()?;
    YggKeyConfig::from_bytes(&buf)
}

fn save_ygg_key(flash: &mut FlashStorage, config: &YggKeyConfig) -> Result<(), ()> {
    let mut pt_mem = [0u8; partitions::PARTITION_TABLE_MAX_LEN];
    let pt = partitions::read_partition_table(flash, &mut pt_mem).map_err(|_| ())?;
    let nvs = pt
        .find_partition(partitions::PartitionType::Data(
            partitions::DataPartitionSubType::Nvs,
        ))
        .map_err(|_| ())?
        .ok_or(())?;
    let mut nvs_partition = nvs.as_embedded_storage(flash);
    let config_bytes = config.as_bytes();
    let mut aligned = [0u8; 64];
    aligned[..config_bytes.len()].copy_from_slice(config_bytes);
    nvs_partition.write(YGG_KEY_OFFSET, &aligned).map_err(|_| ())?;
    Ok(())
}

fn load_ygg_peers(flash: &mut FlashStorage) -> Option<YggPeersConfig> {
    let mut pt_mem = [0u8; partitions::PARTITION_TABLE_MAX_LEN];
    let pt = partitions::read_partition_table(flash, &mut pt_mem).ok()?;
    let nvs = pt
        .find_partition(partitions::PartitionType::Data(
            partitions::DataPartitionSubType::Nvs,
        ))
        .ok()??;
    let mut nvs_partition = nvs.as_embedded_storage(flash);
    let mut buf = [0u8; 256];
    nvs_partition.read(YGG_PEERS_OFFSET, &mut buf).ok()?;
    YggPeersConfig::from_bytes(&buf)
}

fn save_ygg_peers(flash: &mut FlashStorage, config: &YggPeersConfig) -> Result<(), ()> {
    let mut pt_mem = [0u8; partitions::PARTITION_TABLE_MAX_LEN];
    let pt = partitions::read_partition_table(flash, &mut pt_mem).map_err(|_| ())?;
    let nvs = pt
        .find_partition(partitions::PartitionType::Data(
            partitions::DataPartitionSubType::Nvs,
        ))
        .map_err(|_| ())?
        .ok_or(())?;
    let mut nvs_partition = nvs.as_embedded_storage(flash);
    let config_bytes = config.as_bytes();
    let mut aligned = [0u8; 256];
    aligned[..config_bytes.len()].copy_from_slice(config_bytes);
    nvs_partition.write(YGG_PEERS_OFFSET, &aligned).map_err(|_| ())?;
    Ok(())
}

// ============================================================================
// ESP Hardware RNG
// ============================================================================

struct EspRng;

impl rand_core::RngCore for EspRng {
    fn next_u32(&mut self) -> u32 {
        Rng::new().random()
    }

    fn next_u64(&mut self) -> u64 {
        let rng = Rng::new();
        (rng.random() as u64) << 32 | rng.random() as u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let rng = Rng::new();
        for chunk in dest.chunks_mut(4) {
            let random = rng.random().to_le_bytes();
            let len = chunk.len().min(4);
            chunk.copy_from_slice(&random[..len]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for EspRng {}

// ============================================================================
// Minimal Userspace IPv6 + TCP Stack (used when smoltcp feature is disabled)
// ============================================================================

#[cfg(not(feature = "smoltcp"))]
#[allow(dead_code)]
struct Ipv6Header {
    src: [u8; 16],
    dst: [u8; 16],
    payload_len: u16,
    next_header: u8,
    hop_limit: u8,
}

#[cfg(not(feature = "smoltcp"))]
#[allow(dead_code)]
struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    data_offset: u8,
    flags: u8,
    window: u16,
}

#[cfg(not(feature = "smoltcp"))]
fn parse_ipv6(data: &[u8]) -> Option<(Ipv6Header, &[u8])> {
    if data.len() < 40 {
        return None;
    }
    if data[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&data[8..24]);
    dst.copy_from_slice(&data[24..40]);
    let payload_end = 40 + payload_len as usize;
    if data.len() < payload_end {
        return None;
    }
    Some((
        Ipv6Header {
            src,
            dst,
            payload_len,
            next_header,
            hop_limit,
        },
        &data[40..payload_end],
    ))
}

#[cfg(not(feature = "smoltcp"))]
fn parse_tcp(data: &[u8]) -> Option<(TcpHeader, &[u8])> {
    if data.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = data[12] >> 4;
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    let header_len = (data_offset as usize) * 4;
    if data.len() < header_len {
        return None;
    }
    Some((
        TcpHeader {
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            flags,
            window,
        },
        &data[header_len..],
    ))
}

#[cfg(not(feature = "smoltcp"))]
fn tcp_checksum_ipv6(src: &[u8; 16], dst: &[u8; 16], tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
    }
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
    }
    let tcp_len = tcp_segment.len() as u32;
    sum += (tcp_len >> 16) as u32;
    sum += (tcp_len & 0xFFFF) as u32;
    sum += 6u32; // next header = TCP
    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        if i == 16 {
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(not(feature = "smoltcp"))]
fn build_ipv6_tcp(
    src_addr: &[u8; 16],
    dst_addr: &[u8; 16],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    tcp_options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let tcp_header_len = 20 + tcp_options.len();
    let tcp_header_padded = (tcp_header_len + 3) & !3;
    let tcp_data_offset = (tcp_header_padded / 4) as u8;
    let tcp_segment_len = tcp_header_padded + payload.len();

    let mut tcp_seg = Vec::with_capacity(tcp_segment_len);
    tcp_seg.extend_from_slice(&src_port.to_be_bytes());
    tcp_seg.extend_from_slice(&dst_port.to_be_bytes());
    tcp_seg.extend_from_slice(&seq.to_be_bytes());
    tcp_seg.extend_from_slice(&ack.to_be_bytes());
    tcp_seg.push(tcp_data_offset << 4);
    tcp_seg.push(flags);
    tcp_seg.extend_from_slice(&65535u16.to_be_bytes()); // window
    tcp_seg.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    tcp_seg.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
    tcp_seg.extend_from_slice(tcp_options);
    while tcp_seg.len() < tcp_header_padded {
        tcp_seg.push(0);
    }
    tcp_seg.extend_from_slice(payload);

    let cksum = tcp_checksum_ipv6(src_addr, dst_addr, &tcp_seg);
    tcp_seg[16] = (cksum >> 8) as u8;
    tcp_seg[17] = (cksum & 0xFF) as u8;

    let mut pkt = Vec::with_capacity(40 + tcp_seg.len());
    pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version=6
    pkt.extend_from_slice(&(tcp_seg.len() as u16).to_be_bytes());
    pkt.push(6);  // next header = TCP
    pkt.push(64); // hop limit
    pkt.extend_from_slice(src_addr);
    pkt.extend_from_slice(dst_addr);
    pkt.extend_from_slice(&tcp_seg);
    pkt
}

// ============================================================================
// ICMPv6 Echo Reply (used when smoltcp feature is disabled)
// ============================================================================

#[cfg(not(feature = "smoltcp"))]
/// Compute ICMPv6 checksum with IPv6 pseudo-header.
fn icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], icmp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // Pseudo-header: src addr
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
    }
    // Pseudo-header: dst addr
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
    }
    // Pseudo-header: ICMPv6 length (u32 BE)
    let icmp_len = icmp_data.len() as u32;
    sum += (icmp_len >> 16) as u32;
    sum += (icmp_len & 0xFFFF) as u32;
    // Pseudo-header: next header = 58 (ICMPv6)
    sum += IPPROTO_ICMPV6 as u32;
    // ICMPv6 data (skip checksum field at offset 2-3)
    let mut i = 0;
    while i + 1 < icmp_data.len() {
        if i == 2 {
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([icmp_data[i], icmp_data[i + 1]]) as u32;
        i += 2;
    }
    if i < icmp_data.len() {
        sum += (icmp_data[i] as u32) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(not(feature = "smoltcp"))]
/// Build an ICMPv6 Echo Reply for a received Echo Request.
/// Returns the full IPv6 packet, or None if the input isn't a valid echo request.
fn build_icmpv6_echo_reply(our_addr: &[u8; 16], ipv6_packet: &[u8]) -> Option<Vec<u8>> {
    let (ip, payload) = parse_ipv6(ipv6_packet)?;
    if ip.next_header != IPPROTO_ICMPV6 {
        return None;
    }
    if payload.len() < 8 {
        return None;
    }
    // Check it's an Echo Request (type=128, code=0)
    if payload[0] != ICMPV6_ECHO_REQUEST || payload[1] != 0 {
        return None;
    }

    // Build reply: copy entire ICMPv6 payload, change type to 129
    let mut icmp_reply = Vec::with_capacity(payload.len());
    icmp_reply.push(ICMPV6_ECHO_REPLY); // type = Echo Reply
    icmp_reply.push(0);                  // code = 0
    icmp_reply.extend_from_slice(&[0, 0]); // checksum placeholder
    icmp_reply.extend_from_slice(&payload[4..]); // id + seq + data

    // Compute checksum (src=us, dst=them)
    let cksum = icmpv6_checksum(our_addr, &ip.src, &icmp_reply);
    icmp_reply[2] = (cksum >> 8) as u8;
    icmp_reply[3] = (cksum & 0xFF) as u8;

    // Build IPv6 header
    let mut pkt = Vec::with_capacity(40 + icmp_reply.len());
    pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&(icmp_reply.len() as u16).to_be_bytes());
    pkt.push(IPPROTO_ICMPV6);
    pkt.push(64); // hop limit
    pkt.extend_from_slice(our_addr);
    pkt.extend_from_slice(&ip.src);
    pkt.extend_from_slice(&icmp_reply);
    Some(pkt)
}

// ============================================================================
// Mini TCP State Machine (UART bridge variant, used when smoltcp is disabled)
// ============================================================================

#[cfg(not(feature = "smoltcp"))]
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum TcpState {
    Listen,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    Closed,
}

#[cfg(not(feature = "smoltcp"))]
struct MiniTcpUart {
    our_addr: [u8; 16],
    state: TcpState,
    remote_addr: [u8; 16],
    remote_port: u16,
    local_port: u16,
    our_seq: u32,
    their_seq: u32,
}

#[cfg(not(feature = "smoltcp"))]
impl MiniTcpUart {
    fn new(our_addr: [u8; 16], listen_port: u16) -> Self {
        let mut isn = [0u8; 4];
        EspRng.fill_bytes(&mut isn);
        Self {
            our_addr,
            state: TcpState::Listen,
            remote_addr: [0; 16],
            remote_port: 0,
            local_port: listen_port,
            our_seq: u32::from_be_bytes(isn),
            their_seq: 0,
        }
    }

    /// Process an incoming IPv6 packet. Returns response packets to send.
    fn handle_packet(&mut self, ipv6_packet: &[u8]) -> Vec<Vec<u8>> {
        let mut responses = Vec::new();

        let (ip, tcp_data) = match parse_ipv6(ipv6_packet) {
            Some(v) => v,
            None => return responses,
        };

        if ip.next_header != 6 {
            return responses;
        }

        let (tcp, payload) = match parse_tcp(tcp_data) {
            Some(v) => v,
            None => return responses,
        };

        if tcp.dst_port != self.local_port {
            return responses;
        }

        match self.state {
            TcpState::Listen => {
                if tcp.flags & TCP_SYN != 0 && tcp.flags & TCP_ACK == 0 {
                    self.remote_addr = ip.src;
                    self.remote_port = tcp.src_port;
                    self.their_seq = tcp.seq.wrapping_add(1);

                    let mss_opt = [0x02, 0x04, 0x05, 0xA0]; // MSS=1440
                    let pkt = build_ipv6_tcp(
                        &self.our_addr,
                        &self.remote_addr,
                        self.local_port,
                        self.remote_port,
                        self.our_seq,
                        self.their_seq,
                        TCP_SYN | TCP_ACK,
                        &mss_opt,
                        &[],
                    );
                    self.our_seq = self.our_seq.wrapping_add(1);
                    self.state = TcpState::SynReceived;
                    responses.push(pkt);
                }
            }

            TcpState::SynReceived => {
                if tcp.flags & TCP_ACK != 0 && tcp.flags & TCP_SYN == 0 {
                    self.state = TcpState::Established;
                    UART_CONNECTED.store(true, Ordering::Relaxed);
                    log::info!("TCP connection established from overlay peer");

                    if !payload.is_empty() {
                        self.their_seq = self.their_seq.wrapping_add(payload.len() as u32);
                        // Write received data to UART pipe
                        let _ = TCP_TO_UART.try_write(payload);

                        // ACK the data
                        let ack_pkt = build_ipv6_tcp(
                            &self.our_addr,
                            &self.remote_addr,
                            self.local_port,
                            self.remote_port,
                            self.our_seq,
                            self.their_seq,
                            TCP_ACK,
                            &[],
                            &[],
                        );
                        responses.push(ack_pkt);
                    }
                }
            }

            TcpState::Established => {
                if tcp.flags & TCP_RST != 0 {
                    self.reset();
                    return responses;
                }

                if !payload.is_empty() {
                    self.their_seq = self.their_seq.wrapping_add(payload.len() as u32);
                    // Forward data to UART
                    let _ = TCP_TO_UART.try_write(payload);

                    let ack_pkt = build_ipv6_tcp(
                        &self.our_addr,
                        &self.remote_addr,
                        self.local_port,
                        self.remote_port,
                        self.our_seq,
                        self.their_seq,
                        TCP_ACK,
                        &[],
                        &[],
                    );
                    responses.push(ack_pkt);
                }

                if tcp.flags & TCP_FIN != 0 {
                    self.their_seq = self.their_seq.wrapping_add(1);
                    let ack_pkt = build_ipv6_tcp(
                        &self.our_addr,
                        &self.remote_addr,
                        self.local_port,
                        self.remote_port,
                        self.our_seq,
                        self.their_seq,
                        TCP_ACK,
                        &[],
                        &[],
                    );
                    responses.push(ack_pkt);
                    self.reset();
                }
            }

            TcpState::FinWait1 => {
                if tcp.flags & TCP_ACK != 0 {
                    if tcp.flags & TCP_FIN != 0 {
                        self.their_seq = self.their_seq.wrapping_add(1);
                        let ack_pkt = build_ipv6_tcp(
                            &self.our_addr,
                            &self.remote_addr,
                            self.local_port,
                            self.remote_port,
                            self.our_seq,
                            self.their_seq,
                            TCP_ACK,
                            &[],
                            &[],
                        );
                        responses.push(ack_pkt);
                        self.reset();
                    } else {
                        self.state = TcpState::FinWait2;
                    }
                }
            }

            TcpState::FinWait2 => {
                if tcp.flags & TCP_FIN != 0 {
                    self.their_seq = self.their_seq.wrapping_add(1);
                    let ack_pkt = build_ipv6_tcp(
                        &self.our_addr,
                        &self.remote_addr,
                        self.local_port,
                        self.remote_port,
                        self.our_seq,
                        self.their_seq,
                        TCP_ACK,
                        &[],
                        &[],
                    );
                    responses.push(ack_pkt);
                    self.reset();
                }
            }

            TcpState::Closed => {}
        }

        responses
    }

    /// Build a TCP data packet to send UART data back to the connected peer.
    fn send_data(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if self.state != TcpState::Established || data.is_empty() {
            return None;
        }

        let pkt = build_ipv6_tcp(
            &self.our_addr,
            &self.remote_addr,
            self.local_port,
            self.remote_port,
            self.our_seq,
            self.their_seq,
            TCP_PSH | TCP_ACK,
            &[],
            data,
        );
        self.our_seq = self.our_seq.wrapping_add(data.len() as u32);
        Some(pkt)
    }

    fn reset(&mut self) {
        self.state = TcpState::Listen;
        self.remote_addr = [0; 16];
        self.remote_port = 0;
        UART_CONNECTED.store(false, Ordering::Relaxed);
        let mut isn = [0u8; 4];
        EspRng.fill_bytes(&mut isn);
        self.our_seq = u32::from_be_bytes(isn);
        self.their_seq = 0;
    }

    fn is_connected(&self) -> bool {
        self.state == TcpState::Established
    }
}

// ============================================================================
// smoltcp Device (used when smoltcp feature is enabled)
// ============================================================================

#[cfg(feature = "smoltcp")]
mod ygg_device {
    use alloc::collections::VecDeque;
    use alloc::vec;
    use alloc::vec::Vec;

    use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
    use smoltcp::time::Instant as SmolInstant;

    pub struct YggDevice {
        rx_queue: VecDeque<Vec<u8>>,
        tx_queue: VecDeque<Vec<u8>>,
    }

    impl YggDevice {
        pub fn new() -> Self {
            Self {
                rx_queue: VecDeque::new(),
                tx_queue: VecDeque::new(),
            }
        }

        /// Enqueue an inbound IPv6 packet (from Yggdrasil Deliver event).
        pub fn push_rx(&mut self, pkt: Vec<u8>) {
            self.rx_queue.push_back(pkt);
        }

        /// Drain all outbound packets (to send via Yggdrasil).
        pub fn drain_tx(&mut self) -> impl Iterator<Item = Vec<u8>> + '_ {
            self.tx_queue.drain(..)
        }
    }

    pub struct YggRxToken(Vec<u8>);

    impl RxToken for YggRxToken {
        fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
            f(&self.0)
        }
    }

    pub struct YggTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

    impl<'a> TxToken for YggTxToken<'a> {
        fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
            let mut buf = vec![0u8; len];
            let r = f(&mut buf);
            self.0.push_back(buf);
            r
        }
    }

    impl Device for YggDevice {
        type RxToken<'a> = YggRxToken;
        type TxToken<'a> = YggTxToken<'a>;

        fn receive(
            &mut self,
            _timestamp: SmolInstant,
        ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            let data = self.rx_queue.pop_front()?;
            Some((YggRxToken(data), YggTxToken(&mut self.tx_queue)))
        }

        fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
            Some(YggTxToken(&mut self.tx_queue))
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut caps = DeviceCapabilities::default();
            caps.max_transmission_unit = 65535;
            caps.medium = Medium::Ip;
            caps
        }
    }
}

#[cfg(feature = "smoltcp")]
use ygg_device::YggDevice;

// ============================================================================
// IPv6 Address Helpers
// ============================================================================

fn format_ipv6(addr: &[u8; 16]) -> core::net::Ipv6Addr {
    core::net::Ipv6Addr::from(*addr)
}

fn ipv6_to_key(
    addr: &[u8; 16],
    keys: &[(core::net::Ipv6Addr, PublicKey)],
) -> Option<PublicKey> {
    let ipv6 = core::net::Ipv6Addr::from(*addr);
    for (a, k) in keys {
        if *a == ipv6 {
            return Some(*k);
        }
    }
    None
}

fn get_dest_key_from_ipv6(
    pkt: &[u8],
    keys: &[(core::net::Ipv6Addr, PublicKey)],
) -> Option<PublicKey> {
    if pkt.len() < 40 {
        return None;
    }
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&pkt[24..40]);
    ipv6_to_key(&dst, keys)
}

// ============================================================================
// Peer Address Parsing
// ============================================================================

/// Parse "1.2.3.4:port" into (Ipv4Addr, port). IPv6 peer endpoints are
/// wrapped in brackets: "[::1]:port".
fn parse_peer_addr(s: &str) -> Option<(core::net::IpAddr, u16)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    if s.starts_with('[') {
        // IPv6: [addr]:port
        let end_bracket = s.find(']')?;
        let addr_str = &s[1..end_bracket];
        let rest = &s[end_bracket + 1..];
        if !rest.starts_with(':') {
            return None;
        }
        let port: u16 = rest[1..].parse().ok()?;
        let addr: core::net::Ipv6Addr = addr_str.parse().ok()?;
        Some((core::net::IpAddr::V6(addr), port))
    } else {
        // IPv4: addr:port
        let colon = s.rfind(':')?;
        let addr_str = &s[..colon];
        let port: u16 = s[colon + 1..].parse().ok()?;
        let addr: Ipv4Addr = addr_str.parse().ok()?;
        Some((core::net::IpAddr::V4(addr), port))
    }
}

// ============================================================================
// Main Entry
// ============================================================================

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    esp_println::logger::init_logger_from_env();
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(size: 96 * 1024);

    // ── Load/generate Yggdrasil key ────────────────────────────────────
    let mut flash = FlashStorage::new(peripherals.FLASH);

    let seed = if let Some(key_config) = load_ygg_key(&mut flash) {
        log::info!("Loaded Yggdrasil key from flash");
        key_config.seed
    } else {
        log::info!("Generating new Yggdrasil key...");
        let mut seed = [0u8; 32];
        EspRng.fill_bytes(&mut seed);
        let mut key_config = YggKeyConfig::new();
        key_config.magic = YGG_KEY_MAGIC;
        key_config.seed = seed;
        if save_ygg_key(&mut flash, &key_config).is_ok() {
            log::info!("Yggdrasil key saved to flash");
        } else {
            log::error!("Failed to save Yggdrasil key!");
        }
        seed
    };

    // Create yggdrasil-lite node
    let ygg_config = LiteConfig::new(seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key: PublicKey = signing_key.verifying_key().to_bytes();
    let node = YggdrasilLite::new(ygg_config);
    let our_addr = node.address();

    // Store IPv6 address globally
    {
        let mut addr = YGG_IPV6.lock().await;
        *addr = our_addr.0;
    }

    // Parse listen port
    let listen_port: u16 = DEFAULT_YGG_LISTEN_PORT.parse().unwrap_or(2000);
    {
        let mut port = YGG_PORT.lock().await;
        *port = listen_port;
    }

    // ── Load WiFi config ───────────────────────────────────────────────
    let saved_wifi = load_wifi_config(&mut flash);
    if let Some(ref cfg) = saved_wifi {
        log::info!("Loaded WiFi config: SSID='{}'", cfg.ssid_str());
        let mut wifi_config = WIFI_CONFIG.lock().await;
        *wifi_config = *cfg;
    } else {
        log::info!("No saved WiFi config, using defaults");
    }

    // ── Load Yggdrasil peers config ────────────────────────────────────
    let saved_peers = load_ygg_peers(&mut flash);
    if let Some(ref cfg) = saved_peers {
        log::info!("Loaded {} Yggdrasil peer(s) from flash", cfg.count);
        let mut peers = YGG_PEERS.lock().await;
        *peers = *cfg;
    } else {
        // Initialize from env defaults
        let mut cfg = YggPeersConfig::new();
        cfg.set_peers(&[DEFAULT_YGG_PEER1, DEFAULT_YGG_PEER2, DEFAULT_YGG_PEER3]);
        let mut peers = YGG_PEERS.lock().await;
        *peers = cfg;
    }

    drop(flash);

    // ── Print boot banner ──────────────────────────────────────────────
    println!("");
    println!("=============================================");
    println!("  Yggdrasil TCP-UART Bridge");
    println!("=============================================");
    println!(
        "  IPv6:  {}",
        format_ipv6(&our_addr.0)
    );
    println!("  Port:  {}", listen_port);
    println!(
        "  Key:   {}",
        &hex_encode_short(&public_key)
    );
    {
        let peers = YGG_PEERS.lock().await;
        for i in 0..3 {
            if !peers.peers[i].is_empty() {
                println!("  Peer{}: {}", i + 1, peers.peers[i].as_str());
            }
        }
    }
    println!("=============================================");
    println!("");

    // ── Initialize hardware ────────────────────────────────────────────
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    // Initialize UART
    let uart_config = uart::Config::default().with_baudrate(UART_BAUD_RATE);
    let uart = Uart::new(peripherals.UART1, uart_config)
        .unwrap()
        .with_rx(peripherals.GPIO20)
        .with_tx(peripherals.GPIO19)
        .into_async();
    let (uart_rx, uart_tx) = uart.split();
    UART_CONNECTED.store(false, Ordering::Relaxed);

    // ── Initialize WiFi ────────────────────────────────────────────────
    let (mut controller, interfaces) =
        esp_radio::wifi::new(peripherals.WIFI, Default::default()).unwrap();

    let wifi_ap_device = interfaces.access_point;
    let wifi_sta_device = interfaces.station;

    let ap_config = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(AP_IP, 24),
        gateway: Some(AP_IP),
        dns_servers: Default::default(),
    });
    let sta_config = embassy_net::Config::dhcpv4(Default::default());

    let rng = Rng::new();
    let net_seed = (rng.random() as u64) << 32 | rng.random() as u64;

    let (ap_stack, ap_runner) = embassy_net::new(
        wifi_ap_device,
        ap_config,
        mk_static!(StackResources<4>, StackResources::<4>::new()),
        net_seed,
    );
    let (sta_stack, sta_runner) = embassy_net::new(
        wifi_sta_device,
        sta_config,
        mk_static!(StackResources<10>, StackResources::<10>::new()),
        net_seed,
    );

    // Configure APSTA mode
    let wifi_config = WIFI_CONFIG.lock().await;
    let (ssid, password) = if wifi_config.is_valid() {
        log::info!("Using saved WiFi: SSID='{}'", wifi_config.ssid_str());
        (wifi_config.ssid_str(), wifi_config.password_str())
    } else {
        log::info!("Using default WiFi: SSID='{}'", DEFAULT_WIFI_SSID);
        (DEFAULT_WIFI_SSID, DEFAULT_WIFI_PASSWORD)
    };

    let station_config = ModeConfig::AccessPointStation(
        StationConfig::default()
            .with_ssid(ssid.into())
            .with_password(password.into()),
        AccessPointConfig::default().with_ssid("YggBridge".into()),
    );
    drop(wifi_config);

    controller.set_config(&station_config).unwrap();
    log::info!("Starting WiFi...");
    controller.start_async().await.unwrap();
    log::info!("WiFi started!");

    // ── Spawn tasks ────────────────────────────────────────────────────
    spawner.spawn(connection_task(controller)).ok();
    spawner.spawn(net_task(ap_runner)).ok();
    spawner.spawn(net_task(sta_runner)).ok();
    spawner.spawn(uart_rx_task(uart_rx)).ok();
    spawner.spawn(uart_tx_task(uart_tx)).ok();
    spawner.spawn(sta_ip_monitor(sta_stack)).ok();
    spawner.spawn(dhcp_server(ap_stack)).ok();
    spawner.spawn(http_server(ap_stack, "AP")).ok();
    spawner.spawn(http_server(sta_stack, "STA")).ok();

    // Pass the node to the yggdrasil task (runs in main)
    yggdrasil_task(sta_stack, node, signing_key, public_key, our_addr.0, listen_port).await;

    // Should not return
    loop {
        Timer::after(Duration::from_secs(60)).await;
    }
}

// ============================================================================
// Utility
// ============================================================================

fn hex_encode_short(data: &[u8]) -> String<16> {
    let mut s = String::new();
    for &b in data.iter().take(8) {
        let _ = core::fmt::write(&mut s, format_args!("{:02x}", b));
    }
    s
}

// ============================================================================
// WiFi Connection Task
// ============================================================================

#[embassy_executor::task]
async fn connection_task(mut controller: WifiController<'static>) {
    log::info!("WiFi connection task started");

    loop {
        if matches!(controller.is_started(), Ok(true)) {
            let ssid: String<32> = {
                let wifi_config = WIFI_CONFIG.lock().await;
                if wifi_config.is_valid() {
                    String::try_from(wifi_config.ssid_str()).unwrap_or_default()
                } else {
                    String::try_from(DEFAULT_WIFI_SSID).unwrap_or_default()
                }
            };
            log::info!("Connecting to WiFi '{}'...", ssid.as_str());

            match controller.connect_async().await {
                Ok(_) => {
                    WIFI_CONNECTED.store(true, Ordering::Relaxed);
                    log::info!("WiFi connected to '{}'!", ssid.as_str());

                    controller
                        .wait_for_event(WifiEvent::StationDisconnected)
                        .await;
                    WIFI_CONNECTED.store(false, Ordering::Relaxed);
                    log::info!("WiFi disconnected from '{}'", ssid.as_str());
                }
                Err(e) => {
                    log::error!("WiFi connection failed: {:?}", e);
                    Timer::after(Duration::from_millis(5000)).await;
                }
            }
        } else {
            return;
        }
    }
}

#[embassy_executor::task(pool_size = 2)]
async fn net_task(mut runner: Runner<'static, WifiDevice<'static>>) {
    runner.run().await
}

// ============================================================================
// UART Tasks
// ============================================================================

#[embassy_executor::task]
async fn uart_rx_task(mut rx: uart::UartRx<'static, esp_hal::Async>) {
    log::info!("UART RX task started");
    let mut buf = [0u8; 64];
    loop {
        match embedded_io_async::Read::read(&mut rx, &mut buf).await {
            Ok(n) if n > 0 => {
                let _ = UART_TO_TCP.try_write(&buf[..n]);
            }
            Ok(_) => {}
            Err(e) => {
                log::error!("UART RX error: {:?}", e);
                Timer::after(Duration::from_millis(10)).await;
            }
        }
    }
}

#[embassy_executor::task]
async fn uart_tx_task(mut tx: uart::UartTx<'static, esp_hal::Async>) {
    log::info!("UART TX task started");
    let mut buf = [0u8; 64];
    loop {
        let n = TCP_TO_UART.read(&mut buf).await;
        if n > 0 {
            if let Err(e) = embedded_io_async::Write::write_all(&mut tx, &buf[..n]).await {
                log::error!("UART TX error: {:?}", e);
            }
        }
    }
}

// ============================================================================
// STA IP Monitor
// ============================================================================

#[embassy_executor::task]
async fn sta_ip_monitor(stack: embassy_net::Stack<'static>) {
    loop {
        if let Some(config) = stack.config_v4() {
            let address = config.address.address();
            let mut sta_ip = STA_IP.lock().await;
            if *sta_ip != Some(address) {
                *sta_ip = Some(address);
                log::info!("Got STA IP: {}", address);
            }
        } else {
            let mut sta_ip = STA_IP.lock().await;
            if sta_ip.is_some() {
                *sta_ip = None;
            }
        }
        Timer::after(Duration::from_millis(1000)).await;
    }
}

// ============================================================================
// DHCP Server
// ============================================================================

#[embassy_executor::task]
async fn dhcp_server(stack: embassy_net::Stack<'static>) {
    log::info!("DHCP server started");
    let config = DhcpServerConfig {
        ip: AP_IP,
        lease_time: Duration::from_secs(3600),
        gateways: &[AP_IP],
        subnet: None,
        dns: &[AP_IP],
        use_captive_portal: false,
    };

    let mut leaser = SimpleDhcpLeaser {
        start: DHCP_POOL_START,
        end: DHCP_POOL_END,
        leases: Default::default(),
    };
    if let Err(e) = esp_hal_dhcp_server::run_dhcp_server(stack, config, &mut leaser).await {
        log::error!("DHCP server error: {:?}", e);
    }
}

// ============================================================================
// Yggdrasil Task
// ============================================================================

async fn yggdrasil_task(
    sta_stack: embassy_net::Stack<'static>,
    mut node: YggdrasilLite,
    signing_key: SigningKey,
    public_key: PublicKey,
    our_addr: [u8; 16],
    listen_port: u16,
) {
    log::info!("Yggdrasil task started, waiting for STA link...");

    // Wait for STA to get an IP
    loop {
        if sta_stack.is_link_up() {
            if let Some(_cfg) = sta_stack.config_v4() {
                break;
            }
        }
        Timer::after(Duration::from_millis(500)).await;
    }
    log::info!("STA link up, starting Yggdrasil connections");

    // IPv6 → PublicKey routing table (small fixed-size array for no_std)
    let mut addr_to_key: Vec<(core::net::Ipv6Addr, PublicKey)> = Vec::new();

    // Collect peer addresses
    let mut peer_addrs: Vec<(core::net::IpAddr, u16)> = Vec::new();
    {
        let peers = YGG_PEERS.lock().await;
        for i in 0..3 {
            if !peers.peers[i].is_empty() {
                if let Some(addr) = parse_peer_addr(peers.peers[i].as_str()) {
                    peer_addrs.push(addr);
                } else {
                    log::warn!("Failed to parse peer address: {}", peers.peers[i].as_str());
                }
            }
        }
    }

    if peer_addrs.is_empty() {
        log::error!("No valid Yggdrasil peers configured!");
        loop {
            Timer::after(Duration::from_secs(60)).await;
        }
    }

    log::info!("Connecting to {} peer(s)...", peer_addrs.len());

    // For simplicity in the embedded context, connect to the first peer
    // that succeeds. Multi-peer support can be added by running multiple
    // TLS connections in parallel, but embassy_futures::select over
    // multiple TLS readers is complex with borrowed state.
    //
    // We try peers in order and use the first one that connects.

    let (peer_ip, peer_port) = peer_addrs[0];
    log::info!("Connecting to peer {}:{}", peer_ip, peer_port);

    // Retry loop for peer connection
    loop {
        match connect_and_run_peer(
            sta_stack,
            &mut node,
            &signing_key,
            &public_key,
            &mut addr_to_key,
            peer_ip,
            peer_port,
            &our_addr,
            listen_port,
        )
        .await
        {
            Ok(()) => {
                log::info!("Peer connection ended cleanly");
            }
            Err(e) => {
                log::error!("Peer connection error: {}", e);
            }
        }
        log::info!("Reconnecting in 5s...");
        Timer::after(Duration::from_secs(5)).await;

        // Wait for STA link before reconnecting
        loop {
            if sta_stack.is_link_up() {
                if sta_stack.config_v4().is_some() {
                    break;
                }
            }
            Timer::after(Duration::from_millis(500)).await;
        }
    }
}

async fn connect_and_run_peer(
    sta_stack: embassy_net::Stack<'static>,
    node: &mut YggdrasilLite,
    signing_key: &SigningKey,
    public_key: &PublicKey,
    addr_to_key: &mut Vec<(core::net::Ipv6Addr, PublicKey)>,
    peer_ip: core::net::IpAddr,
    peer_port: u16,
    our_addr: &[u8; 16],
    listen_port: u16,
) -> Result<(), &'static str> {
    use embedded_tls::{Aes256GcmSha384, TlsConfig, TlsConnection, TlsContext, UnsecureProvider};

    // ── TCP connect ────────────────────────────────────────────────────
    let mut rx_buffer = [0u8; 4096];
    let mut tx_buffer = [0u8; 4096];
    let mut socket = TcpSocket::new(sta_stack, &mut rx_buffer, &mut tx_buffer);
    socket.set_timeout(Some(Duration::from_secs(30)));

    let endpoint = match peer_ip {
        core::net::IpAddr::V4(v4) => (v4, peer_port),
        core::net::IpAddr::V6(_v6) => {
            // embassy-net IPv6 connect would require different handling
            return Err("IPv6 peer endpoints not yet supported");
        }
    };

    socket.connect(endpoint).await.map_err(|e| {
        log::error!("TCP connect error: {:?}", e);
        "TCP connect failed"
    })?;
    log::info!("TCP connected to peer");

    // ── TLS handshake ──────────────────────────────────────────────────
    let mut tls_read_buf = [0u8; 16384];
    let mut tls_write_buf = [0u8; 4096];

    let tls_config = TlsConfig::new().with_server_name("yggdrasil");

    let mut tls: TlsConnection<'_, TcpSocket<'_>, Aes256GcmSha384> =
        TlsConnection::new(socket, &mut tls_read_buf, &mut tls_write_buf);

    tls.open(TlsContext::new(
        &tls_config,
        UnsecureProvider::new::<Aes256GcmSha384>(EspRng),
    ))
    .await
    .map_err(|e| {
        log::error!("TLS handshake error: {:?}", e);
        "TLS handshake failed"
    })?;
    log::info!("TLS handshake complete");

    // ── Metadata handshake ─────────────────────────────────────────────
    let password: &[u8] = b"";
    let our_meta = Metadata::new(*public_key, 0);
    let meta_bytes = our_meta.encode(signing_key, password);

    tls.write_all(&meta_bytes).await.map_err(|_| "meta write failed")?;
    tls.flush().await.map_err(|_| "meta flush failed")?;
    log::info!("Sent metadata ({} bytes)", meta_bytes.len());

    // Read peer metadata
    let mut meta_accum = Vec::new();
    let mut tmp = [0u8; 512];
    let peer_id;

    loop {
        let n = tls.read(&mut tmp).await.map_err(|_| "meta read failed")?;
        if n == 0 {
            return Err("connection closed during metadata");
        }
        meta_accum.extend_from_slice(&tmp[..n]);

        match Metadata::decode(&meta_accum, password) {
            Ok((peer_meta, consumed)) => {
                if !peer_meta.check() {
                    return Err("incompatible protocol version");
                }
                log::info!(
                    "Peer key: {}...",
                    hex_encode_short(&peer_meta.public_key)
                );

                let pid = node.add_peer(peer_meta.public_key, 0);
                node.mark_handshake_done(pid);
                peer_id = pid;
                log::info!("Peer registered (id={})", pid);

                // Handle leftover bytes
                if meta_accum.len() > consumed {
                    let leftover = meta_accum[consumed..].to_vec();
                    let events = node.handle_peer_data(pid, &leftover, 0, &mut EspRng);
                    for ev in &events {
                        if let NodeEvent::SendToPeer { data, .. } = ev {
                            tls.write_all(data).await.map_err(|_| "write failed")?;
                        }
                    }
                    tls.flush().await.map_err(|_| "flush failed")?;
                }
                break;
            }
            Err(yggdrasil_lite::meta::MetaError::TooShort)
            | Err(yggdrasil_lite::meta::MetaError::BufferTooSmall) => {
                continue;
            }
            Err(_e) => {
                return Err("metadata decode error");
            }
        }
    }

    // ── Initial poll ───────────────────────────────────────────────────
    {
        let events = node.poll(0, &mut EspRng);
        for ev in &events {
            if let NodeEvent::SendToPeer { data, .. } = ev {
                tls.write_all(data).await.map_err(|_| "write failed")?;
            }
        }
        tls.flush().await.map_err(|_| "flush failed")?;
    }

    log::info!(
        "Yggdrasil online! Listening on [{}]:{}",
        format_ipv6(our_addr),
        listen_port
    );

    // ── Event loop ─────────────────────────────────────────────────────

    #[cfg(not(feature = "smoltcp"))]
    {
        let mut mini_tcp = MiniTcpUart::new(*our_addr, listen_port);
        let mut last_poll_ms: u64 = 0;
        let mut last_status_ms: u64 = 0;
        let start = embassy_time::Instant::now();
        let mut tls_buf = [0u8; 4096];
        let mut uart_buf = [0u8; 256];

        loop {
            let now_ms = start.elapsed().as_millis() as u64;

            // ── 1. Read from TLS (with timeout so we don't block forever)
            let tls_read = tls.read(&mut tls_buf);
            let timeout = Timer::after(Duration::from_millis(50));

            match select(tls_read, timeout).await {
                Either::First(Ok(0)) => {
                    log::info!("Peer disconnected (EOF)");
                    return Ok(());
                }
                Either::First(Ok(n)) => {
                    let events = node.handle_peer_data(peer_id, &tls_buf[..n], now_ms, &mut EspRng);
                    process_ygg_events(
                        &events, &mut tls, &mut mini_tcp, addr_to_key, node, our_addr, now_ms,
                    )
                    .await;
                }
                Either::First(Err(_e)) => {
                    log::error!("TLS read error");
                    return Err("TLS read error");
                }
                Either::Second(_) => {
                    // Timeout — proceed to other work
                }
            }

            // ── 2. Send UART data over TCP overlay
            if mini_tcp.is_connected() {
                let uart_read = UART_TO_TCP.read(&mut uart_buf);
                let timeout = Timer::after(Duration::from_millis(1));

                match select(uart_read, timeout).await {
                    Either::First(n) if n > 0 => {
                        if let Some(pkt) = mini_tcp.send_data(&uart_buf[..n]) {
                            if let Some(dest_key) = get_dest_key_from_ipv6(&pkt, addr_to_key) {
                                let mut payload = Vec::with_capacity(1 + pkt.len());
                                payload.push(TYPE_SESSION_TRAFFIC);
                                payload.extend_from_slice(&pkt);

                                let send_events = node.send(&dest_key, &payload, now_ms, &mut EspRng);
                                for sev in &send_events {
                                    if let NodeEvent::SendToPeer { data, .. } = sev {
                                        let _ = tls.write_all(data).await;
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            // ── 3. Periodic node poll
            let now_ms = start.elapsed().as_millis() as u64;
            if now_ms.saturating_sub(last_poll_ms) >= 100 {
                last_poll_ms = now_ms;
                let events = node.poll(now_ms, &mut EspRng);
                if !events.is_empty() {
                    for ev in &events {
                        if let NodeEvent::SendToPeer { data, .. } = ev {
                            let _ = tls.write_all(data).await;
                        }
                    }
                }
            }

            // ── 4. Flush TLS
            let _ = tls.flush().await;

            // ── 5. Status output
            if now_ms.saturating_sub(last_status_ms) >= 30_000 {
                last_status_ms = now_ms;
                log::info!(
                    "uptime={}s peers={} sessions={} paths={} uart={}",
                    now_ms / 1000,
                    node.peer_count(),
                    node.session_count(),
                    node.path_count(),
                    if UART_CONNECTED.load(Ordering::Relaxed) { "connected" } else { "idle" },
                );
            }
        }
    }

    #[cfg(feature = "smoltcp")]
    {
        use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet, SocketStorage};
        use smoltcp::socket::tcp;
        use smoltcp::time::Instant as SmolInstant;
        use smoltcp::wire::{HardwareAddress, IpCidr, Ipv6Address};

        let mut device = YggDevice::new();

        // Configure smoltcp interface
        let mut config = IfaceConfig::new(HardwareAddress::Ip);
        config.random_seed = {
            let mut rng = EspRng;
            (rng.next_u32() as u64) << 32 | rng.next_u32() as u64
        };

        let mut iface = Interface::new(config, &mut device, SmolInstant::from_millis(0));

        // Set our Yggdrasil IPv6 address with /7 prefix
        let local_ip = Ipv6Address::from(*our_addr);
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(local_ip.into(), 7)).unwrap();
        });

        // Create TCP socket with 1KB buffers (UART is only 115200 baud ≈ 11KB/s)
        let tcp_rx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 1024]);
        let tcp_tx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 1024]);
        let tcp_socket = tcp::Socket::new(tcp_rx_buf, tcp_tx_buf);

        let mut socket_storage = [SocketStorage::EMPTY];
        let mut sockets = SocketSet::new(&mut socket_storage[..]);
        let tcp_handle = sockets.add(tcp_socket);

        // Start listening
        sockets
            .get_mut::<tcp::Socket>(tcp_handle)
            .listen(listen_port)
            .unwrap();
        log::info!("smoltcp: TCP listening on port {}", listen_port);

        let mut last_poll_ms: u64 = 0;
        let mut last_status_ms: u64 = 0;
        let start = embassy_time::Instant::now();
        let mut tls_buf = [0u8; 4096];
        let mut uart_buf = [0u8; 256];

        loop {
            let now_ms = start.elapsed().as_millis() as u64;
            let smol_now = SmolInstant::from_millis(now_ms as i64);

            // ── 1. Read from TLS ───────────────────────────────────────
            let tls_read = tls.read(&mut tls_buf);
            let timeout = Timer::after(Duration::from_millis(50));

            match select(tls_read, timeout).await {
                Either::First(Ok(0)) => {
                    log::info!("Peer disconnected (EOF)");
                    return Ok(());
                }
                Either::First(Ok(n)) => {
                    let events = node.handle_peer_data(peer_id, &tls_buf[..n], now_ms, &mut EspRng);
                    for event in &events {
                        match event {
                            NodeEvent::SendToPeer { data, .. } => {
                                let _ = tls.write_all(data).await;
                            }
                            NodeEvent::Deliver { source, data } => {
                                if data.len() > 1 && data[0] == TYPE_SESSION_TRAFFIC {
                                    let ipv6_packet = &data[1..];

                                    // Record source key → IPv6 mapping
                                    let source_addr = addr_for_key(source);
                                    let source_ipv6 = core::net::Ipv6Addr::from(source_addr.0);
                                    let mut found = false;
                                    for (a, k) in addr_to_key.iter_mut() {
                                        if *a == source_ipv6 {
                                            *k = *source;
                                            found = true;
                                            break;
                                        }
                                    }
                                    if !found && addr_to_key.len() < 32 {
                                        addr_to_key.push((source_ipv6, *source));
                                    }

                                    log::debug!("RECV {} bytes from {}", ipv6_packet.len(), source_ipv6);

                                    // Feed to smoltcp — ICMPv6 is handled automatically
                                    device.push_rx(ipv6_packet.to_vec());
                                }
                            }
                        }
                    }
                }
                Either::First(Err(_e)) => {
                    log::error!("TLS read error");
                    return Err("TLS read error");
                }
                Either::Second(_) => {}
            }

            // ── 2. smoltcp poll (processes rx, generates tx) ───────────
            iface.poll(smol_now, &mut device, &mut sockets);

            // ── 3. Drain outbound packets → send via Yggdrasil ─────────
            for pkt in device.drain_tx() {
                if let Some(dest_key) = get_dest_key_from_ipv6(&pkt, addr_to_key) {
                    let mut payload = Vec::with_capacity(1 + pkt.len());
                    payload.push(TYPE_SESSION_TRAFFIC);
                    payload.extend_from_slice(&pkt);

                    let send_events = node.send(&dest_key, &payload, now_ms, &mut EspRng);
                    for sev in &send_events {
                        if let NodeEvent::SendToPeer { data, .. } = sev {
                            let _ = tls.write_all(data).await;
                        }
                    }
                }
            }

            // ── 4. TCP socket ↔ UART bridging ──────────────────────────
            {
                let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);

                // TCP → UART: read from socket, write to UART pipe
                if socket.can_recv() {
                    let mut tmp = [0u8; 256];
                    if let Ok(n) = socket.recv_slice(&mut tmp) {
                        if n > 0 {
                            // Non-blocking write to UART pipe
                            let written = TCP_TO_UART.try_write(&tmp[..n]).unwrap_or(0);
                            if written < n {
                                log::warn!("UART pipe full, dropped {} bytes", n - written);
                            }
                        }
                    }
                }

                // UART → TCP: read from UART pipe, write to socket
                if socket.can_send() {
                    let uart_read = UART_TO_TCP.read(&mut uart_buf);
                    let timeout = Timer::after(Duration::from_millis(1));

                    match select(uart_read, timeout).await {
                        Either::First(n) if n > 0 => {
                            if let Err(e) = socket.send_slice(&uart_buf[..n]) {
                                log::warn!("TCP send error: {:?}", e);
                            }
                        }
                        _ => {}
                    }
                }

                // Track connection state
                let is_active = socket.is_active();
                UART_CONNECTED.store(is_active, Ordering::Relaxed);

                // Re-listen if socket closed
                if !is_active && !socket.is_listening() {
                    log::info!("smoltcp: TCP socket closed, re-listening on port {}", listen_port);
                    socket.abort();
                    if let Err(e) = socket.listen(listen_port) {
                        log::error!("smoltcp: re-listen failed: {:?}", e);
                    }
                }
            }

            // ── 5. Second smoltcp poll (flushes TCP responses) ─────────
            iface.poll(smol_now, &mut device, &mut sockets);

            // Drain tx again after second poll
            for pkt in device.drain_tx() {
                if let Some(dest_key) = get_dest_key_from_ipv6(&pkt, addr_to_key) {
                    let mut payload = Vec::with_capacity(1 + pkt.len());
                    payload.push(TYPE_SESSION_TRAFFIC);
                    payload.extend_from_slice(&pkt);

                    let send_events = node.send(&dest_key, &payload, now_ms, &mut EspRng);
                    for sev in &send_events {
                        if let NodeEvent::SendToPeer { data, .. } = sev {
                            let _ = tls.write_all(data).await;
                        }
                    }
                }
            }

            // ── 6. Periodic node poll ──────────────────────────────────
            let now_ms = start.elapsed().as_millis() as u64;
            if now_ms.saturating_sub(last_poll_ms) >= 100 {
                last_poll_ms = now_ms;
                let events = node.poll(now_ms, &mut EspRng);
                if !events.is_empty() {
                    for ev in &events {
                        if let NodeEvent::SendToPeer { data, .. } = ev {
                            let _ = tls.write_all(data).await;
                        }
                    }
                }
            }

            // ── 7. Flush TLS ───────────────────────────────────────────
            let _ = tls.flush().await;

            // ── 8. Status output ───────────────────────────────────────
            if now_ms.saturating_sub(last_status_ms) >= 30_000 {
                last_status_ms = now_ms;
                log::info!(
                    "uptime={}s peers={} sessions={} paths={} uart={}",
                    now_ms / 1000,
                    node.peer_count(),
                    node.session_count(),
                    node.path_count(),
                    if UART_CONNECTED.load(Ordering::Relaxed) { "connected" } else { "idle" },
                );
            }
        }
    }
}

#[cfg(not(feature = "smoltcp"))]
async fn process_ygg_events<'a>(
    events: &[NodeEvent],
    tls: &mut embedded_tls::TlsConnection<'a, TcpSocket<'a>, embedded_tls::Aes256GcmSha384>,
    mini_tcp: &mut MiniTcpUart,
    addr_to_key: &mut Vec<(core::net::Ipv6Addr, PublicKey)>,
    node: &mut YggdrasilLite,
    our_addr: &[u8; 16],
    now_ms: u64,
) {
    for event in events {
        match event {
            NodeEvent::SendToPeer { data, .. } => {
                let _ = tls.write_all(data).await;
            }
            NodeEvent::Deliver { source, data } => {
                if data.len() > 1 && data[0] == TYPE_SESSION_TRAFFIC {
                    let ipv6_packet = &data[1..];

                    // Record source key → IPv6 mapping
                    let source_addr = addr_for_key(source);
                    let source_ipv6 = core::net::Ipv6Addr::from(source_addr.0);

                    // Update or insert mapping
                    let mut found = false;
                    for (a, k) in addr_to_key.iter_mut() {
                        if *a == source_ipv6 {
                            *k = *source;
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        if addr_to_key.len() < 32 {
                            addr_to_key.push((source_ipv6, *source));
                        }
                    }

                    log::debug!("RECV {} bytes from {}", ipv6_packet.len(), source_ipv6);

                    // Determine protocol from IPv6 next_header
                    let next_header = if ipv6_packet.len() >= 40 {
                        ipv6_packet[6]
                    } else {
                        continue;
                    };

                    let responses = if next_header == IPPROTO_ICMPV6 {
                        // ICMPv6 — handle echo request
                        if let Some(reply) = build_icmpv6_echo_reply(our_addr, ipv6_packet) {
                            log::debug!("ICMP echo reply → {}", source_ipv6);
                            alloc::vec![reply]
                        } else {
                            Vec::new()
                        }
                    } else {
                        // TCP and everything else → mini TCP stack
                        mini_tcp.handle_packet(ipv6_packet)
                    };

                    for resp_pkt in responses {
                        if let Some(dest_key) = get_dest_key_from_ipv6(&resp_pkt, addr_to_key) {
                            let mut payload = Vec::with_capacity(1 + resp_pkt.len());
                            payload.push(TYPE_SESSION_TRAFFIC);
                            payload.extend_from_slice(&resp_pkt);

                            let send_events = node.send(&dest_key, &payload, now_ms, &mut EspRng);
                            for sev in &send_events {
                                if let NodeEvent::SendToPeer { data, .. } = sev {
                                    let _ = tls.write_all(data).await;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// HTTP Server
// ============================================================================

#[embassy_executor::task(pool_size = 2)]
async fn http_server(stack: embassy_net::Stack<'static>, name: &'static str) {
    let mut rx_buffer = [0u8; 2048];
    let mut tx_buffer = [0u8; 2048];

    loop {
        let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);
        socket.set_timeout(Some(Duration::from_secs(30)));

        log::debug!("[{}] HTTP waiting on port {}...", name, HTTP_PORT);

        if let Err(e) = socket
            .accept(IpListenEndpoint {
                addr: None,
                port: HTTP_PORT,
            })
            .await
        {
            log::error!("[{}] HTTP accept error: {:?}", name, e);
            Timer::after(Duration::from_millis(1000)).await;
            continue;
        }

        let _ = handle_http_request(&mut socket).await;

        socket.close();
        Timer::after(Duration::from_millis(100)).await;
        socket.abort();
    }
}

async fn handle_http_request(socket: &mut TcpSocket<'_>) -> Result<(), embassy_net::tcp::Error> {
    let mut buffer = [0u8; 1024];
    let mut pos = 0;

    // Read HTTP request
    loop {
        match socket.read(&mut buffer[pos..]).await {
            Ok(0) => return Ok(()),
            Ok(len) => {
                pos += len;
                if pos >= 4 {
                    let request = unsafe { core::str::from_utf8_unchecked(&buffer[..pos]) };
                    if request.contains("\r\n\r\n") {
                        break;
                    }
                }
                if pos >= buffer.len() {
                    break;
                }
            }
            Err(e) => return Err(e),
        }
    }

    let request = unsafe { core::str::from_utf8_unchecked(&buffer[..pos]) };

    let (method, path) = parse_request_line(request);

    match (method, path) {
        ("GET", "/") => {
            let response = build_index_page().await;
            socket.write_all(response.as_bytes()).await?;
        }
        ("GET", "/api/status") => {
            let response = build_status_json().await;
            socket.write_all(response.as_bytes()).await?;
        }
        ("POST", "/api/wifi") => {
            if let Some(body_start) = request.find("\r\n\r\n") {
                let body = &request[body_start + 4..];
                let response = handle_wifi_config(body).await;
                socket.write_all(response.as_bytes()).await?;
            } else {
                let r = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                socket.write_all(r.as_bytes()).await?;
            }
        }
        ("POST", "/api/ygg/peers") => {
            if let Some(body_start) = request.find("\r\n\r\n") {
                let body = &request[body_start + 4..];
                let response = handle_ygg_peers(body).await;
                socket.write_all(response.as_bytes()).await?;
            } else {
                let r = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                socket.write_all(r.as_bytes()).await?;
            }
        }
        _ => {
            let r = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            socket.write_all(r.as_bytes()).await?;
        }
    }

    Ok(())
}

fn parse_request_line(request: &str) -> (&str, &str) {
    let first_line = request.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");
    (method, path)
}

/// Simple URL-decode for form values (handles %XX and +).
fn url_decode_into(src: &str, dst: &mut [u8]) -> usize {
    let bytes = src.as_bytes();
    let mut si = 0;
    let mut di = 0;
    while si < bytes.len() && di < dst.len() {
        if bytes[si] == b'%' && si + 2 < bytes.len() {
            let hi = hex_nibble(bytes[si + 1]);
            let lo = hex_nibble(bytes[si + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                dst[di] = (h << 4) | l;
                di += 1;
                si += 3;
                continue;
            }
        }
        if bytes[si] == b'+' {
            dst[di] = b' ';
        } else {
            dst[di] = bytes[si];
        }
        di += 1;
        si += 1;
    }
    di
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn find_form_value<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    for pair in body.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v);
            }
        }
    }
    None
}

async fn build_index_page() -> alloc::string::String {
    use core::fmt::Write;

    let ipv6 = {
        let addr = YGG_IPV6.lock().await;
        format_ipv6(&addr)
    };
    let port = {
        let p = YGG_PORT.lock().await;
        *p
    };
    let sta_ip_str = {
        let ip = STA_IP.lock().await;
        if let Some(addr) = *ip {
            let mut s = alloc::string::String::new();
            let _ = write!(s, "{}", addr);
            s
        } else {
            alloc::string::String::from("Not connected")
        }
    };
    let uart_connected = UART_CONNECTED.load(Ordering::Relaxed);
    let peers_html = {
        let peers = YGG_PEERS.lock().await;
        let mut s = alloc::string::String::new();
        for i in 0..3 {
            let val = if peers.peers[i].is_empty() {
                ""
            } else {
                peers.peers[i].as_str()
            };
            let _ = write!(
                s,
                "<label>Peer {}:</label><input name=\"peer{}\" value=\"{}\" size=\"40\"><br>",
                i + 1,
                i + 1,
                val,
            );
        }
        s
    };

    let mut html = alloc::string::String::new();
    let _ = write!(
        html,
        concat!(
            "<html><head><title>YggBridge</title>",
            "<style>body{{font-family:monospace;margin:20px}}",
            "input{{margin:4px 0}}label{{display:inline-block;width:80px}}",
            ".status{{background:#f0f0f0;padding:10px;margin:10px 0}}",
            "</style></head><body>",
            "<h2>Yggdrasil TCP-UART Bridge</h2>",
            "<div class=\"status\">",
            "<b>Yggdrasil IPv6:</b> {}<br>",
            "<b>Port:</b> {}<br>",
            "<b>WiFi STA IP:</b> {}<br>",
            "<b>UART:</b> {}<br>",
            "</div>",
            "<h3>Yggdrasil Peers</h3>",
            "<form method=\"POST\" action=\"/api/ygg/peers\">",
            "{}<button type=\"submit\">Save Peers</button>",
            "</form>",
            "<h3>WiFi Configuration</h3>",
            "<form method=\"POST\" action=\"/api/wifi\">",
            "<label>SSID:</label><input name=\"ssid\" size=\"32\"><br>",
            "<label>Password:</label><input name=\"password\" type=\"password\" size=\"32\"><br>",
            "<button type=\"submit\">Save WiFi</button>",
            "</form>",
            "<p><small>Reboot device after changing settings.</small></p>",
            "</body></html>",
        ),
        ipv6,
        port,
        sta_ip_str,
        if uart_connected { "Connected" } else { "Idle" },
        peers_html,
    );

    let mut response = alloc::string::String::new();
    let _ = write!(
        response,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        html.len(),
        html
    );
    response
}

async fn build_status_json() -> alloc::string::String {
    use core::fmt::Write;

    let ipv6 = {
        let addr = YGG_IPV6.lock().await;
        format_ipv6(&addr)
    };
    let port = {
        let p = YGG_PORT.lock().await;
        *p
    };
    let sta_ip_str = {
        let ip = STA_IP.lock().await;
        if let Some(addr) = *ip {
            let mut s = alloc::string::String::new();
            let _ = write!(s, "{}", addr);
            s
        } else {
            alloc::string::String::from("null")
        }
    };
    let uart_connected = UART_CONNECTED.load(Ordering::Relaxed);
    let wifi_connected = WIFI_CONNECTED.load(Ordering::Relaxed);

    let mut json = alloc::string::String::new();
    let _ = write!(
        json,
        concat!(
            "{{",
            "\"ygg_ipv6\":\"{}\",",
            "\"ygg_port\":{},",
            "\"wifi_connected\":{},",
            "\"sta_ip\":\"{}\",",
            "\"uart_connected\":{}",
            "}}",
        ),
        ipv6,
        port,
        wifi_connected,
        sta_ip_str,
        uart_connected,
    );

    let mut response = alloc::string::String::new();
    let _ = write!(
        response,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        json.len(),
        json
    );
    response
}

async fn handle_wifi_config(body: &str) -> alloc::string::String {
    use core::fmt::Write;

    let mut ssid_buf = [0u8; 32];
    let mut pass_buf = [0u8; 64];

    let ssid_len = if let Some(v) = find_form_value(body, "ssid") {
        url_decode_into(v, &mut ssid_buf)
    } else {
        0
    };
    let pass_len = if let Some(v) = find_form_value(body, "password") {
        url_decode_into(v, &mut pass_buf)
    } else {
        0
    };

    if ssid_len == 0 {
        return alloc::string::String::from(
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 14\r\n\r\nSSID required\r\n",
        );
    }

    let ssid_str = unsafe { core::str::from_utf8_unchecked(&ssid_buf[..ssid_len]) };
    let pass_str = unsafe { core::str::from_utf8_unchecked(&pass_buf[..pass_len]) };

    let mut config = WifiConfig::new();
    config.set_credentials(ssid_str, pass_str);

    // Save to flash
    let mut flash = FlashStorage::new(unsafe { esp_hal::peripherals::FLASH::steal() });
    let result = save_wifi_config(&mut flash, &config);

    // Update global
    {
        let mut wifi_config = WIFI_CONFIG.lock().await;
        *wifi_config = config;
    }

    if result.is_ok() {
        log::info!("WiFi config saved: SSID='{}'", ssid_str);
        let body_str = "WiFi config saved. Reboot to apply.\r\n";
        let mut resp = alloc::string::String::new();
        let _ = write!(
            resp,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
            body_str.len(),
            body_str,
        );
        resp
    } else {
        alloc::string::String::from(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 18\r\n\r\nFailed to save\r\n\r\n",
        )
    }
}

async fn handle_ygg_peers(body: &str) -> alloc::string::String {
    use core::fmt::Write;

    let mut addrs: [([u8; 72], usize); 3] = [([0u8; 72], 0), ([0u8; 72], 0), ([0u8; 72], 0)];

    for i in 0..3 {
        let mut key_buf = [0u8; 8];
        let key_len = {
            let mut s = alloc::string::String::new();
            let _ = write!(s, "peer{}", i + 1);
            let b = s.as_bytes();
            let l = b.len().min(8);
            key_buf[..l].copy_from_slice(&b[..l]);
            l
        };
        let key = unsafe { core::str::from_utf8_unchecked(&key_buf[..key_len]) };
        if let Some(v) = find_form_value(body, key) {
            addrs[i].1 = url_decode_into(v, &mut addrs[i].0);
        }
    }

    let mut config = YggPeersConfig::new();
    config.magic = YGG_PEERS_MAGIC;
    config.count = 0;
    for i in 0..3 {
        if addrs[i].1 > 0 {
            let s = unsafe { core::str::from_utf8_unchecked(&addrs[i].0[..addrs[i].1]) };
            if !s.trim().is_empty() {
                config.peers[i].set(s.trim());
                config.count += 1;
            }
        }
    }

    // Save to flash
    let mut flash = FlashStorage::new(unsafe { esp_hal::peripherals::FLASH::steal() });
    let result = save_ygg_peers(&mut flash, &config);

    // Update global
    {
        let mut peers = YGG_PEERS.lock().await;
        *peers = config;
    }

    if result.is_ok() {
        log::info!("Yggdrasil peers saved ({} peers)", config.count);
        let body_str = "Peers saved. Reboot to apply.\r\n";
        let mut resp = alloc::string::String::new();
        let _ = write!(
            resp,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
            body_str.len(),
            body_str,
        );
        resp
    } else {
        alloc::string::String::from(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 18\r\n\r\nFailed to save\r\n\r\n",
        )
    }
}
