//! ESP32-C6 Yggdrasil IoT Demo
//!
//! Boots → connects to WiFi → establishes TLS connections to Yggdrasil peers →
//! provides a telnet CLI on port 23 with DS18B20 temperature reading and
//! WS2812 RGB LED control, all reachable over the encrypted mesh.
//!
//! Web UI on AP (192.168.4.1) and STA for configuration.

#![no_std]
#![no_main]

extern crate alloc;

mod onewire;
mod telnet;
mod ws2812;

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
    rmt::Rmt,
    timer::timg::TimerGroup,
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

const HTTP_PORT: u16 = 80;
const TELNET_PORT: u16 = 23;
const MAX_TELNET_CLIENTS: usize = 3;

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


// ============================================================================
// Global State
// ============================================================================

static WIFI_CONFIG: Mutex<CriticalSectionRawMutex, WifiConfig> = Mutex::new(WifiConfig::new());
static STA_IP: Mutex<CriticalSectionRawMutex, Option<Ipv4Addr>> = Mutex::new(None);
static WIFI_CONNECTED: AtomicBool = AtomicBool::new(false);
static TELNET_CONNECTED: AtomicBool = AtomicBool::new(false);

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

    esp_alloc::heap_allocator!(size: 100 * 1024);

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

    // Set telnet port in global (for web UI)
    {
        let mut port = YGG_PORT.lock().await;
        *port = TELNET_PORT;
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
    println!("  Yggdrasil IoT Demo");
    println!("=============================================");
    println!(
        "  IPv6:  {}",
        format_ipv6(&our_addr.0)
    );
    println!("  Telnet: port {}", TELNET_PORT);
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

    // Initialize WS2812 LED on GPIO8 via RMT
    let rmt = Rmt::new(peripherals.RMT, esp_hal::time::Rate::from_mhz(80)).unwrap();
    use esp_hal::rmt::TxChannelCreator;
    let rmt_channel = rmt
        .channel0
        .configure_tx(&esp_hal::rmt::TxChannelConfig::default().with_clk_divider(1))
        .unwrap()
        .with_pin(peripherals.GPIO8);
    let mut led = ws2812::Ws2812Led::new(rmt_channel);
    led.set(0, 0, 0); // Start with LED off
    log::info!("WS2812 LED initialized on GPIO8");

    // Initialize DS18B20 temperature sensor on GPIO4
    let mut ds_sensor = onewire::Ds18b20::new(peripherals.GPIO4);
    log::info!("DS18B20 sensor initialized on GPIO4");

    TELNET_CONNECTED.store(false, Ordering::Relaxed);

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
    spawner.spawn(sta_ip_monitor(sta_stack)).ok();
    spawner.spawn(dhcp_server(ap_stack)).ok();
    spawner.spawn(http_server(ap_stack, "AP")).ok();
    spawner.spawn(http_server(sta_stack, "STA")).ok();

    // Pass the node and IoT peripherals to the yggdrasil task (runs in main)
    yggdrasil_task(sta_stack, node, signing_key, public_key, our_addr.0, &mut led, &mut ds_sensor).await;

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
    led: &mut ws2812::Ws2812Led<'_>,
    ds_sensor: &mut onewire::Ds18b20<'_>,
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
            led,
            ds_sensor,
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
    led: &mut ws2812::Ws2812Led<'_>,
    ds_sensor: &mut onewire::Ds18b20<'_>,
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
        "Yggdrasil online! Telnet on [{}]:{}",
        format_ipv6(our_addr),
        TELNET_PORT
    );

    // ── Event loop ─────────────────────────────────────────────────────

        use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet, SocketStorage};
        use smoltcp::phy::Device as _;
        use smoltcp::socket::{icmp, tcp};
        use smoltcp::time::Instant as SmolInstant;
        use smoltcp::wire::{HardwareAddress, IpCidr, IpAddress, Ipv6Address,
                            Icmpv6Packet, Icmpv6Repr};

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

        // Create TCP sockets for telnet (multiple clients) + 1 ICMP socket
        let mut socket_storage = [SocketStorage::EMPTY; MAX_TELNET_CLIENTS + 1];
        let mut sockets = SocketSet::new(&mut socket_storage[..]);

        let mut tcp_handles: Vec<SocketHandle> = Vec::new();
        for _ in 0..MAX_TELNET_CLIENTS {
            let tcp_rx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 512]);
            let tcp_tx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 1024]);
            let tcp_socket = tcp::Socket::new(tcp_rx_buf, tcp_tx_buf);
            let handle = sockets.add(tcp_socket);
            sockets.get_mut::<tcp::Socket>(handle).listen(TELNET_PORT).unwrap();
            tcp_handles.push(handle);
        }
        log::info!("smoltcp: Telnet listening on port {} ({} slots)", TELNET_PORT, MAX_TELNET_CLIENTS);

        // ICMP socket for ping
        const PING_IDENT: u16 = 0x4567;
        let icmp_rx_buf = icmp::PacketBuffer::new(
            alloc::vec![icmp::PacketMetadata::EMPTY; 4],
            alloc::vec![0u8; 512],
        );
        let icmp_tx_buf = icmp::PacketBuffer::new(
            alloc::vec![icmp::PacketMetadata::EMPTY; 4],
            alloc::vec![0u8; 512],
        );
        let mut icmp_socket = icmp::Socket::new(icmp_rx_buf, icmp_tx_buf);
        icmp_socket.bind(icmp::Endpoint::Ident(PING_IDENT)).unwrap();
        let icmp_handle = sockets.add(icmp_socket);
        log::info!("smoltcp: ICMP socket bound (ident=0x{:04x})", PING_IDENT);

        let mut last_poll_ms: u64 = 0;
        let mut last_status_ms: u64 = 0;
        let start = embassy_time::Instant::now();
        let mut tls_buf = [0u8; 4096];

        // Per-client telnet state
        let mut telnet_clis: [telnet::TelnetCli; MAX_TELNET_CLIENTS] =
            core::array::from_fn(|_| telnet::TelnetCli::new());
        let mut telnet_welcomed = [false; MAX_TELNET_CLIENTS];
        let mut telnet_connect_ms = [0u64; MAX_TELNET_CLIENTS]; // timestamp when client connected

        // LED state
        let mut led_r: u8 = 0;
        let mut led_g: u8 = 0;
        let mut led_b: u8 = 0;

        // Temperature state machine: 0=idle, 1=waiting for conversion
        let mut temp_state: u8 = 0;
        let mut last_temp_start_ms: u64 = 0;
        let mut last_temp_reading: Option<onewire::TempReading> = None;

        // Ping state machine
        // State 0=idle, 1=waiting for reply, 2=got reply/timeout, waiting interval before next
        let mut ping_state: u8 = 0;
        let mut ping_target: Ipv6Address = Ipv6Address::UNSPECIFIED;
        let mut ping_seq: u16 = 0;
        let mut ping_sent_ms: u64 = 0;
        let mut ping_count: u8 = 0;       // how many sent so far (send up to PING_TOTAL)
        let mut ping_client: usize = 0;   // which telnet client initiated the ping
        const PING_TOTAL: u8 = 4;
        const PING_TIMEOUT_MS: u64 = 5_000;
        const PING_INTERVAL_MS: u64 = 1_000;

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

            // ── 4. Temperature state machine ──────────────────────────
            {
                let now_ms = start.elapsed().as_millis() as u64;
                match temp_state {
                    0 => {
                        // Start conversion every 5 seconds
                        if now_ms.saturating_sub(last_temp_start_ms) >= 5_000 {
                            if ds_sensor.start_conversion() {
                                temp_state = 1;
                                last_temp_start_ms = now_ms;
                            }
                        }
                    }
                    _ => {
                        // Read after 750ms
                        if now_ms.saturating_sub(last_temp_start_ms) >= 750 {
                            if let Some(reading) = ds_sensor.read_temperature() {
                                last_temp_reading = Some(reading);
                                let t = reading.tenths_c();
                                log::debug!(
                                    "Temp: {}.{}°C",
                                    t / 10,
                                    if t < 0 { -(t % 10) } else { t % 10 }
                                );
                            }
                            temp_state = 0;
                        }
                    }
                }
            }

            // ── 4b. Ping state machine ─────────────────────────────────
            if ping_state > 0 {
                let now_ms = start.elapsed().as_millis() as u64;
                let elapsed = now_ms.saturating_sub(ping_sent_ms);

                if ping_state == 1 {
                    // Waiting for reply — check ICMP socket
                    let mut got_reply = false;
                    {
                        let icmp_sock = sockets.get_mut::<icmp::Socket>(icmp_handle);
                        if icmp_sock.can_recv() {
                            if let Ok((payload, from_addr)) = icmp_sock.recv() {
                                if let Ok(pkt) = Icmpv6Packet::new_checked(payload) {
                                    if pkt.msg_type() == smoltcp::wire::Icmpv6Message::EchoReply {
                                        let rtt = elapsed as u32;
                                        let reply_addr = match from_addr {
                                            IpAddress::Ipv6(a) => a,
                                            _ => ping_target,
                                        };
                                        let tcp_sock = sockets.get_mut::<tcp::Socket>(tcp_handles[ping_client]);
                                        if tcp_sock.can_send() {
                                            let mut resp = [0u8; 256];
                                            let n = telnet::fmt_ping_reply(&mut resp, &reply_addr, ping_seq, rtt);
                                            let _ = tcp_sock.send_slice(&resp[..n]);
                                        }
                                        got_reply = true;
                                    }
                                }
                            }
                        }
                    }

                    if got_reply {
                        if ping_count >= PING_TOTAL {
                            // All pings done
                            let tcp_sock = sockets.get_mut::<tcp::Socket>(tcp_handles[ping_client]);
                            if tcp_sock.can_send() {
                                let _ = tcp_sock.send_slice(telnet::PROMPT);
                            }
                            ping_state = 0;
                        } else {
                            // Wait interval then send next
                            ping_sent_ms = now_ms;
                            ping_state = 2; // waiting interval
                        }
                    } else if elapsed >= PING_TIMEOUT_MS {
                        // Timeout
                        let tcp_sock = sockets.get_mut::<tcp::Socket>(tcp_handles[ping_client]);
                        if tcp_sock.can_send() {
                            let mut resp = [0u8; 128];
                            let n = telnet::fmt_ping_timeout(&mut resp, ping_seq);
                            let _ = tcp_sock.send_slice(&resp[..n]);
                        }
                        if ping_count >= PING_TOTAL {
                            let tcp_sock = sockets.get_mut::<tcp::Socket>(tcp_handles[ping_client]);
                            if tcp_sock.can_send() {
                                let _ = tcp_sock.send_slice(telnet::PROMPT);
                            }
                            ping_state = 0;
                        } else {
                            // Send next immediately
                            ping_sent_ms = now_ms;
                            ping_state = 2;
                        }
                    }
                }

                if ping_state == 2 {
                    // Waiting for interval before next ping
                    let now_ms = start.elapsed().as_millis() as u64;
                    if now_ms.saturating_sub(ping_sent_ms) >= PING_INTERVAL_MS {
                        // Send next ping
                        ping_seq += 1;
                        ping_count += 1;
                        let icmp_sock = sockets.get_mut::<icmp::Socket>(icmp_handle);
                        if icmp_sock.can_send() {
                            let payload_data = [0xABu8; 32];
                            let icmp_repr = Icmpv6Repr::EchoRequest {
                                ident: PING_IDENT,
                                seq_no: ping_seq,
                                data: &payload_data,
                            };
                            let dst = IpAddress::Ipv6(ping_target);
                            if let Ok(icmp_payload) = icmp_sock.send(icmp_repr.buffer_len(), dst) {
                                let mut icmp_pkt = Icmpv6Packet::new_unchecked(icmp_payload);
                                icmp_repr.emit(
                                    &local_ip.into(),
                                    &ping_target.into(),
                                    &mut icmp_pkt,
                                    &device.capabilities().checksum,
                                );
                            }
                        }
                        ping_sent_ms = now_ms;
                        ping_state = 1; // waiting for reply
                    }
                }
            }

            // ── 5. Telnet CLI (all client slots) ──────────────────────
            {
                // Pre-gather remote endpoints for 'w' command (avoids double borrow)
                let mut remote_eps: [Option<smoltcp::wire::IpEndpoint>; MAX_TELNET_CLIENTS] =
                    [None; MAX_TELNET_CLIENTS];
                for si in 0..MAX_TELNET_CLIENTS {
                    if telnet_welcomed[si] {
                        let s = sockets.get_mut::<tcp::Socket>(tcp_handles[si]);
                        remote_eps[si] = s.remote_endpoint();
                    }
                }

                let mut any_connected = false;
                for ci in 0..MAX_TELNET_CLIENTS {
                    let socket = sockets.get_mut::<tcp::Socket>(tcp_handles[ci]);

                    if socket.is_active() {
                        // Send welcome banner on new connection
                        if !telnet_welcomed[ci] {
                            if socket.can_send() {
                                let _ = socket.send_slice(telnet::WELCOME);
                                telnet_welcomed[ci] = true;
                                telnet_connect_ms[ci] = start.elapsed().as_millis() as u64;
                                log::info!("Telnet client {} connected", ci);
                            }
                        } else if !socket.may_recv() {
                            // Remote sent FIN — abort and re-listen
                            log::info!("Telnet client {} disconnected", ci);
                            socket.abort();
                            telnet_welcomed[ci] = false;
                            telnet_clis[ci] = telnet::TelnetCli::new();
                        } else {
                            // Receive and process commands
                            if socket.can_recv() {
                                let mut tmp = [0u8; 128];
                                if let Ok(n) = socket.recv_slice(&mut tmp) {
                                    if n > 0 {
                                        if let Some(cmd) = telnet_clis[ci].feed(&tmp[..n]) {
                                            let mut resp_buf = [0u8; 512];
                                            let mut send_prompt = true;
                                            let resp_len = match cmd {
                                                telnet::Command::Help => {
                                                    telnet::fmt_help(&mut resp_buf)
                                                }
                                                telnet::Command::Temp => {
                                                    telnet::fmt_temp(
                                                        &mut resp_buf,
                                                        last_temp_reading,
                                                    )
                                                }
                                                telnet::Command::Led { r, g, b } => {
                                                    led_r = r;
                                                    led_g = g;
                                                    led_b = b;
                                                    led.set(r, g, b);
                                                    telnet::fmt_led_ok(
                                                        &mut resp_buf, r, g, b,
                                                    )
                                                }
                                                telnet::Command::Status => {
                                                    fmt_telnet_status(
                                                        &mut resp_buf,
                                                        (start.elapsed().as_millis()
                                                            / 1000)
                                                            as u32,
                                                        our_addr,
                                                        node.peer_count(),
                                                        node.session_count(),
                                                        node.path_count(),
                                                        last_temp_reading,
                                                        led_r,
                                                        led_g,
                                                        led_b,
                                                    )
                                                }
                                                telnet::Command::Uptime => {
                                                    telnet::fmt_uptime(
                                                        &mut resp_buf,
                                                        (start.elapsed().as_millis() / 1000) as u32,
                                                    )
                                                }
                                                telnet::Command::Who => {
                                                    let now_ms = start.elapsed().as_millis() as u64;
                                                    let uptime_s = (now_ms / 1000) as u32;
                                                    let mut infos: [telnet::SessionInfo; MAX_TELNET_CLIENTS] = core::array::from_fn(|_| {
                                                        telnet::SessionInfo {
                                                            slot: 0,
                                                            addr: Ipv6Address::UNSPECIFIED,
                                                            port: 0,
                                                            connected_secs: 0,
                                                        }
                                                    });
                                                    let mut count = 0usize;
                                                    for si in 0..MAX_TELNET_CLIENTS {
                                                        if let Some(ep) = remote_eps[si] {
                                                            let addr = match ep.addr {
                                                                IpAddress::Ipv6(a) => a,
                                                                _ => Ipv6Address::UNSPECIFIED,
                                                            };
                                                            let conn_secs = ((now_ms.saturating_sub(telnet_connect_ms[si])) / 1000) as u32;
                                                            infos[count] = telnet::SessionInfo {
                                                                slot: si as u8,
                                                                addr,
                                                                port: ep.port,
                                                                connected_secs: conn_secs,
                                                            };
                                                            count += 1;
                                                        }
                                                    }
                                                    telnet::fmt_who(&mut resp_buf, uptime_s, &infos[..count])
                                                }
                                                telnet::Command::Ping { addr } => {
                                                    if ping_state != 0 {
                                                        telnet::fmt_ping_busy(&mut resp_buf)
                                                    } else {
                                                        // Set up ping state — first ICMP packet
                                                        // sent by state machine (step 4b) on next iteration
                                                        ping_target = addr;
                                                        ping_seq = 0; // will be incremented to 1 in state 2
                                                        ping_count = 0;
                                                        ping_client = ci;
                                                        ping_sent_ms = 0; // triggers immediate send in state 2
                                                        ping_state = 2; // "send next" state
                                                        send_prompt = false; // prompt sent after ping completes
                                                        telnet::fmt_ping_start(&mut resp_buf, &addr)
                                                    }
                                                }
                                                telnet::Command::Unknown => {
                                                    telnet::fmt_unknown(&mut resp_buf)
                                                }
                                            };
                                            if socket.can_send() {
                                                let _ = socket
                                                    .send_slice(&resp_buf[..resp_len]);
                                                if send_prompt {
                                                    let _ =
                                                        socket.send_slice(telnet::PROMPT);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if telnet_welcomed[ci] {
                            any_connected = true;
                        }
                    } else {
                        // Socket fully closed — reset state and re-listen
                        if telnet_welcomed[ci] {
                            telnet_welcomed[ci] = false;
                            telnet_clis[ci] = telnet::TelnetCli::new();
                        }
                        if !socket.is_listening() {
                            socket.abort();
                            if let Err(e) = socket.listen(TELNET_PORT) {
                                log::error!("smoltcp: telnet[{}] re-listen failed: {:?}", ci, e);
                            }
                        }
                    }
                }
                TELNET_CONNECTED.store(any_connected, Ordering::Relaxed);
            }

            // ── 6. Second smoltcp poll (flushes TCP responses) ─────────
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

            // ── 7. Periodic node poll ──────────────────────────────────
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

            // ── 8. Flush TLS ───────────────────────────────────────────
            let _ = tls.flush().await;

            // ── 9. Status output ───────────────────────────────────────
            if now_ms.saturating_sub(last_status_ms) >= 30_000 {
                last_status_ms = now_ms;
                if let Some(r) = last_temp_reading {
                    let t = r.tenths_c();
                    let sign = if t < 0 { "-" } else { "" };
                    let abs = if t < 0 { -t } else { t };
                    log::info!(
                        "uptime={}s peers={} sessions={} paths={} telnet={} temp={}{}.{}C led=({},{},{})",
                        now_ms / 1000,
                        node.peer_count(),
                        node.session_count(),
                        node.path_count(),
                        if TELNET_CONNECTED.load(Ordering::Relaxed) { "connected" } else { "idle" },
                        sign, abs / 10, abs % 10,
                        led_r, led_g, led_b,
                    );
                } else {
                    log::info!(
                        "uptime={}s peers={} sessions={} paths={} telnet={} temp=none led=({},{},{})",
                        now_ms / 1000,
                        node.peer_count(),
                        node.session_count(),
                        node.path_count(),
                        if TELNET_CONNECTED.load(Ordering::Relaxed) { "connected" } else { "idle" },
                        led_r, led_g, led_b,
                    );
                }
            }
        }
}

// ============================================================================
// Telnet status formatter
// ============================================================================

fn fmt_telnet_status(
    buf: &mut [u8],
    uptime_s: u32,
    our_addr: &[u8; 16],
    peer_count: usize,
    session_count: usize,
    path_count: usize,
    temp: Option<onewire::TempReading>,
    led_r: u8,
    led_g: u8,
    led_b: u8,
) -> usize {
    let mut p = 0;

    macro_rules! w {
        ($s:expr) => {
            let n = $s.len().min(buf.len().saturating_sub(p));
            buf[p..p + n].copy_from_slice(&$s[..n]);
            p += n;
        };
    }

    w!(b"Uptime: ");
    p += telnet::fmt_u32(&mut buf[p..], uptime_s);
    w!(b"s\r\n");

    w!(b"IPv6: ");
    {
        let ipv6 = format_ipv6(our_addr);
        // Use core::fmt::write to render IPv6 address into our buffer
        struct BufW<'a>(&'a mut [u8], usize);
        impl core::fmt::Write for BufW<'_> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let b = s.as_bytes();
                let n = b.len().min(self.0.len().saturating_sub(self.1));
                self.0[self.1..self.1 + n].copy_from_slice(&b[..n]);
                self.1 += n;
                Ok(())
            }
        }
        let mut w = BufW(&mut buf[p..], 0);
        let _ = core::fmt::write(&mut w, format_args!("{}", ipv6));
        p += w.1;
    }
    w!(b"\r\n");

    w!(b"Peers: ");
    p += telnet::fmt_u32(&mut buf[p..], peer_count as u32);
    w!(b"  Sessions: ");
    p += telnet::fmt_u32(&mut buf[p..], session_count as u32);
    w!(b"  Paths: ");
    p += telnet::fmt_u32(&mut buf[p..], path_count as u32);
    w!(b"\r\n");

    w!(b"Temperature: ");
    match temp {
        Some(r) => {
            p += r.format(&mut buf[p..]);
            w!(b" C\r\n");
        }
        None => {
            w!(b"no reading yet\r\n");
        }
    }

    w!(b"LED: (");
    p += telnet::fmt_u32(&mut buf[p..], led_r as u32);
    w!(b", ");
    p += telnet::fmt_u32(&mut buf[p..], led_g as u32);
    w!(b", ");
    p += telnet::fmt_u32(&mut buf[p..], led_b as u32);
    w!(b")\r\n");

    p
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
    let telnet_connected = TELNET_CONNECTED.load(Ordering::Relaxed);
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
            "<h2>Yggdrasil IoT Demo</h2>",
            "<div class=\"status\">",
            "<b>Yggdrasil IPv6:</b> {}<br>",
            "<b>Port:</b> {}<br>",
            "<b>WiFi STA IP:</b> {}<br>",
            "<b>Telnet:</b> {}<br>",
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
        if telnet_connected { "Connected" } else { "Idle" },
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
    let telnet_connected = TELNET_CONNECTED.load(Ordering::Relaxed);
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
            "\"telnet_connected\":{}",
            "}}",
        ),
        ipv6,
        port,
        wifi_connected,
        sta_ip_str,
        telnet_connected,
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
