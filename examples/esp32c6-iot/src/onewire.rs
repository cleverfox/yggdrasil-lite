//! DS18B20 temperature sensor — bit-banged one-wire on a single GPIO pin.
//!
//! Two-phase API for non-blocking integration into an event loop:
//!   1. `start_conversion()` — sends Convert T command (~2ms blocking)
//!   2. After 750ms, `read_temperature()` — reads scratchpad (~2ms blocking)

use esp_hal::delay::Delay;
use esp_hal::gpio::{DriveMode, Flex, InputConfig, Level, OutputConfig, Pin, Pull};

/// DS18B20 one-wire driver on a single GPIO pin.
pub struct Ds18b20<'a> {
    pin: Flex<'a>,
    delay: Delay,
}

/// Raw temperature reading from DS18B20 (12-bit, 1/16°C per LSB).
#[derive(Clone, Copy)]
pub struct TempReading {
    pub raw: i16,
}

impl TempReading {
    /// Temperature in tenths of a degree (e.g. 234 = 23.4°C).
    pub fn tenths_c(self) -> i16 {
        ((self.raw as i32) * 10 / 16) as i16
    }

    /// Format as "XX.X" into a byte buffer, return bytes written.
    pub fn format(self, buf: &mut [u8]) -> usize {
        let t = self.tenths_c();
        let neg = t < 0;
        let abs = t.unsigned_abs() as u16;
        let whole = abs / 10;
        let frac = abs % 10;

        let mut pos = 0;
        if neg && pos < buf.len() {
            buf[pos] = b'-';
            pos += 1;
        }

        // Write whole part (up to 3 digits)
        let mut digits = [0u8; 4];
        let mut n = whole;
        let mut dlen = 0;
        if n == 0 {
            digits[0] = b'0';
            dlen = 1;
        } else {
            while n > 0 && dlen < 4 {
                digits[dlen] = b'0' + (n % 10) as u8;
                n /= 10;
                dlen += 1;
            }
            digits[..dlen].reverse();
        }
        for &d in &digits[..dlen] {
            if pos < buf.len() {
                buf[pos] = d;
                pos += 1;
            }
        }
        if pos < buf.len() {
            buf[pos] = b'.';
            pos += 1;
        }
        if pos < buf.len() {
            buf[pos] = b'0' + frac as u8;
            pos += 1;
        }
        pos
    }
}

impl<'a> Ds18b20<'a> {
    /// Create a new DS18B20 driver on the given pin (open-drain with internal pull-up).
    pub fn new(pin: impl Pin + 'a) -> Self {
        let mut flex = Flex::new(pin);
        flex.apply_output_config(&OutputConfig::default().with_drive_mode(DriveMode::OpenDrain));
        flex.set_output_enable(true);
        flex.apply_input_config(&InputConfig::default().with_pull(Pull::Up));
        flex.set_input_enable(true);
        flex.set_level(Level::High); // release bus
        Self {
            pin: flex,
            delay: Delay::new(),
        }
    }

    // ── One-wire primitives ────────────────────────────────────────────

    /// Reset pulse. Returns true if a device is present.
    fn reset(&mut self) -> bool {
        self.pin.set_level(Level::Low);
        self.delay.delay_micros(480);
        self.pin.set_level(Level::High);
        self.delay.delay_micros(70);
        let presence = self.pin.is_low();
        self.delay.delay_micros(410);
        presence
    }

    fn write_bit(&mut self, bit: bool) {
        self.pin.set_level(Level::Low);
        if bit {
            self.delay.delay_micros(6);
            self.pin.set_level(Level::High);
            self.delay.delay_micros(64);
        } else {
            self.delay.delay_micros(60);
            self.pin.set_level(Level::High);
            self.delay.delay_micros(10);
        }
    }

    fn read_bit(&mut self) -> bool {
        self.pin.set_level(Level::Low);
        self.delay.delay_micros(6);
        self.pin.set_level(Level::High);
        self.delay.delay_micros(9);
        let bit = self.pin.is_high();
        self.delay.delay_micros(55);
        bit
    }

    fn write_byte(&mut self, byte: u8) {
        for i in 0..8 {
            self.write_bit((byte >> i) & 1 != 0); // LSB first
        }
    }

    fn read_byte(&mut self) -> u8 {
        let mut byte = 0u8;
        for i in 0..8 {
            if self.read_bit() {
                byte |= 1 << i;
            }
        }
        byte
    }

    // ── Public two-phase API ───────────────────────────────────────────

    /// Phase 1: Start temperature conversion. Returns false if no sensor detected.
    /// Blocks for ~2ms (one-wire reset + 2 command bytes).
    pub fn start_conversion(&mut self) -> bool {
        if !self.reset() {
            return false;
        }
        self.write_byte(0xCC); // Skip ROM (single device on bus)
        self.write_byte(0x44); // Convert T
        true
    }

    /// Phase 2: Read temperature. Call ≥750ms after `start_conversion()`.
    /// Blocks for ~2ms. Returns None if no sensor detected.
    pub fn read_temperature(&mut self) -> Option<TempReading> {
        if !self.reset() {
            return None;
        }
        self.write_byte(0xCC); // Skip ROM
        self.write_byte(0xBE); // Read Scratchpad

        let lsb = self.read_byte();
        let msb = self.read_byte();

        // Abort early — don't need the remaining 7 scratchpad bytes
        self.reset();

        let raw = (msb as i16) << 8 | (lsb as i16);
        Some(TempReading { raw })
    }
}
