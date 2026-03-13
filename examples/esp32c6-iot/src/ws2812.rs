//! WS2812 RGB LED driver via RMT — single LED, no external crate.
//!
//! Uses the ESP32-C6 RMT peripheral at 80MHz to bit-bang WS2812 timing.
//! The `transmit` → `wait` ownership dance is hidden behind an `Option`.

use esp_hal::gpio::Level;
use esp_hal::rmt::{Channel, PulseCode, Tx};

/// WS2812 LED driver wrapping an RMT TX channel.
pub struct Ws2812Led<'ch> {
    channel: Option<Channel<'ch, esp_hal::Blocking, Tx>>,
}

// Timing at 80 MHz RMT clock, divider 1 → 12.5 ns per tick
const T0H: u16 = 32; // 400 ns
const T0L: u16 = 68; // 850 ns
const T1H: u16 = 68; // 850 ns
const T1L: u16 = 32; // 400 ns

impl<'ch> Ws2812Led<'ch> {
    /// Wrap an already-configured RMT TX channel + pin.
    pub fn new(channel: Channel<'ch, esp_hal::Blocking, Tx>) -> Self {
        Self {
            channel: Some(channel),
        }
    }

    /// Set the LED colour. Silently ignored if the channel was lost.
    pub fn set(&mut self, r: u8, g: u8, b: u8) {
        let channel = match self.channel.take() {
            Some(ch) => ch,
            None => return,
        };

        // WS2812 expects GRB order, MSB first
        let grb: u32 = (g as u32) << 16 | (r as u32) << 8 | (b as u32);
        let mut data = [PulseCode::end_marker(); 25]; // 24 data bits + end
        for i in 0..24 {
            data[i] = if (grb >> (23 - i)) & 1 != 0 {
                PulseCode::new(Level::High, T1H, Level::Low, T1L)
            } else {
                PulseCode::new(Level::High, T0H, Level::Low, T0L)
            };
        }

        // transmit() consumes the channel; wait() gives it back
        match channel.transmit(&data) {
            Ok(tx) => match tx.wait() {
                Ok(ch) => self.channel = Some(ch),
                Err((_, ch)) => self.channel = Some(ch),
            },
            Err((_, ch)) => self.channel = Some(ch),
        }
    }
}
