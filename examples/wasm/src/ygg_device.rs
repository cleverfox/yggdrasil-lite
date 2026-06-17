//! smoltcp `Device` implementation bridging Yggdrasil packet delivery
//! to a userspace IPv6/TCP stack.
//!
//! Adapted from examples/lite_node.rs for no_std/WASM (uses alloc).

extern crate alloc;

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
