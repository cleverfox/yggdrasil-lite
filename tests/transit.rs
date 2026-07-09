//! Integration tests for the `transit` feature.
//!
//! Builds small in-memory networks of YggdrasilLite nodes wired directly to
//! each other (no TCP/TLS), and verifies that a transit node forwards
//! discovery and traffic between its peers — and that `no_redistribute`
//! prevents exactly that.

use std::collections::HashMap;

use rand::rngs::OsRng;
use rand::RngCore;
use yggdrasil_lite::{LiteConfig, NodeEvent, PeerId, PublicKey, YggdrasilLite};

/// In-memory network of directly wired nodes.
struct Net {
    nodes: Vec<YggdrasilLite>,
    /// (node_idx, local_peer_id) -> (other_idx, other_peer_id)
    links: HashMap<(usize, PeerId), (usize, PeerId)>,
    now: u64,
    delivered: Vec<Vec<(PublicKey, Vec<u8>)>>,
}

impl Net {
    fn new(n: usize) -> Self {
        let nodes = (0..n)
            .map(|_| {
                let mut seed = [0u8; 32];
                OsRng.fill_bytes(&mut seed);
                YggdrasilLite::new(LiteConfig::new(seed))
            })
            .collect();
        Self {
            nodes,
            links: HashMap::new(),
            now: 1_000,
            delivered: vec![Vec::new(); n],
        }
    }

    fn key(&self, idx: usize) -> PublicKey {
        *self.nodes[idx].public_key()
    }

    /// Wire two nodes together. Returns (peer_id of b at a, peer_id of a at b).
    fn connect(&mut self, a: usize, b: usize) -> (PeerId, PeerId) {
        let key_a = self.key(a);
        let key_b = self.key(b);
        let pa = self.nodes[a].add_peer(key_b, 0);
        let pb = self.nodes[b].add_peer(key_a, 0);
        self.nodes[a].mark_handshake_done(pa);
        self.nodes[b].mark_handshake_done(pb);
        self.links.insert((a, pa), (b, pb));
        self.links.insert((b, pb), (a, pa));
        (pa, pb)
    }

    /// Deliver events (and any cascading responses) until the network is quiet.
    fn dispatch(&mut self, from: usize, events: Vec<NodeEvent>) {
        let mut queue: Vec<(usize, NodeEvent)> =
            events.into_iter().map(|e| (from, e)).collect();
        let mut budget = 100_000usize;
        while let Some((idx, ev)) = queue.pop() {
            budget = budget.checked_sub(1).expect("event storm: possible routing loop");
            match ev {
                NodeEvent::SendToPeer { peer_id, data } => {
                    if let Some(&(other, other_pid)) = self.links.get(&(idx, peer_id)) {
                        let evs = self.nodes[other]
                            .handle_peer_data(other_pid, &data, self.now, &mut OsRng);
                        queue.extend(evs.into_iter().map(|e| (other, e)));
                    }
                }
                NodeEvent::Deliver { source, data } => {
                    self.delivered[idx].push((source, data));
                }
            }
        }
    }

    /// Advance time and poll every node once.
    fn tick(&mut self, dt_ms: u64) {
        self.now += dt_ms;
        for i in 0..self.nodes.len() {
            let evs = self.nodes[i].poll(self.now, &mut OsRng);
            self.dispatch(i, evs);
        }
    }

    fn settle(&mut self, ticks: usize, dt_ms: u64) {
        for _ in 0..ticks {
            self.tick(dt_ms);
        }
    }

    fn send(&mut self, from: usize, to: usize, msg: &[u8]) {
        let dest = self.key(to);
        let evs = self.nodes[from].send(&dest, msg, self.now, &mut OsRng);
        self.dispatch(from, evs);
    }

    fn received(&self, idx: usize, from: usize, msg: &[u8]) -> bool {
        let from_key = self.key(from);
        self.delivered[idx]
            .iter()
            .any(|(src, data)| *src == from_key && data == msg)
    }

    /// Repeatedly send until delivered (sessions may need a handshake round
    /// trip and path discovery first). Returns true if delivered.
    fn send_until_delivered(&mut self, from: usize, to: usize, msg: &[u8], attempts: usize) -> bool {
        for _ in 0..attempts {
            self.send(from, to, msg);
            self.settle(3, 1_000);
            if self.received(to, from, msg) {
                return true;
            }
        }
        false
    }
}

/// Chain A — T — B: the transit node T must let A and B communicate even
/// though they are not directly connected.
#[test]
fn transit_forwards_between_peers() {
    let mut net = Net::new(3);
    net.connect(0, 1); // A — T
    net.connect(1, 2); // T — B

    // Let the tree and bloom filters converge (bloom interval is 10s).
    net.settle(40, 1_000);

    assert!(
        net.send_until_delivered(0, 2, b"hello through transit", 20),
        "A -> B via transit node was never delivered"
    );
    assert!(
        net.send_until_delivered(2, 0, b"reply through transit", 20),
        "B -> A via transit node was never delivered"
    );
}

/// Longer chain A — T1 — T2 — B: two transit hops.
#[test]
fn transit_forwards_across_two_hops() {
    let mut net = Net::new(4);
    net.connect(0, 1);
    net.connect(1, 2);
    net.connect(2, 3);

    net.settle(50, 1_000);

    assert!(
        net.send_until_delivered(0, 3, b"across two transit hops", 25),
        "A -> B across two transit nodes was never delivered"
    );
}

/// A stub node marks both peers no_redistribute: it must never provide
/// transit between them, while its own connectivity keeps working.
#[test]
fn no_redistribute_prevents_transit() {
    let mut net = Net::new(3);
    let (t_pa, _) = net.connect(1, 0); // T's peer id for A
    let (t_pb, _) = net.connect(1, 2); // T's peer id for B
    assert!(net.nodes[1].set_peer_no_redistribute(t_pa, true));
    assert!(net.nodes[1].set_peer_no_redistribute(t_pb, true));

    net.settle(40, 1_000);

    // A and B must not be able to reach each other through the stub.
    assert!(
        !net.send_until_delivered(0, 2, b"should not pass", 15),
        "traffic passed through a node with no_redistribute on all peers"
    );

    // But the stub itself communicates with both peers just fine.
    assert!(
        net.send_until_delivered(0, 1, b"direct to stub", 10),
        "A -> stub direct traffic broken"
    );
    assert!(
        net.send_until_delivered(1, 2, b"stub to B", 10),
        "stub -> B direct traffic broken"
    );
}

/// Marking only one peer is asymmetric: the marked peer can still discover
/// and reach others through us (uplink usage), but nobody can discover the
/// marked peer's keys through us.
#[test]
fn no_redistribute_is_asymmetric() {
    let mut net = Net::new(3);
    net.connect(1, 0); // T — A (A unmarked)
    let (t_pb, _) = net.connect(1, 2); // T — B (B marked)
    assert!(net.nodes[1].set_peer_no_redistribute(t_pb, true));

    net.settle(40, 1_000);

    // A cannot discover/reach B through T.
    assert!(
        !net.send_until_delivered(0, 2, b"a to marked b", 15),
        "A reached a no_redistribute peer through the transit node"
    );

    // B (the marked peer) can still use T as an uplink to reach A.
    assert!(
        net.send_until_delivered(2, 0, b"marked b to a", 20),
        "marked peer could not use the node as an uplink"
    );
}

/// Two directly connected nodes must communicate even when one side marks
/// the link no_redistribute — the flag only affects transit, not the link.
#[test]
fn direct_traffic_unaffected_by_no_redistribute() {
    let mut net = Net::new(2);
    let (t_pa, _) = net.connect(1, 0);
    assert!(net.nodes[1].set_peer_no_redistribute(t_pa, true));
    net.settle(40, 1_000);

    assert!(
        net.send_until_delivered(0, 1, b"a to marked-link peer", 10),
        "direct traffic to a no_redistribute peer broken"
    );
    assert!(
        net.send_until_delivered(1, 0, b"marked-link peer to a", 10),
        "direct traffic from a no_redistribute peer broken"
    );
}
