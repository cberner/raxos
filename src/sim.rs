//! Deterministic whole-cluster simulator and the protocol test suite built
//! on it.
//!
//! N `Replica`s run against a virtual clock and a seeded network that can
//! delay, drop, duplicate, and partition messages, and crash-stop replicas.
//! Safety invariants (agreement, validity, exactly-once, in-order delivery)
//! are checked after every event; liveness is asserted at quiescence. Every
//! run is a pure function of its seed, so any failure reproduces from the
//! seed printed in the panic message.

use std::collections::BTreeMap;

use crate::rng::Rng;
use crate::types::{CommandId, ReplicaId, Slot};
use crate::wire::{Message, Payload};
use crate::{Action, Config, Replica};

const TICK: u64 = MILLIS * 100;
const MILLIS: u64 = 1_000_000;

pub(crate) struct NetConfig {
    pub(crate) min_delay: u64,
    pub(crate) max_delay: u64,
    /// Percent of messages dropped / duplicated, applied only before
    /// `unreliable_until` so liveness runs can settle.
    pub(crate) drop_pct: u64,
    pub(crate) dup_pct: u64,
    pub(crate) unreliable_until: u64,
}

impl Default for NetConfig {
    fn default() -> NetConfig {
        NetConfig {
            min_delay: MILLIS,
            max_delay: 20 * MILLIS,
            drop_pct: 0,
            dup_pct: 0,
            unreliable_until: 0,
        }
    }
}

enum Event {
    Deliver { to: usize, bytes: Vec<u8> },
    Tick { replica: usize },
    Submit { replica: usize, data: Vec<u8> },
    Crash { replica: usize },
}

pub(crate) struct Sim {
    seed: u64,
    replicas: Vec<Replica>,
    alive: Vec<bool>,
    now: u64,
    events: BTreeMap<(u64, u64), Event>,
    event_seq: u64,
    rng: Rng,
    net: NetConfig,
    /// blocked[from][to] = messages blocked until this virtual time.
    blocked_until: Vec<Vec<u64>>,

    // Oracle state.
    submitted: BTreeMap<CommandId, (usize, Vec<u8>)>,
    /// Canonical per-slot delivery (first replica to deliver defines it;
    /// everyone else must match): the agreement invariant.
    canonical: BTreeMap<Slot, Vec<(CommandId, Vec<u8>)>>,
    delivered_watermark: Vec<Slot>,
    delivered_ids: Vec<BTreeMap<CommandId, Slot>>,
    pub(crate) sends_by_kind: BTreeMap<&'static str, u64>,
    pub(crate) hedged_records: u64,
    /// When true, replicas are ticked exactly at their advertised
    /// `next_wakeup()` instead of on a fixed interval, exercising the
    /// deadline contract (each returned deadline must retire or advance
    /// when serviced, or the run trips the event cap).
    wakeup_driven: bool,
    next_tick: Vec<u64>,
    events_processed: u64,
}

impl Sim {
    pub(crate) fn new(
        n: usize,
        seed: u64,
        net: NetConfig,
        configure: impl Fn(Config) -> Config,
    ) -> Sim {
        let mut sim = Sim::build(n, seed, net, configure, false);
        for replica in 0..n {
            sim.schedule(TICK, Event::Tick { replica });
        }
        sim
    }

    pub(crate) fn new_wakeup_driven(
        n: usize,
        seed: u64,
        net: NetConfig,
        configure: impl Fn(Config) -> Config,
    ) -> Sim {
        Sim::build(n, seed, net, configure, true)
    }

    fn build(
        n: usize,
        seed: u64,
        net: NetConfig,
        configure: impl Fn(Config) -> Config,
        wakeup_driven: bool,
    ) -> Sim {
        let ids: Vec<ReplicaId> = (1..=n as u64).map(ReplicaId).collect();
        let mut rng = Rng::new(seed ^ 0x5eed);
        let replicas: Vec<Replica> = ids
            .iter()
            .map(|&me| {
                let config = Config::new(ids.clone(), me, rng.next_u64()).unwrap();
                Replica::new(configure(config))
            })
            .collect();
        Sim {
            seed,
            alive: vec![true; n],
            now: 0,
            events: BTreeMap::new(),
            event_seq: 0,
            rng,
            net,
            blocked_until: vec![vec![0; n]; n],
            submitted: BTreeMap::new(),
            canonical: BTreeMap::new(),
            delivered_watermark: vec![Slot(0); n],
            delivered_ids: vec![BTreeMap::new(); n],
            sends_by_kind: BTreeMap::new(),
            hedged_records: 0,
            wakeup_driven,
            next_tick: vec![u64::MAX; n],
            events_processed: 0,
            replicas,
        }
    }

    /// In wakeup-driven mode, (re)schedules replica `r`'s next tick exactly
    /// at its advertised wakeup. Called after every event touching `r`.
    fn schedule_wakeup(&mut self, r: usize) {
        if !self.wakeup_driven || !self.alive[r] {
            return;
        }
        if let Some(wakeup) = self.replicas[r].next_wakeup() {
            let due = wakeup.max(self.now);
            if due < self.next_tick[r] {
                self.next_tick[r] = due;
                self.schedule(due, Event::Tick { replica: r });
            }
        }
    }

    fn n(&self) -> usize {
        self.replicas.len()
    }

    fn schedule(&mut self, at: u64, event: Event) {
        self.event_seq += 1;
        self.events.insert((at, self.event_seq), event);
    }

    pub(crate) fn submit_at(&mut self, at: u64, replica: usize, data: Vec<u8>) {
        assert!(at >= self.now);
        self.schedule(at, Event::Submit { replica, data });
    }

    pub(crate) fn crash_at(&mut self, at: u64, replica: usize) {
        self.schedule(at, Event::Crash { replica });
    }

    /// Blocks all messages from `from` to `to` until virtual time `until`.
    pub(crate) fn block(&mut self, from: usize, to: usize, until: u64) {
        self.blocked_until[from][to] = self.blocked_until[from][to].max(until);
    }

    pub(crate) fn block_both(&mut self, a: usize, b: usize, until: u64) {
        self.block(a, b, until);
        self.block(b, a, until);
    }

    /// Runs the simulation up to and including virtual time `until`.
    pub(crate) fn run_until(&mut self, until: u64) {
        while let Some((&(at, seq), _)) = self.events.first_key_value() {
            if at > until {
                break;
            }
            let event = self.events.remove(&(at, seq)).unwrap();
            self.now = at;
            self.events_processed += 1;
            assert!(
                self.events_processed < 2_000_000,
                "seed {}: event cap exceeded (stuck wakeup loop?)",
                self.seed
            );
            match event {
                Event::Tick { replica } => {
                    if self.wakeup_driven {
                        if at != self.next_tick[replica] {
                            continue; // superseded by an earlier reschedule
                        }
                        self.next_tick[replica] = u64::MAX;
                    }
                    if self.alive[replica] {
                        self.replicas[replica].tick(self.now);
                        self.drain(replica);
                    }
                    if self.wakeup_driven {
                        self.schedule_wakeup(replica);
                    } else {
                        self.schedule(at + TICK, Event::Tick { replica });
                    }
                }
                Event::Deliver { to, bytes } => {
                    if self.alive[to] {
                        let message = Message::decode(&bytes).expect("sim transports valid bytes");
                        self.replicas[to].receive(self.now, message);
                        self.drain(to);
                        self.schedule_wakeup(to);
                    }
                }
                Event::Submit { replica, data } => {
                    if self.alive[replica] {
                        let id = self.replicas[replica]
                            .submit(self.now, &data)
                            .expect("sim never overfills the pool");
                        self.submitted.insert(id, (replica, data));
                        self.drain(replica);
                        self.schedule_wakeup(replica);
                    }
                }
                Event::Crash { replica } => {
                    self.alive[replica] = false;
                }
            }
        }
        self.now = until;
    }

    /// Drains one replica's actions, transporting sends and checking every
    /// delivery against the oracle.
    fn drain(&mut self, replica: usize) {
        while let Some(action) = self.replicas[replica].poll_action() {
            match action {
                Action::Send { to, message } => {
                    let kind = payload_kind(&message.payload);
                    *self.sends_by_kind.entry(kind).or_default() += 1;
                    if kind == "Record" && replica != 0 {
                        self.hedged_records += 1;
                    }
                    let to_idx = (to.0 - 1) as usize;
                    assert_ne!(to_idx, replica, "seed {}: self-send", self.seed);
                    let bytes = message.encode();
                    // Round-trip through the wire format on every hop.
                    assert!(Message::decode(&bytes).is_ok());
                    if self.now < self.blocked_until[replica][to_idx] {
                        continue;
                    }
                    let unreliable = self.now < self.net.unreliable_until;
                    if unreliable && self.rng.next_u64() % 100 < self.net.drop_pct {
                        continue;
                    }
                    let copies = if unreliable && self.rng.next_u64() % 100 < self.net.dup_pct {
                        2
                    } else {
                        1
                    };
                    for _ in 0..copies {
                        let delay = self
                            .rng
                            .range_inclusive(self.net.min_delay, self.net.max_delay);
                        self.schedule(
                            self.now + delay,
                            Event::Deliver {
                                to: to_idx,
                                bytes: bytes.clone(),
                            },
                        );
                    }
                }
                Action::Deliver { slot, commands } => {
                    self.check_delivery(replica, slot, commands);
                }
            }
        }
    }

    fn check_delivery(&mut self, replica: usize, slot: Slot, commands: Vec<(CommandId, Vec<u8>)>) {
        let seed = self.seed;
        // In-order, gapless delivery.
        assert_eq!(
            slot,
            Slot(self.delivered_watermark[replica].0 + 1),
            "seed {seed}: out-of-order delivery at replica {replica}"
        );
        self.delivered_watermark[replica] = slot;
        // Validity + exactly-once.
        for (id, data) in &commands {
            let (_, submitted_data) = self
                .submitted
                .get(id)
                .unwrap_or_else(|| panic!("seed {seed}: delivered unsubmitted command {id:?}"));
            assert_eq!(
                submitted_data, data,
                "seed {seed}: delivered corrupted command {id:?}"
            );
            let previous = self.delivered_ids[replica].insert(*id, slot);
            assert_eq!(
                previous, None,
                "seed {seed}: duplicate delivery of {id:?} at replica {replica}"
            );
        }
        // Agreement: identical contents in the same slot everywhere.
        match self.canonical.get(&slot) {
            None => {
                self.canonical.insert(slot, commands);
            }
            Some(canonical) => assert_eq!(
                canonical, &commands,
                "seed {seed}: replicas disagree on {slot:?}"
            ),
        }
    }

    /// Asserts full convergence: every live replica delivered everything any
    /// replica delivered, and every command submitted at a replica that
    /// never crashed has been delivered.
    pub(crate) fn assert_converged(&self) {
        let seed = self.seed;
        let max_delivered = self
            .delivered_watermark
            .iter()
            .copied()
            .max()
            .unwrap_or(Slot(0));
        for replica in 0..self.n() {
            if self.alive[replica] {
                assert_eq!(
                    self.delivered_watermark[replica], max_delivered,
                    "seed {seed}: replica {replica} has not converged"
                );
            }
        }
        for (id, (origin, _)) in &self.submitted {
            if !self.alive[*origin] {
                continue;
            }
            for replica in 0..self.n() {
                if self.alive[replica] {
                    assert!(
                        self.delivered_ids[replica].contains_key(id),
                        "seed {seed}: {id:?} submitted at live replica {origin} never \
                         delivered at replica {replica}"
                    );
                }
            }
        }
    }

    pub(crate) fn delivered_watermark(&self, replica: usize) -> Slot {
        self.delivered_watermark[replica]
    }

    pub(crate) fn replica(&self, replica: usize) -> &Replica {
        &self.replicas[replica]
    }

    pub(crate) fn total_sends(&self) -> u64 {
        self.sends_by_kind.values().sum()
    }
}

fn payload_kind(payload: &Payload) -> &'static str {
    match payload {
        Payload::Record { .. } => "Record",
        Payload::RecordReply { .. } => "RecordReply",
        Payload::Decide { .. } => "Decide",
        Payload::Forward { .. } => "Forward",
        Payload::Learn { .. } => "Learn",
        Payload::LearnReply { .. } => "LearnReply",
        Payload::Ping => "Ping",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1000 * MILLIS;

    fn cmd(tag: u64) -> Vec<u8> {
        tag.to_le_bytes().to_vec()
    }

    /// Fault-free fast path: one command at the leader commits in one round
    /// trip, with the minimal message pattern and no hedged activity.
    #[test]
    fn fast_path_is_one_round_trip() {
        let mut sim = Sim::new(3, 1, NetConfig::default(), |config| config);
        sim.submit_at(10 * MILLIS, 0, cmd(1));
        // One max network delay out (Record), one back (RecordReply).
        sim.run_until(10 * MILLIS + 2 * 20 * MILLIS);
        assert_eq!(
            sim.delivered_watermark(0),
            Slot(1),
            "leader decided in 1 RTT"
        );
        sim.run_until(SEC);
        sim.assert_converged();
        assert_eq!(sim.hedged_records, 0, "no hedged proposers activated");
        assert_eq!(sim.sends_by_kind["Record"], 2);
        assert_eq!(sim.sends_by_kind["RecordReply"], 2);
        assert_eq!(sim.sends_by_kind["Decide"], 2);
        assert!(!sim.sends_by_kind.contains_key("Forward"));
        assert!(!sim.sends_by_kind.contains_key("Learn"));
    }

    /// A command submitted at a follower is forwarded to the leader and
    /// committed without the follower ever proposing.
    #[test]
    fn follower_submission_goes_through_leader() {
        let mut sim = Sim::new(3, 2, NetConfig::default(), |config| config);
        sim.submit_at(10 * MILLIS, 2, cmd(1));
        sim.run_until(SEC);
        sim.assert_converged();
        assert_eq!(sim.delivered_watermark(2), Slot(1));
        assert_eq!(sim.sends_by_kind["Forward"], 1);
        assert_eq!(sim.hedged_records, 0);
    }

    /// n = 1 degenerates to a purely local log: everything decides inside
    /// submit() and nothing is ever sent.
    #[test]
    fn single_replica_never_sends() {
        let mut sim = Sim::new(1, 3, NetConfig::default(), |config| config);
        for i in 0..10 {
            sim.submit_at(10 * MILLIS * (i + 1), 0, cmd(i));
        }
        sim.run_until(5 * SEC);
        sim.assert_converged();
        assert_eq!(sim.delivered_watermark(0), Slot(10));
        assert_eq!(sim.total_sends(), 0);
    }

    /// Leader crash: commands already submitted at followers still commit,
    /// via forward-target rotation and hedged proposers.
    #[test]
    fn leader_crash_recovers_via_hedging() {
        let mut sim = Sim::new(3, 4, NetConfig::default(), |config| config);
        sim.submit_at(10 * MILLIS, 0, cmd(1));
        sim.crash_at(500 * MILLIS, 0);
        sim.submit_at(600 * MILLIS, 1, cmd(2));
        sim.submit_at(700 * MILLIS, 2, cmd(3));
        sim.run_until(10 * SEC);
        sim.assert_converged();
        assert!(sim.delivered_watermark(1) >= Slot(3));
        assert!(sim.hedged_records > 0, "recovery must have hedged");
    }

    /// Leader crash mid-pipeline with in-flight slots: hedged proposers
    /// finish the orphaned slots (possibly as empty batches) so delivery
    /// stays contiguous, and the followers converge.
    #[test]
    fn leader_crash_mid_pipeline_completes_orphans() {
        let mut sim = Sim::new(3, 5, NetConfig::default(), |config| config);
        // The leader opens slots but every message it sends after 40ms is
        // lost (crash immediately after some Records may have left).
        for i in 0..8 {
            sim.submit_at(10 * MILLIS + i, 0, cmd(i));
        }
        sim.crash_at(41 * MILLIS, 0);
        sim.submit_at(2 * SEC, 1, cmd(100));
        sim.run_until(20 * SEC);
        sim.assert_converged();
        // The follower-submitted command must have committed even though the
        // leader died with unknown slots in flight.
        assert!(sim.delivered_watermark(1).0 >= 1);
        let delivered: Vec<_> = sim.delivered_ids[1].keys().copied().collect();
        assert!(
            delivered.iter().any(|id| id.origin == ReplicaId(2)),
            "follower command delivered"
        );
    }

    /// A replica cut off from the cluster while it decides many slots
    /// catches up through chunked LearnReplies after healing.
    #[test]
    fn deep_catch_up_after_partition() {
        let mut sim = Sim::new(3, 6, NetConfig::default(), |config| config);
        // Replica 2 is isolated in both directions for 30s.
        for peer in 0..2 {
            sim.block_both(2, peer, 30 * SEC);
        }
        // ~300 commands of ~5KB: several LearnReply chunks.
        for i in 0..300u64 {
            let mut data = vec![0u8; 5000];
            data[..8].copy_from_slice(&i.to_le_bytes());
            sim.submit_at(50 * MILLIS + i * 20 * MILLIS, 0, data);
        }
        sim.run_until(30 * SEC);
        assert_eq!(sim.delivered_watermark(2), Slot(0), "still partitioned");
        assert!(sim.delivered_watermark(0).0 > 0);
        sim.run_until(60 * SEC);
        sim.assert_converged();
        assert!(
            sim.sends_by_kind["LearnReply"] >= 2,
            "catch-up used chunked transfer: {:?}",
            sim.sends_by_kind
        );
    }

    /// A stale proposer activating for an already-decided slot adopts the
    /// decision via the recorder short-circuit (and never violates
    /// agreement, which the oracle checks continuously).
    #[test]
    fn late_proposer_adopts_decided_slot() {
        let mut sim = Sim::new(3, 7, NetConfig::default(), |config| config);
        // Replica 2 cannot hear the leader or its Decides, but replica 1 can.
        sim.block_both(0, 2, 5 * SEC);
        sim.submit_at(10 * MILLIS, 0, cmd(1));
        // Give replica 2 a pending command so it hedge-activates the same
        // frontier slot the cluster already decided.
        sim.submit_at(20 * MILLIS, 2, cmd(2));
        sim.run_until(20 * SEC);
        sim.assert_converged();
        assert!(sim.delivered_watermark(2).0 >= 2);
    }

    /// Retention is garbage collected once every replica acknowledges, and
    /// the escape hatch bounds memory when a replica is gone for good.
    #[test]
    fn retention_gc_and_escape_hatch() {
        // Healthy cluster: retention drains to zero once all replicas ack.
        let mut sim = Sim::new(3, 8, NetConfig::default(), |config| config);
        for i in 0..20 {
            sim.submit_at(10 * MILLIS * (i + 1), 0, cmd(i));
        }
        sim.run_until(30 * SEC);
        sim.assert_converged();
        for replica in 0..3 {
            assert_eq!(
                sim.replica(replica).retained_bytes(),
                0,
                "retention drained after global ack"
            );
        }

        // Dead replica: the budget caps retention.
        let budget = 4096;
        let mut sim = Sim::new(3, 9, NetConfig::default(), |config| {
            config.max_retained_bytes(budget)
        });
        sim.crash_at(1, 2);
        for i in 0..200u64 {
            let mut data = vec![0u8; 500];
            data[..8].copy_from_slice(&i.to_le_bytes());
            sim.submit_at(10 * MILLIS * (i + 1), 0, data);
        }
        sim.run_until(60 * SEC);
        assert_eq!(sim.delivered_watermark(0), Slot(200));
        assert!(
            sim.replica(0).retained_bytes() <= budget + 600,
            "escape hatch bounds retention near the budget: {}",
            sim.replica(0).retained_bytes()
        );
    }

    /// The leader() accessor is total and the read-path helpers behave.
    #[test]
    fn leader_is_total_and_decided_tracks() {
        let sim = Sim::new(3, 10, NetConfig::default(), |config| config);
        assert_eq!(sim.replica(0).leader(), ReplicaId(1));
        assert_eq!(sim.replica(2).leader(), ReplicaId(1));
        assert_eq!(sim.replica(0).decided(), Slot(0));
    }

    /// Randomized chaos: delays, drops, duplication, partitions, and up to f
    /// crashes, then heal and assert convergence. Safety invariants are
    /// checked continuously by the oracle. Reproduce any failure with the
    /// seed in its message.
    fn chaos_run(seed: u64) {
        let mut rng = Rng::new(seed);
        let n = [1usize, 3, 3, 5, 5][rng.next_u64() as usize % 5];
        let f = n / 2;
        let chaos_until = 10 * SEC;
        let net = NetConfig {
            min_delay: MILLIS,
            max_delay: (1 + rng.next_u64() % 60) * MILLIS,
            drop_pct: rng.next_u64() % 25,
            dup_pct: rng.next_u64() % 10,
            unreliable_until: chaos_until,
        };
        let hedge = (10 + rng.next_u64() % 400) * MILLIS;
        let mut sim = Sim::new(n, seed, net, |config| {
            config.hedge_delay(std::time::Duration::from_nanos(hedge))
        });
        // Random directed partitions during the chaos window.
        if n > 1 {
            for _ in 0..rng.next_u64() % 6 {
                let from = (rng.next_u64() as usize) % n;
                let to = (rng.next_u64() as usize) % n;
                if from != to {
                    let until = (rng.next_u64() % 10) * SEC;
                    sim.block(from, to, until.min(chaos_until));
                }
            }
            // Up to f crash-stops.
            for _ in 0..rng.next_u64() % (f as u64 + 1) {
                let victim = 1 + (rng.next_u64() as usize) % (n - 1);
                sim.crash_at((rng.next_u64() % 8) * SEC, victim);
            }
        }
        let commands = 20 + rng.next_u64() % 40;
        for i in 0..commands {
            let replica = (rng.next_u64() as usize) % n;
            let at = 100 * MILLIS + rng.next_u64() % (8 * SEC);
            let mut data = vec![0u8; 16 + (rng.next_u64() as usize % 200)];
            data[..8].copy_from_slice(&i.to_le_bytes());
            data[8..16].copy_from_slice(&seed.to_le_bytes());
            sim.submit_at(at, replica, data);
        }
        // Chaos, then a calm period long enough for retransmits, hedging,
        // pings, and catch-up to converge everything.
        sim.run_until(60 * SEC);
        sim.assert_converged();
    }

    #[test]
    fn chaos_seeds() {
        for seed in 0..150 {
            chaos_run(seed);
        }
    }

    /// Long-run variant for local soak testing: `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn chaos_seeds_soak() {
        for seed in 150..3000 {
            chaos_run(seed);
        }
    }

    /// Regression (review): a scheduler that sleeps exactly until each
    /// `next_wakeup()` must keep making progress -- every advertised
    /// deadline has to retire or advance when serviced. Exercises frontier
    /// materialization, forwarding rotation to a dead leader, hedging, and
    /// heartbeats under exact-deadline driving; a stale deadline loops at
    /// one virtual instant and trips the sim's event cap.
    #[test]
    fn wakeup_driven_scheduler_makes_progress() {
        let mut sim = Sim::new_wakeup_driven(3, 20, NetConfig::default(), |config| config);
        sim.crash_at(1, 0);
        sim.submit_at(100 * MILLIS, 1, cmd(1));
        sim.submit_at(200 * MILLIS, 2, cmd(2));
        sim.run_until(60 * SEC);
        sim.assert_converged();
        assert_eq!(sim.delivered_watermark(1), sim.delivered_watermark(2));
        assert!(sim.delivered_ids[1].len() >= 2, "both commands committed");
    }

    /// Regression (review): byte-identical Record retransmissions from a
    /// proposer that cannot hear replies must not keep resetting hedge
    /// deadlines. With hedge_delay > retransmit_delay, the followers would
    /// otherwise never activate and the reachable quorum would stall.
    #[test]
    fn deaf_proposer_does_not_suppress_hedging() {
        let mut sim = Sim::new(3, 21, NetConfig::default(), |config| {
            config
                .hedge_delay(std::time::Duration::from_millis(600))
                .retransmit_delay(std::time::Duration::from_millis(200))
        });
        // The leader can send but never receives anything back.
        sim.block(1, 0, 60 * SEC);
        sim.block(2, 0, 60 * SEC);
        sim.submit_at(10 * MILLIS, 0, cmd(1));
        sim.run_until(30 * SEC);
        assert!(
            sim.delivered_watermark(1).0 >= 1 && sim.delivered_watermark(2).0 >= 1,
            "hedged proposers must finish the slot despite retransmissions: {:?} {:?}",
            sim.delivered_watermark(1),
            sim.delivered_watermark(2)
        );
        // After healing, the deaf leader catches up too.
        sim.run_until(90 * SEC);
        sim.assert_converged();
    }

    /// Regression (review): the pool byte limit must also bound the entry
    /// count -- zero-length commands (read barriers) would otherwise pool
    /// without bound while consensus is unavailable.
    #[test]
    fn pool_limit_bounds_zero_length_commands() {
        let ids: Vec<ReplicaId> = (1..=3).map(ReplicaId).collect();
        let config = Config::new(ids, ReplicaId(1), 7)
            .unwrap()
            .max_pool_bytes(2800);
        let mut replica = Replica::new(config);
        // No network is connected, so nothing ever delivers.
        let mut accepted = 0u32;
        loop {
            match replica.submit(accepted as u64, &[]) {
                Ok(_) => accepted += 1,
                Err(crate::SubmitError::PoolFull) => break,
                Err(other) => panic!("unexpected: {other}"),
            }
            assert!(accepted <= 200, "entry count must be bounded");
            while replica.poll_action().is_some() {}
        }
        assert!(accepted >= 50, "sane commands are accepted: {accepted}");
    }

    /// Regression (review): decided-ahead values buffered while the frontier
    /// is stuck must respect the retention budget; dropped ones are
    /// re-fetched via Learn once the frontier advances.
    #[test]
    fn decided_ahead_buffering_is_bounded() {
        use crate::types::encode_batch;
        use crate::wire::{Message, Payload};
        let ids: Vec<ReplicaId> = (1..=3).map(ReplicaId).collect();
        let budget = 4096;
        let config = Config::new(ids, ReplicaId(3), 7)
            .unwrap()
            .max_retained_bytes(budget);
        let mut replica = Replica::new(config);
        let value = |seq: u64| {
            encode_batch(&[(
                CommandId {
                    origin: ReplicaId(1),
                    boot: 1,
                    seq,
                },
                vec![0u8; 100].as_slice().into(),
            )])
        };
        // Slot 1's decision never arrives; hundreds of later ones do.
        for slot in 2..=500u64 {
            replica.receive(
                slot,
                Message {
                    from: ReplicaId(1),
                    decided: Slot(500),
                    payload: Payload::Decide {
                        slot: Slot(slot),
                        value: value(slot),
                    },
                },
            );
            while replica.poll_action().is_some() {}
            assert!(
                replica.retained_bytes() <= budget,
                "retained {} exceeded budget at slot {}",
                replica.retained_bytes(),
                slot
            );
        }
        assert_eq!(replica.decided(), Slot(0));
        // The frontier decision arrives: the buffered prefix delivers, and
        // the replica knows it is still behind (Learn will fetch the rest).
        replica.receive(
            1000,
            Message {
                from: ReplicaId(1),
                decided: Slot(500),
                payload: Payload::Decide {
                    slot: Slot(1),
                    value: value(1),
                },
            },
        );
        while replica.poll_action().is_some() {}
        assert!(replica.decided().0 >= 1);
        assert!(
            replica.next_wakeup().is_some(),
            "catch-up work must be scheduled for the dropped suffix"
        );
    }

    /// Regression (review): leader pipelining is bounded by distance from
    /// the frontier. With the frontier slot stuck but later slots deciding,
    /// the leader must stop opening new slots (each decided-ahead value is
    /// exempt from the retention budget, so unbounded opening would mean
    /// unbounded memory).
    #[test]
    fn leader_pipelining_bounded_by_frontier() {
        use crate::wire::{Message, Payload, ReplyFirst};
        let ids: Vec<ReplicaId> = (1..=3).map(ReplicaId).collect();
        let mut leader = Replica::new(
            Config::new(ids, ReplicaId(1), 5)
                .unwrap()
                .max_batch_bytes(1), // one command per slot
        );
        for i in 0..50u64 {
            leader.submit(i, b"cmd").unwrap();
        }
        // Ack every Record except the frontier slot's, via echo replies
        // (the leader's round-1 proposals carry priority H, so one echoed
        // reply completes a fast-path quorum with its own recorder). Later
        // slots decide while slot 1 stays undecided.
        let mut acked = std::collections::BTreeSet::new();
        let mut max_record_slot = 0;
        loop {
            let mut replies = Vec::new();
            while let Some(action) = leader.poll_action() {
                let Action::Send { to, message } = action else {
                    continue;
                };
                let Payload::Record { slot, step, .. } = message.payload else {
                    continue;
                };
                max_record_slot = max_record_slot.max(slot.0);
                if slot.0 > 1 && acked.insert((slot, to)) {
                    replies.push((
                        to,
                        Message {
                            from: to,
                            decided: Slot(0),
                            payload: Payload::RecordReply {
                                slot,
                                req_step: step,
                                step,
                                first: ReplyFirst::Echo,
                                prior_agg: None,
                            },
                        },
                    ));
                }
            }
            if replies.is_empty() {
                break;
            }
            for (_, message) in replies {
                leader.receive(100, message);
            }
        }
        assert_eq!(leader.decided(), Slot(0), "frontier must still be stuck");
        assert!(
            max_record_slot <= 4,
            "leader opened past frontier + pipeline: slot {max_record_slot}"
        );
    }

    /// Regression (review): a single tick re-forwards every due pool entry,
    /// split into batch-bounded chunks, so each serviced deadline advances
    /// (skipping entries would leave next_wakeup returning an expired
    /// deadline, spinning exact-deadline drivers and backlogging others).
    #[test]
    fn reforward_services_all_due_entries_in_one_tick() {
        use crate::wire::Payload;
        let ids: Vec<ReplicaId> = (1..=3).map(ReplicaId).collect();
        let mut follower = Replica::new(
            Config::new(ids, ReplicaId(3), 9)
                .unwrap()
                .max_batch_bytes(64),
        );
        for _ in 0..5 {
            follower.submit(0, &[7u8; 10]).unwrap();
        }
        while follower.poll_action().is_some() {} // initial forwards
        // One tick past the forwarding interval: every due entry must
        // re-forward now, one per bounded chunk (the frontier only
        // materializes in this tick, so hedging has not activated yet).
        follower.tick(600 * MILLIS);
        let mut forwards = 0;
        let mut forwarded_commands = 0;
        while let Some(action) = follower.poll_action() {
            if let Action::Send { message, .. } = &action
                && let Payload::Forward { commands } = &message.payload
            {
                forwards += 1;
                forwarded_commands += commands.len();
            }
        }
        assert_eq!(forwarded_commands, 5);
        assert_eq!(forwards, 5, "chunked in one tick, not deferred");
    }

    /// Regression (review): Duration::MAX as the hedge delay (effectively
    /// disabling hedging) must not overflow deadline arithmetic.
    #[test]
    fn huge_hedge_delay_does_not_overflow() {
        let ids: Vec<ReplicaId> = (1..=3).map(ReplicaId).collect();
        let mut follower = Replica::new(
            Config::new(ids, ReplicaId(3), 11)
                .unwrap()
                .hedge_delay(std::time::Duration::MAX),
        );
        follower.submit(0, b"cmd").unwrap();
        follower.tick(1_000 * MILLIS);
        assert!(follower.next_wakeup().is_some());
        while follower.poll_action().is_some() {}
    }

    /// Regression (review): retransmit_delay is ceiling-clamped like
    /// hedge_delay and every next_wakeup deadline sum saturates, so
    /// `Duration::MAX` ("effectively never") cannot overflow the proposer
    /// retransmit or Learn-retry deadlines once sent_at is nonzero.
    #[test]
    fn huge_retransmit_delay_does_not_overflow() {
        let ids: Vec<ReplicaId> = (1..=3).map(ReplicaId).collect();
        let mut leader = Replica::new(
            Config::new(ids, ReplicaId(1), 13)
                .unwrap()
                .retransmit_delay(std::time::Duration::MAX),
        );
        // A Running proposer with nonzero sent_at exercises the retransmit
        // deadline sum.
        leader.submit(1_000 * MILLIS, b"cmd").unwrap();
        leader.tick(2_000 * MILLIS);
        // A peer advertising a higher watermark puts a Learn in flight,
        // exercising the Learn-retry deadline sum.
        leader.receive(
            3_000 * MILLIS,
            Message {
                from: ReplicaId(2),
                decided: Slot(5),
                payload: Payload::Ping,
            },
        );
        assert!(leader.next_wakeup().is_some());
        while leader.poll_action().is_some() {}
    }

    /// Regression (review): the sparse delivery-dedup set is bounded by a
    /// per-origin sequencing window: commands more than DEDUP_WINDOW
    /// sequences past their origin's delivered high-water mark are not
    /// batched (they wait, lowest-first, for the mark to advance).
    #[test]
    fn batching_respects_the_sequencing_window() {
        use crate::types::decode_batch;
        use crate::wire::Payload;
        let ids: Vec<ReplicaId> = (1..=3).map(ReplicaId).collect();
        let mut leader = Replica::new(Config::new(ids, ReplicaId(1), 12).unwrap());
        let commands: Vec<(CommandId, std::sync::Arc<[u8]>)> = (1..=1100u64)
            .map(|seq| {
                (
                    CommandId {
                        origin: ReplicaId(2),
                        boot: 3,
                        seq,
                    },
                    b"x".as_slice().into(),
                )
            })
            .collect();
        leader.receive(
            0,
            Message {
                from: ReplicaId(2),
                decided: Slot(0),
                payload: Payload::Forward { commands },
            },
        );
        let mut max_batched_seq = 0;
        while let Some(action) = leader.poll_action() {
            let Action::Send { message, .. } = &action else {
                continue;
            };
            let Payload::Record { proposal, .. } = &message.payload else {
                continue;
            };
            for (id, _) in decode_batch(&proposal.value).unwrap() {
                max_batched_seq = max_batched_seq.max(id.seq);
            }
        }
        assert!(max_batched_seq > 0, "the leader proposed something");
        assert!(
            max_batched_seq <= 1024,
            "batched past the sequencing window: {max_batched_seq}"
        );
    }

    /// Regression (review): commands beyond the wire format's length fields
    /// are rejected at submission instead of wrapping during encoding.
    #[test]
    fn oversized_command_rejected() {
        let ids = vec![ReplicaId(1)];
        let mut replica = Replica::new(Config::new(ids, ReplicaId(1), 1).unwrap());
        let big = vec![0u8; (1 << 30) + 1];
        assert_eq!(
            replica.submit(0, &big),
            Err(crate::SubmitError::CommandTooLarge)
        );
        assert!(replica.submit(0, b"small").is_ok());
    }

    /// Regression (review): a replica that falls behind while the leader
    /// dies must still catch up from a surviving follower -- watermarks flow
    /// on every link via symmetric heartbeats, not only from the leader.
    #[test]
    fn laggard_catches_up_from_surviving_follower() {
        let mut sim = Sim::new(3, 22, NetConfig::default(), |config| config);
        for peer in 0..2 {
            sim.block_both(2, peer, 20 * SEC);
        }
        for i in 0..5 {
            sim.submit_at(100 * MILLIS * (i + 1), 0, cmd(i));
        }
        sim.crash_at(10 * SEC, 0);
        sim.run_until(60 * SEC);
        assert_eq!(
            sim.delivered_ids[2].len(),
            5,
            "isolated replica learned every decided command from the follower"
        );
        assert_eq!(sim.delivered_watermark(2), sim.delivered_watermark(1));
    }

    /// The exactly-once mechanism, exercised directly: a command decided in
    /// two different slots (a re-proposal race) is delivered only from the
    /// earlier one; the later slot delivers the remainder of its batch.
    #[test]
    fn command_in_two_decided_slots_delivers_once() {
        use crate::types::encode_batch;
        let ids: Vec<ReplicaId> = vec![ReplicaId(1), ReplicaId(2), ReplicaId(3)];
        let mut replica = Replica::new(Config::new(ids, ReplicaId(3), 7).unwrap());
        let x = (
            CommandId {
                origin: ReplicaId(2),
                boot: 9,
                seq: 1,
            },
            std::sync::Arc::from(b"x".as_slice()),
        );
        let y = (
            CommandId {
                origin: ReplicaId(1),
                boot: 4,
                seq: 1,
            },
            std::sync::Arc::from(b"y".as_slice()),
        );
        let decide = |slot, batch: &[(CommandId, std::sync::Arc<[u8]>)]| Message {
            from: ReplicaId(1),
            decided: Slot(0),
            payload: Payload::Decide {
                slot,
                value: encode_batch(batch),
            },
        };
        replica.receive(0, decide(Slot(1), std::slice::from_ref(&x)));
        replica.receive(0, decide(Slot(2), &[x.clone(), y.clone()]));
        let mut delivered = Vec::new();
        while let Some(action) = replica.poll_action() {
            if let Action::Deliver { slot, commands } = action {
                delivered.push((slot, commands));
            }
        }
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0].0, Slot(1));
        assert_eq!(delivered[0].1, vec![(x.0, b"x".to_vec())]);
        assert_eq!(delivered[1].0, Slot(2));
        assert_eq!(
            delivered[1].1,
            vec![(y.0, b"y".to_vec())],
            "x must not be delivered a second time"
        );
    }

    /// Identical seeds produce bit-identical histories (the determinism the
    /// crate promises).
    #[test]
    fn deterministic_given_seed() {
        let run = |seed| {
            let mut sim = Sim::new(
                3,
                seed,
                NetConfig {
                    drop_pct: 10,
                    dup_pct: 5,
                    unreliable_until: 5 * SEC,
                    ..NetConfig::default()
                },
                |config| config,
            );
            for i in 0..10 {
                sim.submit_at(10 * MILLIS * (i + 1), (i % 3) as usize, cmd(i));
            }
            sim.run_until(30 * SEC);
            (sim.canonical.clone(), sim.total_sends())
        };
        assert_eq!(run(42), run(42));
    }
}
