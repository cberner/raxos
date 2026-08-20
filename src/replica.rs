use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::Arc;

use crate::config::Config;
use crate::pool::{Dedup, Pool};
use crate::proposer::{Folded, ProposerState, Run, StepOutcome};
use crate::recorder::{RecorderSlot, reply_first};
use crate::rng::Rng;
use crate::types::{
    COMMAND_WIRE_OVERHEAD, CommandBatch, CommandId, Proposal, ReplicaId, Slot, decode_batch,
    encode_batch,
};
use crate::wire::{Message, Payload, ReplyFirst};

/// Heartbeat interval (every replica, to every peer): bounds how long a
/// quiesced or lagging replica can remain unaware of the latest decisions,
/// and keeps the acknowledgment watermarks that drive retention GC flowing
/// on all links regardless of which replicas are alive.
const PING_INTERVAL: u64 = 1_000_000_000;

/// Size target for one `LearnReply` chunk.
const LEARN_CHUNK_BYTES: usize = 1 << 20;

/// Maximum sequence distance past an origin's delivered high-water mark that
/// its commands are batched at, bounding the sparse dedup set (see
/// `take_unassigned_batch`).
const DEDUP_WINDOW: u64 = 1024;

/// An effect for the application to perform, drained via
/// [`Replica::poll_action`] after every input call.
pub enum Action {
    /// Transport `message.encode()` to replica `to` (best effort; the
    /// protocol tolerates loss, reordering, and duplication).
    Send {
        /// Destination replica.
        to: ReplicaId,
        /// The message to encode and transmit.
        message: Message,
    },
    /// Apply the commands of a decided slot to the application state
    /// machine.
    ///
    /// Emitted strictly in slot order with no gaps, on every replica, with
    /// identical contents. Commands are deduplicated (exactly-once across
    /// the whole log). `commands` may be empty; such slots still advance the
    /// application's watermark.
    Deliver {
        /// The decided slot.
        slot: Slot,
        /// The slot's commands, in batch order.
        commands: Vec<(CommandId, Vec<u8>)>,
    },
}

impl fmt::Debug for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Send { to, message } => write!(f, "Send({to:?}, {message:?})"),
            Action::Deliver { slot, commands } => {
                write!(f, "Deliver({slot:?}, {} commands)", commands.len())
            }
        }
    }
}

/// Error returned by [`Replica::submit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubmitError {
    /// The local pool of undelivered commands is at `max_pool_bytes`.
    /// Deliver (or drop) in-flight work before submitting more.
    PoolFull,
    /// The command exceeds the wire format's 1 GiB per-command limit.
    CommandTooLarge,
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubmitError::PoolFull => write!(f, "command pool is full"),
            SubmitError::CommandTooLarge => write!(f, "command exceeds the 1 GiB limit"),
        }
    }
}

impl std::error::Error for SubmitError {}

/// Per-slot state: this replica's recorder role and proposer role for the
/// slot, plus the timestamps that drive hedging.
struct SlotState {
    recorder: RecorderSlot,
    proposer: ProposerState,
    /// When this replica first learned the slot exists.
    first_observed: u64,
    /// Last time this replica's recorder saw traffic for the slot. Progress
    /// extends hedging deadlines: as one of the recorders, local traffic
    /// approximates "some proposer is driving this slot".
    last_progress: u64,
}

impl SlotState {
    fn new(now: u64) -> SlotState {
        SlotState {
            recorder: RecorderSlot::new(),
            proposer: ProposerState::Idle,
            first_observed: now,
            last_progress: now,
        }
    }
}

/// One member of a QuePaxa consensus group.
///
/// This is a deterministic, I/O-free state machine: the application feeds in
/// submitted commands, received messages, and time, and carries out the
/// [`Action`]s the replica emits. See the crate docs for the driving
/// contract.
pub struct Replica {
    config: Config,
    quorum: u32,
    me_idx: usize,
    boot: u64,
    rng: Rng,
    /// Slot states, retained from `gc_floor + 1` upward.
    slots: BTreeMap<Slot, SlotState>,
    /// Contiguous decided (and delivered) watermark.
    decided_contig: Slot,
    /// Decided values retained for lagging replicas, `gc_floor + 1` upward.
    /// Contiguous through `decided_contig`; may contain decided-ahead slots
    /// beyond it.
    retained: BTreeMap<Slot, Arc<[u8]>>,
    retained_bytes: usize,
    /// Everything at or below this slot has been freed; a replica that has
    /// not delivered past it can no longer be caught up by this one.
    gc_floor: Slot,
    /// Highest decided watermark seen from each replica (self included),
    /// from message headers. Drives retention GC.
    peer_acked: Vec<Slot>,
    pool: Pool,
    dedup: Dedup,
    next_seq: u64,
    /// Highest slot this replica has opened as leader.
    max_open: Slot,
    /// Since when the pool has held unassigned commands (hedging trigger for
    /// a fresh frontier slot).
    pool_pending_since: Option<u64>,
    /// Outstanding Learn request: (target schedule index, sent time).
    learn_in_flight: Option<(usize, u64)>,
    /// Counts Learn timeouts, rotating retries across candidate peers so a
    /// dead peer with a high advertised watermark cannot pin catch-up.
    learn_attempts: u64,
    last_ping: u64,
    actions: VecDeque<Action>,
}

impl Replica {
    /// Creates the local member of a consensus group.
    pub fn new(config: Config) -> Replica {
        let n = config.replicas.len();
        let me_idx = config
            .replicas
            .binary_search(&config.me)
            .expect("validated by Config::new");
        let boot = config.rng_seed;
        let rng = Rng::new(config.rng_seed);
        Replica {
            quorum: (n / 2 + 1) as u32,
            me_idx,
            boot,
            rng,
            slots: BTreeMap::new(),
            decided_contig: Slot(0),
            retained: BTreeMap::new(),
            retained_bytes: 0,
            gc_floor: Slot(0),
            peer_acked: vec![Slot(0); n],
            pool: Pool::default(),
            dedup: Dedup::default(),
            next_seq: 0,
            max_open: Slot(0),
            pool_pending_since: None,
            learn_in_flight: None,
            learn_attempts: 0,
            last_ping: 0,
            actions: VecDeque::new(),
            config,
        }
    }

    /// The current leader: first replica of the hedging schedule. Unlike
    /// leader-based protocols there is no "no leader" state, and the leader
    /// is a performance role only -- commands submitted anywhere keep
    /// committing (via hedged proposers) while it is slow or down.
    pub fn leader(&self) -> ReplicaId {
        self.config.replicas[0]
    }

    /// The contiguous decided watermark: every slot up to and including this
    /// one has been decided and emitted as a [`Action::Deliver`].
    pub fn decided(&self) -> Slot {
        self.decided_contig
    }

    /// Bytes of decided values currently retained for lagging replicas.
    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Drains the next pending effect. Call after every input until `None`.
    pub fn poll_action(&mut self) -> Option<Action> {
        self.actions.pop_front()
    }

    /// Submits a command for replication. It will be delivered exactly once,
    /// in the same slot, on every replica of the group (as long as this
    /// process stays up to keep re-proposing it). The returned id correlates
    /// the eventual [`Action::Deliver`] entry with this submission.
    ///
    /// `now` is monotonic nanoseconds from any fixed origin; all inputs must
    /// use the same clock.
    pub fn submit(&mut self, now: u64, command: &[u8]) -> Result<CommandId, SubmitError> {
        if command.len() > crate::types::MAX_COMMAND_BYTES {
            return Err(SubmitError::CommandTooLarge);
        }
        if self.pool.bytes + Pool::cost(command.len()) > self.config.max_pool_bytes {
            return Err(SubmitError::PoolFull);
        }
        self.next_seq += 1;
        let id = CommandId {
            origin: self.config.me,
            boot: self.boot,
            seq: self.next_seq,
        };
        let data: Arc<[u8]> = command.into();
        self.pool.insert(id, data.clone(), now);
        if self.is_leader() {
            self.maybe_open_slots(now);
        } else {
            // Forward to the leader (re-forwarded with target rotation from
            // tick() until decided, so a dead leader cannot strand it).
            if let Some(target) = self.forward_target(0) {
                let entry = self.pool.entries.get_mut(&id).expect("just inserted");
                entry.last_forward = now;
                entry.forward_attempts = 1;
                self.send_to(
                    target,
                    Payload::Forward {
                        commands: vec![(id, data)],
                    },
                );
            }
        }
        self.refresh_pool_pending(now);
        Ok(id)
    }

    /// Feeds a message received from the transport into the replica.
    /// Messages from unknown replicas are ignored.
    pub fn receive(&mut self, now: u64, message: Message) {
        let Ok(from_idx) = self.config.replicas.binary_search(&message.from) else {
            return;
        };
        if from_idx == self.me_idx {
            return;
        }
        if self.peer_acked[from_idx] < message.decided {
            self.peer_acked[from_idx] = message.decided;
        }
        let their_decided = message.decided;
        match message.payload {
            Payload::Record {
                slot,
                step,
                proposal,
            } => self.on_record(now, from_idx, slot, step, proposal),
            Payload::RecordReply {
                slot,
                req_step,
                step,
                first,
                prior_agg,
            } => self.on_record_reply(now, from_idx, slot, req_step, step, first, prior_agg),
            Payload::Decide { slot, value } => self.decide_slot(now, slot, value, false),
            Payload::Forward { commands } => self.on_forward(now, commands),
            Payload::Learn { from_slot } => self.on_learn(from_idx, from_slot),
            Payload::LearnReply { first_slot, values } => {
                self.on_learn_reply(now, first_slot, values)
            }
            Payload::Ping => {
                // Header processing above already recorded the watermark;
                // pings carry no payload. Every replica sends its own
                // periodic pings (ping_tick), so no echo is needed.
            }
        }
        self.maybe_request_learn(now, from_idx, their_decided);
        self.maybe_gc();
    }

    /// Advances time-driven work: hedging activation, retransmission,
    /// command re-forwarding, catch-up retries, and heartbeats. Call at a
    /// regular interval (e.g. 100ms), or per [`Replica::next_wakeup`].
    pub fn tick(&mut self, now: u64) {
        self.ensure_frontier_observed(now);
        self.hedge_activate_due(now);
        self.maybe_open_slots(now);
        self.retransmit_due(now);
        self.reforward_due(now);
        self.learn_tick(now);
        self.ping_tick(now);
    }

    /// The earliest time at which [`Replica::tick`] has scheduled work to
    /// do, or `None` when fully idle. Callers on a fixed tick interval can
    /// ignore this. Every returned deadline is retired or advanced by the
    /// tick that services it, so a caller sleeping exactly until each wakeup
    /// makes progress.
    pub fn next_wakeup(&self) -> Option<u64> {
        let mut earliest: Option<u64> = None;
        // Every deadline sum below saturates: the config setters clamp the
        // delays, but saturation keeps maximal delays meaning "effectively
        // never" rather than wrapping into an always-due past instant.
        let mut fold = |deadline: u64| {
            earliest = Some(match earliest {
                None => deadline,
                Some(current) => current.min(deadline),
            });
        };
        let k = self.me_idx as u64;
        for state in self
            .slots
            .range(self.decided_contig.next()..)
            .map(|(_, state)| state)
        {
            match &state.proposer {
                ProposerState::Running(run) => {
                    fold(run.sent_at.saturating_add(self.config.retransmit_delay));
                }
                ProposerState::Idle => {
                    if !matches!(state.recorder, RecorderSlot::Decided(_)) {
                        let base = state.first_observed.max(state.last_progress);
                        fold(base.saturating_add(k.saturating_mul(self.config.hedge_delay)));
                    }
                }
                ProposerState::Done => {}
            }
        }
        // A frontier slot that tick() would materialize is due immediately;
        // once it exists, its own hedge deadline (above) takes over.
        let frontier = self.decided_contig.next();
        if !self.slots.contains_key(&frontier) {
            let beyond = self.slots.range(frontier..).next().is_some();
            if let Some(since) = self.pool_pending_since {
                fold(since);
            } else if beyond {
                fold(0);
            }
        }
        // Re-forwarding deadlines advance with each transmission.
        let interval = self.forward_interval();
        for (id, entry) in self.pool.entries.iter() {
            if id.origin == self.config.me
                && id.boot == self.boot
                && entry.proposed_in.is_none()
                && !self.is_leader()
            {
                fold(entry.last_forward.saturating_add(interval));
            }
        }
        if let Some((_, sent_at)) = self.learn_in_flight {
            fold(sent_at.saturating_add(self.config.retransmit_delay));
        } else if (0..self.n())
            .any(|idx| idx != self.me_idx && self.peer_acked[idx] > self.decided_contig)
        {
            // A known-behind replica retries Learn on the next tick.
            fold(0);
        }
        if self.n() > 1 {
            fold(self.last_ping.saturating_add(PING_INTERVAL));
        }
        earliest
    }

    fn is_leader(&self) -> bool {
        self.me_idx == 0
    }

    fn n(&self) -> usize {
        self.config.replicas.len()
    }

    fn send_to(&mut self, idx: usize, payload: Payload) {
        debug_assert_ne!(idx, self.me_idx);
        let message = Message {
            from: self.config.me,
            decided: self.decided_contig,
            payload,
        };
        self.actions.push_back(Action::Send {
            to: self.config.replicas[idx],
            message,
        });
    }

    /// The forwarding target for a command's `attempts`-th transmission:
    /// the leader first, then rotating through the other replicas.
    fn forward_target(&self, attempts: u64) -> Option<usize> {
        let candidates: Vec<usize> = (0..self.n()).filter(|idx| *idx != self.me_idx).collect();
        if candidates.is_empty() {
            return None;
        }
        Some(candidates[(attempts % candidates.len() as u64) as usize])
    }

    /// How far past the delivered frontier this replica participates as a
    /// recorder or buffers state for.
    fn ahead_window(&self) -> u64 {
        4 * self.config.pipeline as u64 + 64
    }

    fn forward_interval(&self) -> u64 {
        self.config
            .hedge_delay
            .saturating_mul(2)
            .max(self.config.retransmit_delay)
    }

    fn refresh_pool_pending(&mut self, now: u64) {
        if self.pool.has_unassigned() {
            if self.pool_pending_since.is_none() {
                self.pool_pending_since = Some(now);
            }
        } else {
            self.pool_pending_since = None;
        }
    }

    // ---- recorder role ----

    fn on_record(&mut self, now: u64, from_idx: usize, slot: Slot, step: u32, proposal: Proposal) {
        if slot <= self.gc_floor || step < 4 {
            // Freed slots are only ever probed by stragglers that have
            // themselves delivered past them (retention invariant), so there
            // is nothing useful to reply.
            return;
        }
        // A replica far behind the slot does not materialize recorder state
        // for it: open ISRs hold proposal values that no budget covers, and
        // honest proposers only drive slots near their own frontier, so a
        // Record this far ahead means we are lagging -- catch up via Learn
        // first (ignoring a Record is ordinary message loss). The window
        // comfortably covers the leader's pipeline plus hedged stragglers.
        if slot.0 > self.decided_contig.0 + self.ahead_window() {
            return;
        }
        let reply = {
            let state = self
                .slots
                .entry(slot)
                .or_insert_with(|| SlotState::new(now));
            match &mut state.recorder {
                RecorderSlot::Decided(value) => Payload::Decide {
                    slot,
                    value: value.clone(),
                },
                RecorderSlot::Open(isr) => {
                    let request = proposal.clone();
                    let (summary, changed) = isr.record(step, proposal);
                    // Only genuine register changes extend hedging deadlines:
                    // a proposer stuck retransmitting the same step must not
                    // suppress the hedged proposers that would rescue the
                    // slot (its retransmissions are byte-identical).
                    if changed {
                        state.last_progress = now;
                    }
                    // Elide the echo only for same-step replies: that is the
                    // only case the proposer can reconstruct from its own
                    // cached send (and the only case it commonly happens:
                    // the fast path).
                    let first = if summary.step == step {
                        reply_first(&summary.first, &request)
                    } else {
                        ReplyFirst::Full(summary.first)
                    };
                    Payload::RecordReply {
                        slot,
                        req_step: step,
                        step: summary.step,
                        first,
                        prior_agg: summary.prior_agg,
                    }
                }
            }
        };
        self.send_to(from_idx, reply);
    }

    // ---- proposer role ----

    #[allow(clippy::too_many_arguments)]
    fn on_record_reply(
        &mut self,
        now: u64,
        from_idx: usize,
        slot: Slot,
        req_step: u32,
        reply_step: u32,
        first: ReplyFirst,
        prior_agg: Option<Proposal>,
    ) {
        let me = self.config.me;
        let me_idx = self.me_idx;
        let n = self.config.replicas.len();
        let leader_first_round = me_idx == 0;
        let quorum = self.quorum;
        let mut decided: Option<Arc<[u8]>> = None;
        let mut need_drive = false;
        {
            let Some(state) = self.slots.get_mut(&slot) else {
                return;
            };
            let ProposerState::Running(run) = &mut state.proposer else {
                return;
            };
            let first = match first {
                ReplyFirst::Full(proposal) => proposal,
                ReplyFirst::Echo => {
                    if req_step != run.step {
                        // Stale echo: the send it refers to is no longer
                        // cached. Retransmission covers the loss.
                        return;
                    }
                    run.proposal_for(from_idx)
                }
            };
            match run.fold(from_idx, req_step, reply_step, first, prior_agg, quorum) {
                Folded::Ignored => {}
                Folded::CatchUp { step, adopt } => {
                    run.step = step;
                    run.proposal = adopt;
                    run.begin_step(me, me_idx, n, leader_first_round, now, &mut self.rng);
                    need_drive = true;
                }
                Folded::Quorum => match run.step_complete() {
                    StepOutcome::Decided(value) => decided = Some(value),
                    StepOutcome::Advance => {
                        run.begin_step(me, me_idx, n, leader_first_round, now, &mut self.rng);
                        need_drive = true;
                    }
                    StepOutcome::Retry => {}
                },
            }
        }
        if let Some(value) = decided {
            self.decide_slot(now, slot, value, true);
        } else if need_drive {
            self.drive(now, slot);
        }
    }

    /// Starts this replica's proposer for a slot, always at round 1 phase 0
    /// with a fresh value (the only way new values enter a slot).
    fn activate(&mut self, now: u64, slot: Slot, value: Arc<[u8]>) {
        let me = self.config.me;
        let me_idx = self.me_idx;
        let n = self.config.replicas.len();
        let fast_path_leader = me_idx == 0;
        {
            let state = self
                .slots
                .entry(slot)
                .or_insert_with(|| SlotState::new(now));
            if !matches!(state.proposer, ProposerState::Idle)
                || matches!(state.recorder, RecorderSlot::Decided(_))
            {
                return;
            }
            state.proposer = ProposerState::Running(Box::new(Run::start(
                value,
                me,
                me_idx,
                n,
                fast_path_leader,
                now,
                &mut self.rng,
            )));
        }
        self.drive(now, slot);
    }

    /// Transmits the proposer's current step: records locally (which may
    /// catch the proposer up or complete a quorum immediately, looping to
    /// the next step), then broadcasts to the other recorders.
    fn drive(&mut self, now: u64, slot: Slot) {
        let me = self.config.me;
        let me_idx = self.me_idx;
        let n = self.config.replicas.len();
        let leader_first_round = me_idx == 0;
        let quorum = self.quorum;
        let mut decided: Option<Arc<[u8]>> = None;
        loop {
            let Some(state) = self.slots.get_mut(&slot) else {
                return;
            };
            let ProposerState::Running(run) = &mut state.proposer else {
                return;
            };
            if !run.needs_send {
                break;
            }
            run.needs_send = false;
            run.sent_at = now;
            let step = run.step;

            let my_proposal = run.proposal_for(me_idx);
            let summary = match &mut state.recorder {
                RecorderSlot::Open(isr) => isr.record(step, my_proposal).0,
                RecorderSlot::Decided(_) => {
                    // The slot decided while this proposer was mid-flight.
                    state.proposer = ProposerState::Done;
                    return;
                }
            };
            match run.fold(
                me_idx,
                step,
                summary.step,
                summary.first,
                summary.prior_agg,
                quorum,
            ) {
                Folded::CatchUp { step, adopt } => {
                    run.step = step;
                    run.proposal = adopt;
                    run.begin_step(me, me_idx, n, leader_first_round, now, &mut self.rng);
                    continue;
                }
                Folded::Quorum => match run.step_complete() {
                    StepOutcome::Decided(value) => {
                        decided = Some(value);
                        break;
                    }
                    StepOutcome::Advance => {
                        run.begin_step(me, me_idx, n, leader_first_round, now, &mut self.rng);
                        continue;
                    }
                    StepOutcome::Retry => {}
                },
                Folded::Ignored => {}
            }

            for idx in 0..n {
                if idx == me_idx {
                    continue;
                }
                let message = Message {
                    from: me,
                    decided: self.decided_contig,
                    payload: Payload::Record {
                        slot,
                        step,
                        proposal: run.proposal_for(idx),
                    },
                };
                self.actions.push_back(Action::Send {
                    to: self.config.replicas[idx],
                    message,
                });
            }
            break;
        }
        if let Some(value) = decided {
            self.decide_slot(now, slot, value, true);
        }
    }

    // ---- decisions, delivery, retention ----

    /// Installs a decided value for a slot (idempotent) and runs everything
    /// downstream: dissemination, pool bookkeeping, in-order delivery, GC,
    /// and leader pipelining.
    fn decide_slot(&mut self, now: u64, slot: Slot, value: Arc<[u8]>, is_decider: bool) {
        if slot <= self.gc_floor {
            return;
        }
        // Bound the decided-ahead buffer: past the retention budget, ignore
        // remote decisions beyond the frontier instead of storing them. The
        // sender has not seen our acknowledgment, so it retains the value
        // and Learn re-fetches it once the frontier advances. Our own
        // decisions are always kept (proposers only run within the pipeline
        // of the frontier, so they cannot grow this without bound).
        if !is_decider
            && slot > self.decided_contig.next()
            && self.retained_bytes.saturating_add(value.len()) > self.config.max_retained_bytes
        {
            return;
        }
        {
            let state = self
                .slots
                .entry(slot)
                .or_insert_with(|| SlotState::new(now));
            if matches!(state.recorder, RecorderSlot::Decided(_)) {
                state.proposer = ProposerState::Done;
                return;
            }
            state.recorder = RecorderSlot::Decided(value.clone());
            state.proposer = ProposerState::Done;
        }
        if self.retained.insert(slot, value.clone()).is_none() {
            self.retained_bytes += value.len();
        }
        if is_decider {
            for idx in 0..self.n() {
                if idx != self.me_idx {
                    self.send_to(
                        idx,
                        Payload::Decide {
                            slot,
                            value: value.clone(),
                        },
                    );
                }
            }
        }
        // Commands of ours that rode in this slot but lost become
        // immediately re-batchable.
        let winners: BTreeSet<CommandId> = match decode_batch(&value) {
            Some(batch) => batch.into_iter().map(|(id, _)| id).collect(),
            None => {
                debug_assert!(false, "decided value is not a valid batch");
                BTreeSet::new()
            }
        };
        for (id, entry) in self.pool.entries.iter_mut() {
            if entry.proposed_in == Some(slot) && !winners.contains(id) {
                entry.proposed_in = None;
            }
        }
        self.refresh_pool_pending(now);
        self.try_deliver(now);
        self.maybe_open_slots(now);
    }

    fn try_deliver(&mut self, now: u64) {
        loop {
            let next = self.decided_contig.next();
            let Some(value) = self.retained.get(&next) else {
                break;
            };
            let batch = decode_batch(value).unwrap_or_else(|| {
                debug_assert!(false, "decided value is not a valid batch");
                Vec::new()
            });
            let mut commands = Vec::with_capacity(batch.len());
            for (id, data) in batch {
                if self.dedup.mark_delivered(&id) {
                    self.pool.remove(&id);
                    commands.push((id, data.to_vec()));
                }
            }
            self.decided_contig = next;
            self.actions.push_back(Action::Deliver {
                slot: next,
                commands,
            });
        }
        self.peer_acked[self.me_idx] = self.decided_contig;
        self.refresh_pool_pending(now);
        self.maybe_gc();
    }

    fn maybe_gc(&mut self) {
        self.peer_acked[self.me_idx] = self.decided_contig;
        let floor = *self.peer_acked.iter().min().expect("non-empty");
        while self.gc_floor < floor {
            self.gc_floor = self.gc_floor.next();
            if let Some(value) = self.retained.remove(&self.gc_floor) {
                self.retained_bytes -= value.len();
            }
            self.slots.remove(&self.gc_floor);
        }
        // Escape hatch: past the retention budget, free the oldest delivered
        // values even if a (presumably dead) replica has not acknowledged
        // them. A replica lagging behind the freed prefix can never rejoin
        // this group -- the crash-stop model's expectation.
        while self.retained_bytes > self.config.max_retained_bytes {
            let Some((&oldest, _)) = self.retained.first_key_value() else {
                break;
            };
            if oldest > self.decided_contig {
                break;
            }
            let value = self.retained.remove(&oldest).expect("just observed");
            self.retained_bytes -= value.len();
            self.gc_floor = oldest;
            self.slots.remove(&oldest);
        }
    }

    // ---- command pool ----

    fn on_forward(&mut self, now: u64, commands: Vec<(CommandId, Arc<[u8]>)>) {
        for (id, data) in commands {
            if self.dedup.is_delivered(&id) || self.pool.entries.contains_key(&id) {
                continue;
            }
            if data.len() > crate::types::MAX_COMMAND_BYTES
                || self.pool.bytes + Pool::cost(data.len()) > self.config.max_pool_bytes
            {
                // Drop silently: the origin keeps re-forwarding.
                continue;
            }
            self.pool.insert(id, data, now);
        }
        self.refresh_pool_pending(now);
        self.maybe_open_slots(now);
    }

    /// Leader only: opens new slots (up to the pipeline depth) for pool
    /// commands not already riding in an open proposal.
    fn maybe_open_slots(&mut self, now: u64) {
        if !self.is_leader() {
            return;
        }
        loop {
            // Running proposers only exist above the frontier (decided slots
            // are Done), and that range is bounded by the pipeline and the
            // retention budget -- unlike the full map, which grows with
            // retained history while a lagging replica holds GC back.
            let running = self
                .slots
                .range(self.decided_contig.next()..)
                .filter(|(_, state)| matches!(state.proposer, ProposerState::Running(_)))
                .count();
            if running >= self.config.pipeline as usize {
                break;
            }
            let last_known = self
                .slots
                .last_key_value()
                .map(|(&slot, _)| slot)
                .unwrap_or(Slot(0));
            let slot = self
                .max_open
                .max(self.decided_contig)
                .max(last_known)
                .next();
            // Pipelining is bounded by distance from the frontier, not just
            // by concurrently running proposers: with a stuck frontier and
            // later slots still deciding, the leader would otherwise open
            // slots (and accumulate its own decided-ahead values, which the
            // retention budget must not drop) without bound.
            if slot.0 > self.decided_contig.0 + self.config.pipeline as u64 {
                break;
            }
            let batch = self.take_unassigned_batch(slot);
            if batch.is_empty() {
                break;
            }
            self.max_open = slot;
            self.activate(now, slot, encode_batch(&batch));
        }
        self.refresh_pool_pending(now);
    }

    /// Claims unassigned pool commands (up to the batch limit) for `slot`.
    fn take_unassigned_batch(&mut self, slot: Slot) -> CommandBatch {
        let mut batch = Vec::new();
        let mut bytes = 0;
        for (id, entry) in self.pool.entries.iter() {
            if entry.proposed_in.is_some() {
                continue;
            }
            // Per-origin sequencing window: never batch a command more than
            // DEDUP_WINDOW sequences past what has been delivered for its
            // origin. Batches are built lowest-sequence-first, so this does
            // not starve anything; it bounds the sparse dedup state (the
            // delivered-above-the-mark set) that out-of-order commits can
            // otherwise grow while one low sequence stays undecided.
            if id.seq > self.dedup.high_water(id.origin, id.boot) + DEDUP_WINDOW {
                continue;
            }
            // Count encoded size (data plus per-command framing) so the
            // batch limit bounds the wire size, not just the payload bytes.
            let cost = entry.data.len() + COMMAND_WIRE_OVERHEAD;
            if !batch.is_empty() && bytes + cost > self.config.max_batch_bytes {
                break;
            }
            bytes += cost;
            batch.push((*id, entry.data.clone()));
            if bytes >= self.config.max_batch_bytes {
                break;
            }
        }
        for (id, _) in &batch {
            self.pool
                .entries
                .get_mut(id)
                .expect("just seen")
                .proposed_in = Some(slot);
        }
        batch
    }

    // ---- hedging ----

    /// Materializes a slot state for the frontier (lowest undecided slot)
    /// when something needs it decided -- pending commands, or open/decided
    /// slots beyond it that in-order delivery is stuck behind -- so the
    /// hedging deadline machinery below applies to it.
    fn ensure_frontier_observed(&mut self, now: u64) {
        let frontier = self.decided_contig.next();
        if self.slots.contains_key(&frontier) {
            return;
        }
        let beyond = self.slots.range(frontier..).next().is_some();
        if beyond || self.pool_pending_since.is_some() {
            self.slots.insert(frontier, SlotState::new(now));
        }
    }

    /// Activates this replica's proposer for undecided slots that have made
    /// no observed progress for its position in the hedging schedule.
    /// Position k waits `k * hedge_delay`; the leader (k = 0) acts
    /// immediately. Over-activation is harmless: concurrent proposers
    /// cooperate rather than interfere.
    fn hedge_activate_due(&mut self, now: u64) {
        let k = self.me_idx as u64;
        let mut due = Vec::new();
        for (&slot, state) in self.slots.range(self.decided_contig.next()..) {
            if !matches!(state.proposer, ProposerState::Idle)
                || matches!(state.recorder, RecorderSlot::Decided(_))
            {
                continue;
            }
            let base = state.first_observed.max(state.last_progress);
            if now >= base.saturating_add(k.saturating_mul(self.config.hedge_delay)) {
                due.push(slot);
            }
        }
        for slot in due {
            // Lowest slot first, so it takes the pending commands and later
            // orphaned slots complete with empty batches.
            let batch = self.take_unassigned_batch(slot);
            self.activate(now, slot, encode_batch(&batch));
        }
        if !self.pool.has_unassigned() {
            self.pool_pending_since = None;
        }
    }

    // ---- timers ----

    fn retransmit_due(&mut self, now: u64) {
        let mut stale = Vec::new();
        // Running proposers only exist above the frontier; see
        // maybe_open_slots for why the scan must not cover retained history.
        for (&slot, state) in self.slots.range(self.decided_contig.next()..) {
            if let ProposerState::Running(run) = &state.proposer
                && now.saturating_sub(run.sent_at) >= self.config.retransmit_delay
            {
                stale.push(slot);
            }
        }
        for slot in stale {
            if let Some(state) = self.slots.get_mut(&slot)
                && let ProposerState::Running(run) = &mut state.proposer
            {
                // Re-sends are byte-identical (cached priorities) and
                // recorder-idempotent, so re-driving the whole step is safe.
                run.needs_send = true;
            }
            self.drive(now, slot);
        }
    }

    fn reforward_due(&mut self, now: u64) {
        if self.is_leader() {
            return;
        }
        let interval = self.forward_interval();
        // Every due entry is forwarded in this tick (its deadline advances),
        // split into batch-bounded Forward messages per target.
        let mut chunks: Vec<(usize, CommandBatch)> = Vec::new();
        let mut open: BTreeMap<usize, (CommandBatch, usize)> = BTreeMap::new();
        let me = self.config.me;
        for (id, entry) in self.pool.entries.iter_mut() {
            if id.origin != me || id.boot != self.boot || entry.proposed_in.is_some() {
                continue;
            }
            if now.saturating_sub(entry.last_forward) < interval {
                continue;
            }
            let candidates: Vec<usize> = (0..self.config.replicas.len())
                .filter(|idx| *idx != self.me_idx)
                .collect();
            if candidates.is_empty() {
                break;
            }
            let target = candidates[(entry.forward_attempts % candidates.len() as u64) as usize];
            let (commands, bytes) = open.entry(target).or_default();
            let cost = entry.data.len() + COMMAND_WIRE_OVERHEAD;
            if !commands.is_empty() && *bytes + cost > self.config.max_batch_bytes {
                chunks.push((target, std::mem::take(commands)));
                *bytes = 0;
            }
            entry.last_forward = now;
            entry.forward_attempts += 1;
            *bytes += cost;
            commands.push((*id, entry.data.clone()));
        }
        chunks.extend(
            open.into_iter()
                .filter(|(_, (commands, _))| !commands.is_empty())
                .map(|(target, (commands, _))| (target, commands)),
        );
        for (target, commands) in chunks {
            self.send_to(target, Payload::Forward { commands });
        }
    }

    fn learn_tick(&mut self, now: u64) {
        // Inclusive deadline, matching what next_wakeup advertises: a tick
        // exactly at the deadline must retry, or an exact-deadline scheduler
        // would stall.
        if let Some((_, sent_at)) = self.learn_in_flight
            && now.saturating_sub(sent_at) >= self.config.retransmit_delay
        {
            self.learn_in_flight = None;
            self.learn_attempts += 1;
        }
        if self.learn_in_flight.is_none() {
            // Rotate retries across every peer that has advertised more than
            // we have delivered: the peer with the maximum watermark may be
            // dead, while any peer ahead of us can serve the prefix we need
            // (retention keeps a value until all replicas acknowledge it).
            let candidates: Vec<usize> = (0..self.n())
                .filter(|idx| *idx != self.me_idx && self.peer_acked[*idx] > self.decided_contig)
                .collect();
            if !candidates.is_empty() {
                let idx = candidates[(self.learn_attempts % candidates.len() as u64) as usize];
                let acked = self.peer_acked[idx];
                self.maybe_request_learn(now, idx, acked);
            }
        }
    }

    // Periodic heartbeat from every replica to every peer: keeps decided
    // watermarks (which drive catch-up and retention GC) flowing on all
    // links while quiesced, independent of which replicas are alive. Without
    // it, a lagging replica whose only live peer is a non-leader would never
    // hear a newer watermark and could stay behind forever.
    fn ping_tick(&mut self, now: u64) {
        if self.n() == 1 {
            return;
        }
        if now.saturating_sub(self.last_ping) >= PING_INTERVAL {
            self.last_ping = now;
            for idx in 0..self.n() {
                if idx != self.me_idx {
                    self.send_to(idx, Payload::Ping);
                }
            }
        }
    }

    // ---- catch-up ----

    fn maybe_request_learn(&mut self, now: u64, from_idx: usize, their_decided: Slot) {
        if their_decided <= self.decided_contig {
            return;
        }
        if let Some((_, sent_at)) = self.learn_in_flight
            && now.saturating_sub(sent_at) < self.config.retransmit_delay
        {
            return;
        }
        self.learn_in_flight = Some((from_idx, now));
        self.send_to(
            from_idx,
            Payload::Learn {
                from_slot: self.decided_contig.next(),
            },
        );
    }

    fn on_learn(&mut self, from_idx: usize, from_slot: Slot) {
        if from_slot <= self.gc_floor || from_slot > self.decided_contig || from_slot.0 == 0 {
            return;
        }
        let mut values = Vec::new();
        let mut bytes = 0;
        let mut slot = from_slot;
        while slot <= self.decided_contig {
            let value = self
                .retained
                .get(&slot)
                .expect("retention is contiguous through decided_contig")
                .clone();
            bytes += value.len();
            values.push(value);
            if bytes >= LEARN_CHUNK_BYTES {
                break;
            }
            slot = slot.next();
        }
        self.send_to(
            from_idx,
            Payload::LearnReply {
                first_slot: from_slot,
                values,
            },
        );
    }

    fn on_learn_reply(&mut self, now: u64, first_slot: Slot, values: Vec<Arc<[u8]>>) {
        self.learn_in_flight = None;
        for (offset, value) in values.into_iter().enumerate() {
            let slot = Slot(first_slot.0 + offset as u64);
            self.decide_slot(now, slot, value, false);
        }
        // If the sender advertised more, receive()'s epilogue requests the
        // next chunk via maybe_request_learn.
    }
}
