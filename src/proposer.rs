use std::sync::Arc;

use crate::rng::Rng;
use crate::types::{PRIORITY_H, Priority, Proposal, ReplicaId};

/// The proposer role for one slot (paper Algorithm 4).
///
/// `Idle` proposers are hedging candidates: they hold no state and activate
/// only when the slot makes no observed progress for their position in the
/// hedging schedule. `Done` means the slot is decided locally.
pub(crate) enum ProposerState {
    Idle,
    Running(Box<Run>),
    Done,
}

/// An active proposer's state for one slot.
pub(crate) struct Run {
    /// Current step `s = 4 * round + phase`, starting at 4 (round 1 phase 0).
    pub(crate) step: u32,
    /// Current proposal template `p`. During a randomized phase 0 the
    /// priority and proposer components are overridden per recorder by
    /// `proposal_for`; the template is what phases 1-3 spread verbatim.
    pub(crate) proposal: Proposal,
    /// Per-recorder (by schedule index) priority draws for the current step,
    /// non-empty exactly when this step is a randomized phase 0. Cached so
    /// retransmissions are byte-identical: a re-draw would give this proposer
    /// two distinct identities within one step.
    phase0_priorities: Vec<Priority>,
    /// Which recorders (by schedule index) have been counted this step.
    replied: Vec<bool>,
    reply_count: u32,
    /// Running max of the `F_c` components of counted replies.
    best_first: Option<Proposal>,
    /// Running max of the non-nil `A_p` components of counted replies.
    best_agg: Option<Proposal>,
    /// Whether every counted reply's `F_c` carried the reserved priority `H`.
    all_first_high: bool,
    /// When the current step was last transmitted (drives retransmission).
    pub(crate) sent_at: u64,
    /// Whether the current step still needs to be (re)broadcast.
    pub(crate) needs_send: bool,
}

/// Result of folding one recorder reply into a run.
pub(crate) enum Folded {
    /// Duplicate, stale, or below-quorum reply: nothing to do yet.
    Ignored,
    /// The recorder is ahead: adopt its state and re-execute from there.
    CatchUp { step: u32, adopt: Proposal },
    /// This reply completed the quorum for the current step.
    Quorum,
}

/// Result of completing a step at quorum.
pub(crate) enum StepOutcome {
    /// Consensus reached: the slot decides this value.
    Decided(Arc<[u8]>),
    /// Advanced to the next step; it needs to be sent.
    Advance,
    /// Defensive stall (phase 3 with all-nil aggregates, which quorum
    /// intersection makes impossible): re-collect the same step via
    /// retransmission instead of advancing unsafely.
    Retry,
}

impl Run {
    /// Starts a proposer at round 1 phase 0 (`s = 4`) with a fresh value.
    /// This is the only way a new value ever enters a slot.
    pub(crate) fn start(
        value: Arc<[u8]>,
        me: ReplicaId,
        me_idx: usize,
        n: usize,
        fast_path_leader: bool,
        now: u64,
        rng: &mut Rng,
    ) -> Run {
        let mut run = Run {
            step: 4,
            proposal: Proposal {
                priority: PRIORITY_H,
                proposer: me,
                value,
            },
            phase0_priorities: Vec::new(),
            replied: vec![false; n],
            reply_count: 0,
            best_first: None,
            best_agg: None,
            all_first_high: true,
            sent_at: now,
            needs_send: true,
        };
        if !fast_path_leader {
            run.draw_priorities(me, me_idx, n, rng);
        }
        run
    }

    fn draw_priorities(&mut self, me: ReplicaId, me_idx: usize, n: usize, rng: &mut Rng) {
        // One independent draw per recorder (paper section 4.2.4: the
        // proposer chooses a random priority "on behalf of each recorder"),
        // uniform over [1, H - 1]; H is reserved for the fast-path leader.
        self.phase0_priorities = (0..n)
            .map(|_| rng.range_inclusive(1, u64::from(PRIORITY_H) - 1) as Priority)
            .collect();
        // A randomized phase 0 proposes the carried value under our own
        // identity (the abstract algorithm's fresh per-round proposal).
        self.proposal.proposer = me;
        self.proposal.priority = self.phase0_priorities[me_idx];
    }

    /// The exact proposal transmitted to the recorder at schedule index
    /// `idx` for the current step. Deterministic given the run state, which
    /// makes retransmissions byte-identical and lets recorders elide echoes.
    pub(crate) fn proposal_for(&self, idx: usize) -> Proposal {
        if self.phase0_priorities.is_empty() {
            self.proposal.clone()
        } else {
            Proposal {
                priority: self.phase0_priorities[idx],
                proposer: self.proposal.proposer,
                value: self.proposal.value.clone(),
            }
        }
    }

    fn reset_tracking(&mut self) {
        self.replied.fill(false);
        self.reply_count = 0;
        self.best_first = None;
        self.best_agg = None;
        self.all_first_high = true;
    }

    /// Prepares the current step for (re)broadcast after an advance or
    /// catch-up: resets reply tracking and, for randomized phase-0 steps,
    /// draws fresh per-recorder priorities.
    pub(crate) fn begin_step(
        &mut self,
        me: ReplicaId,
        me_idx: usize,
        n: usize,
        leader_first_round: bool,
        now: u64,
        rng: &mut Rng,
    ) {
        self.reset_tracking();
        self.phase0_priorities.clear();
        if self.step.is_multiple_of(4) && !(self.step == 4 && leader_first_round) {
            self.draw_priorities(me, me_idx, n, rng);
        }
        self.sent_at = now;
        self.needs_send = true;
    }

    /// Folds one recorder reply (already reconstituted if it was an echo)
    /// into the current step.
    pub(crate) fn fold(
        &mut self,
        from_idx: usize,
        req_step: u32,
        reply_step: u32,
        first: Proposal,
        prior_agg: Option<Proposal>,
        quorum: u32,
    ) -> Folded {
        if reply_step > self.step {
            // The recorder is ahead of us (paper "proposer catch-up"): adopt
            // its step and first proposal wholesale. Never re-attach our own
            // value here; a decision may already depend on the adopted one.
            return Folded::CatchUp {
                step: reply_step,
                adopt: first,
            };
        }
        if req_step != self.step || reply_step != self.step || self.replied[from_idx] {
            return Folded::Ignored;
        }
        self.replied[from_idx] = true;
        self.reply_count += 1;
        self.all_first_high &= first.priority == PRIORITY_H;
        if self.best_first.as_ref().is_none_or(|best| *best < first) {
            self.best_first = Some(first);
        }
        if let Some(agg) = prior_agg
            && self.best_agg.as_ref().is_none_or(|best| *best < agg)
        {
            self.best_agg = Some(agg);
        }
        if self.reply_count == quorum {
            Folded::Quorum
        } else {
            Folded::Ignored
        }
    }

    /// Executes the phase logic once a quorum of same-step replies is in
    /// (paper Algorithm 4's per-phase branches).
    pub(crate) fn step_complete(&mut self) -> StepOutcome {
        match self.step % 4 {
            0 => {
                // Fast path: every recorder in the quorum saw a reserved-
                // priority proposal first, which only the round-1 leader
                // sends, so its value is already unbeatable.
                let best_first = self
                    .best_first
                    .take()
                    .expect("every reply carries a first proposal");
                if self.all_first_high {
                    return StepOutcome::Decided(best_first.value);
                }
                self.proposal = best_first;
            }
            1 => {
                // Spread of the existent set: no proposer-side action.
            }
            2 => {
                if let Some(best_agg) = &self.best_agg
                    && *best_agg == self.proposal
                {
                    return StepOutcome::Decided(self.proposal.value.clone());
                }
            }
            3 => match self.best_agg.take() {
                Some(best_agg) => self.proposal = best_agg,
                None => {
                    // Impossible by quorum intersection with the phase-2
                    // quorum that must precede any recorder reaching this
                    // step (see the crate's design notes); stall defensively
                    // rather than advance with a stale proposal.
                    debug_assert!(false, "phase-3 quorum returned only nil aggregates");
                    self.reset_tracking();
                    return StepOutcome::Retry;
                }
            },
            _ => unreachable!(),
        }
        self.step += 1;
        StepOutcome::Advance
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arc(bytes: &[u8]) -> Arc<[u8]> {
        bytes.into()
    }

    fn p(priority: u32, proposer: u64, value: &[u8]) -> Proposal {
        Proposal {
            priority,
            proposer: ReplicaId(proposer),
            value: value.into(),
        }
    }

    #[test]
    fn leader_fast_path_decides_at_step_4() {
        let mut rng = Rng::new(1);
        let mut run = Run::start(arc(b"v"), ReplicaId(1), 0, 3, true, 0, &mut rng);
        assert_eq!(run.step, 4);
        // The leader's own proposal carries H to every recorder.
        assert_eq!(run.proposal_for(0).priority, PRIORITY_H);
        assert_eq!(run.proposal_for(2).priority, PRIORITY_H);
        for idx in 0..2 {
            let reply = run.proposal_for(idx);
            match run.fold(idx, 4, 4, reply, None, 2) {
                Folded::Ignored if idx == 0 => {}
                Folded::Quorum if idx == 1 => {}
                _ => panic!("unexpected fold outcome"),
            }
        }
        match run.step_complete() {
            StepOutcome::Decided(value) => assert_eq!(&*value, b"v"),
            _ => panic!("expected fast-path decision"),
        }
    }

    #[test]
    fn slow_path_adopts_best_first_and_decides_in_phase_2() {
        let mut rng = Rng::new(2);
        let mut run = Run::start(arc(b"mine"), ReplicaId(2), 1, 3, false, 0, &mut rng);
        // Phase 0: replies carry different first proposals; the best wins.
        let winner = p(900, 3, b"theirs");
        assert!(matches!(
            run.fold(0, 4, 4, p(10, 1, b"loser"), None, 2),
            Folded::Ignored
        ));
        assert!(matches!(
            run.fold(1, 4, 4, winner.clone(), None, 2),
            Folded::Quorum
        ));
        assert!(matches!(run.step_complete(), StepOutcome::Advance));
        assert_eq!(run.step, 5);
        assert_eq!(run.proposal, winner);

        // Phase 1: any two same-step replies advance.
        run.begin_step(ReplicaId(2), 1, 3, false, 0, &mut rng);
        run.fold(0, 5, 5, p(1, 1, b"x"), None, 2);
        assert!(matches!(
            run.fold(1, 5, 5, p(1, 1, b"x"), None, 2),
            Folded::Quorum
        ));
        assert!(matches!(run.step_complete(), StepOutcome::Advance));

        // Phase 2: aggregates equal to our proposal decide it.
        run.begin_step(ReplicaId(2), 1, 3, false, 0, &mut rng);
        run.fold(0, 6, 6, p(1, 1, b"x"), Some(winner.clone()), 2);
        assert!(matches!(
            run.fold(1, 6, 6, p(1, 1, b"x"), Some(p(5, 1, b"low")), 2),
            Folded::Quorum
        ));
        match run.step_complete() {
            StepOutcome::Decided(value) => assert_eq!(&*value, b"theirs"),
            _ => panic!("expected phase-2 decision"),
        }
    }

    #[test]
    fn phase_2_without_matching_aggregate_advances_and_phase_3_adopts() {
        let mut rng = Rng::new(3);
        let mut run = Run::start(arc(b"mine"), ReplicaId(1), 0, 3, false, 0, &mut rng);
        run.fold(0, 4, 4, p(7, 1, b"a"), None, 1);
        run.step_complete();
        run.begin_step(ReplicaId(1), 0, 3, false, 0, &mut rng);
        run.fold(0, 5, 5, p(7, 1, b"a"), None, 1);
        run.step_complete();
        run.begin_step(ReplicaId(1), 0, 3, false, 0, &mut rng);
        // Phase 2 whose best aggregate differs from our proposal: no decide.
        run.fold(0, 6, 6, p(7, 1, b"a"), Some(p(9000, 3, b"b")), 1);
        assert!(matches!(run.step_complete(), StepOutcome::Advance));
        assert_eq!(run.step, 7);
        run.begin_step(ReplicaId(1), 0, 3, false, 0, &mut rng);
        // Phase 3 adopts the best aggregate as the next round's candidate.
        let carried = p(123, 2, b"c");
        run.fold(0, 7, 7, p(7, 1, b"a"), Some(carried.clone()), 1);
        assert!(matches!(run.step_complete(), StepOutcome::Advance));
        assert_eq!(run.step, 8);
        assert_eq!(run.proposal, carried);
        // The next phase 0 re-randomizes under our identity but keeps the
        // carried value.
        run.begin_step(ReplicaId(1), 0, 3, false, 0, &mut rng);
        let sent = run.proposal_for(2);
        assert_eq!(sent.proposer, ReplicaId(1));
        assert_eq!(&*sent.value, b"c");
        assert_ne!(sent.priority, PRIORITY_H);
    }

    #[test]
    fn catch_up_adopts_wholesale_and_duplicates_are_ignored() {
        let mut rng = Rng::new(4);
        let mut run = Run::start(arc(b"mine"), ReplicaId(1), 0, 3, true, 0, &mut rng);
        let ahead = p(55, 3, b"ahead");
        match run.fold(2, 4, 11, ahead.clone(), None, 2) {
            Folded::CatchUp { step, adopt } => {
                assert_eq!(step, 11);
                assert_eq!(adopt, ahead);
            }
            _ => panic!("expected catch-up"),
        }
        // Same recorder counted twice: second fold is ignored.
        assert!(matches!(
            run.fold(1, 4, 4, p(1, 1, b"x"), None, 2),
            Folded::Ignored
        ));
        assert!(matches!(
            run.fold(1, 4, 4, p(1, 1, b"x"), None, 2),
            Folded::Ignored
        ));
        // Stale replies (older request step) are ignored.
        assert!(matches!(
            run.fold(0, 3, 3, p(1, 1, b"x"), None, 2),
            Folded::Ignored
        ));
    }

    #[test]
    fn retransmission_is_byte_identical() {
        let mut rng = Rng::new(5);
        let run = Run::start(arc(b"v"), ReplicaId(2), 1, 5, false, 0, &mut rng);
        for idx in 0..5 {
            assert_eq!(run.proposal_for(idx), run.proposal_for(idx));
        }
        // Distinct recorders get independent draws (overwhelmingly distinct).
        let all: Vec<Priority> = (0..5).map(|idx| run.proposal_for(idx).priority).collect();
        let mut deduped = all.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(all.len(), deduped.len());
    }
}
