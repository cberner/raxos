use std::sync::Arc;

use crate::types::Proposal;
use crate::wire::ReplyFirst;

/// The interval summary register for one slot (paper Algorithm 3), the
/// entirety of a recorder's per-slot state while the slot is undecided.
///
/// Proposals play the role of the paper's binary integers: `aggregate` is
/// `max` under the total `(priority, proposer, value)` order and `None` is
/// the nil value.
#[derive(Default)]
pub(crate) struct IsrSlot {
    /// Current logical clock step `S`.
    step: u32,
    /// First proposal received in the current step (`F_c`). `Some` whenever
    /// `step > 0`.
    first: Option<Proposal>,
    /// Maximum proposal seen in the current step (`A_c`).
    current_agg: Option<Proposal>,
    /// Maximum proposal seen in the prior step (`A_p`).
    prior_agg: Option<Proposal>,
}

/// The `(S, F_c, A_p)` summary returned by `record`.
pub(crate) struct IsrSummary {
    pub(crate) step: u32,
    pub(crate) first: Proposal,
    pub(crate) prior_agg: Option<Proposal>,
}

impl IsrSlot {
    /// Handles one `record` invocation. The returned flag reports whether
    /// the register's state changed: byte-identical retransmissions and
    /// stale invocations leave it untouched, which callers use to
    /// distinguish real protocol progress from duplicate traffic.
    pub(crate) fn record(&mut self, step: u32, proposal: Proposal) -> (IsrSummary, bool) {
        let mut changed = false;
        if step == self.step {
            if agg_less(&self.current_agg, &proposal) {
                self.current_agg = Some(proposal);
                changed = true;
            }
        } else if step > self.step {
            self.prior_agg = if step == self.step + 1 {
                self.current_agg.take()
            } else {
                None
            };
            self.step = step;
            self.first = Some(proposal.clone());
            self.current_agg = Some(proposal);
            changed = true;
        }
        // step < self.step: the invocation is stale; drop the proposal and
        // return the current summary so the caller can catch up.
        let summary = IsrSummary {
            step: self.step,
            first: self
                .first
                .clone()
                .expect("record is never invoked with step 0"),
            prior_agg: self.prior_agg.clone(),
        };
        (summary, changed)
    }
}

fn agg_less(current: &Option<Proposal>, candidate: &Proposal) -> bool {
    match current {
        None => true,
        Some(existing) => existing < candidate,
    }
}

/// A recorder's view of one slot: an open ISR, or the decided value.
pub(crate) enum RecorderSlot {
    Open(IsrSlot),
    Decided(Arc<[u8]>),
}

impl RecorderSlot {
    pub(crate) fn new() -> RecorderSlot {
        RecorderSlot::Open(IsrSlot::default())
    }
}

/// Builds the `first` field of a `RecordReply`, eliding the value bytes when
/// the recorded first proposal is exactly the request's own proposal (the
/// common case on the fast path, where every recorder would otherwise echo
/// the leader's batch back at it).
pub(crate) fn reply_first(summary_first: &Proposal, request: &Proposal) -> ReplyFirst {
    if summary_first == request {
        ReplyFirst::Echo
    } else {
        ReplyFirst::Full(summary_first.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ReplicaId;

    fn p(priority: u32, proposer: u64, value: &[u8]) -> Proposal {
        Proposal {
            priority,
            proposer: ReplicaId(proposer),
            value: value.into(),
        }
    }

    #[test]
    fn first_step_records_first_and_aggregate() {
        let mut isr = IsrSlot::default();
        let (s, _) = isr.record(4, p(10, 1, b"a"));
        assert_eq!(s.step, 4);
        assert_eq!(s.first, p(10, 1, b"a"));
        assert_eq!(s.prior_agg, None);
    }

    #[test]
    fn same_step_aggregates_max_but_keeps_first() {
        let mut isr = IsrSlot::default();
        isr.record(4, p(10, 1, b"a"));
        let (s, _) = isr.record(4, p(50, 2, b"b"));
        assert_eq!(s.step, 4);
        assert_eq!(s.first, p(10, 1, b"a"), "F_c is immutable within a step");
        // The aggregate becomes visible as A_p after advancing one step.
        let (s, _) = isr.record(5, p(1, 3, b"c"));
        assert_eq!(s.step, 5);
        assert_eq!(s.first, p(1, 3, b"c"));
        assert_eq!(s.prior_agg, Some(p(50, 2, b"b")));
    }

    #[test]
    fn aggregate_ignores_lower_proposals() {
        let mut isr = IsrSlot::default();
        isr.record(4, p(50, 1, b"a"));
        isr.record(4, p(10, 2, b"b"));
        let (s, _) = isr.record(5, p(1, 3, b"c"));
        assert_eq!(s.prior_agg, Some(p(50, 1, b"a")));
    }

    #[test]
    fn skipping_steps_nils_prior_aggregate() {
        let mut isr = IsrSlot::default();
        isr.record(4, p(10, 1, b"a"));
        let (s, _) = isr.record(6, p(20, 2, b"b"));
        assert_eq!(s.step, 6);
        assert_eq!(s.first, p(20, 2, b"b"));
        assert_eq!(s.prior_agg, None, "nothing was seen in step 5");
    }

    #[test]
    fn stale_step_is_ignored_but_summarized() {
        let mut isr = IsrSlot::default();
        isr.record(6, p(10, 1, b"a"));
        let (s, _) = isr.record(4, p(99, 2, b"b"));
        assert_eq!(s.step, 6, "stale proposal must not regress the step");
        assert_eq!(s.first, p(10, 1, b"a"));
        // The stale proposal was dropped entirely.
        let (s, _) = isr.record(7, p(1, 3, b"c"));
        assert_eq!(s.prior_agg, Some(p(10, 1, b"a")));
    }

    #[test]
    fn step_is_monotone() {
        let mut isr = IsrSlot::default();
        let mut last = 0;
        for (step, pri) in [(4, 3), (4, 9), (7, 2), (5, 8), (7, 1), (12, 5)] {
            let (s, _) = isr.record(step, p(pri, 1, b"x"));
            assert!(s.step >= last);
            last = s.step;
        }
    }

    #[test]
    fn reply_first_elides_exact_echo_only() {
        let request = p(10, 1, b"a");
        assert!(matches!(
            reply_first(&request.clone(), &request),
            ReplyFirst::Echo
        ));
        // Same priority and proposer but different value: no elision.
        assert!(matches!(
            reply_first(&p(10, 1, b"other"), &request),
            ReplyFirst::Full(_)
        ));
        assert!(matches!(
            reply_first(&p(11, 1, b"a"), &request),
            ReplyFirst::Full(_)
        ));
    }
}
