use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::types::{COMMAND_WIRE_OVERHEAD, CommandId, ReplicaId, Slot};

/// A submitted-but-undelivered command held by this replica.
pub(crate) struct PoolEntry {
    pub(crate) data: Arc<[u8]>,
    /// Slot this entry currently rides in as part of one of our own open
    /// proposals, if any. Cleared when that slot decides without it, making
    /// the entry immediately re-batchable.
    pub(crate) proposed_in: Option<Slot>,
    /// When we last forwarded this entry (origin replicas only).
    pub(crate) last_forward: u64,
    /// How many times it has been forwarded; rotates the target through the
    /// schedule so a dead leader cannot strand commands.
    pub(crate) forward_attempts: u64,
}

/// The command pool: everything submitted here or forwarded to us that has
/// not yet been delivered.
#[derive(Default)]
pub(crate) struct Pool {
    pub(crate) entries: BTreeMap<CommandId, PoolEntry>,
    pub(crate) bytes: usize,
}

impl Pool {
    /// Accounted cost of one entry: its bytes plus per-command overhead, so
    /// the pool byte limit also bounds the entry count (zero-length commands
    /// are common: read barriers).
    pub(crate) fn cost(data_len: usize) -> usize {
        data_len + COMMAND_WIRE_OVERHEAD
    }

    pub(crate) fn insert(&mut self, id: CommandId, data: Arc<[u8]>, now: u64) {
        let cost = Pool::cost(data.len());
        let entry = PoolEntry {
            data,
            proposed_in: None,
            last_forward: now,
            forward_attempts: 0,
        };
        if self.entries.insert(id, entry).is_none() {
            self.bytes += cost;
        }
    }

    pub(crate) fn remove(&mut self, id: &CommandId) {
        if let Some(entry) = self.entries.remove(id) {
            self.bytes -= Pool::cost(entry.data.len());
        }
    }

    pub(crate) fn has_unassigned(&self) -> bool {
        self.entries
            .values()
            .any(|entry| entry.proposed_in.is_none())
    }
}

/// Tracks which commands have been delivered, per `(origin, boot)`, as a
/// contiguous sequence high-water mark plus a sparse set of delivered
/// sequence numbers above it.
///
/// Delivery order equals slot order, which is agreed, so this state is a
/// pure function of the log prefix: every replica computes the same
/// delivered set, which is what makes exactly-once delivery deterministic.
/// The sparse set only holds entries while re-proposal races commit an
/// origin's commands out of sequence order, and drains as the mark advances.
#[derive(Default)]
pub(crate) struct Dedup {
    per_origin: BTreeMap<(ReplicaId, u64), OriginDedup>,
}

#[derive(Default)]
struct OriginDedup {
    high_water: u64,
    above: BTreeSet<u64>,
}

impl Dedup {
    /// The contiguous delivered sequence high-water mark for an origin's
    /// boot (0 when nothing has been delivered).
    pub(crate) fn high_water(&self, origin: ReplicaId, boot: u64) -> u64 {
        self.per_origin
            .get(&(origin, boot))
            .map(|state| state.high_water)
            .unwrap_or(0)
    }

    pub(crate) fn is_delivered(&self, id: &CommandId) -> bool {
        match self.per_origin.get(&(id.origin, id.boot)) {
            None => false,
            Some(origin) => id.seq <= origin.high_water || origin.above.contains(&id.seq),
        }
    }

    /// Records a delivery. Returns false if it was already delivered.
    pub(crate) fn mark_delivered(&mut self, id: &CommandId) -> bool {
        let origin = self.per_origin.entry((id.origin, id.boot)).or_default();
        if id.seq <= origin.high_water || !origin.above.insert(id.seq) {
            return false;
        }
        while origin.above.remove(&(origin.high_water + 1)) {
            origin.high_water += 1;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(origin: u64, seq: u64) -> CommandId {
        CommandId {
            origin: ReplicaId(origin),
            boot: 7,
            seq,
        }
    }

    #[test]
    fn dedup_marks_and_drains_contiguously() {
        let mut dedup = Dedup::default();
        assert!(!dedup.is_delivered(&id(1, 1)));
        assert!(dedup.mark_delivered(&id(1, 1)));
        assert!(!dedup.mark_delivered(&id(1, 1)), "duplicate rejected");
        assert!(dedup.is_delivered(&id(1, 1)));

        // Out-of-order delivery parks seq 3 in the sparse set...
        assert!(dedup.mark_delivered(&id(1, 3)));
        assert!(dedup.is_delivered(&id(1, 3)));
        assert!(!dedup.is_delivered(&id(1, 2)));
        // ...and seq 2 drains both into the high-water mark.
        assert!(dedup.mark_delivered(&id(1, 2)));
        assert!(dedup.is_delivered(&id(1, 2)));
        assert!(!dedup.mark_delivered(&id(1, 3)), "still deduplicated");
    }

    #[test]
    fn dedup_is_per_origin_and_boot() {
        let mut dedup = Dedup::default();
        assert!(dedup.mark_delivered(&id(1, 1)));
        assert!(!dedup.is_delivered(&id(2, 1)));
        let restarted = CommandId {
            origin: ReplicaId(1),
            boot: 8,
            seq: 1,
        };
        assert!(!dedup.is_delivered(&restarted), "fresh boot, fresh seqs");
        assert!(dedup.mark_delivered(&restarted));
    }

    #[test]
    fn pool_accounts_bytes() {
        let mut pool = Pool::default();
        pool.insert(id(1, 1), b"abcd".as_slice().into(), 0);
        pool.insert(id(1, 1), b"abcd".as_slice().into(), 0);
        pool.insert(id(1, 2), b"xy".as_slice().into(), 0);
        // Costs include per-entry overhead so zero-length commands still
        // count against the limit.
        assert_eq!(pool.bytes, Pool::cost(4) + Pool::cost(2));
        assert!(Pool::cost(0) > 0);
        assert!(pool.has_unassigned());
        pool.remove(&id(1, 1));
        assert_eq!(pool.bytes, Pool::cost(2));
        pool.remove(&id(1, 1));
        assert_eq!(pool.bytes, Pool::cost(2));
    }
}
