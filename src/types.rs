use std::fmt;
use std::sync::Arc;

/// Identifies a replica within a consensus group.
///
/// Ids are assigned by the application, must be nonzero, and must be unique
/// within the group. All replicas of a group must be configured with the same
/// id set.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReplicaId(pub u64);

impl fmt::Debug for ReplicaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r{}", self.0)
    }
}

/// A position in the replicated log.
///
/// Slots are decided independently and each decided slot has exactly one value
/// forever. The first slot is 1; slot 0 means "nothing decided yet".
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slot(pub u64);

impl Slot {
    pub(crate) fn next(self) -> Slot {
        Slot(self.0 + 1)
    }
}

impl fmt::Debug for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "slot{}", self.0)
    }
}

/// Uniquely identifies a submitted command across the group.
///
/// `origin` is the replica the command was submitted at and `seq` is a
/// per-origin counter. `boot` distinguishes process restarts of the same
/// origin: it is derived from `Config::new`'s `rng_seed`, which therefore must
/// differ across restarts of the same replica (pass fresh entropy). Without
/// it, a restarted origin would reuse sequence numbers and its fresh commands
/// would be dropped as duplicates by delivery deduplication.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommandId {
    /// Replica the command was submitted at.
    pub origin: ReplicaId,
    /// Process-restart nonce of the origin.
    pub boot: u64,
    /// Per-origin submission counter, starting at 1.
    pub seq: u64,
}

impl fmt::Debug for CommandId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cmd({:?},{:x},{})", self.origin, self.boot, self.seq)
    }
}

/// Proposal priorities. The maximum value is reserved for the leader's
/// round-1 fast path; 0 is the ISR nil value and is never sent.
pub(crate) type Priority = u32;

/// The reserved fast-path priority (`H` in the paper).
pub(crate) const PRIORITY_H: Priority = u32::MAX;

/// A prioritized proposal: the unit of consensus within one slot.
///
/// Ordered by `(priority, proposer, value bytes)`. The proposer component
/// makes ties between distinct replicas impossible (the paper's Appendix A
/// tie-breaking approach); the value component keeps the order total even if
/// a restarted replica equivocates, which is outside the crash-stop model but
/// must not break recorder determinism.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Proposal {
    pub(crate) priority: Priority,
    pub(crate) proposer: ReplicaId,
    pub(crate) value: Arc<[u8]>,
}

impl Ord for Proposal {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.priority, self.proposer, self.value.as_ref()).cmp(&(
            other.priority,
            other.proposer,
            other.value.as_ref(),
        ))
    }
}

impl PartialOrd for Proposal {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Proposal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "prop(pri={:x},{:?},{}B)",
            self.priority,
            self.proposer,
            self.value.len()
        )
    }
}

/// A set of commands riding together, as batched into one consensus value
/// or one `Forward` message.
pub(crate) type CommandBatch = Vec<(CommandId, Arc<[u8]>)>;

/// Maximum size of a single command. Keeps every encoded batch far below
/// the wire format's u32 length fields even with the batch-size limit's
/// one-oversized-command allowance.
pub(crate) const MAX_COMMAND_BYTES: usize = 1 << 30;

/// Encoded overhead per command in a batch or Forward message: the id
/// (origin, boot, seq) plus the length prefix.
pub(crate) const COMMAND_WIRE_OVERHEAD: usize = 28;

/// Upper bound for the configurable batch-size limit; see the size proof in
/// `Config::max_batch_bytes`.
pub(crate) const MAX_BATCH_BYTES_LIMIT: usize = 1 << 30;

/// Tag byte identifying the kind of a consensus value.
///
/// Tag 1 is reserved for internal schedule-change entries (leader
/// auto-tuning), which are not implemented yet; decoding rejects it.
const VALUE_TAG_BATCH: u8 = 0;

/// Encodes a batch of commands as a consensus value.
pub(crate) fn encode_batch(commands: &[(CommandId, Arc<[u8]>)]) -> Arc<[u8]> {
    let mut out = Vec::with_capacity(
        1 + 4
            + commands
                .iter()
                .map(|(_, data)| 28 + data.len())
                .sum::<usize>(),
    );
    out.push(VALUE_TAG_BATCH);
    out.extend_from_slice(&(commands.len() as u32).to_le_bytes());
    for (id, data) in commands {
        out.extend_from_slice(&id.origin.0.to_le_bytes());
        out.extend_from_slice(&id.boot.to_le_bytes());
        out.extend_from_slice(&id.seq.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
    out.into()
}

/// Decodes a consensus value into its batch of commands.
///
/// Values are only ever produced by `encode_batch` on some replica, so a
/// decode failure indicates a bug or an out-of-model fault; callers treat it
/// as an empty batch after a debug assertion.
pub(crate) fn decode_batch(value: &[u8]) -> Option<Vec<(CommandId, Arc<[u8]>)>> {
    let mut cursor = Cursor { buf: value, pos: 0 };
    if cursor.u8()? != VALUE_TAG_BATCH {
        return None;
    }
    let count = cursor.u32()?;
    let mut commands = Vec::with_capacity(count.min(1024) as usize);
    for _ in 0..count {
        let id = CommandId {
            origin: ReplicaId(cursor.u64()?),
            boot: cursor.u64()?,
            seq: cursor.u64()?,
        };
        let len = cursor.u32()? as usize;
        let data: Arc<[u8]> = cursor.bytes(len)?.into();
        commands.push((id, data));
    }
    if cursor.pos != value.len() {
        return None;
    }
    Some(commands)
}

/// Bounds-checked little-endian reader used by all decoding in the crate.
pub(crate) struct Cursor<'a> {
    pub(crate) buf: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        let bytes = self.bytes(4)?;
        Some(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub(crate) fn u64(&mut self) -> Option<u64> {
        let bytes = self.bytes(8)?;
        Some(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        if end > self.buf.len() {
            return None;
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Some(slice)
    }

    pub(crate) fn finished(&self) -> bool {
        self.pos == self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_order_is_priority_then_proposer_then_value() {
        let p = |priority, proposer: u64, value: &[u8]| Proposal {
            priority,
            proposer: ReplicaId(proposer),
            value: value.into(),
        };
        assert!(p(2, 1, b"z") > p(1, 9, b"a"));
        assert!(p(1, 2, b"a") > p(1, 1, b"z"));
        assert!(p(1, 1, b"b") > p(1, 1, b"a"));
        assert_eq!(p(1, 1, b"a"), p(1, 1, b"a"));
    }

    #[test]
    fn batch_round_trip() {
        let id = |origin, boot, seq| CommandId {
            origin: ReplicaId(origin),
            boot,
            seq,
        };
        let commands: Vec<(CommandId, Arc<[u8]>)> = vec![
            (id(1, 7, 1), b"hello".as_slice().into()),
            (id(2, 9, 44), b"".as_slice().into()),
            (id(3, 1, u64::MAX), vec![0u8; 300].into()),
        ];
        let encoded = encode_batch(&commands);
        let decoded = decode_batch(&encoded).unwrap();
        assert_eq!(commands, decoded);

        assert_eq!(decode_batch(&encode_batch(&[])).unwrap(), vec![]);
    }

    #[test]
    fn batch_decode_rejects_garbage() {
        assert!(decode_batch(&[]).is_none());
        assert!(decode_batch(&[1, 0, 0, 0, 0]).is_none()); // reserved tag
        assert!(decode_batch(&[0, 1, 0, 0, 0]).is_none()); // truncated command
        let valid = encode_batch(&[(
            CommandId {
                origin: ReplicaId(1),
                boot: 2,
                seq: 3,
            },
            b"x".as_slice().into(),
        )]);
        // Truncations of a valid batch never decode.
        for len in 0..valid.len() {
            assert!(decode_batch(&valid[..len]).is_none());
        }
        // Trailing garbage is rejected.
        let mut extended = valid.to_vec();
        extended.push(0);
        assert!(decode_batch(&extended).is_none());
    }
}
