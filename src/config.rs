use std::fmt;
use std::time::Duration;

use crate::types::ReplicaId;

/// Configuration for one [`Replica`](crate::Replica) of a consensus group.
///
/// Constructed with [`Config::new`] and refined with the builder-style
/// setters. Every replica of a group must be configured with the same replica
/// set; the hedging schedule is the ascending id order, so it is identical on
/// all replicas regardless of the order ids were passed in.
#[non_exhaustive]
#[derive(Clone)]
pub struct Config {
    pub(crate) replicas: Vec<ReplicaId>,
    pub(crate) me: ReplicaId,
    pub(crate) rng_seed: u64,
    pub(crate) hedge_delay: u64,
    pub(crate) retransmit_delay: u64,
    pub(crate) pipeline: u32,
    pub(crate) max_batch_bytes: usize,
    pub(crate) max_pool_bytes: usize,
    pub(crate) max_retained_bytes: usize,
}

/// Error returned by [`Config::new`] for an invalid replica set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// The replica set is empty.
    NoReplicas,
    /// A replica id is zero, which is reserved.
    ZeroReplicaId,
    /// The same id appears more than once in the replica set.
    DuplicateReplicaId,
    /// `me` is not a member of the replica set.
    UnknownLocalReplica,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            ConfigError::NoReplicas => "replica set is empty",
            ConfigError::ZeroReplicaId => "replica id 0 is reserved",
            ConfigError::DuplicateReplicaId => "duplicate replica id",
            ConfigError::UnknownLocalReplica => "local replica is not in the replica set",
        };
        write!(f, "{message}")
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Creates a configuration for a group made of `replicas` (any order;
    /// deduplication is an error), identifying the local replica as `me`.
    ///
    /// `rng_seed` seeds proposal-priority randomization and doubles as the
    /// process-restart nonce in [`CommandId`](crate::CommandId)s, so it must
    /// differ across restarts of the same replica: pass fresh entropy in
    /// production. Given the same seed and the same sequence of inputs, a
    /// `Replica` behaves identically, which is what makes simulation testing
    /// of this crate deterministic.
    pub fn new(
        replicas: Vec<ReplicaId>,
        me: ReplicaId,
        rng_seed: u64,
    ) -> Result<Config, ConfigError> {
        let mut replicas = replicas;
        replicas.sort();
        if replicas.is_empty() {
            return Err(ConfigError::NoReplicas);
        }
        if replicas[0].0 == 0 {
            return Err(ConfigError::ZeroReplicaId);
        }
        if replicas.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ConfigError::DuplicateReplicaId);
        }
        if !replicas.contains(&me) {
            return Err(ConfigError::UnknownLocalReplica);
        }
        Ok(Config {
            replicas,
            me,
            rng_seed,
            hedge_delay: Duration::from_millis(200).as_nanos() as u64,
            retransmit_delay: Duration::from_millis(500).as_nanos() as u64,
            pipeline: 4,
            max_batch_bytes: 1 << 20,
            max_pool_bytes: 16 << 20,
            max_retained_bytes: 32 << 20,
        })
    }

    /// Base hedging delay (default 200ms): the k-th replica in the schedule
    /// starts proposing for a slot only after the slot has made no observed
    /// progress for `k * hedge_delay`. Zero is legal; too-small values cost
    /// only redundant messages, never safety or liveness. Clamped to about
    /// 416 days so per-replica deadline arithmetic cannot overflow even for
    /// `Duration::MAX` (which effectively disables hedging).
    pub fn hedge_delay(mut self, delay: Duration) -> Config {
        self.hedge_delay = delay.as_nanos().min(1 << 55) as u64;
        self
    }

    /// How long a proposer waits for recorder replies before re-sending
    /// (default 500ms). The transport may drop messages; retransmissions are
    /// byte-identical and idempotent.
    /// Clamped to at least 1ms: a zero delay would make an exact-deadline
    /// scheduler (driving ticks by `next_wakeup`) spin retransmitting at a
    /// single instant. Clamped to the same ~416 day ceiling as
    /// [`hedge_delay`](Config::hedge_delay), so `Duration::MAX` means
    /// "effectively never" instead of overflowing deadline arithmetic.
    pub fn retransmit_delay(mut self, delay: Duration) -> Config {
        self.retransmit_delay = delay.as_nanos().clamp(1_000_000, 1 << 55) as u64;
        self
    }

    /// Maximum consensus slots the leader keeps in flight concurrently
    /// (default 4, minimum 1). Only the leader pipelines.
    pub fn pipeline(mut self, depth: u32) -> Config {
        self.pipeline = depth.max(1);
        self
    }

    /// Maximum encoded bytes of commands batched into one slot (default
    /// 1 MiB, clamped to 1 GiB). A single command larger than this still
    /// forms an (oversized) batch of one. The clamp, together with the 1 GiB
    /// per-command limit enforced by [`submit`](crate::Replica::submit),
    /// keeps every encoded batch within the wire format's u32 length fields.
    pub fn max_batch_bytes(mut self, bytes: usize) -> Config {
        self.max_batch_bytes = bytes.clamp(1, crate::types::MAX_BATCH_BYTES_LIMIT);
        self
    }

    /// Maximum bytes of submitted-but-undelivered commands held in the local
    /// pool (default 16 MiB). [`submit`](crate::Replica::submit) fails with
    /// `PoolFull` beyond it.
    pub fn max_pool_bytes(mut self, bytes: usize) -> Config {
        self.max_pool_bytes = bytes.max(1);
        self
    }

    /// Memory budget for retaining decided values so lagging replicas can
    /// catch up (default 32 MiB). Values are normally freed once every
    /// replica has acknowledged them; past this budget the oldest are freed
    /// anyway, and a replica that lagged behind the freed prefix can never
    /// rejoin this group (matching the crash-stop model). The same budget
    /// bounds buffering of decided-ahead values while the frontier is stuck:
    /// beyond it, remote decisions are dropped and re-fetched later. Pass
    /// `usize::MAX` to never free unacknowledged values (unbounded memory if
    /// a replica is gone forever, but stragglers always remain recoverable).
    pub fn max_retained_bytes(mut self, bytes: usize) -> Config {
        self.max_retained_bytes = bytes.max(1);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_replica_set() {
        let r = |id| ReplicaId(id);
        assert_eq!(
            Config::new(vec![], r(1), 0).err(),
            Some(ConfigError::NoReplicas)
        );
        assert_eq!(
            Config::new(vec![r(0), r(1)], r(1), 0).err(),
            Some(ConfigError::ZeroReplicaId)
        );
        assert_eq!(
            Config::new(vec![r(1), r(2), r(1)], r(1), 0).err(),
            Some(ConfigError::DuplicateReplicaId)
        );
        assert_eq!(
            Config::new(vec![r(1), r(2)], r(3), 0).err(),
            Some(ConfigError::UnknownLocalReplica)
        );
        assert!(Config::new(vec![r(1)], r(1), 0).is_ok());
    }

    #[test]
    fn schedule_is_sorted_id_order() {
        let r = |id| ReplicaId(id);
        let config = Config::new(vec![r(5), r(2), r(9)], r(5), 0).unwrap();
        assert_eq!(config.replicas, vec![r(2), r(5), r(9)]);
    }

    #[test]
    fn setters_clamp() {
        let config = Config::new(vec![ReplicaId(1)], ReplicaId(1), 0)
            .unwrap()
            .pipeline(0)
            .max_batch_bytes(0)
            .retransmit_delay(Duration::ZERO);
        assert_eq!(config.pipeline, 1);
        assert_eq!(config.max_batch_bytes, 1);
        // A zero retransmit delay would spin an exact-deadline scheduler.
        assert_eq!(config.retransmit_delay, 1_000_000);

        // Maximal delays clamp to the overflow-safe ceiling instead of
        // truncating to an arbitrary u64.
        let config = Config::new(vec![ReplicaId(1)], ReplicaId(1), 0)
            .unwrap()
            .hedge_delay(Duration::MAX)
            .retransmit_delay(Duration::MAX);
        assert_eq!(config.hedge_delay, 1 << 55);
        assert_eq!(config.retransmit_delay, 1 << 55);
    }
}
