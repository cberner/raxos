//! An implementation of the QuePaxa consensus algorithm.
//!
//! QuePaxa (Tennage et al., "QuePaxa: Escaping the Tyranny of Timeouts in
//! Consensus", SOSP 2023) is a randomized, timeout-free consensus protocol
//! with a Multi-Paxos-class fast path: under normal conditions a designated
//! leader commits a slot in one round trip, while randomized asynchronous
//! rounds guarantee safety and liveness under arbitrary network conditions.
//! Instead of view changes triggered by timeouts, every replica may propose
//! on a hedging schedule; concurrent proposers cooperate rather than
//! interfere, so a mistuned hedging delay costs only redundant messages,
//! never correctness or availability.
//!
//! # Model
//!
//! A group is `n` replicas (ids fixed at configuration; `n = 2f + 1`
//! tolerates `f` failures, and `n = 1` degenerates to a purely local log).
//! Failures are crash-stop and consensus state is in memory: a restarted
//! process must join as a *new* replica identity or accept the guarantees of
//! the group having one fewer healthy member; there is no persistence in
//! this version. Commands submitted at any replica are delivered exactly
//! once, in the same slot order, on every replica.
//!
//! # Driving a replica
//!
//! [`Replica`] is a deterministic, I/O-free state machine; the application
//! owns the network and the clock:
//!
//! - call [`Replica::submit`] to replicate a command,
//! - decode incoming transport bytes with [`Message::decode`] and feed them
//!   to [`Replica::receive`],
//! - call [`Replica::tick`] on a coarse interval (e.g. 100ms), or exactly at
//!   [`Replica::next_wakeup`],
//! - after every such call, drain [`Replica::poll_action`] and perform the
//!   [`Action`]s: transport encoded messages ([`Action::Send`], best-effort;
//!   loss, reordering, and duplication are tolerated) and apply decided
//!   commands ([`Action::Deliver`], in slot order, deduplicated).
//!
//! All inputs take `now` in monotonic nanoseconds from one fixed origin.
//! Given the same configuration (including its `rng_seed`) and input
//! sequence, a replica's outputs are bit-identical, which is what enables
//! the deterministic whole-cluster simulation this crate is tested with.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod config;
mod pool;
mod proposer;
mod recorder;
mod replica;
mod rng;
mod types;
mod wire;

#[cfg(test)]
mod sim;

pub use config::{Config, ConfigError};
pub use replica::{Action, Replica, SubmitError};
pub use types::{CommandId, ReplicaId, Slot};
pub use wire::{Message, WireError};
