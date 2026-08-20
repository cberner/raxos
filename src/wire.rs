use std::fmt;
use std::sync::Arc;

use crate::types::{CommandId, Cursor, Priority, Proposal, ReplicaId, Slot};

const VERSION: u8 = 1;

const KIND_RECORD: u8 = 1;
const KIND_RECORD_REPLY: u8 = 2;
const KIND_DECIDE: u8 = 3;
const KIND_FORWARD: u8 = 4;
const KIND_LEARN: u8 = 5;
const KIND_LEARN_REPLY: u8 = 6;
const KIND_PING: u8 = 7;

/// A protocol message exchanged between replicas of one group.
///
/// Messages are opaque to the application: it transports the bytes produced
/// by [`Message::encode`] to the replica named by
/// [`Action::Send`](crate::Action::Send) and feeds received bytes through
/// [`Message::decode`] into [`Replica::receive`](crate::Replica::receive).
/// The sender's identity travels inside the message, so the transport does
/// not need to authenticate or annotate it. Delivery may be lossy, reordered,
/// or duplicated; the protocol tolerates all three.
pub struct Message {
    /// Sending replica.
    pub(crate) from: ReplicaId,
    /// Sender's contiguous decided watermark, piggybacked on every message.
    /// Drives lagging-replica catch-up and retention GC.
    pub(crate) decided: Slot,
    pub(crate) payload: Payload,
}

pub(crate) enum Payload {
    /// Proposer -> recorder: the ISR `record(step, proposal)` invocation for
    /// one slot (paper Algorithm 4).
    Record {
        slot: Slot,
        step: u32,
        proposal: Proposal,
    },
    /// Recorder -> proposer: the ISR summary. `req_step` echoes the step of
    /// the `Record` this answers so the proposer can correlate replies over a
    /// lossy transport; `step`/`first`/`prior_agg` are the ISR's
    /// `(S, F_c, A_p)`.
    RecordReply {
        slot: Slot,
        req_step: u32,
        step: u32,
        first: ReplyFirst,
        prior_agg: Option<Proposal>,
    },
    /// The decided value of a slot. Broadcast once by a decider, and also a
    /// recorder's reply to any `Record` for an already-decided slot.
    Decide { slot: Slot, value: Arc<[u8]> },
    /// Command forwarding to the (presumed) leader.
    Forward {
        commands: Vec<(CommandId, Arc<[u8]>)>,
    },
    /// Request for decided values starting at `from_slot`, sent by a replica
    /// that observed a higher decided watermark than its own.
    Learn { from_slot: Slot },
    /// Consecutive decided values for slots `first_slot..`, chunked by size.
    LearnReply {
        first_slot: Slot,
        values: Vec<Arc<[u8]>>,
    },
    /// Leader idle heartbeat (and its echo from non-leaders): keeps decided
    /// watermarks flowing so catch-up and GC make progress when quiesced.
    Ping,
}

/// The `F_c` component of a `RecordReply`.
pub(crate) enum ReplyFirst {
    /// `F_c` equals the proposal carried by the `Record` this reply answers.
    /// Elides the value bytes: on the fast path every recorder echoes the
    /// leader's own batch, which would otherwise return `n - 1` copies of it.
    Echo,
    /// `F_c` differs from the request's proposal and is carried in full.
    Full(Proposal),
}

/// Error returned by [`Message::decode`] for malformed input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireError;

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed raxos message")
    }
}

impl std::error::Error for WireError {}

impl Message {
    /// Serializes this message for transport.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.push(VERSION);
        out.push(self.payload.kind());
        out.extend_from_slice(&self.from.0.to_le_bytes());
        out.extend_from_slice(&self.decided.0.to_le_bytes());
        match &self.payload {
            Payload::Record {
                slot,
                step,
                proposal,
            } => {
                out.extend_from_slice(&slot.0.to_le_bytes());
                out.extend_from_slice(&step.to_le_bytes());
                encode_proposal(&mut out, proposal);
            }
            Payload::RecordReply {
                slot,
                req_step,
                step,
                first,
                prior_agg,
            } => {
                out.extend_from_slice(&slot.0.to_le_bytes());
                out.extend_from_slice(&req_step.to_le_bytes());
                out.extend_from_slice(&step.to_le_bytes());
                match first {
                    ReplyFirst::Echo => out.push(0),
                    ReplyFirst::Full(proposal) => {
                        out.push(1);
                        encode_proposal(&mut out, proposal);
                    }
                }
                match prior_agg {
                    None => out.push(0),
                    Some(proposal) => {
                        out.push(1);
                        encode_proposal(&mut out, proposal);
                    }
                }
            }
            Payload::Decide { slot, value } => {
                out.extend_from_slice(&slot.0.to_le_bytes());
                encode_bytes(&mut out, value);
            }
            Payload::Forward { commands } => {
                out.extend_from_slice(&(commands.len() as u32).to_le_bytes());
                for (id, data) in commands {
                    encode_command_id(&mut out, id);
                    encode_bytes(&mut out, data);
                }
            }
            Payload::Learn { from_slot } => {
                out.extend_from_slice(&from_slot.0.to_le_bytes());
            }
            Payload::LearnReply { first_slot, values } => {
                out.extend_from_slice(&first_slot.0.to_le_bytes());
                out.extend_from_slice(&(values.len() as u32).to_le_bytes());
                for value in values {
                    encode_bytes(&mut out, value);
                }
            }
            Payload::Ping => {}
        }
        out
    }

    /// Parses a message received from the transport.
    ///
    /// Rejects unknown versions and kinds, truncated input, and trailing
    /// garbage. Never panics on arbitrary input.
    pub fn decode(data: &[u8]) -> Result<Message, WireError> {
        let mut c = Cursor { buf: data, pos: 0 };
        if c.u8().ok_or(WireError)? != VERSION {
            return Err(WireError);
        }
        let kind = c.u8().ok_or(WireError)?;
        let from = ReplicaId(c.u64().ok_or(WireError)?);
        if from.0 == 0 {
            return Err(WireError);
        }
        let decided = Slot(c.u64().ok_or(WireError)?);
        let payload = match kind {
            KIND_RECORD => Payload::Record {
                slot: Slot(c.u64().ok_or(WireError)?),
                step: c.u32().ok_or(WireError)?,
                proposal: decode_proposal(&mut c)?,
            },
            KIND_RECORD_REPLY => {
                let slot = Slot(c.u64().ok_or(WireError)?);
                let req_step = c.u32().ok_or(WireError)?;
                let step = c.u32().ok_or(WireError)?;
                let first = match c.u8().ok_or(WireError)? {
                    0 => ReplyFirst::Echo,
                    1 => ReplyFirst::Full(decode_proposal(&mut c)?),
                    _ => return Err(WireError),
                };
                let prior_agg = match c.u8().ok_or(WireError)? {
                    0 => None,
                    1 => Some(decode_proposal(&mut c)?),
                    _ => return Err(WireError),
                };
                Payload::RecordReply {
                    slot,
                    req_step,
                    step,
                    first,
                    prior_agg,
                }
            }
            KIND_DECIDE => Payload::Decide {
                slot: Slot(c.u64().ok_or(WireError)?),
                value: decode_bytes(&mut c)?,
            },
            KIND_FORWARD => {
                let count = c.u32().ok_or(WireError)?;
                let mut commands = Vec::with_capacity(count.min(1024) as usize);
                for _ in 0..count {
                    let id = decode_command_id(&mut c)?;
                    let data = decode_bytes(&mut c)?;
                    commands.push((id, data));
                }
                Payload::Forward { commands }
            }
            KIND_LEARN => Payload::Learn {
                from_slot: Slot(c.u64().ok_or(WireError)?),
            },
            KIND_LEARN_REPLY => {
                let first_slot = Slot(c.u64().ok_or(WireError)?);
                let count = c.u32().ok_or(WireError)?;
                let mut values = Vec::with_capacity(count.min(1024) as usize);
                for _ in 0..count {
                    values.push(decode_bytes(&mut c)?);
                }
                Payload::LearnReply { first_slot, values }
            }
            KIND_PING => Payload::Ping,
            _ => return Err(WireError),
        };
        if !c.finished() {
            return Err(WireError);
        }
        Ok(Message {
            from,
            decided,
            payload,
        })
    }
}

impl Payload {
    fn kind(&self) -> u8 {
        match self {
            Payload::Record { .. } => KIND_RECORD,
            Payload::RecordReply { .. } => KIND_RECORD_REPLY,
            Payload::Decide { .. } => KIND_DECIDE,
            Payload::Forward { .. } => KIND_FORWARD,
            Payload::Learn { .. } => KIND_LEARN,
            Payload::LearnReply { .. } => KIND_LEARN_REPLY,
            Payload::Ping => KIND_PING,
        }
    }

    fn kind_name(&self) -> &'static str {
        match self {
            Payload::Record { .. } => "Record",
            Payload::RecordReply { .. } => "RecordReply",
            Payload::Decide { .. } => "Decide",
            Payload::Forward { .. } => "Forward",
            Payload::Learn { .. } => "Learn",
            Payload::LearnReply { .. } => "LearnReply",
            Payload::Ping => "Ping",
        }
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Message({} from={:?} decided={})",
            self.payload.kind_name(),
            self.from,
            self.decided.0
        )
    }
}

fn encode_bytes(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
}

fn decode_bytes(c: &mut Cursor<'_>) -> Result<Arc<[u8]>, WireError> {
    let len = c.u32().ok_or(WireError)? as usize;
    Ok(c.bytes(len).ok_or(WireError)?.into())
}

fn encode_proposal(out: &mut Vec<u8>, proposal: &Proposal) {
    out.extend_from_slice(&proposal.priority.to_le_bytes());
    out.extend_from_slice(&proposal.proposer.0.to_le_bytes());
    encode_bytes(out, &proposal.value);
}

fn decode_proposal(c: &mut Cursor<'_>) -> Result<Proposal, WireError> {
    let priority: Priority = c.u32().ok_or(WireError)?;
    let proposer = ReplicaId(c.u64().ok_or(WireError)?);
    if priority == 0 || proposer.0 == 0 {
        return Err(WireError);
    }
    let value = decode_bytes(c)?;
    Ok(Proposal {
        priority,
        proposer,
        value,
    })
}

fn encode_command_id(out: &mut Vec<u8>, id: &CommandId) {
    out.extend_from_slice(&id.origin.0.to_le_bytes());
    out.extend_from_slice(&id.boot.to_le_bytes());
    out.extend_from_slice(&id.seq.to_le_bytes());
}

fn decode_command_id(c: &mut Cursor<'_>) -> Result<CommandId, WireError> {
    Ok(CommandId {
        origin: ReplicaId(c.u64().ok_or(WireError)?),
        boot: c.u64().ok_or(WireError)?,
        seq: c.u64().ok_or(WireError)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    fn proposal(rng: &mut Rng) -> Proposal {
        let len = (rng.next_u64() % 40) as usize;
        let value: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
        Proposal {
            priority: (rng.range_inclusive(1, u32::MAX as u64)) as u32,
            proposer: ReplicaId(rng.range_inclusive(1, 9)),
            value: value.into(),
        }
    }

    fn samples(rng: &mut Rng) -> Vec<Message> {
        let value: Arc<[u8]> = b"some decided value".as_slice().into();
        let id = CommandId {
            origin: ReplicaId(rng.range_inclusive(1, 9)),
            boot: rng.next_u64(),
            seq: rng.next_u64(),
        };
        vec![
            Message {
                from: ReplicaId(1),
                decided: Slot(7),
                payload: Payload::Record {
                    slot: Slot(8),
                    step: 4,
                    proposal: proposal(rng),
                },
            },
            Message {
                from: ReplicaId(2),
                decided: Slot(0),
                payload: Payload::RecordReply {
                    slot: Slot(8),
                    req_step: 4,
                    step: 6,
                    first: ReplyFirst::Echo,
                    prior_agg: None,
                },
            },
            Message {
                from: ReplicaId(3),
                decided: Slot(u64::MAX),
                payload: Payload::RecordReply {
                    slot: Slot(1),
                    req_step: 9,
                    step: 9,
                    first: ReplyFirst::Full(proposal(rng)),
                    prior_agg: Some(proposal(rng)),
                },
            },
            Message {
                from: ReplicaId(4),
                decided: Slot(3),
                payload: Payload::Decide {
                    slot: Slot(4),
                    value: value.clone(),
                },
            },
            Message {
                from: ReplicaId(5),
                decided: Slot(3),
                payload: Payload::Forward {
                    commands: vec![(id, value.clone()), (id, b"".as_slice().into())],
                },
            },
            Message {
                from: ReplicaId(6),
                decided: Slot(3),
                payload: Payload::Learn { from_slot: Slot(4) },
            },
            Message {
                from: ReplicaId(7),
                decided: Slot(9),
                payload: Payload::LearnReply {
                    first_slot: Slot(4),
                    values: vec![value, b"v2".as_slice().into()],
                },
            },
            Message {
                from: ReplicaId(8),
                decided: Slot(1),
                payload: Payload::Ping,
            },
        ]
    }

    fn assert_equal(a: &Message, b: &Message) {
        // Compare via re-encoding: Message deliberately does not implement
        // PartialEq in its public API.
        assert_eq!(a.encode(), b.encode());
    }

    #[test]
    fn round_trips() {
        let mut rng = Rng::new(11);
        for message in samples(&mut rng) {
            let decoded = Message::decode(&message.encode()).unwrap();
            assert_equal(&message, &decoded);
        }
    }

    #[test]
    fn rejects_truncation_and_trailing_garbage() {
        let mut rng = Rng::new(12);
        for message in samples(&mut rng) {
            let encoded = message.encode();
            for len in 0..encoded.len() {
                assert!(Message::decode(&encoded[..len]).is_err(), "len {len}");
            }
            let mut extended = encoded.clone();
            extended.push(0);
            assert!(Message::decode(&extended).is_err());
        }
    }

    #[test]
    fn rejects_bad_version_kind_and_ids() {
        let mut rng = Rng::new(13);
        let encoded = samples(&mut rng)[0].encode();
        let mut bad_version = encoded.clone();
        bad_version[0] = 2;
        assert!(Message::decode(&bad_version).is_err());
        let mut bad_kind = encoded.clone();
        bad_kind[1] = 99;
        assert!(Message::decode(&bad_kind).is_err());
        let mut zero_from = encoded.clone();
        zero_from[2..10].fill(0);
        assert!(Message::decode(&zero_from).is_err());
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut rng = Rng::new(14);
        for _ in 0..2000 {
            let len = (rng.next_u64() % 64) as usize;
            let data: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
            let _ = Message::decode(&data);
        }
        // Mutations of valid messages must never panic either.
        for message in samples(&mut rng) {
            let encoded = message.encode();
            for _ in 0..200 {
                let mut mutated = encoded.clone();
                let idx = (rng.next_u64() as usize) % mutated.len();
                mutated[idx] = rng.next_u64() as u8;
                let _ = Message::decode(&mutated);
            }
        }
    }
}
