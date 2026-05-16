//! Fiat–Shamir interpreter for the IOR framework.
//!
//! **Status: skeleton.** Per the design doc §7.1, the FS compiler is
//! one of the framework's two compiler targets (BCS being the other).
//! This module implements the first cycle of the FS interpreter:
//! walk a [`ValidatedTrace`] and dispatch each event to an
//! [`FsBackend`] implementation.
//!
//! The backend trait is the seam between the framework and any
//! concrete transcript (spongefish, the old `prover_state` API, a
//! mock for tests). The interpreter itself is transcript-agnostic;
//! it just walks events and calls the backend in IR-declared order.
//!
//! What this layer does NOT do (yet):
//! - Generate real Fiat–Shamir randomness (the backend supplies it).
//! - Re-validate child traces inside `RunSubprotocol`. The trace
//!   checker validates only the top-level structural conformance;
//!   nested traces are trusted by the interpreter today. Lifting
//!   trace validation through subprotocols is a follow-up.
//! - Implement a real backend. `RecordingBackend` is for unit tests.

use crate::iop::ir::{EventNode, ObligationId, ProtocolIR, Tag};
use crate::iop::trace::{Evidence, ExecutionTrace, TraceEvent, ValidatedTrace};

/// Backend abstraction over a Fiat–Shamir transcript. One method per
/// [`EventNode`] variant; implementations route to whichever concrete
/// transcript / channel they're built on (spongefish, mock, etc).
///
/// Each method receives the IR event's `tag` plus the digests/data
/// the trace event carries. Returning `Err(_)` aborts the
/// interpretation.
pub trait FsBackend {
    type Error;

    fn absorb_public(
        &mut self,
        tag: Tag,
        value_digest: &[u8; 32],
    ) -> Result<(), Self::Error>;

    fn prover_message(
        &mut self,
        tag: Tag,
        value_digest: &[u8; 32],
    ) -> Result<(), Self::Error>;

    fn sample_challenge(
        &mut self,
        tag: Tag,
        value_digest: &[u8; 32],
    ) -> Result<(), Self::Error>;

    fn commit_oracle(
        &mut self,
        tag: Tag,
        oracle_digest: &[u8; 32],
        commitment_digest: &[u8; 32],
    ) -> Result<(), Self::Error>;

    fn query_oracle(
        &mut self,
        tag: Tag,
        commitment_digest: &[u8; 32],
        positions_digest: &[u8; 32],
    ) -> Result<(), Self::Error>;

    fn open_oracle(
        &mut self,
        tag: Tag,
        commitment_digest: &[u8; 32],
        positions_digest: &[u8; 32],
        values_digest: &[u8; 32],
        evidence: &Evidence,
    ) -> Result<(), Self::Error>;

    /// Called before the interpreter recurses into a child IR/trace.
    /// Default impl is a no-op (the recursion itself drives the
    /// child's events through the same backend).
    fn enter_subprotocol(
        &mut self,
        _tag: Tag,
        _child_ir: &ProtocolIR,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called after the interpreter finishes recursing. Default no-op.
    fn leave_subprotocol(
        &mut self,
        _tag: Tag,
        _child_ir: &ProtocolIR,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn emit_obligation(
        &mut self,
        tag: Tag,
        obligation: &ObligationId,
        value_digest: &[u8; 32],
    ) -> Result<(), Self::Error>;

    fn discharge_obligation(
        &mut self,
        tag: Tag,
        obligation: &ObligationId,
        evidence_digests: &[[u8; 32]],
    ) -> Result<(), Self::Error>;
}

/// Errors the interpreter itself can produce, separate from backend
/// errors. Wrapped backend errors flow through `Backend(E)`.
#[derive(Debug)]
pub enum FsInterpretError<E> {
    /// Trace event's variant doesn't match the IR event's variant at
    /// the same index. Should not happen on a `ValidatedTrace`; this
    /// is a defensive guard for child traces (which aren't validated
    /// yet — see module docs).
    KindMismatch {
        index: usize,
        ir_kind: &'static str,
        trace_kind: &'static str,
    },
    /// A `RunSubprotocol` trace event but no corresponding IR child,
    /// or vice versa. Same defensive note.
    SubprotocolShapeMismatch { index: usize },
    /// Backend returned an error.
    Backend(E),
}

impl<E> From<E> for FsInterpretError<E> {
    fn from(e: E) -> Self {
        FsInterpretError::Backend(e)
    }
}

/// Walks a validated trace, dispatching each event to the backend.
/// The single entrypoint of the FS interpreter.
pub fn interpret<'ir, B: FsBackend>(
    validated: &ValidatedTrace<'ir>,
    backend: &mut B,
) -> Result<(), FsInterpretError<B::Error>> {
    walk(validated.ir(), validated.trace(), backend)
}

fn walk<B: FsBackend>(
    ir: &ProtocolIR,
    trace: &ExecutionTrace,
    backend: &mut B,
) -> Result<(), FsInterpretError<B::Error>> {
    for (i, trace_event) in trace.events.iter().enumerate() {
        let ir_node = &ir.events[trace_event.ir_event()];
        dispatch(i, ir_node, trace_event, backend)?;
    }
    Ok(())
}

fn dispatch<B: FsBackend>(
    index: usize,
    ir_node: &EventNode,
    trace_event: &TraceEvent,
    backend: &mut B,
) -> Result<(), FsInterpretError<B::Error>> {
    match (ir_node, trace_event) {
        (EventNode::AbsorbPublic { tag, .. }, TraceEvent::AbsorbPublic { value_digest, .. }) => {
            backend.absorb_public(tag, value_digest)?;
        }
        (EventNode::SendMessage { tag, .. }, TraceEvent::SendMessage { value_digest, .. }) => {
            backend.prover_message(tag, value_digest)?;
        }
        (
            EventNode::SampleChallenge { tag, .. },
            TraceEvent::SampleChallenge { value_digest, .. },
        ) => {
            backend.sample_challenge(tag, value_digest)?;
        }
        (
            EventNode::CommitOracle { tag, .. },
            TraceEvent::CommitOracle {
                oracle_digest,
                commitment_digest,
                ..
            },
        ) => {
            backend.commit_oracle(tag, oracle_digest, commitment_digest)?;
        }
        (
            EventNode::QueryOracle { tag, .. },
            TraceEvent::QueryOracle {
                commitment_digest,
                positions_digest,
                ..
            },
        ) => {
            backend.query_oracle(tag, commitment_digest, positions_digest)?;
        }
        (
            EventNode::OpenOracle { tag, .. },
            TraceEvent::OpenOracle {
                commitment_digest,
                positions_digest,
                values_digest,
                evidence,
                ..
            },
        ) => {
            backend.open_oracle(
                tag,
                commitment_digest,
                positions_digest,
                values_digest,
                evidence,
            )?;
        }
        (
            EventNode::RunSubprotocol { tag, child: ir_child },
            TraceEvent::RunSubprotocol { child: trace_child, .. },
        ) => {
            backend.enter_subprotocol(tag, ir_child)?;
            walk(ir_child, trace_child, backend)?;
            backend.leave_subprotocol(tag, ir_child)?;
        }
        (
            EventNode::EmitObligation { tag, .. },
            TraceEvent::EmitObligation {
                obligation,
                value_digest,
                ..
            },
        ) => {
            backend.emit_obligation(tag, obligation, value_digest)?;
        }
        (
            EventNode::DischargeObligation { tag, .. },
            TraceEvent::DischargeObligation {
                obligation,
                evidence_digests,
                ..
            },
        ) => {
            backend.discharge_obligation(tag, obligation, evidence_digests)?;
        }
        _ => {
            return Err(FsInterpretError::KindMismatch {
                index,
                ir_kind: ir_event_kind_str(ir_node),
                trace_kind: trace_event.kind(),
            });
        }
    }
    Ok(())
}

fn ir_event_kind_str(node: &EventNode) -> &'static str {
    match node {
        EventNode::AbsorbPublic { .. } => "AbsorbPublic",
        EventNode::SendMessage { .. } => "SendMessage",
        EventNode::SampleChallenge { .. } => "SampleChallenge",
        EventNode::CommitOracle { .. } => "CommitOracle",
        EventNode::QueryOracle { .. } => "QueryOracle",
        EventNode::OpenOracle { .. } => "OpenOracle",
        EventNode::RunSubprotocol { .. } => "RunSubprotocol",
        EventNode::EmitObligation { .. } => "EmitObligation",
        EventNode::DischargeObligation { .. } => "DischargeObligation",
    }
}

// ─────────────────────────────────────────────────────────────────────
// RecordingBackend — captures every backend call. For tests only.
// ─────────────────────────────────────────────────────────────────────

/// Captured backend call. Mirrors [`FsBackend`] method names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordedCall {
    AbsorbPublic { tag: Tag, value: [u8; 32] },
    ProverMessage { tag: Tag, value: [u8; 32] },
    SampleChallenge { tag: Tag, value: [u8; 32] },
    CommitOracle {
        tag: Tag,
        oracle: [u8; 32],
        commitment: [u8; 32],
    },
    QueryOracle {
        tag: Tag,
        commitment: [u8; 32],
        positions: [u8; 32],
    },
    OpenOracle {
        tag: Tag,
        commitment: [u8; 32],
        positions: [u8; 32],
        values: [u8; 32],
        scheme: &'static str,
        bytes_len: usize,
    },
    EnterSubprotocol { tag: Tag, child_name: &'static str },
    LeaveSubprotocol { tag: Tag, child_name: &'static str },
    EmitObligation {
        tag: Tag,
        obligation: ObligationId,
        value: [u8; 32],
    },
    DischargeObligation {
        tag: Tag,
        obligation: ObligationId,
        evidence_count: usize,
    },
}

/// Backend that just captures every call. The test inspects
/// `log` afterwards.
#[derive(Default)]
pub struct RecordingBackend {
    pub log: Vec<RecordedCall>,
}

impl FsBackend for RecordingBackend {
    type Error = std::convert::Infallible;

    fn absorb_public(&mut self, tag: Tag, value_digest: &[u8; 32]) -> Result<(), Self::Error> {
        self.log.push(RecordedCall::AbsorbPublic {
            tag,
            value: *value_digest,
        });
        Ok(())
    }
    fn prover_message(&mut self, tag: Tag, value_digest: &[u8; 32]) -> Result<(), Self::Error> {
        self.log.push(RecordedCall::ProverMessage {
            tag,
            value: *value_digest,
        });
        Ok(())
    }
    fn sample_challenge(&mut self, tag: Tag, value_digest: &[u8; 32]) -> Result<(), Self::Error> {
        self.log.push(RecordedCall::SampleChallenge {
            tag,
            value: *value_digest,
        });
        Ok(())
    }
    fn commit_oracle(
        &mut self,
        tag: Tag,
        oracle_digest: &[u8; 32],
        commitment_digest: &[u8; 32],
    ) -> Result<(), Self::Error> {
        self.log.push(RecordedCall::CommitOracle {
            tag,
            oracle: *oracle_digest,
            commitment: *commitment_digest,
        });
        Ok(())
    }
    fn query_oracle(
        &mut self,
        tag: Tag,
        commitment_digest: &[u8; 32],
        positions_digest: &[u8; 32],
    ) -> Result<(), Self::Error> {
        self.log.push(RecordedCall::QueryOracle {
            tag,
            commitment: *commitment_digest,
            positions: *positions_digest,
        });
        Ok(())
    }
    fn open_oracle(
        &mut self,
        tag: Tag,
        commitment_digest: &[u8; 32],
        positions_digest: &[u8; 32],
        values_digest: &[u8; 32],
        evidence: &Evidence,
    ) -> Result<(), Self::Error> {
        let (scheme, bytes_len) = match evidence {
            Evidence::Bytes { scheme, bytes } => (*scheme, bytes.len()),
        };
        self.log.push(RecordedCall::OpenOracle {
            tag,
            commitment: *commitment_digest,
            positions: *positions_digest,
            values: *values_digest,
            scheme,
            bytes_len,
        });
        Ok(())
    }
    fn enter_subprotocol(
        &mut self,
        tag: Tag,
        child_ir: &ProtocolIR,
    ) -> Result<(), Self::Error> {
        // Child names in our examples are always &'static str-backed.
        let child_name: &'static str = match &child_ir.name {
            std::borrow::Cow::Borrowed(s) => s,
            std::borrow::Cow::Owned(_) => "owned",
        };
        self.log
            .push(RecordedCall::EnterSubprotocol { tag, child_name });
        Ok(())
    }
    fn leave_subprotocol(
        &mut self,
        tag: Tag,
        child_ir: &ProtocolIR,
    ) -> Result<(), Self::Error> {
        let child_name: &'static str = match &child_ir.name {
            std::borrow::Cow::Borrowed(s) => s,
            std::borrow::Cow::Owned(_) => "owned",
        };
        self.log
            .push(RecordedCall::LeaveSubprotocol { tag, child_name });
        Ok(())
    }
    fn emit_obligation(
        &mut self,
        tag: Tag,
        obligation: &ObligationId,
        value_digest: &[u8; 32],
    ) -> Result<(), Self::Error> {
        self.log.push(RecordedCall::EmitObligation {
            tag,
            obligation: obligation.clone(),
            value: *value_digest,
        });
        Ok(())
    }
    fn discharge_obligation(
        &mut self,
        tag: Tag,
        obligation: &ObligationId,
        evidence_digests: &[[u8; 32]],
    ) -> Result<(), Self::Error> {
        self.log.push(RecordedCall::DischargeObligation {
            tag,
            obligation: obligation.clone(),
            evidence_count: evidence_digests.len(),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iop::ir::{
        ChallengeDistribution, EventNode, ObligationNode, PortDecl, ProtocolIR, StepNode,
        TypeFingerprint, Visibility,
    };
    use crate::iop::trace::{check, ExecutionTrace, TraceEvent};
    use std::borrow::Cow;

    fn dummy_fingerprint() -> [u8; 32] {
        [0xAB; 32]
    }

    fn validated_one_event() -> (
        ProtocolIR,
        ExecutionTrace,
    ) {
        let mut ir = ProtocolIR::empty("Toy");
        ir.events.push(EventNode::SampleChallenge {
            tag: "toy:c",
            output: Cow::Borrowed("a.c"),
            distribution: ChallengeDistribution::Field,
        });
        ir.steps.push(StepNode {
            id: Cow::Borrowed("a"),
            component: Cow::Borrowed("A"),
            inputs: vec![],
            outputs: vec![PortDecl {
                name: Cow::Borrowed("c"),
                ty: TypeFingerprint::of("F"),
                visibility: Visibility::Public,
            }],
            events: vec![0],
        });
        let mut trace = ExecutionTrace::empty(dummy_fingerprint());
        trace.events.push(TraceEvent::SampleChallenge {
            ir_event: 0,
            value_digest: [7u8; 32],
        });
        (ir, trace)
    }

    /// Empty IR + trace → zero backend calls.
    #[test]
    fn empty_trace_no_calls() {
        let ir = ProtocolIR::empty("X");
        let trace = ExecutionTrace::empty(dummy_fingerprint());
        let v = check(&ir, dummy_fingerprint(), trace).unwrap();
        let mut b = RecordingBackend::default();
        interpret(&v, &mut b).unwrap();
        assert!(b.log.is_empty());
    }

    /// Single SampleChallenge → one sample_challenge call with the
    /// right tag and value digest.
    #[test]
    fn single_sample_challenge_dispatches_correctly() {
        let (ir, trace) = validated_one_event();
        let v = check(&ir, dummy_fingerprint(), trace).unwrap();
        let mut b = RecordingBackend::default();
        interpret(&v, &mut b).unwrap();
        assert_eq!(
            b.log,
            vec![RecordedCall::SampleChallenge {
                tag: "toy:c",
                value: [7u8; 32],
            }]
        );
    }

    /// All non-subprotocol variants dispatch to the right backend
    /// method in IR-declared order. One event per variant.
    #[test]
    fn all_variants_dispatch_in_order() {
        let mut ir = ProtocolIR::empty("AllVariants");
        ir.events.push(EventNode::AbsorbPublic {
            tag: "ab",
            value: Cow::Borrowed("a.v"),
        });
        ir.events.push(EventNode::SendMessage {
            tag: "sm",
            value: Cow::Borrowed("a.v"),
        });
        ir.events.push(EventNode::SampleChallenge {
            tag: "sc",
            output: Cow::Borrowed("a.c"),
            distribution: ChallengeDistribution::Field,
        });
        ir.events.push(EventNode::CommitOracle {
            tag: "co",
            oracle: Cow::Borrowed("a.o"),
            commitment: Cow::Borrowed("a.k"),
            oracle_interface: Cow::Borrowed("iface"),
        });
        ir.events.push(EventNode::QueryOracle {
            tag: "qo",
            commitment: Cow::Borrowed("a.k"),
            positions: Cow::Borrowed("a.p"),
            oracle_interface: Cow::Borrowed("iface"),
        });
        ir.events.push(EventNode::OpenOracle {
            tag: "oo",
            commitment: Cow::Borrowed("a.k"),
            positions: Cow::Borrowed("a.p"),
            values: Cow::Borrowed("a.vs"),
            oracle_interface: Cow::Borrowed("iface"),
        });
        ir.events.push(EventNode::EmitObligation {
            tag: "eo",
            obligation: Cow::Borrowed("ob1"),
        });
        ir.events.push(EventNode::DischargeObligation {
            tag: "do",
            obligation: Cow::Borrowed("ob1"),
            evidence: vec![Cow::Borrowed("a.v")],
        });
        ir.obligations.push(ObligationNode {
            id: Cow::Borrowed("ob1"),
            emitter: Cow::Borrowed("a"),
            discharger: Some(Cow::Borrowed("a")),
            semantic_label: Cow::Borrowed("test"),
        });

        let mut trace = ExecutionTrace::empty(dummy_fingerprint());
        trace.events.push(TraceEvent::AbsorbPublic {
            ir_event: 0,
            value_digest: [1; 32],
        });
        trace.events.push(TraceEvent::SendMessage {
            ir_event: 1,
            value_digest: [2; 32],
        });
        trace.events.push(TraceEvent::SampleChallenge {
            ir_event: 2,
            value_digest: [3; 32],
        });
        trace.events.push(TraceEvent::CommitOracle {
            ir_event: 3,
            oracle_digest: [4; 32],
            commitment_digest: [5; 32],
        });
        trace.events.push(TraceEvent::QueryOracle {
            ir_event: 4,
            commitment_digest: [5; 32],
            positions_digest: [6; 32],
        });
        trace.events.push(TraceEvent::OpenOracle {
            ir_event: 5,
            commitment_digest: [5; 32],
            positions_digest: [6; 32],
            values_digest: [7; 32],
            evidence: Evidence::Bytes {
                scheme: "merkle-blake3",
                bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
            },
        });
        trace.events.push(TraceEvent::EmitObligation {
            ir_event: 6,
            obligation: Cow::Borrowed("ob1"),
            value_digest: [8; 32],
        });
        trace.events.push(TraceEvent::DischargeObligation {
            ir_event: 7,
            obligation: Cow::Borrowed("ob1"),
            evidence_digests: vec![[9; 32]],
        });

        let v = check(&ir, dummy_fingerprint(), trace).unwrap();
        let mut b = RecordingBackend::default();
        interpret(&v, &mut b).unwrap();
        assert_eq!(b.log.len(), 8);
        assert!(matches!(b.log[0], RecordedCall::AbsorbPublic { tag: "ab", .. }));
        assert!(matches!(b.log[1], RecordedCall::ProverMessage { tag: "sm", .. }));
        assert!(matches!(b.log[2], RecordedCall::SampleChallenge { tag: "sc", .. }));
        assert!(matches!(b.log[3], RecordedCall::CommitOracle { tag: "co", .. }));
        assert!(matches!(b.log[4], RecordedCall::QueryOracle { tag: "qo", .. }));
        match &b.log[5] {
            RecordedCall::OpenOracle {
                tag: "oo",
                scheme: "merkle-blake3",
                bytes_len: 4,
                ..
            } => {}
            other => panic!("unexpected: {other:?}"),
        }
        assert!(matches!(b.log[6], RecordedCall::EmitObligation { tag: "eo", .. }));
        assert!(matches!(b.log[7], RecordedCall::DischargeObligation {
            tag: "do",
            evidence_count: 1,
            ..
        }));
    }

    /// RunSubprotocol recurses: child events appear inside parent's
    /// Enter/Leave bookends.
    #[test]
    fn run_subprotocol_recurses_with_bookends() {
        // Build a child IR with one SampleChallenge.
        let mut child_ir = ProtocolIR::empty("ChildIor");
        child_ir.events.push(EventNode::SampleChallenge {
            tag: "child:c",
            output: Cow::Borrowed("c.x"),
            distribution: ChallengeDistribution::Field,
        });
        child_ir.steps.push(StepNode {
            id: Cow::Borrowed("c"),
            component: Cow::Borrowed("Child"),
            inputs: vec![],
            outputs: vec![],
            events: vec![0],
        });

        // Build a parent IR with one RunSubprotocol containing the child.
        let mut parent = ProtocolIR::empty("Parent");
        parent.events.push(EventNode::SampleChallenge {
            tag: "parent:before",
            output: Cow::Borrowed("p.b"),
            distribution: ChallengeDistribution::Field,
        });
        parent.events.push(EventNode::RunSubprotocol {
            tag: "parent:run",
            child: Box::new(child_ir.clone()),
        });
        parent.events.push(EventNode::SampleChallenge {
            tag: "parent:after",
            output: Cow::Borrowed("p.a"),
            distribution: ChallengeDistribution::Field,
        });
        parent.steps.push(StepNode {
            id: Cow::Borrowed("p"),
            component: Cow::Borrowed("Parent"),
            inputs: vec![],
            outputs: vec![],
            events: vec![0, 1, 2],
        });

        // Build the trace.
        let mut child_trace = ExecutionTrace::empty(dummy_fingerprint());
        child_trace.events.push(TraceEvent::SampleChallenge {
            ir_event: 0,
            value_digest: [42; 32],
        });
        let mut trace = ExecutionTrace::empty(dummy_fingerprint());
        trace.events.push(TraceEvent::SampleChallenge {
            ir_event: 0,
            value_digest: [1; 32],
        });
        trace.events.push(TraceEvent::RunSubprotocol {
            ir_event: 1,
            child: Box::new(child_trace),
        });
        trace.events.push(TraceEvent::SampleChallenge {
            ir_event: 2,
            value_digest: [2; 32],
        });

        let v = check(&parent, dummy_fingerprint(), trace).unwrap();
        let mut b = RecordingBackend::default();
        interpret(&v, &mut b).unwrap();

        // Order: parent:before, EnterSubprotocol, child:c,
        // LeaveSubprotocol, parent:after.
        assert_eq!(b.log.len(), 5);
        assert!(matches!(
            b.log[0],
            RecordedCall::SampleChallenge { tag: "parent:before", .. }
        ));
        assert!(matches!(
            b.log[1],
            RecordedCall::EnterSubprotocol { tag: "parent:run", child_name: "ChildIor" }
        ));
        assert!(matches!(
            b.log[2],
            RecordedCall::SampleChallenge { tag: "child:c", .. }
        ));
        assert!(matches!(
            b.log[3],
            RecordedCall::LeaveSubprotocol { tag: "parent:run", child_name: "ChildIor" }
        ));
        assert!(matches!(
            b.log[4],
            RecordedCall::SampleChallenge { tag: "parent:after", .. }
        ));
    }

    /// Backend errors abort the walk; the call that errored doesn't
    /// produce subsequent calls.
    #[test]
    fn backend_error_aborts_walk() {
        struct FailingBackend;
        impl FsBackend for FailingBackend {
            type Error = &'static str;
            fn absorb_public(&mut self, _: Tag, _: &[u8; 32]) -> Result<(), Self::Error> {
                Ok(())
            }
            fn prover_message(&mut self, _: Tag, _: &[u8; 32]) -> Result<(), Self::Error> {
                Ok(())
            }
            fn sample_challenge(&mut self, _: Tag, _: &[u8; 32]) -> Result<(), Self::Error> {
                Err("boom")
            }
            fn commit_oracle(
                &mut self,
                _: Tag,
                _: &[u8; 32],
                _: &[u8; 32],
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn query_oracle(
                &mut self,
                _: Tag,
                _: &[u8; 32],
                _: &[u8; 32],
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn open_oracle(
                &mut self,
                _: Tag,
                _: &[u8; 32],
                _: &[u8; 32],
                _: &[u8; 32],
                _: &Evidence,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn emit_obligation(
                &mut self,
                _: Tag,
                _: &ObligationId,
                _: &[u8; 32],
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn discharge_obligation(
                &mut self,
                _: Tag,
                _: &ObligationId,
                _: &[[u8; 32]],
            ) -> Result<(), Self::Error> {
                Ok(())
            }
        }

        let (ir, trace) = validated_one_event();
        let v = check(&ir, dummy_fingerprint(), trace).unwrap();
        let result = interpret(&v, &mut FailingBackend);
        assert!(matches!(result, Err(FsInterpretError::Backend("boom"))));
    }
}
