//! Execution trace + trace checker for the IOR framework.
//!
//! **Status: skeleton.** Per the design doc's §12.1 decision
//! (validated-trace architecture, audit-class hidden-effect control):
//!
//! ```text
//! ProtocolIR     = static declaration  (src/iop/ir.rs)
//! ExecutionTrace = this module          (runtime record)
//! TraceChecker   = `check()` below      (validates trace ⊢ IR)
//! ValidatedTrace = `ValidatedTrace<'_>` (compiler-consumable)
//! ```
//!
//! The runtime trace is a sibling of the static IR. Trace events
//! cross-reference IR events by index. Values are summarised by
//! 32-byte digests (placeholders; the real digest scheme is decided
//! by the compiler). Evidence carries scheme-tagged opaque bytes
//! that VC implementations return from `open_multiple`.
//!
//! This module is intentionally weak. The first checker validates
//! structural conformance only — event count, event-id resolution,
//! event-kind matching, ordering, fingerprint. Stronger checks
//! (challenge replay, opening cross-validation, OQ2-typed wire
//! compatibility) are deferred to later iterations as listed in
//! the design doc.

use crate::iop::ir::{EventId, EventNode, ObligationId, ProtocolIR};

/// Scheme-tagged opaque evidence — what the orchestrator attaches
/// to an `OpenOracle` trace event when ark-vc's `open_multiple`
/// returns. The first version is bytes + scheme tag; typed
/// `OpeningProof` variants come later once OQ2 matures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    Bytes {
        scheme: &'static str,
        bytes: Vec<u8>,
    },
}

/// One concrete execution event. Each variant mirrors an
/// `EventNode` variant in the IR. The `ir_event` field is the index
/// into `ProtocolIR::events` that this trace event realises.
///
/// The 32-byte `*_digest` fields are placeholders for the
/// commitment to the underlying value at the protocol's transcript
/// position. Concrete digest semantics (FS-sponge state, BCS
/// Merkle-root, etc.) are the compiler's responsibility.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceEvent {
    AbsorbPublic {
        ir_event: EventId,
        value_digest: [u8; 32],
    },
    SendMessage {
        ir_event: EventId,
        value_digest: [u8; 32],
    },
    SampleChallenge {
        ir_event: EventId,
        value_digest: [u8; 32],
    },
    CommitOracle {
        ir_event: EventId,
        oracle_digest: [u8; 32],
        commitment_digest: [u8; 32],
    },
    QueryOracle {
        ir_event: EventId,
        commitment_digest: [u8; 32],
        positions_digest: [u8; 32],
    },
    OpenOracle {
        ir_event: EventId,
        commitment_digest: [u8; 32],
        positions_digest: [u8; 32],
        values_digest: [u8; 32],
        evidence: Evidence,
    },
    RunSubprotocol {
        ir_event: EventId,
        child: Box<ExecutionTrace>,
    },
    EmitObligation {
        ir_event: EventId,
        obligation: ObligationId,
        value_digest: [u8; 32],
    },
    DischargeObligation {
        ir_event: EventId,
        obligation: ObligationId,
        evidence_digests: Vec<[u8; 32]>,
    },
}

impl TraceEvent {
    /// Returns the `EventId` this trace event realises.
    pub fn ir_event(&self) -> EventId {
        match self {
            TraceEvent::AbsorbPublic { ir_event, .. }
            | TraceEvent::SendMessage { ir_event, .. }
            | TraceEvent::SampleChallenge { ir_event, .. }
            | TraceEvent::CommitOracle { ir_event, .. }
            | TraceEvent::QueryOracle { ir_event, .. }
            | TraceEvent::OpenOracle { ir_event, .. }
            | TraceEvent::RunSubprotocol { ir_event, .. }
            | TraceEvent::EmitObligation { ir_event, .. }
            | TraceEvent::DischargeObligation { ir_event, .. } => *ir_event,
        }
    }

    /// Discriminant kind (for `TraceChecker` event-kind matching).
    pub fn kind(&self) -> &'static str {
        match self {
            TraceEvent::AbsorbPublic { .. } => "AbsorbPublic",
            TraceEvent::SendMessage { .. } => "SendMessage",
            TraceEvent::SampleChallenge { .. } => "SampleChallenge",
            TraceEvent::CommitOracle { .. } => "CommitOracle",
            TraceEvent::QueryOracle { .. } => "QueryOracle",
            TraceEvent::OpenOracle { .. } => "OpenOracle",
            TraceEvent::RunSubprotocol { .. } => "RunSubprotocol",
            TraceEvent::EmitObligation { .. } => "EmitObligation",
            TraceEvent::DischargeObligation { .. } => "DischargeObligation",
        }
    }
}

/// Discriminant kind for an IR `EventNode` — mirrors `TraceEvent::kind`.
fn ir_event_kind(node: &EventNode) -> &'static str {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionTrace {
    /// Must match the `ProtocolIR`'s schema fingerprint, when the IR
    /// is paired with one. Detects schema drift between prover/verifier.
    pub protocol_fingerprint: [u8; 32],
    pub events: Vec<TraceEvent>,
}

impl ExecutionTrace {
    pub fn empty(protocol_fingerprint: [u8; 32]) -> Self {
        Self {
            protocol_fingerprint,
            events: Vec::new(),
        }
    }
}

/// Compiler-consumable proof that an `ExecutionTrace` structurally
/// conforms to a `ProtocolIR`. Only `TraceChecker::check` produces
/// one; the field is private to enforce that compilers can't
/// fabricate validated traces.
#[derive(Debug)]
pub struct ValidatedTrace<'ir> {
    ir: &'ir ProtocolIR,
    trace: ExecutionTrace,
}

impl<'ir> ValidatedTrace<'ir> {
    pub fn ir(&self) -> &'ir ProtocolIR {
        self.ir
    }
    pub fn trace(&self) -> &ExecutionTrace {
        &self.trace
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceError {
    /// Trace has a different number of events than the IR declares.
    EventCountMismatch { ir: usize, trace: usize },
    /// A trace event references an `ir_event` index that doesn't exist.
    InvalidIrEventId { trace_index: usize, ir_event: EventId },
    /// Trace event kind doesn't match the IR event kind at the same index.
    EventKindMismatch {
        trace_index: usize,
        ir_kind: &'static str,
        trace_kind: &'static str,
    },
    /// Trace event's `ir_event` does not equal its trace position
    /// (trace events must appear in IR-declared order).
    OrderingMismatch {
        trace_index: usize,
        ir_event: EventId,
    },
    /// Trace fingerprint doesn't match the IR's schema fingerprint
    /// (caller is responsible for providing the expected fingerprint).
    FingerprintMismatch {
        expected: [u8; 32],
        got: [u8; 32],
    },
    /// An emitted obligation has no matching discharge in the trace.
    ObligationUndischarged { id: ObligationId },
}

/// Validates that the given execution trace structurally conforms to
/// the protocol IR. Returns a `ValidatedTrace` on success.
///
/// This is the audit-class gate. It catches structural drift; it does
/// not validate challenge derivation, oracle opening correctness,
/// witness-dependent control flow, or any semantic property of
/// individual events. Those are deferred to later trace-checker
/// versions or to compiler-stage checks.
pub fn check<'ir>(
    ir: &'ir ProtocolIR,
    expected_fingerprint: [u8; 32],
    trace: ExecutionTrace,
) -> Result<ValidatedTrace<'ir>, TraceError> {
    if trace.protocol_fingerprint != expected_fingerprint {
        return Err(TraceError::FingerprintMismatch {
            expected: expected_fingerprint,
            got: trace.protocol_fingerprint,
        });
    }

    if trace.events.len() != ir.events.len() {
        return Err(TraceError::EventCountMismatch {
            ir: ir.events.len(),
            trace: trace.events.len(),
        });
    }

    let mut emitted_obligations: Vec<ObligationId> = Vec::new();
    let mut discharged_obligations: Vec<ObligationId> = Vec::new();

    for (i, trace_event) in trace.events.iter().enumerate() {
        let ir_id = trace_event.ir_event();
        if ir_id != i {
            return Err(TraceError::OrderingMismatch {
                trace_index: i,
                ir_event: ir_id,
            });
        }
        let ir_node = ir.events.get(ir_id).ok_or(TraceError::InvalidIrEventId {
            trace_index: i,
            ir_event: ir_id,
        })?;
        let ir_kind = ir_event_kind(ir_node);
        let trace_kind = trace_event.kind();
        if ir_kind != trace_kind {
            return Err(TraceError::EventKindMismatch {
                trace_index: i,
                ir_kind,
                trace_kind,
            });
        }

        match trace_event {
            TraceEvent::EmitObligation { obligation, .. } => {
                emitted_obligations.push(obligation.clone());
            }
            TraceEvent::DischargeObligation { obligation, .. } => {
                discharged_obligations.push(obligation.clone());
            }
            _ => {}
        }
    }

    // Each emitted obligation must be discharged OR exported via the
    // IR's `obligations` list (discharger = Some means in-trace
    // discharge expected; discharger = None means exported, no trace
    // entry needed).
    for emitted in &emitted_obligations {
        let in_trace = discharged_obligations.iter().any(|d| d == emitted);
        let exported = ir
            .obligations
            .iter()
            .any(|o| o.id == *emitted && o.discharger.is_none());
        if !in_trace && !exported {
            return Err(TraceError::ObligationUndischarged {
                id: emitted.clone(),
            });
        }
    }

    Ok(ValidatedTrace { ir, trace })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iop::ir::{
        ChallengeDistribution, EventNode, ObligationNode, PortDecl, ProtocolIR, StepNode,
        TypeFingerprint, Visibility,
    };
    use std::borrow::Cow;

    fn dummy_fingerprint() -> [u8; 32] {
        [0xAB; 32]
    }

    /// Smallest possible trace: one SampleChallenge event, matching IR.
    #[test]
    fn checker_passes_minimal_matching_trace() {
        let mut ir = ProtocolIR::empty("MinimalToy");
        ir.events.push(EventNode::SampleChallenge {
            tag: "toy:c",
            output: Cow::Borrowed("a.c"),
            distribution: ChallengeDistribution::Field,
        });
        ir.steps.push(StepNode {
            id: Cow::Borrowed("a"),
            component: Cow::Borrowed("Toy"),
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
            value_digest: [0u8; 32],
        });

        assert!(check(&ir, dummy_fingerprint(), trace).is_ok());
    }

    /// Wrong fingerprint must fail.
    #[test]
    fn checker_rejects_fingerprint_mismatch() {
        let ir = ProtocolIR::empty("X");
        let trace = ExecutionTrace::empty([0u8; 32]);
        let err = check(&ir, dummy_fingerprint(), trace).unwrap_err();
        assert!(matches!(err, TraceError::FingerprintMismatch { .. }));
    }

    /// Trace longer than IR must fail.
    #[test]
    fn checker_rejects_event_count_mismatch() {
        let ir = ProtocolIR::empty("X"); // 0 events
        let mut trace = ExecutionTrace::empty(dummy_fingerprint());
        trace.events.push(TraceEvent::AbsorbPublic {
            ir_event: 0,
            value_digest: [0; 32],
        });
        let err = check(&ir, dummy_fingerprint(), trace).unwrap_err();
        assert!(matches!(err, TraceError::EventCountMismatch { ir: 0, trace: 1 }));
    }

    /// Wrong event kind must fail.
    #[test]
    fn checker_rejects_event_kind_mismatch() {
        let mut ir = ProtocolIR::empty("X");
        ir.events.push(EventNode::SendMessage {
            tag: "x",
            value: Cow::Borrowed("a.v"),
        });

        let mut trace = ExecutionTrace::empty(dummy_fingerprint());
        // Trace claims it's a SampleChallenge — kind mismatch.
        trace.events.push(TraceEvent::SampleChallenge {
            ir_event: 0,
            value_digest: [0; 32],
        });

        let err = check(&ir, dummy_fingerprint(), trace).unwrap_err();
        assert!(matches!(err, TraceError::EventKindMismatch { .. }));
    }

    /// Trace events out of order must fail.
    #[test]
    fn checker_rejects_ordering_mismatch() {
        let mut ir = ProtocolIR::empty("X");
        ir.events.push(EventNode::SendMessage {
            tag: "a",
            value: Cow::Borrowed("a.v"),
        });
        ir.events.push(EventNode::SendMessage {
            tag: "b",
            value: Cow::Borrowed("a.w"),
        });

        let mut trace = ExecutionTrace::empty(dummy_fingerprint());
        // Trace events claim ir_event = 1, 0 — out of order.
        trace.events.push(TraceEvent::SendMessage {
            ir_event: 1,
            value_digest: [0; 32],
        });
        trace.events.push(TraceEvent::SendMessage {
            ir_event: 0,
            value_digest: [0; 32],
        });

        let err = check(&ir, dummy_fingerprint(), trace).unwrap_err();
        assert!(matches!(err, TraceError::OrderingMismatch { trace_index: 0, ir_event: 1 }));
    }

    /// Obligation emitted but not discharged in trace and not
    /// exported in IR must fail.
    #[test]
    fn checker_rejects_undischarged_obligation() {
        let mut ir = ProtocolIR::empty("X");
        ir.events.push(EventNode::EmitObligation {
            tag: "x",
            obligation: Cow::Borrowed("ob1"),
        });
        ir.obligations.push(ObligationNode {
            id: Cow::Borrowed("ob1"),
            emitter: Cow::Borrowed("a"),
            discharger: Some(Cow::Borrowed("b")), // not exported
            semantic_label: Cow::Borrowed("test"),
        });

        let mut trace = ExecutionTrace::empty(dummy_fingerprint());
        trace.events.push(TraceEvent::EmitObligation {
            ir_event: 0,
            obligation: Cow::Borrowed("ob1"),
            value_digest: [0; 32],
        });

        let err = check(&ir, dummy_fingerprint(), trace).unwrap_err();
        assert!(matches!(err, TraceError::ObligationUndischarged { .. }));
    }

    /// Exported obligation (discharger = None) is OK without an
    /// in-trace discharge.
    #[test]
    fn checker_accepts_exported_obligation_without_discharge() {
        let mut ir = ProtocolIR::empty("X");
        ir.events.push(EventNode::EmitObligation {
            tag: "x",
            obligation: Cow::Borrowed("ob1"),
        });
        ir.obligations.push(ObligationNode {
            id: Cow::Borrowed("ob1"),
            emitter: Cow::Borrowed("a"),
            discharger: None, // exported
            semantic_label: Cow::Borrowed("test"),
        });

        let mut trace = ExecutionTrace::empty(dummy_fingerprint());
        trace.events.push(TraceEvent::EmitObligation {
            ir_event: 0,
            obligation: Cow::Borrowed("ob1"),
            value_digest: [0; 32],
        });

        assert!(check(&ir, dummy_fingerprint(), trace).is_ok());
    }

    /// In-trace EmitObligation + DischargeObligation succeeds.
    #[test]
    fn checker_accepts_emit_then_discharge() {
        let mut ir = ProtocolIR::empty("X");
        ir.events.push(EventNode::EmitObligation {
            tag: "x",
            obligation: Cow::Borrowed("ob1"),
        });
        ir.events.push(EventNode::DischargeObligation {
            tag: "x",
            obligation: Cow::Borrowed("ob1"),
            evidence: vec![],
        });
        ir.obligations.push(ObligationNode {
            id: Cow::Borrowed("ob1"),
            emitter: Cow::Borrowed("a"),
            discharger: Some(Cow::Borrowed("b")),
            semantic_label: Cow::Borrowed("test"),
        });

        let mut trace = ExecutionTrace::empty(dummy_fingerprint());
        trace.events.push(TraceEvent::EmitObligation {
            ir_event: 0,
            obligation: Cow::Borrowed("ob1"),
            value_digest: [0; 32],
        });
        trace.events.push(TraceEvent::DischargeObligation {
            ir_event: 1,
            obligation: Cow::Borrowed("ob1"),
            evidence_digests: vec![],
        });

        assert!(check(&ir, dummy_fingerprint(), trace).is_ok());
    }
}
