//! Builder API for `ProtocolIR`. Addresses finding F5 (imperative
//! population is tedious) without committing to a macro DSL.
//!
//! Two builders:
//! - [`ProtocolIrBuilder`]: top-level. Owns the in-progress IR.
//!   Method chaining for params, public/private inputs, wires,
//!   outputs, obligations. Returns step sub-builders.
//! - [`StepBuilder`]: scoped to one step. Method chaining for the
//!   step's inputs, outputs, and events. Pushes events to the
//!   parent IR's `events` vector as they're declared, tracking
//!   their indices in the step's own event list.
//!
//! Status: skeleton. No validation built in (a `ProtocolIR` produced
//! by the builder may still fail `TraceChecker` invariants — the
//! builder is sugar, not a verifier).

use std::borrow::Cow;

use crate::iop::ir::{
    ChallengeDistribution, EventId, EventNode, ObligationId, ObligationNode, OutputDecl, ParamDecl,
    PortBinding, PortDecl, PortId, ProtocolIR, StepId, StepNode, Symbol, Tag, TypeFingerprint,
    Visibility, Wire,
};

/// Top-level builder for a [`ProtocolIR`].
pub struct ProtocolIrBuilder {
    ir: ProtocolIR,
}

impl ProtocolIrBuilder {
    pub fn new(name: impl Into<Symbol>) -> Self {
        Self {
            ir: ProtocolIR::empty(name),
        }
    }

    pub fn param(&mut self, name: impl Into<Symbol>, ty: impl Into<Symbol>) -> &mut Self {
        self.ir.params.push(ParamDecl {
            name: name.into(),
            ty: TypeFingerprint(ty.into()),
        });
        self
    }

    pub fn public_input(
        &mut self,
        name: impl Into<Symbol>,
        ty: impl Into<Symbol>,
    ) -> &mut Self {
        self.ir.public_inputs.push(PortDecl {
            name: name.into(),
            ty: TypeFingerprint(ty.into()),
            visibility: Visibility::Public,
        });
        self
    }

    pub fn private_input(
        &mut self,
        name: impl Into<Symbol>,
        ty: impl Into<Symbol>,
    ) -> &mut Self {
        self.ir.private_inputs.push(PortDecl {
            name: name.into(),
            ty: TypeFingerprint(ty.into()),
            visibility: Visibility::ProverPrivate,
        });
        self
    }

    pub fn wire(
        &mut self,
        from: impl Into<PortId>,
        to: impl Into<PortId>,
        ty: impl Into<Symbol>,
        visibility: Visibility,
    ) -> &mut Self {
        self.ir.wires.push(Wire {
            from: from.into(),
            to: to.into(),
            ty: TypeFingerprint(ty.into()),
            visibility,
        });
        self
    }

    pub fn output(
        &mut self,
        name: impl Into<Symbol>,
        source: impl Into<PortId>,
        ty: impl Into<Symbol>,
        visibility: Visibility,
    ) -> &mut Self {
        self.ir.outputs.push(OutputDecl {
            name: name.into(),
            source: source.into(),
            ty: TypeFingerprint(ty.into()),
            visibility,
        });
        self
    }

    pub fn obligation(
        &mut self,
        id: impl Into<ObligationId>,
        emitter: impl Into<StepId>,
        discharger: Option<Symbol>,
        label: impl Into<Symbol>,
    ) -> &mut Self {
        self.ir.obligations.push(ObligationNode {
            id: id.into(),
            emitter: emitter.into(),
            discharger,
            semantic_label: label.into(),
        });
        self
    }

    pub fn step(
        &mut self,
        id: impl Into<StepId>,
        component: impl Into<Symbol>,
    ) -> StepBuilder<'_> {
        StepBuilder {
            builder: self,
            id: id.into(),
            component: component.into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            event_ids: Vec::new(),
        }
    }

    pub fn finish(self) -> ProtocolIR {
        self.ir
    }
}

/// Sub-builder for one step. Pushes events to the parent IR's
/// `events` vector as they're declared; tracks their indices.
/// Call `build()` to commit the step to the parent IR.
pub struct StepBuilder<'a> {
    builder: &'a mut ProtocolIrBuilder,
    id: StepId,
    component: Symbol,
    inputs: Vec<PortBinding>,
    outputs: Vec<PortDecl>,
    event_ids: Vec<EventId>,
}

impl<'a> StepBuilder<'a> {
    pub fn input(
        mut self,
        name: impl Into<Symbol>,
        source: impl Into<PortId>,
    ) -> Self {
        self.inputs.push(PortBinding {
            input: name.into(),
            source: source.into(),
        });
        self
    }

    pub fn output(
        mut self,
        name: impl Into<Symbol>,
        ty: impl Into<Symbol>,
        visibility: Visibility,
    ) -> Self {
        self.outputs.push(PortDecl {
            name: name.into(),
            ty: TypeFingerprint(ty.into()),
            visibility,
        });
        self
    }

    fn push_event(&mut self, event: EventNode) -> EventId {
        let id = self.builder.ir.events.len();
        self.builder.ir.events.push(event);
        self.event_ids.push(id);
        id
    }

    pub fn absorb_public(mut self, tag: Tag, value: impl Into<PortId>) -> Self {
        self.push_event(EventNode::AbsorbPublic {
            tag,
            value: value.into(),
        });
        self
    }

    pub fn send_message(mut self, tag: Tag, value: impl Into<PortId>) -> Self {
        self.push_event(EventNode::SendMessage {
            tag,
            value: value.into(),
        });
        self
    }

    pub fn sample_challenge(
        mut self,
        tag: Tag,
        output: impl Into<PortId>,
        distribution: ChallengeDistribution,
    ) -> Self {
        self.push_event(EventNode::SampleChallenge {
            tag,
            output: output.into(),
            distribution,
        });
        self
    }

    pub fn commit_oracle(
        mut self,
        tag: Tag,
        oracle: impl Into<PortId>,
        commitment: impl Into<PortId>,
        oracle_interface: impl Into<Symbol>,
    ) -> Self {
        self.push_event(EventNode::CommitOracle {
            tag,
            oracle: oracle.into(),
            commitment: commitment.into(),
            oracle_interface: oracle_interface.into(),
        });
        self
    }

    pub fn query_oracle(
        mut self,
        tag: Tag,
        commitment: impl Into<PortId>,
        positions: impl Into<PortId>,
        oracle_interface: impl Into<Symbol>,
    ) -> Self {
        self.push_event(EventNode::QueryOracle {
            tag,
            commitment: commitment.into(),
            positions: positions.into(),
            oracle_interface: oracle_interface.into(),
        });
        self
    }

    pub fn open_oracle(
        mut self,
        tag: Tag,
        commitment: impl Into<PortId>,
        positions: impl Into<PortId>,
        values: impl Into<PortId>,
        oracle_interface: impl Into<Symbol>,
    ) -> Self {
        self.push_event(EventNode::OpenOracle {
            tag,
            commitment: commitment.into(),
            positions: positions.into(),
            values: values.into(),
            oracle_interface: oracle_interface.into(),
        });
        self
    }

    pub fn run_subprotocol(mut self, tag: Tag, child: ProtocolIR) -> Self {
        self.push_event(EventNode::RunSubprotocol {
            tag,
            child: Box::new(child),
        });
        self
    }

    pub fn emit_obligation(
        mut self,
        tag: Tag,
        obligation: impl Into<ObligationId>,
    ) -> Self {
        self.push_event(EventNode::EmitObligation {
            tag,
            obligation: obligation.into(),
        });
        self
    }

    pub fn discharge_obligation(
        mut self,
        tag: Tag,
        obligation: impl Into<ObligationId>,
        evidence: Vec<PortId>,
    ) -> Self {
        self.push_event(EventNode::DischargeObligation {
            tag,
            obligation: obligation.into(),
            evidence,
        });
        self
    }

    pub fn build(self) {
        self.builder.ir.steps.push(StepNode {
            id: self.id,
            component: self.component,
            inputs: self.inputs,
            outputs: self.outputs,
            events: self.event_ids,
        });
    }
}

// Allow `&'static str` to flow into `Symbol` directly via Into.
impl From<&'static str> for TypeFingerprint {
    fn from(s: &'static str) -> Self {
        TypeFingerprint(Cow::Borrowed(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The builder produces a valid `ProtocolIR` for the smallest
    /// case: one step with one event.
    #[test]
    fn builder_one_step_one_event() {
        let mut b = ProtocolIrBuilder::new("MinimalToy");
        b.param("n", "usize");
        b.step("a", "ToyChallengeSampler")
            .output("c", "F", Visibility::Public)
            .sample_challenge("toy:c", "a.c", ChallengeDistribution::Field)
            .build();
        b.output("c", "a.c", "F", Visibility::Public);
        let ir = b.finish();

        assert_eq!(ir.name, "MinimalToy");
        assert_eq!(ir.steps.len(), 1);
        assert_eq!(ir.events.len(), 1);
        assert_eq!(ir.steps[0].event_ids_len(), 1);
        assert_eq!(ir.outputs.len(), 1);
    }

    /// The builder produces a valid `ProtocolIR` for two steps with
    /// a cross-wire and obligation. Mirrors the manual two-step IR
    /// test in `iop::ir::tests`.
    #[test]
    fn builder_two_steps_with_wire_and_obligation() {
        let mut b = ProtocolIrBuilder::new("ObligationToy");

        b.step("a", "Emitter")
            .emit_obligation("toy:emit", "ob1")
            .build();
        b.step("b", "Discharger")
            .output("witness", "F", Visibility::ProverPrivate)
            .discharge_obligation(
                "toy:discharge",
                "ob1",
                vec![Cow::Borrowed("b.witness")],
            )
            .build();

        b.obligation(
            "ob1",
            "a",
            Some(Cow::Borrowed("b")),
            "deferred check",
        );

        let ir = b.finish();
        assert_eq!(ir.steps.len(), 2);
        assert_eq!(ir.events.len(), 2);
        assert_eq!(ir.obligations.len(), 1);
        assert_eq!(ir.obligations[0].emitter, "a");
        assert_eq!(ir.obligations[0].discharger.as_deref(), Some("b"));
    }

    /// Builder allows nested subprotocol via `run_subprotocol`.
    #[test]
    fn builder_supports_subprotocol_nesting() {
        // Inner child IR.
        let mut inner = ProtocolIrBuilder::new("InnerToy");
        inner
            .step("x", "InnerStep")
            .sample_challenge("inner:c", "x.c", ChallengeDistribution::Field)
            .build();
        let inner_ir = inner.finish();

        // Outer IR with a RunSubprotocol pointing at inner.
        let mut outer = ProtocolIrBuilder::new("OuterToy");
        outer
            .step("a", "OuterStep")
            .run_subprotocol("outer:run_inner", inner_ir)
            .build();
        let outer_ir = outer.finish();

        assert_eq!(outer_ir.events.len(), 1);
        match &outer_ir.events[0] {
            EventNode::RunSubprotocol { child, .. } => {
                assert_eq!(child.name, "InnerToy");
                assert_eq!(child.events.len(), 1);
            }
            _ => panic!("expected RunSubprotocol"),
        }
    }
}

// --- helper trait so the test above doesn't depend on private state ---
impl StepNode {
    fn event_ids_len(&self) -> usize {
        self.events.len()
    }
}
