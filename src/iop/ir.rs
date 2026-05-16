//! Protocol Intermediate Representation (IR).
//!
//! Compiler-facing value describing a protocol's full structure:
//! steps, wires, events, obligations, outputs. Backend-agnostic.
//!
//! **Status: skeleton.** Type definitions only. No compilation,
//! validation, or builder ergonomics yet. See
//! `docs/ior-framework-design.md` for the framework these belong in,
//! and `docs/ior-framework-direction.md` for what was rejected and
//! why these particular shapes were chosen.
//!
//! Open questions tagged inline:
//! - **OQ2** (wire types): represented here as opaque
//!   [`TypeFingerprint`] strings. Whether to upgrade to a richer
//!   encoding (TypeId, structural fingerprint, type-level HList) is
//!   undecided.
//! - **HQ3** (`V::open_multiple` abstraction): see
//!   [`EventNode::OpenOracle`] — captures commitment / positions /
//!   values / interface, but the abstract notion of "oracle
//!   interface" still needs filling in.
//! - **OQ4** (compile-time vs runtime IR): this module is the
//!   runtime IR. A type-level companion may or may not coexist.

use std::borrow::Cow;

/// Human-readable, FS-domain-separator-friendly label.
pub type Tag = &'static str;

/// Symbolic identifier for any IR object. Stable within one
/// [`ProtocolIR`].
pub type Symbol = Cow<'static, str>;

/// Reference to a port declared somewhere in the protocol.
/// Convention: `"step_id.port_name"` or `"input.name"`.
pub type PortId = Symbol;

pub type StepId = Symbol;
pub type ObligationId = Symbol;

/// Reference to an oracle-interface definition (e.g., "codeword
/// over RS code with degree bound d"). The concrete shape of an
/// oracle interface is **HQ3** and is intentionally not specified
/// here yet.
pub type OracleInterfaceId = Symbol;

/// Index into a [`ProtocolIR::events`] vector.
pub type EventId = usize;

/// Wire / port visibility. Public ports affect the transcript;
/// prover-private ports do not.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Visibility {
    Public,
    ProverPrivate,
}

/// **OQ2 placeholder.** Right now a wire's type is just a string —
/// "Vec<F>", "V::Commitment", etc. Loses type safety. A real
/// framework needs structural fingerprinting, `TypeId` (where
/// applicable), or a type-level encoding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TypeFingerprint(pub Cow<'static, str>);

impl TypeFingerprint {
    pub fn of(name: impl Into<Cow<'static, str>>) -> Self {
        Self(name.into())
    }
}

/// Declaration of a typed slot on a step's input or output side.
#[derive(Clone, Debug)]
pub struct PortDecl {
    pub name: Symbol,
    pub ty: TypeFingerprint,
    pub visibility: Visibility,
}

/// Binding of a step's input port to the upstream source supplying
/// it. The source is another step's output port, an input of the
/// whole protocol, or a parameter.
#[derive(Clone, Debug)]
pub struct PortBinding {
    pub input: Symbol,
    pub source: PortId,
}

/// One step: a concrete IOR component invocation in the protocol.
#[derive(Clone, Debug)]
pub struct StepNode {
    pub id: StepId,
    /// Name of the IOR component this step instantiates (e.g.,
    /// "Pesat", "TwinConstraint"). The mapping from component name
    /// to a concrete IOR impl is the framework's responsibility.
    pub component: Symbol,
    pub inputs: Vec<PortBinding>,
    pub outputs: Vec<PortDecl>,
    /// Indices into the protocol's `events` list. The compiler
    /// emits these in declared order when running this step.
    pub events: Vec<EventId>,
}

/// Typed connection between an output port and a downstream input.
/// The protocol's dataflow graph.
#[derive(Clone, Debug)]
pub struct Wire {
    pub from: PortId,
    pub to: PortId,
    pub ty: TypeFingerprint,
    pub visibility: Visibility,
}

/// Distribution from which a challenge is sampled. Field-element
/// challenges are most common; byte challenges occur for query
/// indices (SampleQueries-style).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ChallengeDistribution {
    Field,
    Bytes { count: usize },
}

/// One transcript / oracle / subprotocol event a step emits.
/// Compilers (FS, BCS) interpret these per backend.
#[derive(Clone, Debug)]
pub enum EventNode {
    /// Absorb a public value (parameter, public input, prior public
    /// state) into the FS sponge.
    AbsorbPublic { tag: Tag, value: PortId },

    /// Prover writes a message. Verifier reads it back. Affects FS
    /// state on both sides.
    SendMessage { tag: Tag, value: PortId },

    /// Verifier samples a challenge from the sponge / random oracle.
    SampleChallenge {
        tag: Tag,
        output: PortId,
        distribution: ChallengeDistribution,
    },

    /// Commit to an oracle (e.g., a codeword). The commitment port
    /// becomes available to subsequent steps.
    CommitOracle {
        tag: Tag,
        oracle: PortId,
        commitment: PortId,
        oracle_interface: OracleInterfaceId,
    },

    /// (Verifier-side) request value(s) at queried positions of a
    /// previously committed oracle.
    QueryOracle {
        tag: Tag,
        commitment: PortId,
        positions: PortId,
        oracle_interface: OracleInterfaceId,
    },

    /// (Prover-side / orchestrator-side) emit opening material
    /// (auth paths) at queried positions of a previously committed
    /// oracle. The verifier consumes these from the transcript via
    /// the corresponding `QueryOracle`.
    OpenOracle {
        tag: Tag,
        commitment: PortId,
        positions: PortId,
        values: PortId,
        oracle_interface: OracleInterfaceId,
    },

    /// Nested protocol run (e.g., a sumcheck subprotocol whose own
    /// events are described by a child IR). The integration story
    /// for `effsc::sumcheck` lives here — see §6 of the design doc.
    RunSubprotocol {
        tag: Tag,
        child: Box<ProtocolIR>,
    },

    /// Emit a deferred check obligation. Must be discharged by some
    /// later step's `DischargeObligation` event or exported as part
    /// of the protocol's output.
    EmitObligation {
        tag: Tag,
        obligation: ObligationId,
    },

    /// Discharge a previously emitted obligation, attaching any
    /// evidence ports the check consumes.
    DischargeObligation {
        tag: Tag,
        obligation: ObligationId,
        evidence: Vec<PortId>,
    },
}

/// A deferred check: emitted by one step, discharged by another (or
/// exported via the protocol's outputs).
#[derive(Clone, Debug)]
pub struct ObligationNode {
    pub id: ObligationId,
    pub emitter: StepId,
    /// `None` if the obligation is exported rather than discharged.
    pub discharger: Option<StepId>,
    pub semantic_label: Symbol,
}

/// Output port of the whole protocol: maps a protocol-level name to
/// a port inside some step (or to an input port that's threaded
/// through unchanged).
#[derive(Clone, Debug)]
pub struct OutputDecl {
    pub name: Symbol,
    pub source: PortId,
    pub ty: TypeFingerprint,
    pub visibility: Visibility,
}

/// A protocol-level parameter (e.g., the code, the committer key).
/// Available throughout the protocol but is not itself a transcript
/// event.
#[derive(Clone, Debug)]
pub struct ParamDecl {
    pub name: Symbol,
    pub ty: TypeFingerprint,
}

/// The full Protocol IR. Compiler-facing value.
#[derive(Clone, Debug)]
pub struct ProtocolIR {
    pub name: Symbol,
    pub params: Vec<ParamDecl>,
    pub public_inputs: Vec<PortDecl>,
    pub private_inputs: Vec<PortDecl>,
    pub steps: Vec<StepNode>,
    pub wires: Vec<Wire>,
    pub events: Vec<EventNode>,
    pub obligations: Vec<ObligationNode>,
    pub outputs: Vec<OutputDecl>,
}

impl ProtocolIR {
    pub fn empty(name: impl Into<Symbol>) -> Self {
        Self {
            name: name.into(),
            params: vec![],
            public_inputs: vec![],
            private_inputs: vec![],
            steps: vec![],
            wires: vec![],
            events: vec![],
            obligations: vec![],
            outputs: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smallest possible IR: one step that samples one challenge.
    /// Confirms the type definitions compose.
    #[test]
    fn build_minimal_ir() {
        let mut ir = ProtocolIR::empty("MinimalToy");

        let event_id = ir.events.len();
        ir.events.push(EventNode::SampleChallenge {
            tag: "minimal:rho",
            output: Cow::Borrowed("step_a.rho"),
            distribution: ChallengeDistribution::Field,
        });

        ir.steps.push(StepNode {
            id: Cow::Borrowed("step_a"),
            component: Cow::Borrowed("ToyChallengeSampler"),
            inputs: vec![],
            outputs: vec![PortDecl {
                name: Cow::Borrowed("rho"),
                ty: TypeFingerprint::of("F"),
                visibility: Visibility::Public,
            }],
            events: vec![event_id],
        });

        ir.outputs.push(OutputDecl {
            name: Cow::Borrowed("rho"),
            source: Cow::Borrowed("step_a.rho"),
            ty: TypeFingerprint::of("F"),
            visibility: Visibility::Public,
        });

        assert_eq!(ir.steps.len(), 1);
        assert_eq!(ir.events.len(), 1);
        assert_eq!(ir.outputs.len(), 1);
    }

    /// Two steps with a cross-wire: validates wires + multi-step IR
    /// shape. Step A samples `tau`; step B consumes it via a wire.
    #[test]
    fn build_two_step_ir_with_wire() {
        let mut ir = ProtocolIR::empty("TwoStepToy");

        // Step A: sample challenge.
        let e0 = ir.events.len();
        ir.events.push(EventNode::SampleChallenge {
            tag: "toy:tau",
            output: Cow::Borrowed("a.tau"),
            distribution: ChallengeDistribution::Field,
        });
        ir.steps.push(StepNode {
            id: Cow::Borrowed("a"),
            component: Cow::Borrowed("Sampler"),
            inputs: vec![],
            outputs: vec![PortDecl {
                name: Cow::Borrowed("tau"),
                ty: TypeFingerprint::of("F"),
                visibility: Visibility::Public,
            }],
            events: vec![e0],
        });

        // Step B: consume tau via a wire, send a prover message.
        let e1 = ir.events.len();
        ir.events.push(EventNode::SendMessage {
            tag: "toy:msg",
            value: Cow::Borrowed("b.msg"),
        });
        ir.steps.push(StepNode {
            id: Cow::Borrowed("b"),
            component: Cow::Borrowed("Consumer"),
            inputs: vec![PortBinding {
                input: Cow::Borrowed("tau"),
                source: Cow::Borrowed("a.tau"),
            }],
            outputs: vec![PortDecl {
                name: Cow::Borrowed("msg"),
                ty: TypeFingerprint::of("F"),
                visibility: Visibility::Public,
            }],
            events: vec![e1],
        });

        ir.wires.push(Wire {
            from: Cow::Borrowed("a.tau"),
            to: Cow::Borrowed("b.tau"),
            ty: TypeFingerprint::of("F"),
            visibility: Visibility::Public,
        });

        assert_eq!(ir.steps.len(), 2);
        assert_eq!(ir.wires.len(), 1);
        assert_eq!(ir.events.len(), 2);
    }

    /// IR with a deferred obligation: step A emits, step B
    /// discharges. The pattern WARP's TwinConstraint → Bridge uses.
    #[test]
    fn build_ir_with_obligation() {
        let mut ir = ProtocolIR::empty("ObligationToy");

        // Step A: emit obligation.
        let e_emit = ir.events.len();
        ir.events.push(EventNode::EmitObligation {
            tag: "toy:deferred",
            obligation: Cow::Borrowed("deferred_check"),
        });
        ir.steps.push(StepNode {
            id: Cow::Borrowed("a"),
            component: Cow::Borrowed("Emitter"),
            inputs: vec![],
            outputs: vec![],
            events: vec![e_emit],
        });

        // Step B: discharge obligation with evidence.
        let e_discharge = ir.events.len();
        ir.events.push(EventNode::DischargeObligation {
            tag: "toy:discharge",
            obligation: Cow::Borrowed("deferred_check"),
            evidence: vec![Cow::Borrowed("b.witness")],
        });
        ir.steps.push(StepNode {
            id: Cow::Borrowed("b"),
            component: Cow::Borrowed("Discharger"),
            inputs: vec![],
            outputs: vec![PortDecl {
                name: Cow::Borrowed("witness"),
                ty: TypeFingerprint::of("F"),
                visibility: Visibility::ProverPrivate,
            }],
            events: vec![e_discharge],
        });

        ir.obligations.push(ObligationNode {
            id: Cow::Borrowed("deferred_check"),
            emitter: Cow::Borrowed("a"),
            discharger: Some(Cow::Borrowed("b")),
            semantic_label: Cow::Borrowed("deferred algebraic check"),
        });

        assert_eq!(ir.obligations.len(), 1);
        let obl = &ir.obligations[0];
        assert_eq!(obl.emitter, "a");
        assert_eq!(obl.discharger.as_deref(), Some("b"));
    }
}
