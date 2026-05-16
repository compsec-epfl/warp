//! Worked IR examples for the universal-framework research arc.
//!
//! Status: **skeleton.** These are research artifacts, not production
//! code. The point of building them is to surface what the IR's type
//! definitions can and can't express, which becomes input to the next
//! design iteration.
//!
//! See `docs/ior-framework-design.md` §11 for the meta-discussion of
//! each example.

use std::borrow::Cow;

use crate::iop::ir::{
    ChallengeDistribution, EventNode, OutputDecl, ParamDecl, PortBinding, PortDecl, ProtocolIR,
    StepNode, TypeFingerprint, Visibility,
};

/// §11.1 — WARP's Pesat IOR expressed as a single-step protocol IR.
///
/// This is the smallest "real" worked example. It surfaces several
/// design tensions that the next IR revision must resolve (see
/// findings in `docs/ior-framework-design.md` §11.1).
///
/// Returned `ProtocolIR` is intentionally a *partial* protocol: just
/// Pesat with the upstream params/private-inputs it needs and the
/// downstream outputs it produces. No wires (single-step). Verifies
/// that the IR types can describe one IOR's full structure.
pub fn warp_pesat_only_ir() -> ProtocolIR {
    let mut ir = ProtocolIR::empty("WarpPesatOnly");

    // ── Params: protocol-wide configuration (code, ck, fold factors).
    ir.params.push(ParamDecl {
        name: Cow::Borrowed("code"),
        ty: TypeFingerprint::of("C: LinearCode<F>"),
    });
    ir.params.push(ParamDecl {
        name: Cow::Borrowed("ck"),
        ty: TypeFingerprint::of("V::CommitterKey"),
    });
    ir.params.push(ParamDecl {
        name: Cow::Borrowed("l1_first_fold_factor"),
        ty: TypeFingerprint::of("usize"),
    });
    ir.params.push(ParamDecl {
        name: Cow::Borrowed("log_m"),
        ty: TypeFingerprint::of("usize"),
    });

    // ── Private input: prover-only witnesses.
    ir.private_inputs.push(PortDecl {
        name: Cow::Borrowed("witnesses"),
        ty: TypeFingerprint::of("Vec<Vec<F>>"),
        visibility: Visibility::ProverPrivate,
    });

    // ── Events: the three transcript-visible actions Pesat performs.
    //
    // FINDING: Pesat *computes* its `codewords` and `mus` from
    // `witnesses` before any transcript event. The IR has no event
    // variant for "internal prover compute" — and probably shouldn't,
    // since internal compute isn't transcript-visible. But the codewords
    // port has to exist as a step output even though no event creates
    // it. The reader has to infer that codewords are derived from
    // witnesses by the component's prove() body. This is exactly the
    // trace-vs-declaration gap (OQ1).
    let e_commit = ir.events.len();
    ir.events.push(EventNode::CommitOracle {
        tag: "pesat:commit_fresh",
        oracle: Cow::Borrowed("pesat.codewords"),
        commitment: Cow::Borrowed("pesat.rt_0_commitment"),
        oracle_interface: Cow::Borrowed("joint_rs_codeword[l1, n]"),
    });
    let e_send_mus = ir.events.len();
    ir.events.push(EventNode::SendMessage {
        tag: "pesat:send_mus",
        value: Cow::Borrowed("pesat.mus_codeword_first_coords"),
    });
    // FINDING: Pesat samples `l1` challenges each of `log_m` field
    // elements (so `l1 * log_m` field elements total, shaped
    // `Vec<Vec<F>>`). The current `ChallengeDistribution` is scalar —
    // Field or Bytes{count} — and has no shape annotation. Encoding
    // "vector-of-vectors of field elements" as a single event loses
    // shape; emitting `l1` events loses the per-step structural
    // boundary. **Open issue:** add structured shape annotations to
    // `SampleChallenge`, e.g., `Field { shape: Shape::Matrix(l1, log_m) }`.
    let e_squeeze_taus = ir.events.len();
    ir.events.push(EventNode::SampleChallenge {
        tag: "pesat:squeeze_taus",
        output: Cow::Borrowed("pesat.taus_zero_check_challenges"),
        distribution: ChallengeDistribution::Field,
    });

    // ── Step node.
    ir.steps.push(StepNode {
        id: Cow::Borrowed("pesat"),
        component: Cow::Borrowed("Pesat"),
        inputs: vec![
            PortBinding {
                input: Cow::Borrowed("code"),
                source: Cow::Borrowed("params.code"),
            },
            PortBinding {
                input: Cow::Borrowed("ck"),
                source: Cow::Borrowed("params.ck"),
            },
            PortBinding {
                input: Cow::Borrowed("l1_first_fold_factor"),
                source: Cow::Borrowed("params.l1_first_fold_factor"),
            },
            PortBinding {
                input: Cow::Borrowed("log_m"),
                source: Cow::Borrowed("params.log_m"),
            },
            PortBinding {
                input: Cow::Borrowed("witnesses"),
                source: Cow::Borrowed("private.witnesses"),
            },
        ],
        outputs: vec![
            // Public reduced-statement outputs.
            PortDecl {
                name: Cow::Borrowed("mus_codeword_first_coords"),
                ty: TypeFingerprint::of("Vec<F>"),
                visibility: Visibility::Public,
            },
            PortDecl {
                name: Cow::Borrowed("taus_zero_check_challenges"),
                ty: TypeFingerprint::of("Vec<Vec<F>>"),
                visibility: Visibility::Public,
            },
            PortDecl {
                name: Cow::Borrowed("rt_0_commitment"),
                ty: TypeFingerprint::of("V::Commitment"),
                visibility: Visibility::Public,
            },
            // Prover-private witness-side outputs threaded to next steps.
            PortDecl {
                name: Cow::Borrowed("codewords"),
                ty: TypeFingerprint::of("Vec<Vec<F>>"),
                visibility: Visibility::ProverPrivate,
            },
            PortDecl {
                name: Cow::Borrowed("td_0_committed_codeword"),
                ty: TypeFingerprint::of("CommittedCodewords<F, V>"),
                visibility: Visibility::ProverPrivate,
            },
        ],
        events: vec![e_commit, e_send_mus, e_squeeze_taus],
    });

    // ── Outputs of the (single-step) protocol.
    //
    // FINDING: every step output also becomes a protocol output here
    // because there's no downstream step to consume them. For a
    // multi-step IR, *some* of these outputs become wires (consumed by
    // later steps) and *some* are exported. The `OutputDecl` /
    // `Wire` distinction is fine but the population logic — "is this
    // output consumed downstream or exported?" — needs a builder.
    for (name, ty, vis) in [
        (
            "mus_codeword_first_coords",
            "Vec<F>",
            Visibility::Public,
        ),
        (
            "taus_zero_check_challenges",
            "Vec<Vec<F>>",
            Visibility::Public,
        ),
        (
            "rt_0_commitment",
            "V::Commitment",
            Visibility::Public,
        ),
        ("codewords", "Vec<Vec<F>>", Visibility::ProverPrivate),
        (
            "td_0_committed_codeword",
            "CommittedCodewords<F, V>",
            Visibility::ProverPrivate,
        ),
    ] {
        ir.outputs.push(OutputDecl {
            name: Cow::Borrowed(name),
            source: Cow::Owned(format!("pesat.{}", name)),
            ty: TypeFingerprint::of(ty),
            visibility: vis,
        });
    }

    ir
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pesat_ir_builds() {
        let ir = warp_pesat_only_ir();
        assert_eq!(ir.name, "WarpPesatOnly");
        assert_eq!(ir.steps.len(), 1);
        assert_eq!(ir.events.len(), 3);
        assert_eq!(ir.outputs.len(), 5);
        assert_eq!(ir.params.len(), 4);
    }

    /// The step's `events` field must reference valid indices into the
    /// protocol's `events` vector. Cheap self-consistency check; the
    /// kind of validation a real builder would enforce automatically.
    #[test]
    fn pesat_step_events_reference_real_events() {
        let ir = warp_pesat_only_ir();
        for step in &ir.steps {
            for &eid in &step.events {
                assert!(
                    eid < ir.events.len(),
                    "step {:?} references event {} but only {} events exist",
                    step.id,
                    eid,
                    ir.events.len()
                );
            }
        }
    }

    /// Every step output port should also appear as a protocol-level
    /// output (since this is a single-step protocol with no
    /// downstream consumers). Catches a class of population bug.
    #[test]
    fn pesat_all_step_outputs_are_protocol_outputs() {
        let ir = warp_pesat_only_ir();
        let step = &ir.steps[0];
        for out_port in &step.outputs {
            assert!(
                ir.outputs.iter().any(|o| o.name == out_port.name),
                "step output {:?} not exported as protocol output",
                out_port.name
            );
        }
    }

    /// Output ports referenced by the protocol's `outputs` must point
    /// to real step output ports.
    #[test]
    fn pesat_output_sources_resolve() {
        let ir = warp_pesat_only_ir();
        for output in &ir.outputs {
            let source: &str = &output.source;
            let (step_id, port_name) = source.split_once('.').expect("source must be step.port");
            let step = ir
                .steps
                .iter()
                .find(|s| s.id == step_id)
                .unwrap_or_else(|| panic!("no step {step_id}"));
            assert!(
                step.outputs.iter().any(|p| p.name == port_name),
                "output {:?} source {} not found in step {} outputs",
                output.name,
                source,
                step_id
            );
        }
    }
}
