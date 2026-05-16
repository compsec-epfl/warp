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

/// §11.2 first half — `SumcheckIOR` expressed as a ProtocolIR
/// parameterised by `num_rounds`.
///
/// Per design doc §6 decision (Option D): SumcheckIOR is defined IN
/// the framework. Effsc is refactored to be one high-performance
/// implementation of it; effsc's own transcript trait is removed.
/// This IR sketch is the framework-canonical declaration that any
/// implementation (effsc-backed, toy, future) must match.
///
/// At IR-construction time `num_rounds` is concrete. Each round
/// generates two events: `SendMessage` (round polynomial coeffs)
/// then `SampleChallenge` (round challenge). For `num_rounds = N`
/// the IR has `2N` events.
///
/// The returned ProtocolIR is intended to be embedded inside an
/// outer IOR's `RunSubprotocol` child rather than run standalone —
/// but it is a valid standalone IR.
pub fn warp_sumcheck_ior(num_rounds: usize, degree: usize) -> ProtocolIR {
    let mut ir = ProtocolIR::empty("SumcheckIOR");

    ir.params.push(ParamDecl {
        name: Cow::Borrowed("num_rounds"),
        ty: TypeFingerprint::of("usize"),
    });
    ir.params.push(ParamDecl {
        name: Cow::Borrowed("degree"),
        ty: TypeFingerprint::of("usize"),
    });
    ir.public_inputs.push(PortDecl {
        name: Cow::Borrowed("claim"),
        ty: TypeFingerprint::of("F"),
        visibility: Visibility::Public,
    });
    ir.private_inputs.push(PortDecl {
        name: Cow::Borrowed("polynomial"),
        ty: TypeFingerprint::of("MultilinearOrTablewisePoly<F>"),
        visibility: Visibility::ProverPrivate,
    });

    // Per-round events: SendMessage(round_poly) → SampleChallenge(chal).
    //
    // FINDING F7: For `num_rounds = N`, the IR contains `2N` events. No
    // loop construct in the IR itself — recursion lives in the
    // SumcheckIOR-as-subprotocol abstraction. This is the right
    // factoring (a generic Loop event would be more powerful but less
    // type-checkable); the cost is IR size scales linearly with rounds.
    let mut step_events = Vec::with_capacity(num_rounds * 2);
    let mut step_outputs = Vec::with_capacity(num_rounds + 1);
    for i in 0..num_rounds {
        let e_send = ir.events.len();
        ir.events.push(EventNode::SendMessage {
            tag: "sumcheck:round_poly",
            value: Cow::Owned(format!("sumcheck.round_poly_{}", i)),
        });
        step_events.push(e_send);

        let e_chal = ir.events.len();
        ir.events.push(EventNode::SampleChallenge {
            tag: "sumcheck:round_chal",
            output: Cow::Owned(format!("sumcheck.chal_{}", i)),
            distribution: ChallengeDistribution::Field,
        });
        step_events.push(e_chal);

        // FINDING F8: Each round needs TWO output ports (round_poly,
        // chal_i). For N rounds that's 2N ports declared, all named
        // with index suffixes. Without shape annotations (F2's open
        // issue) we can't express "Vec<F> indexed by round."
        step_outputs.push(PortDecl {
            name: Cow::Owned(format!("round_poly_{}", i)),
            ty: TypeFingerprint::of("Vec<F>  // degree+1 coeffs"),
            visibility: Visibility::Public,
        });
        step_outputs.push(PortDecl {
            name: Cow::Owned(format!("chal_{}", i)),
            ty: TypeFingerprint::of("F"),
            visibility: Visibility::Public,
        });
    }

    // Final reduced-statement ports.
    step_outputs.push(PortDecl {
        name: Cow::Borrowed("final_claim"),
        ty: TypeFingerprint::of("F"),
        visibility: Visibility::Public,
    });
    step_outputs.push(PortDecl {
        name: Cow::Borrowed("challenges"),
        ty: TypeFingerprint::of("Vec<F>  // length = num_rounds"),
        visibility: Visibility::Public,
    });

    ir.steps.push(StepNode {
        id: Cow::Borrowed("sumcheck"),
        component: Cow::Borrowed("SumcheckIOR"),
        inputs: vec![
            PortBinding {
                input: Cow::Borrowed("claim"),
                source: Cow::Borrowed("public.claim"),
            },
            PortBinding {
                input: Cow::Borrowed("polynomial"),
                source: Cow::Borrowed("private.polynomial"),
            },
        ],
        outputs: step_outputs,
        events: step_events,
    });

    ir.outputs.push(OutputDecl {
        name: Cow::Borrowed("final_claim"),
        source: Cow::Borrowed("sumcheck.final_claim"),
        ty: TypeFingerprint::of("F"),
        visibility: Visibility::Public,
    });
    ir.outputs.push(OutputDecl {
        name: Cow::Borrowed("challenges"),
        source: Cow::Borrowed("sumcheck.challenges"),
        ty: TypeFingerprint::of("Vec<F>"),
        visibility: Visibility::Public,
    });

    // Mark unused param to keep signature honest; degree is consumed
    // by the implementation's polynomial-round-coefficient computation
    // but doesn't appear in the IR-event structure beyond as parameter.
    let _ = degree;

    ir
}

/// §11.2 — WARP's `TwinConstraint` IOR expressed as a multi-step IR
/// using the [`ProtocolIrBuilder`]. Stresses:
/// - cross-step wires (consumes Pesat's `mus_codeword_first_coords`
///   and `taus_zero_check_challenges`)
/// - `RunSubprotocol` with an embedded `SumcheckIOR` child IR
/// - `EmitObligation` for the deferred oracle-check Bridge later
///   discharges
///
/// `log_l` and `tc_degree` are the sumcheck dimensions (log of the
/// total fold factor and the sumcheck polynomial's per-round degree
/// respectively).
pub fn warp_twin_constraint_ior(log_l: usize, tc_degree: usize) -> ProtocolIR {
    use crate::iop::ir_builder::ProtocolIrBuilder;

    let mut b = ProtocolIrBuilder::new("WarpTwinConstraint");

    // Parameters wired in by the outer protocol.
    b.param("log_l", "usize")
        .param("tc_degree", "usize")
        .param("log_m", "usize")
        .param("l", "usize"); // total fold factor

    // Public inputs consumed from upstream IORs (Pesat's reduced
    // statement) and from the accumulator instance.
    b.public_input("pesat.mus_codeword_first_coords", "Vec<F>")
        .public_input("pesat.taus_zero_check_challenges", "Vec<Vec<F>>")
        .public_input("acc_instance.alpha_fold_vectors", "Vec<Vec<F>>")
        .public_input("acc_instance.mu_claimed_evals", "Vec<F>");

    // Private inputs: prover-side codewords from Pesat + accumulators.
    b.private_input("pesat.codewords", "Vec<Vec<F>>")
        .private_input("acc_witness.codewords", "Vec<Vec<F>>");

    // The SumcheckIOR child IR — built once at IR-construction time
    // for a specific `log_l`. The framework decision (§6 sub-fork)
    // makes sumcheck a first-class IR component embedded here via
    // RunSubprotocol.
    let sumcheck_child = warp_sumcheck_ior(log_l, tc_degree);

    // FINDING F9: The SumcheckIOR child IR is opaque to TwinConstraint's
    // own wires. Its outputs (`final_claim`, `challenges`) are
    // referenced via the RunSubprotocol event, but there's no wire
    // mechanism between outer-IR ports and inner-IR ports yet. The
    // framework needs a convention: subprotocol outputs are
    // "extracted" back into the outer IR via a synthetic port.
    // Sketched here as `twin.gamma_sumcheck_*` outputs on the step.

    b.step("twin_constraint", "TwinConstraint")
        .input("mus", "input.pesat.mus_codeword_first_coords")
        .input("taus", "input.pesat.taus_zero_check_challenges")
        .input("alpha", "input.acc_instance.alpha_fold_vectors")
        .input("acc_mu", "input.acc_instance.mu_claimed_evals")
        .input("fresh_codewords", "input.pesat.codewords")
        .input("acc_codewords", "input.acc_witness.codewords")
        // Public reduced-statement outputs.
        .output("zeta_0", "Vec<F>", Visibility::Public)
        .output("beta_tau", "Vec<F>", Visibility::Public)
        .output("gamma_sumcheck_challenges", "Vec<F>", Visibility::Public)
        .output("final_claim", "F", Visibility::Public)
        // Prover-private outputs threaded to later IORs.
        .output("f_oracle", "Oracle<F>", Visibility::ProverPrivate)
        .output("z_witness_assignment", "Vec<F>", Visibility::ProverPrivate)
        // Sample omega challenge (global combination).
        .sample_challenge(
            "twin_constraint:squeeze_omega",
            "twin_constraint.omega",
            ChallengeDistribution::Field,
        )
        // Sample tau (per-step folding challenge).
        .sample_challenge(
            "twin_constraint:squeeze_tau",
            "twin_constraint.beta_tau",
            ChallengeDistribution::Field,
        )
        // Run the sumcheck subprotocol. The child IR has its own
        // event sequence (2 * log_l events); from TwinConstraint's
        // perspective it's a single RunSubprotocol event.
        .run_subprotocol("twin_constraint:gamma_sumcheck", sumcheck_child)
        // Emit the deferred obligation. Bridge will discharge it
        // by computing `eq(τ,γ)·(ν₀ + ω·η)` and comparing to
        // final_claim. The obligation's "data" (gamma challenges,
        // final claim) is exposed via the step's outputs above; the
        // event itself just names the obligation.
        .emit_obligation(
            "twin_constraint:emit_deferred",
            "tc_deferred_oracle_check",
        )
        .build();

    // Register the obligation with its discharger.
    b.obligation(
        "tc_deferred_oracle_check",
        "twin_constraint",
        Some(Cow::Borrowed("bridge")),
        "post-sumcheck oracle-eval equality check",
    );

    // Outputs of the TwinConstraint slice of the protocol.
    for (name, ty, vis) in [
        ("zeta_0", "Vec<F>", Visibility::Public),
        ("beta_tau", "Vec<F>", Visibility::Public),
        (
            "gamma_sumcheck_challenges",
            "Vec<F>",
            Visibility::Public,
        ),
        ("final_claim", "F", Visibility::Public),
        ("f_oracle", "Oracle<F>", Visibility::ProverPrivate),
        (
            "z_witness_assignment",
            "Vec<F>",
            Visibility::ProverPrivate,
        ),
    ] {
        b.output(
            Cow::Borrowed(name),
            Cow::Owned(format!("twin_constraint.{}", name)),
            ty,
            vis,
        );
    }

    b.finish()
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

    /// SumcheckIOR with `num_rounds = 4` should have `8` events
    /// (4 sends + 4 challenges) plus the right output cardinality.
    #[test]
    fn sumcheck_ir_event_count_scales_linearly() {
        let ir = warp_sumcheck_ior(4, 2);
        assert_eq!(ir.events.len(), 8);
        assert_eq!(ir.steps.len(), 1);
        let step = &ir.steps[0];
        assert_eq!(step.events.len(), 8);
        // 4 round_poly + 4 chal + 2 final = 10 output ports.
        assert_eq!(step.outputs.len(), 10);
    }

    /// SumcheckIOR with 0 rounds is degenerate but should still build.
    #[test]
    fn sumcheck_ir_zero_rounds_builds() {
        let ir = warp_sumcheck_ior(0, 0);
        assert_eq!(ir.events.len(), 0);
        // Only the final_claim + challenges ports remain.
        assert_eq!(ir.steps[0].outputs.len(), 2);
    }

    /// SumcheckIOR's event sequence must alternate send → challenge.
    /// This is the per-round protocol invariant.
    #[test]
    fn sumcheck_ir_events_alternate_send_challenge() {
        let ir = warp_sumcheck_ior(3, 2);
        for (i, event) in ir.events.iter().enumerate() {
            if i % 2 == 0 {
                assert!(
                    matches!(event, EventNode::SendMessage { .. }),
                    "event {i} should be SendMessage, got {event:?}"
                );
            } else {
                assert!(
                    matches!(event, EventNode::SampleChallenge { .. }),
                    "event {i} should be SampleChallenge, got {event:?}"
                );
            }
        }
    }

    /// TwinConstraint IR builds and exposes the expected event
    /// shape: 2 challenges + 1 subprotocol + 1 obligation = 4 events.
    #[test]
    fn twin_constraint_ir_builds() {
        let ir = warp_twin_constraint_ior(/* log_l = */ 4, /* tc_degree = */ 3);
        assert_eq!(ir.name, "WarpTwinConstraint");
        assert_eq!(ir.steps.len(), 1);
        assert_eq!(ir.events.len(), 4); // omega, tau, sumcheck, emit
        assert_eq!(ir.obligations.len(), 1);
        assert_eq!(ir.obligations[0].id, "tc_deferred_oracle_check");
    }

    /// The embedded SumcheckIOR child is reachable from the
    /// RunSubprotocol event and has its own event sequence
    /// (2 * log_l events).
    #[test]
    fn twin_constraint_ir_embeds_sumcheck_child() {
        let log_l = 5;
        let ir = warp_twin_constraint_ior(log_l, 2);

        // Find the RunSubprotocol event.
        let child_ir = ir
            .events
            .iter()
            .find_map(|e| match e {
                EventNode::RunSubprotocol { child, .. } => Some(child),
                _ => None,
            })
            .expect("expected RunSubprotocol event");

        assert_eq!(child_ir.name, "SumcheckIOR");
        assert_eq!(child_ir.events.len(), 2 * log_l);
    }

    /// The deferred obligation's emitter/discharger naming is
    /// consistent: emitted by twin_constraint, discharged by bridge.
    #[test]
    fn twin_constraint_obligation_lifecycle_is_declared() {
        let ir = warp_twin_constraint_ior(3, 2);
        let obl = &ir.obligations[0];
        assert_eq!(obl.emitter, "twin_constraint");
        assert_eq!(obl.discharger.as_deref(), Some("bridge"));
    }

    /// TwinConstraint declares an EmitObligation event matching the
    /// registered obligation id.
    #[test]
    fn twin_constraint_emit_event_matches_obligation() {
        let ir = warp_twin_constraint_ior(3, 2);
        let emit_event = ir.events.iter().find(|e| {
            matches!(e, EventNode::EmitObligation { obligation, .. }
                if obligation == "tc_deferred_oracle_check")
        });
        assert!(emit_event.is_some());
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
