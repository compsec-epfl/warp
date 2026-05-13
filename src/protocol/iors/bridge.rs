//! TC → OOD bridge IOR. Publishes `(td_new, η, ν₀)` and discharges
//! TwinConstraint's deferred oracle check `eq(τ,γ)·(ν₀ + ω·η) ≟ final_claim`.
use ark_ff::Field;
use ark_vc::mvc::MultiVectorCommitment;
use ark_vc::vc::VectorCommitment;
use effsc::hypercube::compute_hypercube_eq_evals;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::crypto::vc::CommittedCodewords;
use crate::error::{ProverError, VerifierError};
use crate::protocol::ior::{ProverTriple, IOR};
use crate::protocol::iors::twin_constraint::DeferredOracleCheck;
use crate::protocol::oracles::evaluation::Oracle;
use crate::relations::PolyPredicate;

pub struct BridgeStatement<F: Field> {
    pub zeta_0: Vec<F>,
    pub beta_tau: Vec<F>,
    pub log_m: usize,
    pub n_minus_k: usize,
}

pub struct BridgeWitness<'a, F: Field> {
    pub z_witness_assignment: &'a [F],
    pub f_oracle: &'a Oracle<F>,
}

pub struct BridgeProverInputs<'a, F, P, V>
where
    F: Field,
    P: PolyPredicate<F>,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub predicate: &'a P,
    pub ck: &'a V::CommitterKey,
    pub _f: PhantomData<F>,
}

pub struct BridgeVerifierInputs<'a, F: Field> {
    pub deferred: &'a DeferredOracleCheck<F>,
    pub gamma_twin_constraint_challenges: &'a [F],
}

pub struct BridgeReductionInputs<F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub eta_predicate_eval: F,
    pub nu_0_oracle_eval: F,
    pub td_new_commitment: V::Commitment,
}

pub struct BridgeReducedStatement<F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub eta_predicate_eval: F,
    pub nu_0_oracle_eval: F,
    pub td_new_commitment: V::Commitment,
}

pub struct BridgeReducedWitness<F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub td_new: CommittedCodewords<F, V>,
    pub new_x: Vec<F>,
    pub new_w: Vec<F>,
}

pub struct Bridge<F, P, V>(PhantomData<F>, PhantomData<P>, PhantomData<V>);

impl<F, P, V> Default for Bridge<F, P, V> {
    fn default() -> Self {
        Self(PhantomData, PhantomData, PhantomData)
    }
}

impl<F, P, V> IOR for Bridge<F, P, V>
where
    F: Field + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: PolyPredicate<F>,
    V: MultiVectorCommitment<Alphabet = F, Index = usize>,
    V::Commitment: Encoding<[u8]> + NargSerialize + NargDeserialize + Clone,
{
    const NAME: &'static str = "Bridge";

    type Statement<'b>
        = BridgeStatement<F>
    where
        Self: 'b;
    type Witness<'b>
        = BridgeWitness<'b, F>
    where
        Self: 'b;
    type ProverInputs<'b>
        = BridgeProverInputs<'b, F, P, V>
    where
        Self: 'b;
    type VerifierInputs<'b>
        = BridgeVerifierInputs<'b, F>
    where
        Self: 'b;
    type ReductionInputs = BridgeReductionInputs<F, V>;
    type ReducedStatement = BridgeReducedStatement<F, V>;
    type ProofString = ();
    type ReducedWitness = BridgeReducedWitness<F, V>;
    type VerifierOutputs = ();

    fn reduce_statement<'a>(
        &self,
        _statement: &Self::Statement<'a>,
        inputs: &Self::ReductionInputs,
    ) -> Self::ReducedStatement
    where
        Self: 'a,
    {
        BridgeReducedStatement {
            eta_predicate_eval: inputs.eta_predicate_eval,
            nu_0_oracle_eval: inputs.nu_0_oracle_eval,
            td_new_commitment: inputs.td_new_commitment.clone(),
        }
    }

    #[tracing::instrument(
        name = "bridge",
        skip_all,
        fields(log_m = statement.log_m, n_minus_k = statement.n_minus_k)
    )]
    fn prove_inner<'a>(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement<'a>,
        witness: &Self::Witness<'a>,
        inputs: &Self::ProverInputs<'a>,
    ) -> ProverTriple<Self::ReductionInputs, Self::ProofString, Self::ReducedWitness>
    where
        Self: 'a,
    {
        // η = ⟨ eq(β_τ), p(z) ⟩
        let beta_eq_evals = compute_hypercube_eq_evals(statement.log_m, &statement.beta_tau);
        let eta = inputs
            .predicate
            .evaluate_bundled(&beta_eq_evals, witness.z_witness_assignment)
            .map_err(|_| ProverError::SpongeFish)?;

        // ν₀ = f̂(ζ₀)
        let nu_0 = witness.f_oracle.query_at_point(&statement.zeta_0);

        // (new_x, new_w) = z[..N-k], z[N-k..]
        let (new_x_slice, new_w_slice) = witness.z_witness_assignment.split_at(statement.n_minus_k);
        let new_x = new_x_slice.to_vec();
        let new_w = new_w_slice.to_vec();

        // td_new ← V.commit(f.evals())
        let td_new = {
            let _s = tracing::info_span!("bridge.commit_new_oracle").entered();
            count_ops!(MerkleTreeBuilds);
            let codeword = witness.f_oracle.evals().to_vec();
            let (commitment, state) = <V as VectorCommitment>::commit(inputs.ck, codeword.iter())
                .map_err(|_| ProverError::SpongeFish)?;
            CommittedCodewords::<F, V> {
                commitment,
                state,
                codewords: vec![codeword],
            }
        };
        let td_new_commitment: V::Commitment = td_new.commitment.clone();

        // Absorb (td_new.commitment, η, ν₀)
        prover_state.prover_message(&td_new_commitment);
        prover_state.prover_message(&eta);
        prover_state.prover_message(&nu_0);

        Ok((
            BridgeReductionInputs {
                eta_predicate_eval: eta,
                nu_0_oracle_eval: nu_0,
                td_new_commitment,
            },
            (),
            BridgeReducedWitness {
                td_new,
                new_x,
                new_w,
            },
        ))
    }

    #[tracing::instrument(name = "bridge.verify", skip_all)]
    fn verify_inner<'a, 'b>(
        &self,
        verifier_state: &mut VerifierState<'a>,
        _statement: &Self::Statement<'b>,
        inputs: &Self::VerifierInputs<'b>,
    ) -> Result<(Self::ReductionInputs, Self::VerifierOutputs), VerifierError>
    where
        Self: 'b,
    {
        // Read (commitment, η, ν₀) from the transcript.
        let td_new_commitment: V::Commitment = verifier_state.prover_message()?;
        let eta: F = verifier_state.prover_message()?;
        let nu_0: F = verifier_state.prover_message()?;

        // Discharge TC's deferred check.
        inputs
            .deferred
            .discharge(inputs.gamma_twin_constraint_challenges, nu_0, eta)?;

        Ok((
            BridgeReductionInputs {
                eta_predicate_eval: eta,
                nu_0_oracle_eval: nu_0,
                td_new_commitment,
            },
            (),
        ))
    }
}
