//! TC → OOD bridge IOR. Publishes `(td_new, η, ν₀)` and discharges
//! TwinConstraint's deferred oracle check `eq(τ,γ)·(ν₀ + ω·η) ≟ final_claim`.
use ark_ff::Field;
use ark_mt::MerkleHasher;
use effsc::hypercube::compute_hypercube_eq_evals;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::crypto::merkle::{warp_scheme, WarpCommitted};
use crate::error::{ProverError, VerifierError};
use crate::protocol::ior::{ProverTriple, IOR};
use crate::protocol::iors::twin_constraint::DeferredOracleCheck;
use crate::protocol::oracles::evaluation::Oracle;
use crate::relations::BundledPESAT;

pub struct BridgeStatement<F: Field> {
    pub zeta_0: Vec<F>,
    pub beta_tau: Vec<F>,
    pub log_m: usize,
    pub n_minus_k: usize,
}

pub struct BridgeWitness<'a, F: Field> {
    pub z: &'a [F],
    pub f: &'a Oracle<F>,
}

pub struct BridgeProverInputs<'a, F, P, H>
where
    F: Field,
    P: BundledPESAT<F>,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub bundled_pesat: &'a P,
    pub hasher: &'a H,
    pub code_len: usize,
    pub _f: PhantomData<F>,
}

pub struct BridgeVerifierInputs<'a, F: Field> {
    pub deferred: &'a DeferredOracleCheck<F>,
    pub gamma: &'a [F],
}

pub struct BridgeReductionInputs<F: Field, H: MerkleHasher> {
    pub eta: F,
    pub nu_0: F,
    pub td_new_root: H::Digest,
}

pub struct BridgeReducedStatement<F: Field, H: MerkleHasher> {
    pub eta: F,
    pub nu_0: F,
    pub td_new_root: H::Digest,
}

pub struct BridgeReducedWitness<F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub td_new: WarpCommitted<H, F>,
    pub new_x: Vec<F>,
    pub new_w: Vec<F>,
}

pub struct Bridge<F, P, H>(PhantomData<F>, PhantomData<P>, PhantomData<H>);

impl<F, P, H> Default for Bridge<F, P, H> {
    fn default() -> Self {
        Self(PhantomData, PhantomData, PhantomData)
    }
}

impl<F, P, H> IOR for Bridge<F, P, H>
where
    F: Field + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: BundledPESAT<F>,
    H: MerkleHasher<Symbol = Vec<F>>,
    H::Digest: Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize + Clone,
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
        = BridgeProverInputs<'b, F, P, H>
    where
        Self: 'b;
    type VerifierInputs<'b>
        = BridgeVerifierInputs<'b, F>
    where
        Self: 'b;
    type ReductionInputs = BridgeReductionInputs<F, H>;
    type ReducedStatement = BridgeReducedStatement<F, H>;
    type ProofString = ();
    type ReducedWitness = BridgeReducedWitness<F, H>;
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
            eta: inputs.eta,
            nu_0: inputs.nu_0,
            td_new_root: inputs.td_new_root.clone(),
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
            .bundled_pesat
            .evaluate_bundled(&beta_eq_evals, witness.z)
            .map_err(|_| ProverError::SpongeFish)?;

        // ν₀ = f̂(ζ₀)
        let nu_0 = witness.f.query_at_point(&statement.zeta_0);

        // (new_x, new_w) = z[..N-k], z[N-k..]
        let (new_x_slice, new_w_slice) = witness.z.split_at(statement.n_minus_k);
        let new_x = new_x_slice.to_vec();
        let new_w = new_w_slice.to_vec();

        // td_new ← Merkle.commit(f.evals())
        let td_new = {
            let _s = tracing::info_span!("bridge.commit_new_oracle").entered();
            count_ops!(MerkleTreeBuilds);
            let scheme = warp_scheme::<H, F>(inputs.hasher.clone(), inputs.code_len);
            scheme.commit(&[witness.f.evals().to_vec()])
        };
        let td_new_root = td_new.root().clone();

        // Absorb (td_new.root, η, ν₀)
        prover_state.prover_message(&td_new_root);
        prover_state.prover_message(&eta);
        prover_state.prover_message(&nu_0);

        Ok((
            BridgeReductionInputs {
                eta,
                nu_0,
                td_new_root,
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
        // Read (td_digest, η, ν₀) from the transcript.
        let td_new_root: H::Digest = verifier_state.prover_message()?;
        let eta: F = verifier_state.prover_message()?;
        let nu_0: F = verifier_state.prover_message()?;

        // Discharge TC's deferred check.
        inputs.deferred.discharge(inputs.gamma, nu_0, eta)?;

        Ok((
            BridgeReductionInputs {
                eta,
                nu_0,
                td_new_root,
            },
            (),
        ))
    }
}
