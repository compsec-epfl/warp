use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use rayon::prelude::*;
use spongefish::codecs::arkworks_algebra::{
    FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField,
};
use thiserror::Error;

pub mod multilinear_constraint_batching;
pub mod twin_constraint_pseudo_batching;

#[derive(Error, Debug)]
pub enum WARPSumcheckProverError {
    #[error(transparent)]
    SpongeFishProofError(#[from] spongefish::ProofError),
    #[error(transparent)]
    SpongeFishDomainSeparatorError(#[from] spongefish::DomainSeparatorMismatch),
}

#[derive(Error, Debug)]
pub enum WARPSumcheckVerifierError {
    #[error(transparent)]
    SpongeFishProofError(#[from] spongefish::ProofError),
    #[error(transparent)]
    SpongeFishDomainSeparatorError(#[from] spongefish::DomainSeparatorMismatch),
    #[error("Found invalid number of sumcheck rounds")]
    NumSumcheckRounds,
    #[error("Sumcheck round verification failed")]
    SumcheckRound,
    #[error("Incorrect target")]
    Target,
}

pub fn protogalaxy_trick<F: Field>(
    c: impl Iterator<Item = (F, F)>,
    mut q: Vec<DensePolynomial<F>>,
) -> DensePolynomial<F> {
    for (a, b) in c {
        q = q
            .par_chunks(2)
            .map(|p| {
                &p[0]
                    + DensePolynomial::from_coefficients_vec(vec![a, b]).naive_mul(&(&p[1] - &p[0]))
            })
            .collect();
    }
    assert_eq!(q.len(), 1);
    q.pop().unwrap()
}

pub trait Sumcheck<F: Field> {
    type Evaluations;
    type ProverAuxiliary<'a>;
    type VerifierAuxiliary<'a>;
    type Target;
    type Challenge;

    fn prove_round(
        prover_state: &mut (impl FieldToUnitSerialize<F> + UnitToField<F>),
        evals: &mut Self::Evaluations,
        aux: &Self::ProverAuxiliary<'_>,
    ) -> Result<Self::Challenge, WARPSumcheckProverError>;

    fn verify_round(
        verifier_state: &mut (impl FieldToUnitDeserialize<F> + UnitToField<F>),
        target: &mut Self::Target,
        aux: &Self::VerifierAuxiliary<'_>,
    ) -> Result<Self::Challenge, WARPSumcheckVerifierError>;

    fn prove(
        prover_state: &mut (impl FieldToUnitSerialize<F> + UnitToField<F>),
        evals: &mut Self::Evaluations,
        aux: &Self::ProverAuxiliary<'_>,
        n_rounds: usize,
    ) -> Result<Vec<Self::Challenge>, WARPSumcheckProverError> {
        let mut challenges = Vec::with_capacity(n_rounds);
        for _ in 0..n_rounds {
            let c = Self::prove_round(prover_state, evals, aux)?;
            challenges.push(c);
        }
        Ok(challenges)
    }

    fn verify(
        verifier_state: &mut (impl FieldToUnitDeserialize<F> + UnitToField<F>),
        target: &mut Self::Target,
        aux: &Self::VerifierAuxiliary<'_>,
        n_rounds: usize,
    ) -> Result<Vec<Self::Challenge>, WARPSumcheckVerifierError> {
        let mut challenges = Vec::with_capacity(n_rounds);
        for _ in 0..n_rounds {
            let c = Self::verify_round(verifier_state, target, aux)?;
            challenges.push(c);
        }
        Ok(challenges)
    }
}
