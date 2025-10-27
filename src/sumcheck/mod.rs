use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use rayon::prelude::*;
use spongefish::codecs::arkworks_algebra::{
    FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField,
};

use crate::WARPError;

pub fn vsbw_reduce_evaluations<F: Field>(evals: &[F], c: F) -> Vec<F> {
    evals.chunks(2).map(|e| e[0] + c * (e[1] - e[0])).collect()
}

pub fn vsbw_reduce_vec_evaluations<F: Field>(evals: &[Vec<F>], c: F) -> Vec<Vec<F>> {
    evals
        .chunks(2)
        .map(|e| {
            e[0].par_iter()
                .zip(&e[1])
                .map(|(&a, &b)| a + c * (b - a))
                .collect()
        })
        .collect()
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
    ) -> Result<Self::Challenge, WARPError>;

    fn verify_round(
        verifier_state: &mut (impl FieldToUnitDeserialize<F> + UnitToField<F>),
        target: &mut Self::Target,
        aux: &Self::VerifierAuxiliary<'_>,
    ) -> Result<Self::Challenge, WARPError>;

    fn prove(
        prover_state: &mut (impl FieldToUnitSerialize<F> + UnitToField<F>),
        evals: &mut Self::Evaluations,
        aux: &Self::ProverAuxiliary<'_>,
        n_rounds: usize,
    ) -> Result<Vec<Self::Challenge>, WARPError> {
        let mut challenges = Vec::with_capacity(n_rounds);
        for _ in 0..n_rounds {
            let c = Self::prove_round(prover_state, evals, &aux)?;
            challenges.push(c);
        }
        Ok(challenges)
    }

    fn verify(
        verifier_state: &mut (impl FieldToUnitDeserialize<F> + UnitToField<F>),
        target: &mut Self::Target,
        aux: &Self::VerifierAuxiliary<'_>,
        n_rounds: usize,
    ) -> Result<Vec<Self::Challenge>, WARPError> {
        let mut challenges = Vec::with_capacity(n_rounds);
        for _ in 0..n_rounds {
            let c = Self::verify_round(verifier_state, target, aux)?;
            challenges.push(c);
        }
        Ok(challenges)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use efficient_sumcheck::{
        multilinear::{TimeProver, TimeProverConfig},
        prover::Prover,
        streams::{multivariate_claim, MemoryStream},
        tests::polynomials::three_variable_polynomial_evaluations,
        Sumcheck,
    };

    #[test]
    fn test_equivalence_with_efficient_sumcheck() {
        let f: Vec<Fr> = three_variable_polynomial_evaluations::<Fr>();

        // run the protocol using efficient sumcheck
        let f_memory_stream = MemoryStream::new(f.clone());
        let mut time_prover = TimeProver::<Fr, MemoryStream<Fr>>::new(TimeProverConfig {
            num_variables: 3,
            claim: multivariate_claim(f_memory_stream.clone()),
            stream: f_memory_stream,
        });
        let transcript = Sumcheck::<Fr>::prove::<MemoryStream<Fr>, _>(
            &mut time_prover,
            &mut ark_std::test_rng(),
        );

        // run the above code with the same challenges
        let f_prime = vsbw_reduce_evaluations(&f, transcript.verifier_messages[0]);
        let result = vsbw_reduce_evaluations(&f_prime, transcript.verifier_messages[1]);

        // show equivalence
        assert_eq!(result, time_prover.evaluations.clone().unwrap(),);
    }
}
