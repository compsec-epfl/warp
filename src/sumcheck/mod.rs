use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use rayon::prelude::*;
use spongefish::codecs::arkworks_algebra::{
    FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField,
};

use crate::WARPError;

pub fn vsbw_reduce_evaluations<F: Field>(evals: &[F], c: F) -> Vec<F> {
    // evals.chunks(2).map(|e| e[0] + c * (e[1] - e[0])).collect()
    // instead of adjacent pairs, efficient sumcheck does first half with second half
    // TODO (z-tech): possibly one is more memory efficient than the other? But seems low priority
    let mid = evals.len() / 2;
    evals[..mid]
        .iter()
        .zip(&evals[mid..])
        .map(|(&a, &b)| a + c * (b - a))
        .collect()
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
        // NOTE (z-tech): this comes directly from the test below step_by_step_compare_to_efficient_sumcheck

        // f = 4*x_1*x_2 + 7*x_2*x_3 + 2*x_1 + 13*x_2
        let f: Vec<Fr> = three_variable_polynomial_evaluations::<Fr>();

        // run the protocol using efficient sumcheck
        let f_memory_stream = MemoryStream::new(f.clone());
        let mut time_prover = TimeProver::<Fr, MemoryStream<Fr>>::new(TimeProverConfig {
            num_variables: 3,
            claim: multivariate_claim(f_memory_stream.clone()),
            stream: f_memory_stream,
        });
        let transcript =
            Sumcheck::<Fr>::prove::<MemoryStream<Fr>, _>(&mut time_prover, &mut ark_std::test_rng());

        // run all rounds not including last one with code above ^
        let f1 = vsbw_reduce_evaluations(&f, transcript.verifier_messages[0]);
        let f2 = vsbw_reduce_evaluations(&f1, transcript.verifier_messages[1]);
        let last_challenge = Fr::from(7);
        let f3 = vsbw_reduce_evaluations(&f2, last_challenge);

        // compute the scalar given the efficient sumcheck transcript
        let a = time_prover.evaluations.clone().unwrap()[0];
        let b = time_prover.evaluations.clone().unwrap()[1];
        assert_eq!(
            f3,
            vec![a + last_challenge * (b - a)],
        );
        // hence these are equivalent
    }

    #[test]
    fn step_by_step_compare_to_efficient_sumcheck() {
        // f = 4*x_1*x_2 + 7*x_2*x_3 + 2*x_1 + 13*x_2
        let f: Vec<Fr> = three_variable_polynomial_evaluations::<Fr>();

        // setup efficient sumcheck
        let f_memory_stream = MemoryStream::new(f.clone());
        let mut time_prover = TimeProver::<Fr, MemoryStream<Fr>>::new(TimeProverConfig {
            num_variables: 3,
            claim: multivariate_claim(f_memory_stream.clone()),
            stream: f_memory_stream,
        });

        // round 0
        time_prover.next_message(None); // <-- no compression happens here this builds claim_check = g(0) + g(1)

        // round 1
        let challenge_round_1 = Fr::from(3);
        let exp_round_1 = vec![Fr::from(6), Fr::from(6), Fr::from(31), Fr::from(38)];
        time_prover.next_message(Some(challenge_round_1)); // <-- first compression
        assert_eq!(
            exp_round_1,
            time_prover.evaluations.clone().unwrap()
        );
        assert_eq!(
            exp_round_1,
            vsbw_reduce_evaluations(&f, challenge_round_1),
        );

        // round 2
        let challenge_round_2 = Fr::from(7);
        let exp_round_2 = vec![Fr::from(181), Fr::from(230)];
        time_prover.next_message(Some(challenge_round_2));
        assert_eq!(
            exp_round_2,
            time_prover.evaluations.clone().unwrap()
        );
        assert_eq!(
            exp_round_2,
            vsbw_reduce_evaluations(&exp_round_1, challenge_round_2),
        );

        // last round
        let challenge_last_round = Fr::from(5);
        let exp_last_round = vec![Fr::from(426)];
        // time_prover.next_message(Some(challenge_last_round));
        // NOTE: when evaluations.len() == 2 this is already univariate, so efficient sumcheck
        // doesn't fold again. But you can just do the one fold like this if you really want:
        let a = time_prover.evaluations.clone().unwrap()[0];
        let b = time_prover.evaluations.clone().unwrap()[1];
        assert_eq!(
            exp_last_round,
            vec![a + challenge_last_round * (b - a)],
        );
        assert_eq!(
            exp_last_round,
            vsbw_reduce_evaluations(&exp_round_2, challenge_last_round),
        );
    }
}
