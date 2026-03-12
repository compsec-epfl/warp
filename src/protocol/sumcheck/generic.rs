/// Generic sumcheck prover and verifier for use with protogalaxy-style folding.
///
/// This module is intended to be moved into efficient-sumcheck.
use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use efficient_sumcheck::experimental::inner_product::FastMap;
use efficient_sumcheck::multilinear::reductions::{pairwise, tablewise};
use efficient_sumcheck::{hypercube::Hypercube, order_strategy::AscendingOrder};
use spongefish::codecs::arkworks_algebra::{
    FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField,
};
use spongefish::ProofError;

// [CBBZ23] hyperplonk optimization
/// Accumulate equality polynomial evaluations at binary query points into a sparse map.
///
/// For each query `zetas[i]` (a binary field-element vector representing a hypercube point),
/// converts it to a hypercube index and sums the corresponding evaluation `eq_evals[i]`.
/// Queries at indices `0..=s` are skipped.
///
/// Returns a sparse map from hypercube index → accumulated evaluation sum.
pub fn accumulate_sparse_evaluations<F: Field>(
    zetas: Vec<&[F]>,
    eq_evals: Vec<F>,
    s: usize,
    r: usize,
) -> FastMap<F> {
    let mut result = FastMap::default();
    for i in 1 + s..r {
        let index = zetas[i]
            .iter()
            .enumerate()
            .filter_map(|(j, bit)| bit.is_one().then_some(1 << j))
            .sum::<usize>();
        *result.entry(index).or_insert(F::zero()) += &eq_evals[i];
    }
    result
}

/// Compute equality polynomial evaluations over the boolean hypercube.
///
/// Returns `[eq(point, i) for i in {0,1}^num_variables]` where
/// `eq(x, y) = Π_j (x_j · y_j + (1 - x_j)(1 - y_j))`.
pub fn compute_hypercube_eq_evals<F: Field>(num_variables: usize, point: &[F]) -> Vec<F> {
    Hypercube::<AscendingOrder>::new(num_variables)
        .map(|(index, _)| {
            (0..num_variables).fold(F::one(), |acc, j| {
                let bit = F::from((index >> j & 1) as u64);
                acc * (point[j] * bit + (F::one() - point[j]) * (F::one() - bit))
            })
        })
        .collect()
}

pub mod protogalaxy {
    use ark_ff::Field;
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
    use rayon::prelude::*;

    /// Fold a vector of polynomials using a tree of linear coefficient pairs.
    ///
    /// Given `n` polynomials and `log_n` coefficient pairs `(a, b)` representing
    /// linear functions `a + b·X`, recursively halve the polynomial vector:
    /// at each level, combine pairs `(p[0], p[1])` as `p[0] + (a + b·X)·(p[1] - p[0])`.
    ///
    /// Cost: O(n) field operations.
    pub fn fold<F: Field>(
        coeffs: impl Iterator<Item = (F, F)>,
        mut polys: Vec<DensePolynomial<F>>,
    ) -> DensePolynomial<F> {
        for (a, b) in coeffs {
            polys = polys
                .par_chunks(2)
                .map(|p| {
                    &p[0]
                        + DensePolynomial::from_coefficients_vec(vec![a, b])
                            .naive_mul(&(&p[1] - &p[0]))
                })
                .collect();
        }
        assert_eq!(polys.len(), 1);
        polys.pop().unwrap()
    }
}

/// Run a generic sumcheck prover for `n_rounds` rounds.
///
/// Arguments:
/// - `compute_h`: given the current tablewise and pairwise evaluations, returns the
///   round polynomial `h(X)` in coefficient form
/// - `tablewise`: evaluation table groups, each reduced via `tablewise::reduce_evaluations`
/// - `pairwise`: evaluation vectors, each reduced via `pairwise::reduce_evaluations`
/// - `n_rounds`: number of sumcheck rounds
/// - `prover_state`: spongefish transcript
///
/// Each round: compute `h` → send coefficients → receive challenge → reduce all tables.
pub fn sumcheck_prove<F: Field>(
    mut compute_h: impl FnMut(&[Vec<Vec<F>>], &[Vec<F>]) -> DensePolynomial<F>,
    tablewise: &mut [Vec<Vec<F>>],
    pairwise: &mut [Vec<F>],
    n_rounds: usize,
    prover_state: &mut (impl FieldToUnitSerialize<F> + UnitToField<F>),
) -> Result<Vec<F>, ProofError> {
    let mut challenges = Vec::with_capacity(n_rounds);

    for _ in 0..n_rounds {
        // compute round polynomial from current table state
        let h = compute_h(tablewise, pairwise);

        // send coefficients to transcript
        prover_state.add_scalars(&h.coeffs)?;

        // receive challenge
        let [c] = prover_state.challenge_scalars::<1>()?;
        challenges.push(c);

        // reduce all tables with the challenge
        for table in tablewise.iter_mut() {
            tablewise::reduce_evaluations(table, c);
        }
        for table in pairwise.iter_mut() {
            pairwise::reduce_evaluations(table, c);
        }
    }

    Ok(challenges)
}

/// Run a generic sumcheck verifier for `n_rounds` rounds.
///
/// Each round: read `degree + 1` coefficients → check `h(0) + h(1) == target` →
/// receive challenge → update `target = h(challenge)`.
///
/// Returns the challenges vector.
pub fn sumcheck_verify<F: Field>(
    degree: usize,
    target: &mut F,
    n_rounds: usize,
    verifier_state: &mut (impl FieldToUnitDeserialize<F> + UnitToField<F>),
) -> Result<Vec<F>, ProofError> {
    let mut challenges = Vec::with_capacity(n_rounds);

    for _ in 0..n_rounds {
        let mut h_coeffs = vec![F::zero(); degree + 1];
        verifier_state.fill_next_scalars(&mut h_coeffs)?;
        let h = DensePolynomial::from_coefficients_vec(h_coeffs);

        if h.evaluate(&F::zero()) + h.evaluate(&F::one()) != *target {
            return Err(ProofError::InvalidProof);
        }

        let [c] = verifier_state.challenge_scalars::<1>()?;
        *target = h.evaluate(&c);
        challenges.push(c);
    }

    Ok(challenges)
}
