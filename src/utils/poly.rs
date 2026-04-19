use ark_ff::Field;

/// `eq(τ, y)` where `y ∈ {0,1}^{τ.len()}` is the Boolean point whose bit `j`
/// is `(point >> j) & 1`. Matches the LSB-indexed formula used by
/// [`effsc::hypercube::compute_hypercube_eq_evals`], so
/// `eq_poly(τ, i) == compute_hypercube_eq_evals(τ.len(), τ)[i]`.
pub fn eq_poly<F: Field>(tau: &[F], point: usize) -> F {
    let num_variables = tau.len();
    (0..num_variables).fold(F::one(), |acc, j| {
        if (point >> j) & 1 == 1 {
            acc * tau[j]
        } else {
            acc * (F::one() - tau[j])
        }
    })
}

pub fn eq_poly_non_binary<F: Field>(x: &[F], y: &[F]) -> F {
    assert_eq!(x.len(), y.len());
    x.iter().zip(y).fold(F::one(), |acc, (x_i, y_i)| {
        acc * (*x_i * *y_i + (F::one() - x_i) * (F::one() - y_i))
    })
}
