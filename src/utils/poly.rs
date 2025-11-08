use ark_ff::Field;
use efficient_sumcheck::{
    hypercube::HypercubeMember, interpolation::LagrangePolynomial,
    order_strategy::AscendingOrder
};

pub fn eq_poly<F: Field>(original_tau: &[F], point: usize) -> F {
    // TODO (z-tech): will fix and get rid of this function
    let num_variables = original_tau.len();
    let mut tau = original_tau.to_vec();
    tau.reverse();
    let tau_hat: Vec<F> = tau.iter().map(|t| F::ONE - *t).collect();
    LagrangePolynomial::<F, AscendingOrder>::lag_poly(
        tau,
        tau_hat,
        HypercubeMember::new(num_variables, point),
    )
}

pub fn eq_poly_non_binary<F: Field>(x: &[F], y: &[F]) -> F {
    assert_eq!(x.len(), y.len());
    let res = x.iter().zip(y).fold(F::one(), |acc, (x_i, y_i)| {
        acc * (*x_i * *y_i + (F::one() - x_i) * (F::one() - y_i))
    });
    res
}
