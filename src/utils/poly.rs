use ark_ff::Field;
use efficient_sumcheck::{
    hypercube::HypercubeMember, interpolation::LagrangePolynomial, order_strategy::AscendingOrder,
};

/// Precomputed state for repeated `eq(tau, point)` queries on the
/// same `tau`. Pays the reverse-and-tau-hat cost once instead of
/// per call — five of warp's `eq_poly` callers sit in hot loops of
/// length up to `n` (code length), so hoisting the setup out of the
/// loop is a straight win.
///
/// Use `EqPolyPrep::new(tau)` once, then `.eval(point)` per query.
/// For one-off calls, [`eq_poly`] is a convenience wrapper.
pub struct EqPolyPrep<F: Field> {
    tau_reversed: Vec<F>,
    tau_hat: Vec<F>,
}

impl<F: Field> EqPolyPrep<F> {
    pub fn new(tau: &[F]) -> Self {
        let mut tau_reversed = tau.to_vec();
        tau_reversed.reverse();
        let tau_hat: Vec<F> = tau_reversed.iter().map(|t| F::ONE - *t).collect();
        Self {
            tau_reversed,
            tau_hat,
        }
    }

    pub fn eval(&self, point: usize) -> F {
        LagrangePolynomial::<F, AscendingOrder>::lag_poly(
            self.tau_reversed.clone(),
            self.tau_hat.clone(),
            HypercubeMember::new(self.tau_reversed.len(), point),
        )
    }
}

/// Single-shot `eq(tau, point)`. Non-hot-path callers should use
/// this; hot-path callers building multiple values against the same
/// `tau` should build an [`EqPolyPrep`] once and reuse it.
pub fn eq_poly<F: Field>(original_tau: &[F], point: usize) -> F {
    EqPolyPrep::new(original_tau).eval(point)
}

pub fn eq_poly_non_binary<F: Field>(x: &[F], y: &[F]) -> F {
    assert_eq!(x.len(), y.len());
    let res = x.iter().zip(y).fold(F::one(), |acc, (x_i, y_i)| {
        acc * (*x_i * *y_i + (F::one() - x_i) * (F::one() - y_i))
    });
    res
}
