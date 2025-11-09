use ark_ff::Field;
use ark_poly::DenseMultilinearExtension;
use ark_poly::Polynomial;
use ark_std::log2;
use efficient_sumcheck::hypercube::Hypercube;
use efficient_sumcheck::order_strategy::AscendingOrder;

use crate::utils::poly::eq_poly;
use crate::{relations::BundledPESAT, WARPError};

pub trait LinearCode<F: Field> {
    type Config: Clone;
    fn new(config: Self::Config) -> Self;
    fn encode(&self, message: &[F]) -> Vec<F>;
    fn message_len(&self) -> usize;
    fn code_len(&self) -> usize;
}

pub trait MultiConstraintChecker<F: Field> {
    fn as_multilinear_extension(num_vars: usize, f: &[F]) -> DenseMultilinearExtension<F>;

    fn check_constraints<P: BundledPESAT<F>>(
        &self,
        constraints: &MultiConstraints<F>,
        w: &[F],
        f: &[F],
        p: &P,
    ) -> Result<(), WARPError>;
}

#[derive(Clone)]
pub struct MultiConstraints<F: Field> {
    pub r: usize,
    // (\alpha_i, \mu_i)_{r}
    pub evaluations: Vec<(Vec<F>, F)>,
    // (tau, x)
    pub beta: (Vec<F>, Vec<F>),
    // we store computations for eq(\tau, j)_{j \in {0, 1}^{\log m}} within a table indexed by
    // hypercube points
    pub tau_eq_evals: Vec<F>,
    // expected evaluation result of the bundled pesat \hat{p}(beta, w)
    pub eta: F,
}

impl<F: Field> MultiConstraints<F> {
    pub fn new(
        evaluations: Vec<(Vec<F>, F)>,
        beta: (Vec<F>, Vec<F>), // (tau, x)
        eta: F,
    ) -> Self {
        let hypercube = Hypercube::<AscendingOrder>::new(beta.0.len());
        let tau = &beta.0;

        // TODO: multithread this
        // initialize table for eq(tau, i)
        let tau_eq_evals = hypercube
            .map(|(index, _point)| eq_poly(tau, index))
            .collect();

        MultiConstraints {
            r: evaluations.len(),
            evaluations,
            tau_eq_evals,
            beta,
            eta,
        }
    }
}

impl<F: Field, C: LinearCode<F>> MultiConstraintChecker<F> for C {
    fn as_multilinear_extension(num_vars: usize, f: &[F]) -> DenseMultilinearExtension<F> {
        DenseMultilinearExtension::from_evaluations_slice(num_vars, f)
    }

    fn check_constraints<P: BundledPESAT<F>>(
        &self,
        constraints: &MultiConstraints<F>,
        w: &[F],
        f: &[F],
        p: &P,
    ) -> Result<(), WARPError> {
        let mut z = constraints.beta.1.clone();
        z.extend_from_slice(w);

        // evaluate bundled constraints
        let eval_bundled = p.evaluate_bundled(&constraints.tau_eq_evals, &z)?;
        let is_correct_bundled_eval = eval_bundled == constraints.eta;

        // evaluate multilinear points
        let is_correct_multilinear_evals = if !constraints.evaluations.is_empty() {
            let num_vars = log2(self.code_len()) as usize;
            let f_hat: DenseMultilinearExtension<F> = Self::as_multilinear_extension(num_vars, f);
            constraints
                .evaluations
                .iter()
                .fold(true, |acc, (point, eval)| {
                    (f_hat.evaluate(point) == *eval) & acc
                })
        } else {
            true
        };

        if is_correct_bundled_eval & is_correct_multilinear_evals {
            Ok(())
        } else {
            Err(WARPError::UnsatisfiedMultiConstraints(
                is_correct_bundled_eval,
                is_correct_multilinear_evals,
            ))
        }
    }
}
