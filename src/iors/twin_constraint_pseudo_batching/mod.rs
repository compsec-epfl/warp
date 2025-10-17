use ark_ff::{Field, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseMultilinearExtension, DenseUVPolynomial, Polynomial,
};
use ark_std::log2;
use rayon::prelude::*;
use spongefish::codecs::arkworks_algebra::{
    FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField,
};
use whir::poly_utils::hypercube::BinaryHypercubePoint;

use crate::{
    relations::{
        r1cs::{R1CSConstraints, R1CS},
        relation::BundledPESAT,
    },
    sumcheck::{protogalaxy_trick, vsbw_reduce_evaluations, vsbw_reduce_vec_evaluations, Sumcheck},
    utils::poly::eq_poly,
    WARPError,
};

pub struct Evals<F> {
    u: Vec<Vec<F>>,
    z: Vec<Vec<F>>,
    a: Vec<Vec<F>>,
    b: Vec<Vec<F>>,
    tau: Vec<F>,
}

impl<F> Evals<F> {
    pub fn new(
        u: Vec<Vec<F>>,
        z: Vec<Vec<F>>,
        a: Vec<Vec<F>>,
        b: Vec<Vec<F>>,
        tau: Vec<F>,
    ) -> Self {
        Self { u, z, a, b, tau }
    }
}

pub struct TwinConstraintPseudoBatchingSumcheck {}

impl<F: Field> Sumcheck<F> for TwinConstraintPseudoBatchingSumcheck {
    type Evaluations = Evals<F>;
    type ProverAuxiliary<'a> = (&'a R1CSConstraints<F>, F);
    type VerifierAuxiliary<'a> = (usize, usize); // log_m, log_n
    type Target = F;
    type Challenge = F;

    fn prove_round(
        prover_state: &mut (impl FieldToUnitSerialize<F> + UnitToField<F>),
        Evals { u, z, a, b, tau }: &mut Self::Evaluations,
        &(r1cs, xi): &Self::ProverAuxiliary<'_>,
    ) -> Result<Self::Challenge, WARPError> {
        // compute prover message `h`
        let f_iter = u.chunks(2).zip(a.chunks(2)).map(|(u, a)| {
            protogalaxy_trick(
                a[0].iter().zip(&a[1]).map(|(&l, &r)| (l, r - l)),
                u[0].par_iter()
                    .zip(&u[1])
                    .map(|(&l, &r)| DensePolynomial::from_coefficients_vec(vec![l, r - l]))
                    .collect::<Vec<_>>(),
            )
        });
        let p_iter = b.chunks(2).zip(z.chunks(2)).map(|(b, z)| {
            protogalaxy_trick(
                b[0].iter().zip(&b[1]).map(|(&l, &r)| (l, r - l)),
                r1cs.par_iter()
                    .map(|(a, b, c)| {
                        let a0 = a.iter().map(|(t, i)| z[0][*i] * t).sum::<F>();
                        let a1 = a.iter().map(|(t, i)| z[1][*i] * t).sum::<F>() - a0;
                        let b0 = b.iter().map(|(t, i)| z[0][*i] * t).sum::<F>();
                        let b1 = b.iter().map(|(t, i)| z[1][*i] * t).sum::<F>() - b0;
                        let c0 = c.iter().map(|(t, i)| z[0][*i] * t).sum::<F>();
                        let c1 = c.iter().map(|(t, i)| z[1][*i] * t).sum::<F>() - c0;
                        vec![a0 * b0 - c0, a0 * b1 + a1 * b0 - c1, a1 * b1]
                    })
                    .map(DensePolynomial::from_coefficients_vec)
                    .collect::<Vec<_>>(),
            )
        });
        let t_iter = tau
            .chunks(2)
            .map(|t| DensePolynomial::from_coefficients_vec(vec![t[0], t[1] - t[0]]));
        let h = f_iter
            .zip(p_iter)
            .zip(t_iter)
            .map(|((f, p), t)| (f + p * xi).naive_mul(&t))
            .fold(DensePolynomial::zero(), |acc, r| acc + r);
        println!("coeffs size: {}", h.coeffs.len());
        prover_state.add_scalars(&h.coeffs)?;
        println!("done");
        // get challenge
        let [c] = prover_state.challenge_scalars::<1>()?;
        // update evaluation tables
        *u = vsbw_reduce_vec_evaluations(u, c);
        *z = vsbw_reduce_vec_evaluations(z, c);
        *a = vsbw_reduce_vec_evaluations(a, c);
        *b = vsbw_reduce_vec_evaluations(b, c);
        *tau = vsbw_reduce_evaluations(tau, c);
        Ok(c)
    }

    fn verify_round(
        verifier_state: &mut (impl FieldToUnitDeserialize<F> + UnitToField<F>),
        target: &mut Self::Target,
        aux: &Self::VerifierAuxiliary<'_>,
    ) -> Result<Self::Challenge, WARPError> {
        let mut h_coeffs = vec![F::zero(); 2 + (aux.1 + 1).max(aux.0 + 2) as usize];
        verifier_state.fill_next_scalars(&mut h_coeffs)?;
        let h = DensePolynomial::from_coefficients_vec(h_coeffs);
        if h.evaluate(&F::zero()) + h.evaluate(&F::one()) != *target {
            return Err(WARPError::VerificationFailed(
                "Evaluations of the claimed polynomial do not sum to the target".to_string(),
            ));
        }

        // get challenge
        let [c] = verifier_state.challenge_scalars::<1>()?;
        // update sumcheck target for next round
        *target = h.evaluate(&c);
        Ok(c)
    }
}

pub fn prover<F: Field, const L: usize>(
    prover_state: &mut (impl FieldToUnitSerialize<F> + UnitToField<F>),
    r1cs: &R1CS<F>,
    alpha_vec: Vec<Vec<F>>,
    _mu_vec: Vec<F>,
    beta_vec: Vec<Vec<F>>,
    _eta_vec: Vec<F>,
    u_vec: Vec<Vec<F>>,
    z_vec: Vec<Vec<F>>,
    m: usize,
    n: usize,
) -> Result<((Vec<F>, Vec<F>, F, Vec<F>, F), Vec<F>), WARPError> {
    let log_n = log2(n) as usize;

    // 6.1 step 1, sample challenge \tau and \xi
    let mut tau = vec![F::zero(); log2(L) as usize];
    prover_state.fill_challenge_scalars(&mut tau)?;
    let tau_eq_evals = (0..L)
        .map(|i| eq_poly(&tau, BinaryHypercubePoint(i)))
        .collect::<Vec<_>>();
    let [xi] = prover_state.challenge_scalars::<1>()?;

    // 6.1 step 2, initialize evaluation tables
    let mut evals = Evals {
        u: u_vec,
        z: z_vec,
        a: alpha_vec,
        b: beta_vec,
        tau: tau_eq_evals,
    };

    // 6.1 step 2, sumcheck starts
    let gamma = TwinConstraintPseudoBatchingSumcheck::prove(
        prover_state,
        &mut evals,
        &(&r1cs.p, xi),
        log2(L) as usize,
    )?;

    // 6.1 step 3, compute new instance and witness for pseudo-batching accumulation relation
    let alpha = evals.a.pop().unwrap();

    let u = evals.u.pop().unwrap();
    let u_mle = DenseMultilinearExtension::from_evaluations_slice(log_n, &u);
    let mu = u_mle.evaluate(&alpha);

    let beta = evals.b.pop().unwrap();

    let z = evals.z.pop().unwrap();

    let beta_eq_evals = (0..m)
        .map(|i| eq_poly(&beta, BinaryHypercubePoint(i)))
        .collect::<Vec<_>>();

    let eta = r1cs.evaluate_bundled(&beta_eq_evals, &z)?;

    prover_state.add_scalars(&[mu])?;
    prover_state.add_scalars(&[eta])?;

    Ok(((gamma, alpha, mu, beta, eta), u))
}

pub fn verifier<F: Field, const L: usize>(
    verifier_state: &mut (impl FieldToUnitDeserialize<F> + UnitToField<F>),
    alpha_vec: Vec<Vec<F>>,
    mu_vec: Vec<F>,
    beta_vec: Vec<Vec<F>>,
    eta_vec: Vec<F>,
    log_m: usize,
    log_n: usize,
) -> Result<(Vec<F>, Vec<F>, F, Vec<F>, F), WARPError> {
    // 6.1 step 1, sample challenge \tau and \xi
    let mut tau = vec![F::zero(); log2(L) as usize];
    verifier_state.fill_challenge_scalars(&mut tau)?;
    let tau_eq_evals = (0..L)
        .map(|i| eq_poly(&tau, BinaryHypercubePoint(i)))
        .collect::<Vec<_>>();
    let [xi] = verifier_state.challenge_scalars::<1>()?;

    // 6.1 step 2, RHS of the equation (sumcheck target)
    let mut sigma = (0..L)
        .map(|i| tau_eq_evals[i] * (mu_vec[i] + xi * eta_vec[i]))
        .sum::<F>();
    let gamma = TwinConstraintPseudoBatchingSumcheck::verify(
        verifier_state,
        &mut sigma,
        &(log_m, log_n),
        log2(L) as usize,
    )?;

    // 6.1 step 3, compute new instance and witness for pseudo-batching accumulation relation
    let alpha = (0..log_n as usize)
        .map(|j| {
            (0..L)
                .map(|i| eq_poly(&gamma, BinaryHypercubePoint(i)) * alpha_vec[i][j])
                .sum::<F>()
        })
        .collect();
    let beta = (0..log_m as usize)
        .map(|j| {
            (0..L)
                .map(|i| eq_poly(&gamma, BinaryHypercubePoint(i)) * beta_vec[i][j])
                .sum::<F>()
        })
        .collect();

    let [mu]: [F; 1] = verifier_state.next_scalars()?;
    let [eta]: [F; 1] = verifier_state.next_scalars()?;

    // New target decision
    assert_eq!(
        sigma,
        (mu + xi * eta)
            * tau
                .iter()
                .zip(&gamma)
                .map(|(a, b)| a.double() * b - a - b + F::one())
                .product::<F>()
    );

    Ok((gamma, alpha, mu, beta, eta))
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ark_bls12_381::Fr;
    use ark_ff::{PrimeField, UniformRand};
    use ark_poly::{DenseMultilinearExtension, Polynomial};
    use ark_r1cs_std::{
        alloc::AllocVar,
        eq::EqGadget,
        fields::{fp::FpVar, FieldVar},
    };
    use ark_relations::r1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
    };
    use ark_std::{log2, test_rng};
    use spongefish::{duplex_sponge::DuplexSponge, DomainSeparator};
    use spongefish_poseidon::bls12_381::PoseidonPermx5_255_5;
    use whir::poly_utils::hypercube::BinaryHypercube;

    use crate::{
        linear_code::{LinearCode, ReedSolomon, ReedSolomonConfig},
        relations::{r1cs::R1CS, relation::BundledPESAT},
        utils::poly::eq_poly,
    };

    use super::*;

    struct C<F: PrimeField, const M: usize> {
        v: Vec<F>,
        x: F,
    }

    impl<F: PrimeField, const M: usize> ConstraintSynthesizer<F> for C<F, M> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let v = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(self.v))?;
            let x = FpVar::new_input(cs.clone(), || Ok(self.x))?;

            let mut r = FpVar::one();

            for i in 0..M - 1 {
                r *= &v[i];
            }

            r.enforce_equal(&x)?;

            Ok(())
        }
    }

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        const L: usize = 2;
        const M: usize = 1 << 10;

        let rng = &mut test_rng();

        let cs = ConstraintSystem::new_ref();

        let witness = (0..M - 1).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        let instance = witness.iter().product::<Fr>();
        let circuit = C::<_, M> {
            v: witness.clone(),
            x: instance,
        };
        circuit.generate_constraints(cs.clone())?;
        let r1cs = R1CS::try_from(cs)?;
        const N: usize = M * 4;
        assert_eq!(N, (r1cs.k * 2).next_power_of_two());

        let code = ReedSolomon::new(ReedSolomonConfig::default(r1cs.k, N));

        // Prepare for l instances and witnesses for twin constraint relation
        let mut alpha_vec = vec![];
        let mut mu_vec = vec![];
        let mut beta_vec = vec![];
        let mut eta_vec = vec![];
        let mut x_vec = vec![];
        let mut z_vec = vec![];
        let mut u_vec = vec![];

        for _ in 0..L {
            let cs = ConstraintSystem::new_ref();

            let witness = (0..M - 1).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
            let instance = witness.iter().product::<Fr>();
            let circuit = C::<_, M> {
                v: witness.clone(),
                x: instance,
            };
            circuit.generate_constraints(cs.clone())?;

            let cs = cs.into_inner().unwrap();
            let (x, w) = (cs.instance_assignment, cs.witness_assignment);
            let z = [&x[..], &w].concat();

            let beta = (0..r1cs.log_m).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

            let mut beta_eq_evals = Vec::<Fr>::new();
            let hypercube = BinaryHypercube::new(r1cs.log_m);

            for point in hypercube {
                beta_eq_evals.push(eq_poly(&beta, point));
            }

            let eta = r1cs.evaluate_bundled(&beta_eq_evals, &z)?;

            let u = code.encode(&w);
            let u_mle = DenseMultilinearExtension::from_evaluations_slice(log2(N) as usize, &u);
            let alpha = (0..log2(N)).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
            let mu = u_mle.evaluate(&alpha);

            alpha_vec.push(alpha);
            mu_vec.push(mu);
            beta_vec.push(beta);
            eta_vec.push(eta);
            x_vec.push(x);
            z_vec.push(z);
            u_vec.push(u);
        }

        // Now impl the IOR from l twin constraint relations to pseudo-batching accumulation relation
        let mut domain_separator = DomainSeparator::<DuplexSponge<PoseidonPermx5_255_5>, Fr>::new(
            "ior::twin_constraint_pseudo_batching",
        )
        .squeeze(log2(L) as usize, "tau")
        .squeeze(1, "xi");
        for i in 0..log2(L) {
            domain_separator = domain_separator
                .absorb(
                    2 + (log2(N) as usize + 1).max(r1cs.log_m + 2),
                    &format!("h_{}", i),
                )
                .squeeze(1, &format!("challenge_{}", i));
        }
        domain_separator = domain_separator.absorb(1, "mu").absorb(1, "eta");

        let mut prover_state = domain_separator.to_prover_state();

        let (prover_instance, prover_witness) = prover::<Fr, L>(
            &mut prover_state,
            &r1cs,
            alpha_vec.clone(),
            mu_vec.clone(),
            beta_vec.clone(),
            eta_vec.clone(),
            u_vec.clone(),
            z_vec.clone(),
            M,
            code.code_len(),
        )?;

        let mut verifier_state = domain_separator.to_verifier_state(prover_state.narg_string());
        let verifier_instance = verifier::<Fr, L>(
            &mut verifier_state,
            alpha_vec,
            mu_vec,
            beta_vec,
            eta_vec,
            r1cs.log_m,
            log2(code.code_len()) as usize,
        )?;

        assert_eq!(prover_instance, verifier_instance);

        Ok(())
    }
}
