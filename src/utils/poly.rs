use ark_ff::Field;
use whir::poly_utils::hypercube::BinaryHypercubePoint;

// from whir
// https://github.com/WizardOfMenlo/whir/blob/22c675807fc9295fef68a11945713dc3e184e1c1/src/poly_utils/multilinear.rs#L105
pub fn eq_poly<F: Field>(tau: &[F], mut point: BinaryHypercubePoint) -> F {
    let n_variables = tau.len();
    assert!(*point < (1 << n_variables)); // Ensure correct length

    let mut acc = F::ONE;

    for val in tau.iter() {
        let b = *point % 2;
        acc *= if b == 1 { *val } else { F::ONE - *val };
        *point >>= 1;
    }

    acc
}

pub fn eq_poly_non_binary<F: Field>(x: &[F], y: &[F]) -> F {
    assert_eq!(x.len(), y.len());
    let res = x.into_iter().zip(y).fold(F::one(), |acc, (x_i, y_i)| {
        acc * (*x_i * *y_i + (F::one() - x_i) * (F::one() - y_i))
    });
    res
}
