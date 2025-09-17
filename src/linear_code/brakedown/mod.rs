use ark_crypto_primitives::{crh::CRHScheme, merkle_tree::Config as MerkleConfig};
use ark_ff::{Field, PrimeField};
use ark_poly::Polynomial;
use ark_poly_commit::linear_codes::{
    BrakedownPCParams as BrakedownConfig, LinCodeParametersInfo, LinearEncode, MultilinearBrakedown,
};
use ark_serialize::CanonicalSerialize;
use ark_std::marker::PhantomData;

use crate::linear_code::LinearCode;

#[derive(Clone, CanonicalSerialize)]
pub struct Brakedown<
    F: Field + PrimeField,
    M: MerkleConfig,
    H: CRHScheme,
    P: Polynomial<F> + ark_poly::MultilinearExtension<F>,
> {
    config: BrakedownConfig<F, M, H>,
    _p: PhantomData<P>,
}

impl<
        F: Field + PrimeField,
        M: MerkleConfig,
        H: CRHScheme,
        P: Polynomial<F> + ark_poly::MultilinearExtension<F>,
    > LinearCode<F> for Brakedown<F, M, H, P>
{
    type Config = BrakedownConfig<F, M, H>;

    fn new(config: Self::Config) -> Self {
        Self {
            config,
            _p: PhantomData::<P>,
        }
    }

    fn encode(&self, message: &[F]) -> Vec<F> {
        // assert_eq!(message.len(), ...);
        MultilinearBrakedown::<F, M, P, H>::encode(message, &self.config).unwrap()
    }

    fn decode(&self, received: &[F]) -> Option<Vec<F>> {
        let (k, _n) = self.config.compute_dimensions(0);
        // No error-correction here: just return the first k symbols
        Some(received[..k].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr as BLS12_381;
    use ark_crypto_primitives::crh::poseidon::CRH as PoseidonCRH;
    use ark_poly::DenseMultilinearExtension as DME;
    use ark_std::{test_rng, vec::Vec};

    // your Poseidon helpers + Merkle config
    use crate::merkle::poseidon::{poseidon_test_params, PoseidonMerkleConfig};

    // Column hash = Poseidon CRH
    type ColHash = PoseidonCRH<BLS12_381>;
    // Multilinear polynomial type parameter
    type Poly = DME<BLS12_381>;
    // Our LinearCode adapter specialized to concrete types
    type BD = super::Brakedown<BLS12_381, PoseidonMerkleConfig<BLS12_381>, ColHash, Poly>;
    // Convenience alias
    type Params = ark_poly_commit::linear_codes::BrakedownPCParams<
        BLS12_381,
        PoseidonMerkleConfig<BLS12_381>,
        ColHash,
    >;

    #[test]
    fn sanity() {
        let mut rng = test_rng();

        // k must be 2^ell
        let k: usize = 8;
        assert!(k.is_power_of_two(), "k must be a power of two");
        let ell: usize = k.trailing_zeros() as usize; // <- correct log2(k)

        // Poseidon params
        let poseidon_params = poseidon_test_params();
        let leaf_params = poseidon_params.clone();
        let two_to_one_params = poseidon_params.clone();
        let col_hash_params = poseidon_params;

        // Build params for a multilinear with `ell` variables
        let params: Params = ark_poly_commit::linear_codes::MultilinearBrakedown::<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            Poly,
            ColHash,
        >::setup(
            /*_max_degree=*/ 0,
            /*num_vars=*/ Some(ell),
            &mut rng,
            leaf_params,
            two_to_one_params,
            col_hash_params,
        );

        let bd = BD::new(params);

        // message of length k = 2^ell
        let message: Vec<BLS12_381> = (0..k as u64).map(BLS12_381::from).collect();

        let codeword = bd.encode(&message);

        let (k_expected, n) = bd.config.compute_dimensions(0);
        assert_eq!(k_expected, k, "params expect k={k_expected}");
        assert_eq!(codeword.len(), n, "unexpected codeword length");
        assert!(n > k, "Brakedown should expand");

        let decoded = bd.decode(&codeword).unwrap();
        assert_eq!(decoded, message);
    }
}
