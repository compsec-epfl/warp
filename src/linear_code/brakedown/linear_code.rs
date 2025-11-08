use ark_crypto_primitives::{crh::CRHScheme, merkle_tree::Config as MerkleConfig};
use ark_ff::{Field, PrimeField};
use ark_poly::DenseMultilinearExtension;
use ark_poly_commit::linear_codes::{BrakedownPCParams, LinearEncode, MultilinearBrakedown};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};

use crate::linear_code::{BrakedownConfig, LinearCode};

#[derive(Clone, CanonicalSerialize)]
pub struct Brakedown<F, M, H>
where
    F: Field + PrimeField,
    M: MerkleConfig,
    H: CRHScheme,
{
    code_len: usize,
    message_len: usize,
    params: BrakedownPCParams<F, M, H>, // NOTE: generated in calls to ::new(...)
}

impl<F, M, H> LinearCode<F> for Brakedown<F, M, H>
where
    F: Field + PrimeField,
    M: MerkleConfig,
    H: CRHScheme,
{
    type Config = BrakedownConfig<F, M, H>;

    fn new(config: Self::Config) -> Self {
        let params: BrakedownPCParams<F, M, H> = BrakedownPCParams::default(
            &mut StdRng::from_seed(config.rng_seed),
            // NOTE (z-tech): must supply whatever makes pp.m == msg.len() to make 128-bit security
            2 * config.message_len,
            true,
            config.leaf_hash_param,
            config.one_two_hash_param,
            config.column_hash_param,
        );
        let tmp_message = vec![F::zero(); config.message_len];

        // TODO (z-tech): fix this
        let tmp_code =
            <MultilinearBrakedown<F, M, DenseMultilinearExtension<F>, H> as LinearEncode<
                F,
                M,
                DenseMultilinearExtension<F>,
                H,
            >>::encode(&tmp_message, &params)
            .unwrap();
        // using this to get code_len

        Self {
            message_len: config.message_len,
            code_len: tmp_code.len(),
            params,
        }
    }

    fn encode(&self, message: &[F]) -> Vec<F> {
        <MultilinearBrakedown<F, M, DenseMultilinearExtension<F>, H> as LinearEncode<
            F,
            M,
            DenseMultilinearExtension<F>,
            H,
        >>::encode(message, &self.params)
        .unwrap()
    }

    fn message_len(&self) -> usize {
        self.message_len
    }

    fn code_len(&self) -> usize {
        self.code_len
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr as BLS12_381;
    use ark_crypto_primitives::crh::poseidon::CRH as PoseidonCRH;
    use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
    use ark_poly::DenseMultilinearExtension;
    use ark_poly_commit::linear_codes::{BrakedownPCParams, LinearEncode, MultilinearBrakedown};
    use ark_std::{
        marker::PhantomData,
        {rand::RngCore, test_rng},
    };

    use crate::linear_code::{Brakedown, BrakedownConfig, LinearCode};
    use crate::merkle::poseidon::{poseidon_test_params, PoseidonMerkleConfig};

    #[test]
    fn instantiate_sanity() {
        // NOTE (z-tech): I needed this test to figure out how the API works

        // params depend on message_len
        let message_len = 1024usize;
        let message: Vec<BLS12_381> = (0..message_len)
            .map(|i| BLS12_381::from(i as u64 + 1))
            .collect();

        // TODO (z-tech): works like this, but probably these can be optimized
        let leaf_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let one_two_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let column_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();

        // generate params
        let pp: BrakedownPCParams<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonCRH<BLS12_381>,
        > = BrakedownPCParams::default(
            &mut test_rng(),
            2 * message_len, // supply whatever makes pp.m == msg.len() to make 128-bit security
            true,
            leaf_hash_param.clone(),
            one_two_hash_param.clone(),
            column_hash_param.clone(),
        );

        // encode
        let _codeword = <MultilinearBrakedown<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            DenseMultilinearExtension<BLS12_381>,
            PoseidonCRH<BLS12_381>,
        > as LinearEncode<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            DenseMultilinearExtension<BLS12_381>,
            PoseidonCRH<BLS12_381>,
        >>::encode(&message, &pp)
        .unwrap();
    }

    #[test]
    fn sanity() {
        // NOTE (z-tech): this does the same as "instantiate_sanity" but calling from the trait

        // params depend on message_len
        let message_len = 1024usize;
        let message: Vec<BLS12_381> = (0..message_len)
            .map(|i| BLS12_381::from(i as u64 + 1))
            .collect();

        // TODO (z-tech): works like this, but probably these can be optimized
        let leaf_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let one_two_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let column_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();

        // generate seed
        let mut rng = ark_std::test_rng();
        let mut rng_seed = [0u8; 32];
        rng.fill_bytes(&mut rng_seed);

        // config
        let config =
            BrakedownConfig::<BLS12_381, PoseidonMerkleConfig<BLS12_381>, PoseidonCRH<BLS12_381>> {
                message_len,
                leaf_hash_param,
                one_two_hash_param,
                column_hash_param,
                rng_seed,
                _f: PhantomData::<BLS12_381>,
            };

        // encode
        let brakedown =
            <Brakedown<BLS12_381, PoseidonMerkleConfig<BLS12_381>, PoseidonCRH<BLS12_381>>>::new(
                config,
            );
        let _codeword = brakedown.encode(&message);
    }
}
