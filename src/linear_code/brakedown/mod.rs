#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr as BLS12_381;
    use ark_crypto_primitives::crh::poseidon::CRH;
    use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
    use ark_poly::DenseMultilinearExtension;
    use ark_poly_commit::linear_codes::{BrakedownPCParams, LinearEncode, MultilinearBrakedown};
    use ark_std::test_rng;

    use crate::merkle::poseidon::{poseidon_test_params, PoseidonMerkleConfig};
    #[test]
    fn encode_with_brakedown_demo() {
        // NOTE (z-tech): params depend on message_len
        let message_len = 1024usize;
        let message: Vec<BLS12_381> = (0..message_len)
            .map(|i| BLS12_381::from(i as u64 + 1))
            .collect();

        // TODO (z-tech): works like this, but probably these can be optimized
        let leaf_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let one_two_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let column_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();

        // generate params
        let pp: BrakedownPCParams<BLS12_381, PoseidonMerkleConfig<BLS12_381>, CRH<BLS12_381>> =
            BrakedownPCParams::default(
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
            CRH<BLS12_381>,
        > as LinearEncode<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            DenseMultilinearExtension<BLS12_381>,
            CRH<BLS12_381>,
        >>::encode(&message, &pp)
        .unwrap();
    }
}
