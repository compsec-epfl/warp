use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_ff::PrimeField;

// TODO: source an appropriate config
pub fn initialize_poseidon_config<F: PrimeField>() -> PoseidonConfig<F> {
    let full_rounds = 8;
    let partial_rounds = 60;
    let alpha = 5;
    let rate = 4;
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );
    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, 1)
}
