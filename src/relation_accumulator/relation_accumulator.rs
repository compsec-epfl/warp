use ark_crypto_primitives::Error;
use ark_ff::Field;

pub trait RelationAccumulator<F: Field> {
    type Config;
    type Commitment;
    type Instance;
    type Proof;
    fn commit(config: Self::Config, instances: &[Self::Instance]) -> Self;
    fn commitment(&self) -> Self::Commitment;
    fn open(&self, index: usize) -> Result<Self::Proof, Error>;
    fn verify(
        config: &Self::Config,
        commitment: &Self::Commitment,
        instance: &Self::Instance,
        proof: &Self::Proof,
    ) -> bool;
}
