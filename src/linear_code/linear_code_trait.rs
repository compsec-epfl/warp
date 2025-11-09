use ark_ff::Field;

pub trait LinearCode<F: Field> {
    type Config;
    fn new(config: Self::Config) -> Self;
    fn encode(&self, message: &[F]) -> Vec<F>;
}
