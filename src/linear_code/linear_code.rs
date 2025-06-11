use ark_ff::Field;

pub trait LinearCode<F: Field> {
    type Config;

    fn new(config: Self::Config) -> Self;

    // encode a k-symbol message into an n-symbol codeword
    fn encode(&self, message: &[F]) -> Vec<F>;

    // decode an n-symbol codeword back into the original k-symbol message
    // should return None if decoding fails (bc errors are beyond capacity etc)
    fn decode(&self, received: &[F]) -> Option<Vec<F>>;
}
