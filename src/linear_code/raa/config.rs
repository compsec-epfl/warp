#[derive(Clone)]
pub struct RAAConfig {
    pub message_len: usize,
    pub num_repetitions: usize,
    pub rng_seed: [u8; 32],
}
