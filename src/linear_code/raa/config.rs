use ark_serialize::CanonicalSerialize;

#[derive(Clone, CanonicalSerialize)]
pub struct RAAConfig {
    pub message_len: usize,
    pub num_repetitions: usize,
    pub seed: [u8; 32],
}
