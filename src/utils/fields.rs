use ark_ff::{ark_ff_macros::SmallFpConfig, SmallFp};

// Goldilock's prime 2^64 - 2^32 + 1
#[derive(SmallFpConfig)]
#[modulus = "18446744069414584321"]
#[generator = "7"]
pub struct GoldilocksConfig;
pub type Goldilocks = SmallFp<GoldilocksConfig>;
