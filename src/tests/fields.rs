use ark_ff::fields::{Fp128, Fp64, MontBackend, MontConfig};

#[derive(MontConfig)]
#[modulus = "2147483647"] // q = 2147483647 Mersenne31
#[generator = "2"]
pub struct F32Config;
pub type F32 = Fp64<MontBackend<F32Config, 1>>;

#[derive(MontConfig)]
#[modulus = "18446744069414584321"] // q = 2^64 - 2^32 + 1 Goldilocks
#[generator = "2"]
pub struct F64Config;
pub type F64 = Fp64<MontBackend<F64Config, 1>>;

#[derive(MontConfig)]
#[modulus = "143244528689204659050391023439224324689"] // q = 143244528689204659050391023439224324689
#[generator = "2"]
pub struct F128Config;
pub type F128 = Fp128<MontBackend<F128Config, 2>>;
