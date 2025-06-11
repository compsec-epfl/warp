use ark_ff::fields::{Fp64, MontBackend, MontConfig};
use ark_bls12_381::Fr as BLS12_381;
use ark_bn254::Fr as BN254;

use criterion::{criterion_group, criterion_main, Criterion};
use warp::linear_code::{LinearCode, ReedSolomon, ReedSolomonConfig};

#[derive(MontConfig)]
#[modulus = "18446744069414584321"] // q = 2^64 - 2^32 + 1
#[generator = "2"]
pub struct GoldilocksConfig;
pub type Goldilocks = Fp64<MontBackend<GoldilocksConfig, 1>>;

fn bench_for_field<F: ark_ff::Field + ark_ff::FftField + std::fmt::Debug + 'static>(
    c: &mut Criterion,
    field_name: &str,
) {
    let sizes = vec![(223, 256), (256, 512), (1024, 2048), (4096, 8192)];

    let mut encode_group = c.benchmark_group(format!("rs_encode_{}", field_name));
    for &(k, n) in &sizes {
        let rs = ReedSolomon::<F>::new(ReedSolomonConfig::default(k, n));
        let message: Vec<F> = (0..k).map(|i| F::from(i as u64)).collect();
        encode_group.bench_function(format!("encode_{}_{}", k, n), |b| {
            b.iter(|| rs.encode(&message))
        });
    }
    encode_group.finish();

    let mut decode_group = c.benchmark_group(format!("rs_decode_{}", field_name));
    for &(k, n) in &sizes {
        let rs = ReedSolomon::<F>::new(ReedSolomonConfig::default(k, n));
        let message: Vec<F> = (0..k).map(|i| F::from(i as u64)).collect();
        let codeword = rs.encode(&message);
        decode_group.bench_function(format!("decode_{}_{}", k, n), |b| {
            b.iter(|| rs.decode(&codeword).unwrap())
        });
    }
    decode_group.finish();
}

fn bench_all_fields(c: &mut Criterion) {
    bench_for_field::<Goldilocks>(c, "goldilocks");
    bench_for_field::<BLS12_381>(c, "bls12_381");
    bench_for_field::<BN254>(c, "bn254");
}

criterion_group!(benches, bench_all_fields);
criterion_main!(benches);