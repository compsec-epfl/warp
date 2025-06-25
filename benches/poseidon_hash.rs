use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_std::{rand::RngCore, test_rng};

use ark_bls12_381::Fr as BLS12_381;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use warp::merkle::poseidon::poseidon_test_params;

fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = test_rng();
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    buf
}

fn bench_poseidon(c: &mut Criterion) {
    let poseidon_config = poseidon_test_params();
    let mut group = c.benchmark_group("poseidon_hash");

    // Throughput tracking (bytes/sec) for each input size
    group.sample_size(20);

    // Build a list of sizes: 0→128→256→…→1024, then doubling: 2 KiB, 4 KiB, …, 100 KiB
    let mut sizes = Vec::new();
    let mut size = 0;
    while size <= 100 * 1024 {
        sizes.push(size);
        size = if size < 1024 { size + 128 } else { size * 2 };
    }

    for &size in &sizes {
        let mut sponge = PoseidonSponge::<BLS12_381>::new(&poseidon_config);

        group.throughput(criterion::Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{} bytes", size)),
            &size,
            |b, &s| {
                let input = random_bytes(s);
                b.iter(|| {
                    sponge.absorb(&input);
                    let hash_fe = sponge.squeeze_field_elements::<BLS12_381>(1)[0];
                    black_box(hash_fe);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_poseidon);
criterion_main!(benches);
