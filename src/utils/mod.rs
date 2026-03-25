use ark_ff::{Field, PrimeField};

pub mod fields;
pub mod poly;
pub mod poseidon;

pub const fn chunk_size_bytes(modulus_bit_size: u32) -> usize {
    modulus_bit_size.div_ceil(64) as usize * 8
}

pub fn chunk_size<F: PrimeField>() -> usize {
    chunk_size_bytes(F::MODULUS_BIT_SIZE)
}

pub fn concat_slices<F: Clone>(a: &[F], b: &[F]) -> Vec<F> {
    let mut v = Vec::<F>::with_capacity(a.len() + b.len());
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    v
}

pub fn scale_and_sum<F: Field>(vectors: &[Vec<F>], scalars: &[F]) -> Vec<F> {
    let n = vectors[0].len();
    let mut result = vec![F::default(); n];

    vectors.iter().zip(scalars).for_each(|(v, &a)| {
        result.iter_mut().zip(v).for_each(|(r, &x)| *r += a * x);
    });

    result
}
