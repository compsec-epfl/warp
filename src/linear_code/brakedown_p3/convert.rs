use ark_ff::PrimeField;
use num_bigint::BigUint;
// use p3_field::integers::QuotientMap;
use p3_field::{PrimeField32, PrimeField64};

/**
 * TODO(z-tech): as far as I can tell, p3 supports only prime fields smaller than
 * 64 bits (using two types for: u32 and u64 and also BN254
 */

pub fn ark_to_p3_32<S, D>(source: &S) -> D
where
    S: PrimeField,
    D: PrimeField32,
{
    let big_uint: BigUint = (*source).into();
    let limbs: Vec<u64> = big_uint.to_u64_digits();
    let source_usize = *limbs.first().unwrap_or(&0) as usize;
    D::from_canonical_usize(source_usize)
}

pub fn p3_to_ark_32<S, D>(source: &S) -> D
where
    S: PrimeField32,
    D: PrimeField,
{
    let source_u64 = source.as_canonical_u64();
    D::from(source_u64)
}

pub fn vec_ark_to_vec_p3_32<S, D>(source: &[S]) -> Vec<D>
where
    S: PrimeField,
    D: PrimeField32,
{
    source.iter().map(|s| ark_to_p3_32(s)).collect()
}

pub fn vec_p3_to_vec_ark_32<S, D>(source: &[S]) -> Vec<D>
where
    S: PrimeField32,
    D: PrimeField,
{
    source.iter().map(|s| p3_to_ark_32(s)).collect()
}

pub fn ark_to_p3_64<S, D>(source: &S) -> D
where
    S: PrimeField,
    D: PrimeField64,
{
    let big_uint: BigUint = (*source).into();
    let limbs: Vec<u64> = big_uint.to_u64_digits();
    let source_usize = *limbs.first().unwrap_or(&0) as usize;
    D::from_canonical_usize(source_usize)
}

pub fn p3_to_ark_64<S, D>(source: &S) -> D
where
    S: PrimeField64,
    D: PrimeField,
{
    let source_u64 = source.as_canonical_u64();
    D::from(source_u64)
}

pub fn vec_ark_to_vec_p3_64<S, D>(source: &[S]) -> Vec<D>
where
    S: PrimeField,
    D: PrimeField64,
{
    source.iter().map(|s| ark_to_p3_64(s)).collect()
}

pub fn vec_p3_to_vec_ark_64<S, D>(source: &[S]) -> Vec<D>
where
    S: PrimeField64,
    D: PrimeField,
{
    source.iter().map(|s| p3_to_ark_64(s)).collect()
}

#[cfg(test)]
mod tests {

    use p3_field::AbstractField;
    use p3_goldilocks::Goldilocks;
    use p3_mersenne_31::Mersenne31;

    use super::*;
    use ark_ff::{Fp64, MontBackend, MontConfig};

    #[derive(MontConfig)]
    #[modulus = "18446744069414584321"] // q = 2^64 - 2^32 + 1 Goldilocks
    #[generator = "2"]
    pub struct ArkGoldilocksConfig;
    pub type ArkGoldilocks = Fp64<MontBackend<ArkGoldilocksConfig, 1>>;

    #[derive(MontConfig)]
    #[modulus = "2147483647"] // mersenne 31
    #[generator = "2"]
    pub struct ArkM31Config;
    pub type ArkM31 = Fp64<MontBackend<ArkM31Config, 1>>;

    #[test]
    fn sanity_32_bit() {
        // couple values
        let ark_vals: Vec<ArkM31> = vec![ArkM31::from(0), ArkM31::from(1), ArkM31::from(u32::MAX)];
        // assert p3 equivalents
        let p3_vals: Vec<Mersenne31> = vec_ark_to_vec_p3_32(&ark_vals);
        assert_eq!(*p3_vals.get(0).unwrap(), Mersenne31::from_canonical_u32(0));
        assert_eq!(*p3_vals.get(1).unwrap(), Mersenne31::from_canonical_u32(1));
        assert_eq!(
            *p3_vals.get(2).unwrap(),
            Mersenne31::from_canonical_u32(u32::MAX) // TODO(z-tech): why does this fail?
        );
        // assert roundtrip equivalents
        let roundtrip_vals: Vec<ArkM31> = vec_p3_to_vec_ark_32(&p3_vals);
        assert_eq!(ark_vals, roundtrip_vals);
    }

    #[test]
    fn sanity_64_bit() {
        // couple values
        let ark_vals: Vec<ArkGoldilocks> = vec![
            ArkGoldilocks::from(0),
            ArkGoldilocks::from(1),
            ArkGoldilocks::from(u64::MAX),
        ];
        // assert p3 equivalents
        let p3_vals: Vec<Goldilocks> = vec_ark_to_vec_p3_64(&ark_vals);
        assert_eq!(*p3_vals.get(0).unwrap(), Goldilocks::from_canonical_u64(0));
        assert_eq!(*p3_vals.get(1).unwrap(), Goldilocks::from_canonical_u64(1));
        assert_eq!(
            *p3_vals.get(2).unwrap(),
            Goldilocks::from_canonical_u64(u64::MAX)
        );
        // assert roundtrip equivalents
        let roundtrip_vals: Vec<ArkGoldilocks> = vec_p3_to_vec_ark_64(&p3_vals);
        assert_eq!(ark_vals, roundtrip_vals);
    }
}
