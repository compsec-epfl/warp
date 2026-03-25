use ark_ff::Field;
use spongefish::ProverState;

pub struct QueryIndices<F: Field> {
    pub leaf_positions: Vec<usize>,     // for merkle tree lookups
    pub evaluation_points: Vec<Vec<F>>, // for eq polynomial evals
}

impl<F: Field> QueryIndices<F> {
    // take the prover state and sample for queries
    pub fn sample(
        prover_state: &mut ProverState,
        log_codeword_len: usize,
        num_queries: usize,
    ) -> Self {
        let num_bytes = (num_queries * log_codeword_len).div_ceil(8);
        let squeezed_bytes: Vec<u8> = prover_state
            .verifier_messages_vec::<[u8; 1]>(num_bytes)
            .into_iter()
            .map(|[b]| b)
            .collect();
        Self::from_squeezed_bytes(&squeezed_bytes, log_codeword_len, num_queries)
    }

    // format the queries from squeezed bytes
    pub fn from_squeezed_bytes(squeezed_bytes: &[u8], log_n: usize, count: usize) -> Self {
        let evaluation_points = Self::evaluation_points_from_squeezed_bytes(squeezed_bytes, log_n, count);
        // Compute all leaf positions in one batch
        let leaf_positions = Self::leaf_positions_from_evaluation_points(&evaluation_points);
        Self {
            leaf_positions,
            evaluation_points,
        }
    }

    // Get Vec of len=num_queries, where each elements is vec of F in {0,1} len=log_codeword_len
    fn evaluation_points_from_squeezed_bytes(
        squeezed_bytes: &[u8],
        log_codeword_len: usize,
        num_queries: usize,
    ) -> Vec<Vec<F>> {
        squeezed_bytes
            .iter()
            .flat_map(|squeezed_byte| (0..8).map(move |i| F::from((squeezed_byte >> i) & 1 == 1)))
            .take(num_queries * log_codeword_len)
            .collect::<Vec<F>>()
            .chunks(log_codeword_len)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    // Convert each evaluation point (vector of F in {0,1}) to its little-endian leaf index.
    fn leaf_positions_from_evaluation_points(evaluation_points: &[Vec<F>]) -> Vec<usize> {
        let binary_to_leaf_index = |bits: &Vec<F>| -> usize {
            bits.iter()
                .rev()
                .fold(0, |acc, &b| (acc << 1) | b.is_one() as usize)
        };
        evaluation_points.iter().map(binary_to_leaf_index).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr as BLS12_381;
    use ark_std::{One, Zero};
    use crate::utils::fields::Goldilocks;

    // check dimensions, binary values, and leaf position range
    fn check_query_indices<F: Field>(bytes: &[u8], log_n: usize, num_queries: usize) {
        let q = QueryIndices::<F>::from_squeezed_bytes(bytes, log_n, num_queries);

        assert_eq!(q.leaf_positions.len(), num_queries);
        assert_eq!(q.evaluation_points.len(), num_queries);

        for (i, eval_pt) in q.evaluation_points.iter().enumerate() {
            assert_eq!(eval_pt.len(), log_n);
            for &bit in eval_pt {
                assert!(bit.is_zero() || bit.is_one());
            }
            assert!(q.leaf_positions[i] < (1 << log_n));
        }
    }

    // check leaf_positions match manual binary-to-index conversion
    fn check_roundtrip<F: Field>(bytes: &[u8], log_n: usize, num_queries: usize) {
        let q = QueryIndices::<F>::from_squeezed_bytes(bytes, log_n, num_queries);
        for (i, eval_pt) in q.evaluation_points.iter().enumerate() {
            let expected = eval_pt
                .iter()
                .rev()
                .fold(0usize, |acc, &b| (acc << 1) | b.is_one() as usize);
            assert_eq!(q.leaf_positions[i], expected);
        }
    }

    // BLS12-381 (multi-limb, 256-bit)

    #[test]
    fn bls12_381_basic() {
        let bytes = vec![0b10110010, 0b01101001, 0b11110000, 0b00001111];
        check_query_indices::<BLS12_381>(&bytes, 4, 3);
    }

    #[test]
    fn bls12_381_roundtrip() {
        let bytes: Vec<u8> = (0..16).collect();
        check_roundtrip::<BLS12_381>(&bytes, 8, 10);
    }

    #[test]
    fn bls12_381_single_bit_queries() {
        // log_n = 1 → each query is a single bit
        let bytes = vec![0b10101010];
        let q = QueryIndices::<BLS12_381>::from_squeezed_bytes(&bytes, 1, 8);
        assert_eq!(q.leaf_positions.len(), 8);
        for &pos in &q.leaf_positions {
            assert!(pos <= 1);
        }
    }

    // Goldilocks (SmallFp, single-limb u128)

    #[test]
    fn goldilocks_basic() {
        let bytes = vec![0xFF, 0x00, 0xAB, 0xCD];
        check_query_indices::<Goldilocks>(&bytes, 4, 3);
    }

    #[test]
    fn goldilocks_roundtrip() {
        let bytes: Vec<u8> = (0..16).collect();
        check_roundtrip::<Goldilocks>(&bytes, 8, 10);
    }

    #[test]
    fn goldilocks_large_log_n() {
        // 16-bit queries → range [0, 65536)
        let bytes: Vec<u8> = (0..=255).cycle().take(64).collect();
        check_query_indices::<Goldilocks>(&bytes, 16, 4);
    }

    // edge cases

    #[test]
    fn zero_bytes_produce_zero_indices() {
        let bytes = vec![0u8; 8];
        let q = QueryIndices::<BLS12_381>::from_squeezed_bytes(&bytes, 4, 4);
        for &pos in &q.leaf_positions {
            assert_eq!(pos, 0);
        }
        for eval_pt in &q.evaluation_points {
            for &bit in eval_pt {
                assert!(bit.is_zero());
            }
        }
    }

    #[test]
    fn all_ones_bytes() {
        let bytes = vec![0xFF; 8];
        let q = QueryIndices::<Goldilocks>::from_squeezed_bytes(&bytes, 4, 4);
        for &pos in &q.leaf_positions {
            assert_eq!(pos, (1 << 4) - 1);
        }
        for eval_pt in &q.evaluation_points {
            for &bit in eval_pt {
                assert!(bit.is_one());
            }
        }
    }

    #[test]
    fn deterministic_output() {
        let bytes = vec![0x42, 0x13, 0x7F, 0xE0];
        let q1 = QueryIndices::<BLS12_381>::from_squeezed_bytes(&bytes, 4, 4);
        let q2 = QueryIndices::<BLS12_381>::from_squeezed_bytes(&bytes, 4, 4);
        assert_eq!(q1.leaf_positions, q2.leaf_positions);
        assert_eq!(q1.evaluation_points, q2.evaluation_points);
    }
}
