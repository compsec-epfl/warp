use ark_ff::{Field, PrimeField};
use ark_std::{
    marker::PhantomData,
    rand::{prelude::SliceRandom, rngs::StdRng, SeedableRng},
};

use crate::linear_code::{raa::config::RAAConfig, LinearCode};

#[derive(Clone)]
pub struct RAA<F: Field> {
    message_len: usize,
    interleaver_permutation_1: Vec<usize>,
    interleaver_permutation_2: Vec<usize>,
    num_repetitions: usize, // >= 2, rate is roughly 1 / num_repetitions btw
    code_len: usize,
    _f: PhantomData<F>,
}

impl<F: Field> RAA<F> {
    #[inline]
    fn permute(&self, message: &[F], permutation: &[usize]) -> Vec<F> {
        debug_assert_eq!(message.len(), permutation.len());
        let mut out = vec![F::zero(); message.len()];
        for (i, &j) in permutation.iter().enumerate() {
            out[i] = message[j];
        }
        out
    }

    #[inline]
    fn accumulate(&self, message: &[F]) -> Vec<F> {
        let mut prefix_sums = Vec::with_capacity(message.len());
        let mut sum = F::zero();
        for message in message {
            sum += message;
            prefix_sums.push(sum);
        }
        prefix_sums
    }

    #[inline]
    fn repeat(&self, msg: &[F]) -> Vec<F> {
        let mut out = Vec::with_capacity(self.code_len);
        for &x in msg {
            for _ in 0..self.num_repetitions {
                out.push(x);
            }
        }
        out
    }
}

impl<F> LinearCode<F> for RAA<F>
where
    F: Field + PrimeField,
{
    type Config = RAAConfig;

    fn new(config: Self::Config) -> Self {
        assert!(config.num_repetitions >= 2, "num_repetitions must be >= 2");
        let code_len = config.num_repetitions * config.message_len;

        let mut interleaver_permutation_1: Vec<usize> = (0..code_len).collect();
        let mut interleaver_permutation_2: Vec<usize> = (0..code_len).collect();
        let mut rng = StdRng::from_seed(config.rng_seed);
        interleaver_permutation_1.shuffle(&mut rng);
        interleaver_permutation_2.shuffle(&mut rng);

        Self {
            message_len: config.message_len,
            interleaver_permutation_1,
            interleaver_permutation_2,
            num_repetitions: config.num_repetitions,
            code_len,
            _f: PhantomData::<F>,
        }
    }

    fn encode(&self, message: &[F]) -> Vec<F> {
        assert_eq!(
            message.len(),
            self.message_len,
            "length of message incorrect"
        );

        // RAA: repeat -> permute -> accumulate -> permute -> accumulate
        let repeated = self.repeat(message);
        let permuted_1 = self.permute(&repeated, &self.interleaver_permutation_1);
        let accumulated_1 = self.accumulate(&permuted_1);
        let permuted_2 = self.permute(&accumulated_1, &self.interleaver_permutation_2);
        let accumulated_2 = self.accumulate(&permuted_2);

        accumulated_2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{rand::RngCore, test_rng};

    use crate::tests::F32;

    #[test]
    fn raa_encode_basic() {
        let message_len = 16usize;
        let message: Vec<F32> = (0..message_len)
            .map(|i| F32::from((i + 1) as u64))
            .collect();

        let mut rng = test_rng();
        let mut rng_seed = [0u8; 32];
        rng.fill_bytes(&mut rng_seed);

        let config = RAAConfig {
            message_len,
            num_repetitions: 3,
            rng_seed,
        };

        let raa: RAA<F32> = RAA::new(config);
        let codeword = raa.encode(&message);
        assert_eq!(codeword.len(), 3 * message_len);
    }
}
