use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    marker::PhantomData,
    rand::{prelude::SliceRandom, rngs::StdRng, SeedableRng},
};

use crate::linear_code::{raa::config::RAAConfig, LinearCode};

// https://people.eecs.berkeley.edu/~venkatg/pubs/papers/RAA.pdf

#[derive(Clone, CanonicalSerialize)]
pub struct RAA<F: Field> {
    message_len: usize,
    permutation_1: Vec<usize>,
    permutation_2: Vec<usize>,
    num_repetitions: usize, // >= 2, apparently rate is roughly 1 / num_repetitions btw
    code_len: usize,
    _f: PhantomData<F>,
}

impl<F: Field> RAA<F> {
    #[inline]
    fn permute(&self, message: &[F], permutation: &[usize]) -> Vec<F> {
        assert_eq!(message.len(), permutation.len());
        let mut permuted = vec![F::zero(); message.len()];
        for (i, &j) in permutation.iter().enumerate() {
            permuted[i] = message[j];
        }
        permuted
    }

    #[inline]
    fn accumulate(&self, message: &[F]) -> Vec<F> {
        // this is also called "prefix_sum"
        let mut accumulated = Vec::with_capacity(message.len());
        let mut sum = F::zero();
        for message in message {
            sum += message;
            accumulated.push(sum);
        }
        accumulated
    }

    #[inline]
    fn repeat(&self, msg: &[F]) -> Vec<F> {
        let mut repeated = Vec::with_capacity(self.code_len);
        for &x in msg {
            for _ in 0..self.num_repetitions {
                repeated.push(x);
            }
        }
        repeated
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

        let mut permutation_1: Vec<usize> = (0..code_len).collect();
        let mut permutation_2: Vec<usize> = (0..code_len).collect();
        let mut rng = StdRng::from_seed(config.seed);
        permutation_1.shuffle(&mut rng);
        permutation_2.shuffle(&mut rng);

        Self {
            message_len: config.message_len,
            permutation_1,
            permutation_2,
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
        let permuted_1 = self.permute(&repeated, &self.permutation_1);
        let accumulated_1 = self.accumulate(&permuted_1);
        let permuted_2 = self.permute(&accumulated_1, &self.permutation_2);
        let accumulated_2 = self.accumulate(&permuted_2);

        // return message + encoding
        let mut codeword = Vec::with_capacity(self.message_len + accumulated_2.len());
        codeword.extend_from_slice(message);
        codeword.extend_from_slice(&accumulated_2);
        codeword
    }

    fn message_len(&self) -> usize {
        self.message_len
    }
    fn code_len(&self) -> usize {
        self.code_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{rand::RngCore, test_rng};

    use crate::tests::F32;

    #[test]
    fn sanity() {
        let message_len = 16usize;
        let message: Vec<F32> = (0..message_len)
            .map(|i| F32::from((i + 1) as u64))
            .collect();

        let mut rng = test_rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        let config = RAAConfig {
            message_len,
            num_repetitions: 3,
            seed,
        };

        let raa: RAA<F32> = RAA::new(config);
        let codeword = raa.encode(&message);
        assert_eq!(codeword.len(), 4 * message_len);
    }
}
