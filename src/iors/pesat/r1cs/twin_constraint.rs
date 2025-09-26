use ark_crypto_primitives::merkle_tree::{Config, MerkleTree};
use ark_ff::{FftField, Field};
use ark_poly::Polynomial;

use crate::{linear_code::MultiConstrainedLinearCode, relations::r1cs::R1CS, WARPError};
use spongefish::{
    DuplexSpongeInterface, ProofError, ProverState, Unit as SpongefishUnit, UnitTranscript,
};

use crate::iors::{IORConfig, IOR};

// L should be a power of 2
// we have L incoming (instance, witness) pairs (noted l1 when in WARP context)
// a twin constraint code is the code for which R = 1
pub struct R1CSTwinConstraintIOR<
    F: Field + SpongefishUnit,
    MC: MultiConstrainedLinearCode<F, 1>,
    MT: Config,
    const L: usize, // L instances
> {
    r1cs: R1CS<F>,
    config: IORConfig<F, MC, MT, 1>,
}

impl<
        F: FftField + SpongefishUnit,
        MC: MultiConstrainedLinearCode<F, 1>,
        MT: Config<InnerDigest = F, Leaf = Vec<F>>,
        S: DuplexSpongeInterface<F>,
        const L: usize,
    > IOR<F, MC, MT, S, 1> for R1CSTwinConstraintIOR<F, MC, MT, L>
{
    // we have L incoming (instance, witness) pairs
    // (x, w) s.t. R1CS(x, w) = 0
    type Instance<'a> = Vec<Vec<F>>;
    type Witness<'a> = Vec<Vec<F>>;

    // L twin constraint codes
    type OutputInstance<'a> = Vec<MC>;

    // L corresponding codewords
    type OutputWitness<'a> = Vec<Vec<F>>;

    fn prove<'a>(
        &self,
        prover_state: &mut ProverState<S, F>,
        instance: Self::Instance<'a>,
        witness: Self::Witness<'a>,
    ) -> Result<(Self::OutputInstance<'a>, Self::OutputWitness<'a>), WARPError> {
        debug_assert!(instance.len() == L);
        debug_assert!(instance.len() == witness.len());

        let mut output_witness = vec![vec![F::default(); self.config.code.message_len()]; L];
        let mut output_instance = Vec::<MC>::with_capacity(L);

        let message_length = self.config.code.message_len();
        let num_vars = message_length.ilog2() as usize;

        // TODO: let user provide alpha (?)
        let alpha = vec![F::ZERO; num_vars];

        // we "stack" codewords to make a single merkle commitment over alphabet \mathbb{F}^{L}
        // we have L codeword instances, each has length n, i.e. build an n * L table
        let mut stacked_witnesses = vec![vec![F::default(); L]; message_length];

        // stores multilinear evaluations of \hat{f}
        let mut mu = vec![F::default(); L];

        // encode and evaluate the multilinear extension over [0; nvars]
        // TODO: multithread this (?)
        for i in 0..L {
            let f_i = self.config.code.encode(&witness[i]);

            // stacking codewords
            // w_i elements are in position in each of the j vecs
            // 0 [w_0[0], w_1[0], ..] // L elements
            // 1 [w_0[1], w_1[1], ..]
            // ..
            // N - 1 [w_0[N-1], w_1[N-1], ..]
            for (j, value) in f_i.iter().enumerate() {
                stacked_witnesses[j][i] = *value;
            }

            // evaluate the dense mle for the codeword
            let f_hat = MC::as_multilinear_extension(num_vars, &f_i);
            mu[i] = f_hat.evaluate(&alpha);

            output_witness[i] = f_i;
        }

        // commit
        let mt = MerkleTree::<MT>::new(
            &self.config.mt_leaf_hash_params,
            &self.config.mt_two_to_one_hash_params,
            &stacked_witnesses,
        )?;

        // absorb root and multilinear evaluations
        prover_state
            .add_units(&[mt.root()])
            .map_err(|e| ProofError::InvalidDomainSeparator(e))?;
        prover_state
            .add_units(&mu)
            .map_err(|e| ProofError::InvalidDomainSeparator(e))?;

        // for i \in [l_1] get \mathbf{\tau_i} \in \mathbf{F}^{\log M}
        // \beta_i = [x_i, \tau_i]
        let tau_len: usize = self.r1cs.log_m;

        for i in 0..L {
            let mut tau_i = vec![F::default(); tau_len];
            prover_state
                .fill_challenge_units(&mut tau_i)
                .map_err(|e| ProofError::InvalidDomainSeparator(e))?;

            output_instance[i] = MC::new(
                self.config.code.config(),
                [(vec![F::ZERO; num_vars], mu[i])],
                (tau_i, instance[i].clone()),
                F::ZERO,
            );
        }

        Ok((output_instance, output_witness))
    }

    fn verify() {
        todo!()
    }
}

#[cfg(test)]
pub mod tests {
    use crate::linear_code::ReedSolomonConfig;
    use ark_ec::AdditiveGroup;
    use spongefish::duplex_sponge::DuplexSponge;
    use spongefish_poseidon::PoseidonPermutation;

    use ark_bls12_381::Fr;

    type TestSponge = DuplexSponge<PoseidonPermutation<255, Fr, 2, 3>>;

    #[test]
    pub fn test_pesat_ior() {
        const L1: usize = 2;
        let config = ReedSolomonConfig::<Fr>::default(4, 8);
        let test_instance = &vec![Fr::ZERO; 4];
        let test_wtns = &vec![Fr::ZERO; 4];

        // initialize l1 test instances and witnesses
        let instance = [test_instance; L1];
        let witness = [test_wtns; L1];

        // PESATIOR::<Fr, ReedSolomon<Fr>, TestSponge, L1>::prove(&config, &instance, &witness);
    }
}
