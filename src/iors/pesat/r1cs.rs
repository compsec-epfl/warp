use ark_crypto_primitives::merkle_tree::{Config, MerkleTree};
use ark_ff::Field;
use ark_poly::Polynomial;

use crate::{linear_code::MultiConstrainedCode, relations::r1cs::R1CS, WARPError};
use spongefish::{
    DuplexSpongeInterface, ProofError, ProverState, Unit as SpongefishUnit, UnitTranscript,
};

use crate::iors::{IORConfig, IOR};

// L should be a power of 2
// we have L incoming (instance, witness) pairs (noted l1 when in WARP context)
pub struct R1CSIOR<
    F: Field + SpongefishUnit,
    MC: MultiConstrainedCode<F>,
    MT: Config,
    const L: usize, // L instances
> {
    r1cs: R1CS<F>,
    config: IORConfig<F, MC, MT>,
}

impl<
        F: Field + SpongefishUnit,
        MC: MultiConstrainedCode<F>,
        MT: Config<InnerDigest = F, Leaf = Vec<F>>,
        S: DuplexSpongeInterface<F>,
        const L: usize,
    > IOR<F, MC, MT, S> for R1CSIOR<F, MC, MT, L>
{
    // we have L incoming (instance, witness) pairs
    // (x, w) s.t. PESAT(x, w) = 0
    type Instance<'a> = &'a [&'a Vec<F>; L];
    type Witness<'a> = &'a [&'a Vec<F>; L];

    // TODO: define R as const somewhere (?)
    // ((\alpha_i, \mu_i)_{i \in [r]}, \beta, \eta), u)_j)_{j \in [L]}
    type OutputInstance<'a> = &'a [&'a Vec<F>; L];
    type OutputWitness<'a> = &'a [&'a Vec<F>; L];

    fn prove<'a>(
        &self,
        prover_state: &mut ProverState<S, F>,
        instance: Self::Instance<'a>,
        witness: Self::Witness<'a>,
    ) -> Result<(Self::OutputInstance<'a>, Self::OutputWitness<'a>), WARPError> {
        let message_length = self.config.code.message_len();
        let num_vars = message_length.ilog2() as usize;
        let alpha = vec![F::ZERO; num_vars];

        // we "stack" codewords to make a single merkle commitment over alphabet \mathbb{F}^{L}
        // we have L codeword instances, each has length n, i.e. stacking an n * L table
        let mut stacked_witnesses = vec![vec![F::default(); L]; message_length];

        // stores multilinear evaluations of \hat{f}
        let mut mu = vec![F::default(); L];

        // encode, evaluate the multilinear extension over [0; nvars]
        // TODO: multithread this
        for (j, w) in witness.iter().enumerate() {
            let f_i = self.config.code.encode(*w);

            // all i-th elements of witnesses go into the j-th vector
            for (i, value) in f_i.iter().enumerate() {
                stacked_witnesses[i][j] = *value;
            }

            let f_hat = MC::as_multilinear_extension(num_vars, &f_i);
            mu[j] = f_hat.evaluate(&alpha);
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

        let num_instance_variables = self.r1cs.n - self.r1cs.k;
        let len_tau_x = num_instance_variables + tau_len;
        let mut betas = vec![vec![F::default(); len_tau_x]; L];
        let etas = vec![F::ZERO; L];

        for i in 0..L {
            let mut tau_i = vec![F::default(); tau_len];
            prover_state
                .fill_challenge_units(&mut tau_i)
                .map_err(|e| ProofError::InvalidDomainSeparator(e))?;
            tau_i.extend_from_slice(instance[i]);
            betas[i] = tau_i;
        }
        todo!()
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
