use std::marker::PhantomData;

use ark_crypto_primitives::merkle_tree::{Config, MerkleTree};
use ark_ff::{FftField, Field};
use ark_poly::Polynomial;

use crate::{
    linear_code::{LinearCode, MultiConstrainedLinearCode},
    relations::r1cs::R1CS,
    WARPError,
};
use spongefish::{
    DuplexSpongeInterface, ProofError, ProverState, Unit as SpongefishUnit, UnitTranscript,
};

use crate::iors::{IORConfig, IOR};

// L should be a power of 2
// we have L incoming (instance, witness) pairs (noted l1 when in WARP context)
// a twin constraint code is the code for which R = 1
pub struct R1CSTwinConstraintIOR<
    F: Field + SpongefishUnit,
    C: LinearCode<F>,
    MC: MultiConstrainedLinearCode<F, C, 1>,
    MT: Config,
    const L: usize, // L instances
> {
    r1cs: R1CS<F>,
    config: IORConfig<F, C, MT>,
    _mc: PhantomData<MC>,
}

impl<
        F: FftField + SpongefishUnit,
        C: LinearCode<F>,
        MC: MultiConstrainedLinearCode<F, C, 1>,
        MT: Config<InnerDigest = F, Leaf = [F]>,
        S: DuplexSpongeInterface<F>,
        const L: usize,
    > IOR<F, C, MT, S> for R1CSTwinConstraintIOR<F, C, MC, MT, L>
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
        debug_assert!(self.config.code.code_len().is_power_of_two());

        let code_length = self.config.code.code_len();
        let mut output_witness = vec![vec![F::default(); code_length]; L];
        let mut output_instance = Vec::<MC>::with_capacity(L);

        // TODO: let user provide alpha (?)
        let num_vars = code_length.ilog2() as usize;
        let alpha = vec![F::ZERO; num_vars];

        // we "stack" codewords to make a single merkle commitment over alphabet \mathbb{F}^{L}
        // we have L codeword instances, each has length n, i.e. build an n * L table
        let mut stacked_witnesses = vec![vec![F::default(); L]; code_length];

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
            // for each tau we compute eq(\tau_i, j)_{j \in {0, 1}^{\log m}}
            // to obtain the final twin constrained code
            //
            output_instance.push(MC::new_with_constraint(
                self.config.code.config(),
                [(vec![F::ZERO; num_vars], mu[i])],
                (tau_i, instance[i].clone()),
                F::ZERO,
            ));
        }

        Ok((output_instance, output_witness))
    }

    fn verify() {
        todo!()
    }
}

#[cfg(test)]
pub mod tests {
    use crate::iors::pesat::r1cs::twin_constraint::R1CSTwinConstraintIOR;
    use crate::iors::IORConfig;
    use crate::iors::IOR;
    use crate::linear_code::linear_code::LinearCode;
    use crate::linear_code::{MultiConstrainedReedSolomon, ReedSolomon};
    use crate::merkle::poseidon::{PoseidonMerkleConfig, PoseidonMerkleConfigGadget};
    use crate::relations::r1cs::merkle_inclusion::MerkleInclusionInstance;
    use crate::relations::r1cs::MerkleInclusionWitness;
    use crate::relations::relation::ToPolySystem;
    use crate::relations::Relation;
    use crate::{
        linear_code::ReedSolomonConfig,
        relations::r1cs::{merkle_inclusion::tests::get_test_merkle_tree, MerkleInclusionRelation},
    };
    use ark_ff::Field;
    use spongefish::duplex_sponge::DuplexSponge;
    use spongefish::duplex_sponge::Permutation;
    use spongefish::DomainSeparator;
    use spongefish::Unit as SpongefishUnit;
    use spongefish_poseidon::PoseidonPermutation;
    use std::marker::PhantomData;

    use ark_bls12_381::Fr;

    type TestPermutation = PoseidonPermutation<255, Fr, 2, 3>;
    type TestSponge = DuplexSponge<TestPermutation>;
    type TwinConstraintRS = MultiConstrainedReedSolomon<Fr, ReedSolomon<Fr>, 1>;

    pub(crate) fn new_test_pesat_ior_domain_separator<
        F: Field + SpongefishUnit,
        C: Permutation<U = F>,
    >(
        l1: usize,
        log_m: usize,
    ) -> DomainSeparator<DuplexSponge<C>, F> {
        DomainSeparator::<DuplexSponge<C>, F>::new("ior::pesat")
            .absorb(1, "root")
            .absorb(l1, "mu")
            .squeeze(log_m * l1, "tau")
    }

    #[test]
    pub fn test_ior_twin_constraints() {
        const L1: usize = 2;

        // prepare r1cs, code and example tree
        let height = 3;
        let (mt_config, leaves, mt) = get_test_merkle_tree(height);
        let r1cs = MerkleInclusionRelation::into_r1cs(&mt_config).unwrap();
        let code_config = ReedSolomonConfig::<Fr>::default(r1cs.k, r1cs.k.next_power_of_two());
        let code = ReedSolomon::new(code_config);
        let log_m = r1cs.log_m;

        // initialize ior
        let ior_config: IORConfig<Fr, ReedSolomon<Fr>, PoseidonMerkleConfig<Fr>> = IORConfig {
            code,
            _f: std::marker::PhantomData,
            mt_leaf_hash_params: mt_config.leaf_hash_param.clone(),
            mt_two_to_one_hash_params: mt_config.two_to_one_hash_param.clone(),
        };
        let r1cs_twinrs_ior = R1CSTwinConstraintIOR::<_, _, TwinConstraintRS, _, L1> {
            r1cs,
            config: ior_config,
            _mc: std::marker::PhantomData,
        };

        // intialize prover state
        let domain_separator =
            new_test_pesat_ior_domain_separator::<Fr, TestPermutation>(L1, log_m);
        let mut prover_state = domain_separator.to_prover_state();

        let mut witnesses = vec![];
        let mut instances = vec![];

        // intialize some instances and witnesses
        for i in 0..L1 {
            let proof = mt.generate_proof(i).unwrap();
            let instance = MerkleInclusionInstance::<
                Fr,
                PoseidonMerkleConfig<Fr>,
                PoseidonMerkleConfigGadget<Fr>,
            > {
                root: mt.root(),
                leaf: (*leaves[i]).to_vec(),
                _merkle_config_gadget: PhantomData,
            };
            let witness = MerkleInclusionWitness::<
                Fr,
                PoseidonMerkleConfig<Fr>,
                PoseidonMerkleConfigGadget<Fr>,
            > {
                proof,
                _merkle_config_gadget: PhantomData,
            };

            let relation = MerkleInclusionRelation::new(instance, witness, mt_config.clone());

            witnesses.push(relation.w);
            instances.push(relation.x);
        }

        r1cs_twinrs_ior
            .prove(&mut prover_state, instances, witnesses)
            .unwrap();
    }
}
