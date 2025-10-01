use std::marker::PhantomData;

use ark_crypto_primitives::merkle_tree::{Config, MerkleTree};
use ark_ff::{FftField, Field};
use ark_poly::Polynomial;
use ark_std::iterable::Iterable;

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
    MC: MultiConstrainedLinearCode<F, C, R1CS<F>, 1>,
    MT: Config,
> {
    // l instances
    l: usize,
    r1cs: R1CS<F>,
    config: IORConfig<F, C, MT>,
    _mc: PhantomData<MC>,
}
impl<
        F: Field + SpongefishUnit,
        C: LinearCode<F> + Clone,
        MC: MultiConstrainedLinearCode<F, C, R1CS<F>, 1>,
        MT: Config,
    > R1CSTwinConstraintIOR<F, C, MC, MT>
{
    pub fn new(r1cs: R1CS<F>, config: &IORConfig<F, C, MT>, l: usize) -> Self {
        let config = IORConfig::new(
            config.code.clone(),
            config.mt_leaf_hash_params.clone(),
            config.mt_two_to_one_hash_params.clone(),
        );
        Self {
            r1cs,
            config,
            l,
            _mc: PhantomData,
        }
    }
}

impl<
        F: FftField + SpongefishUnit,
        C: LinearCode<F>,
        MC: MultiConstrainedLinearCode<F, C, R1CS<F>, 1>,
        MT: Config<InnerDigest = F, Leaf = [F]>,
        S: DuplexSpongeInterface<F>,
    > IOR<F, C, MT, S> for R1CSTwinConstraintIOR<F, C, MC, MT>
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
        debug_assert!(instance.len() == self.l);
        debug_assert!(instance.len() == witness.len());
        debug_assert!(self.config.code.code_len().is_power_of_two());

        let code_length = self.config.code.code_len();
        let mut output_witness = vec![vec![F::default(); code_length]; self.l];
        let mut output_instance = Vec::<MC>::with_capacity(self.l);

        // TODO: let user provide alpha (?)
        let num_vars = code_length.ilog2() as usize;
        let alpha = vec![F::ZERO; num_vars];

        // we "stack" codewords to make a single merkle commitment over alphabet \mathbb{F}^{L}
        // we have L codeword instances, each has length n, i.e. build an n * L table
        // we chunk them below
        let mut stacked_witnesses = vec![F::default(); self.l * code_length];

        // stores multilinear evaluations of \hat{f}
        let mut mu = vec![F::default(); self.l];

        // encode and evaluate the multilinear extension over [0; nvars]
        // TODO: multithread this (?)
        for i in 0..self.l {
            let f_i = self.config.code.encode(&witness[i]);

            // stacking codewords
            // w_i elements are in position in each of the j vecs
            // 0 [w_0[0], w_1[0], ..] // L elements
            // 1 [w_0[1], w_1[1], ..]
            // ..
            // N - 1 [w_0[N-1], w_1[N-1], ..]
            for (j, value) in f_i.iter().enumerate() {
                stacked_witnesses[(j * self.l) + i] = *value;
            }

            // evaluate the dense mle for the codeword
            let f_hat = MC::as_multilinear_extension(num_vars, &f_i);
            mu[i] = f_hat.evaluate(&alpha);

            output_witness[i] = f_i;
        }

        let leaves: Vec<&[F]> = stacked_witnesses.chunks_exact(code_length).collect();

        // commit
        let mt = MerkleTree::<MT>::new(
            &self.config.mt_leaf_hash_params,
            &self.config.mt_two_to_one_hash_params,
            leaves,
        )?;

        // absorb root and multilinear evaluations
        prover_state
            .add_units(&[mt.root()])
            .map_err(ProofError::InvalidDomainSeparator)?;
        prover_state
            .add_units(&mu)
            .map_err(ProofError::InvalidDomainSeparator)?;

        // for i \in [l_1] get \mathbf{\tau_i} \in \mathbf{F}^{\log M}
        // \beta_i = [x_i, \tau_i]
        let tau_len: usize = self.r1cs.log_m;

        for i in 0..self.l {
            let mut tau_i = vec![F::default(); tau_len];
            prover_state
                .fill_challenge_units(&mut tau_i)
                .map_err(ProofError::InvalidDomainSeparator)?;

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
    use crate::linear_code::MultiConstrainedLinearCode;
    use crate::linear_code::{MultiConstrainedReedSolomon, ReedSolomon};
    use crate::merkle::poseidon::{PoseidonMerkleConfig, PoseidonMerkleConfigGadget};
    use crate::relations::r1cs::merkle_inclusion::MerkleInclusionInstance;
    use crate::relations::r1cs::MerkleInclusionWitness;
    use crate::relations::r1cs::R1CS;
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
    type TwinConstraintRS = MultiConstrainedReedSolomon<Fr, ReedSolomon<Fr>, R1CS<Fr>, 1>;

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
        let l = 2;

        // prepare r1cs, code and example tree
        let height = 3;
        let (mt_config, leaves, mt) = get_test_merkle_tree(height);
        let r1cs = MerkleInclusionRelation::into_r1cs(&mt_config).unwrap();
        let code_config = ReedSolomonConfig::<Fr>::default(r1cs.k, r1cs.k.next_power_of_two());
        let code = ReedSolomon::new(code_config);
        let log_m = r1cs.log_m;

        // initialize ior
        let ior_config: IORConfig<Fr, ReedSolomon<Fr>, PoseidonMerkleConfig<Fr>> = IORConfig::new(
            code,
            mt_config.leaf_hash_param.clone(),
            mt_config.two_to_one_hash_param.clone(),
        );
        let r1cs_twinrs_ior = R1CSTwinConstraintIOR::<_, _, TwinConstraintRS, _> {
            r1cs: r1cs.clone(),
            config: ior_config,
            l,
            _mc: std::marker::PhantomData,
        };

        // intialize prover state
        let domain_separator = new_test_pesat_ior_domain_separator::<Fr, TestPermutation>(l, log_m);
        let mut prover_state = domain_separator.to_prover_state();

        let mut witnesses = vec![];
        let mut instances = vec![];

        // intialize some instances and witnesses
        for i in 0..l {
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

        let (new_instances, new_witnesses) = r1cs_twinrs_ior
            .prove(&mut prover_state, instances, witnesses)
            .unwrap();

        // check multicodewords constraints
        for (mc, c) in new_instances.iter().zip(new_witnesses) {
            mc.check_constraints(&c, &r1cs).unwrap();
        }
    }
}
