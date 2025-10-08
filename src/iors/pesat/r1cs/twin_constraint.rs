use std::marker::PhantomData;

use ark_crypto_primitives::merkle_tree::{Config, MerkleTree};
use ark_ff::{FftField, Field};

use crate::{
    iors::pesat::TwinConstraintIORConfig,
    linear_code::{LinearCode, MultiConstrainedLinearCode},
    relations::r1cs::R1CS,
    utils::DigestToUnitSerialize,
    WARPError,
};
use spongefish::{
    codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField},
    ProverState, Unit as SpongefishUnit, UnitToBytes,
};

use crate::iors::IOR;

// L should be a power of 2
// we have L incoming (instance, witness) pairs (noted l1 when in WARP context)
// a twin constraint code is the code for which R = 1
pub struct R1CSTwinConstraintIOR<
    F: Field + SpongefishUnit,
    C: LinearCode<F>,
    MC: MultiConstrainedLinearCode<F, C, R1CS<F>>,
    MT: Config,
> {
    // NOTE: when proving we only need log(M), not the R1CS itself
    r1cs: R1CS<F>,
    pub config: TwinConstraintIORConfig<F, C, MT>,
    _mc: PhantomData<MC>,
}
impl<
        F: Field + SpongefishUnit,
        C: LinearCode<F> + Clone,
        MC: MultiConstrainedLinearCode<F, C, R1CS<F>>,
        MT: Config,
    > R1CSTwinConstraintIOR<F, C, MC, MT>
{
    pub fn new(r1cs: R1CS<F>, config: TwinConstraintIORConfig<F, C, MT>) -> Self {
        Self {
            r1cs,
            config,
            _mc: PhantomData,
        }
    }
}

impl<
        F: FftField + SpongefishUnit,
        C: LinearCode<F>,
        MC: MultiConstrainedLinearCode<F, C, R1CS<F>>,
        MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
    > IOR<F, C, MT> for R1CSTwinConstraintIOR<F, C, MC, MT>
{
    // we have L incoming (instance, witness) pairs
    // (x, w) s.t. R1CS(x, w) = 0
    type Instance = Vec<Vec<F>>;
    type Witness = Vec<Vec<F>>;

    // L twin constraint codes
    type OutputInstance = Vec<MC>;

    // L corresponding ewords
    type OutputWitness = Vec<Vec<F>>;

    fn prove(
        &self,
        prover_state: &mut ProverState,
        instance: Self::Instance,
        witness: Self::Witness,
    ) -> Result<(Self::OutputInstance, Self::OutputWitness), WARPError>
    where
        ProverState: UnitToField<F> + UnitToBytes + DigestToUnitSerialize<MT>,
    {
        debug_assert!(instance.len() == self.config.l);
        debug_assert!(instance.len() == witness.len());
        debug_assert!(self.config.code.code_len().is_power_of_two());

        let code_length = self.config.code.code_len();
        let mut output_witness = vec![vec![F::default(); code_length]; self.config.l];
        let mut output_instance = Vec::<MC>::with_capacity(self.config.l);

        // TODO: let user provide alpha (?)
        let num_vars = code_length.ilog2() as usize;
        let alpha = 0;

        // we "stack" codewords to make a single merkle commitment over alphabet \mathbb{F}^{L}
        let mut stacked_witnesses = vec![F::default(); self.config.l * code_length];

        // stores multilinear evaluations of \hat{f}
        let mut mu = vec![F::default(); self.config.l];

        // encode and evaluate the multilinear extension over [0; nvars]
        // TODO: multithread this (?)
        for i in 0..self.config.l {
            let f_i = self.config.code.encode(&witness[i]);

            // stacking codewords in flat array, which we chunk below
            // [w_0[0], .., w_{N-1}[0], .., w_0[N-1], .., w_{N-1}[N-1]] // L * N elements
            for (j, value) in f_i.iter().enumerate() {
                stacked_witnesses[(j * self.config.l) + i] = *value;
            }

            // evaluate the dense mle for the codeword
            // \hat{f}(alpha) == f[alpha]
            mu[i] = *f_i
                .get(alpha)
                .ok_or(WARPError::CodewordSize(f_i.len(), alpha))?;

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
        prover_state.add_digest(mt.root())?;
        prover_state.add_scalars(&mu)?;

        // for i \in [l_1] get \mathbf{\tau_i} \in \mathbf{F}^{\log M}
        // \beta_i = [x_i, \tau_i]
        let tau_len: usize = self.r1cs.log_m;

        for i in 0..self.config.l {
            let mut tau_i = vec![F::default(); tau_len];
            prover_state.fill_challenge_scalars(&mut tau_i)?;

            output_instance.push(MC::new_with_constraint(
                self.config.code.config(),
                vec![(vec![F::zero(); num_vars], mu[i])],
                (tau_i, instance[i].clone()),
                F::zero(),
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
    use crate::domainsep::WARPDomainSeparator;
    use crate::iors::pesat::r1cs::twin_constraint::R1CSTwinConstraintIOR;
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
    use spongefish::DomainSeparator;
    use std::marker::PhantomData;
    use whir::crypto::merkle_tree::blake3::Blake3MerkleTreeParams;

    use ark_bls12_381::Fr;

    use super::TwinConstraintIORConfig;

    type TwinConstraintRS = MultiConstrainedReedSolomon<Fr, ReedSolomon<Fr>, R1CS<Fr>>;

    #[test]
    pub fn test_ior_twin_constraints() {
        let domainsep = DomainSeparator::new("test::ior");

        let l = 2;

        // prepare r1cs, code and example tree
        let height = 3;
        let (mt_config, leaves, mt) = get_test_merkle_tree(height);
        let r1cs = MerkleInclusionRelation::into_r1cs(&mt_config).unwrap();
        let code_config = ReedSolomonConfig::<Fr>::default(r1cs.k, r1cs.k.next_power_of_two());
        let code = ReedSolomon::new(code_config);
        let log_m = r1cs.log_m;

        // initialize ior
        let ior_config = TwinConstraintIORConfig::<_, _, Blake3MerkleTreeParams<Fr>>::new(
            code,
            (),
            (),
            l,
            log_m,
        );

        let r1cs_twinrs_ior = R1CSTwinConstraintIOR::<_, _, TwinConstraintRS, _> {
            r1cs: r1cs.clone(),
            config: ior_config,
            _mc: std::marker::PhantomData,
        };

        // intialize prover state
        let domainsep = domainsep.pesat_ior(&r1cs_twinrs_ior.config);
        let mut prover_state = domainsep.to_prover_state();

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
