use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree},
};
use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use spongefish::{
    codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField},
    ProverState, Unit as SpongefishUnit,
};

use crate::{
    iors::IOR,
    linear_code::{LinearCode, MultiConstrainedLinearCode},
    relations::relation::BundledPESAT,
    WARPError,
};

use spongefish::UnitToBytes;

pub struct TwinConstraintPseudoBatchingIORConfig<
    F: Field + SpongefishUnit,
    C: LinearCode<F>,
    MT: Config,
> {
    code: C,
    l: usize,
    t: usize,
    s: usize,
    mt_leaf_hash_params: <MT::LeafHash as CRHScheme>::Parameters,
    mt_two_to_one_hash_params: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    _f: PhantomData<F>,
}

pub struct TwinConstraintPseudoBatchingIOR<
    F: Field + SpongefishUnit,
    C: LinearCode<F>,
    P: BundledPESAT<F>,
    MC: MultiConstrainedLinearCode<F, C, P, 1>,
    MT: Config,
> {
    // note that R is one by def and is provided as a constant
    config: TwinConstraintPseudoBatchingIORConfig<F, C, MT>,
    _mc: PhantomData<MC>,
    _p: PhantomData<P>,
}

impl<
        F: Field + SpongefishUnit + UnitToBytes,
        C: LinearCode<F>,
        P: BundledPESAT<F>,
        MC: MultiConstrainedLinearCode<F, C, P, 1>,
        MT: Config<Leaf = [F], InnerDigest = F>,
    > IOR<F, C, MT> for TwinConstraintPseudoBatchingIOR<F, C, P, MC, MT>
{
    // instance is a vector \gamma, an twin constraint and corresponding codewords
    // (\gamma, (\alpha, \mu), \beta, \eta, (u_1, \dots, u_l))
    type Instance = (Vec<F>, MC, Vec<Vec<F>>);

    // witness is the RLC of the above codewords
    // \Sigma_{i \in l}( \gamma_i \cdot u_{i})
    type Witness = Vec<F>;

    // output instance is multi constraint with 1 + s + t multilinear evaluation claims
    type OutputInstance = MC;

    // output witness is a codeword
    type OutputWitness = Vec<F>;

    fn prove<'a>(
        &self,
        prover_state: &mut ProverState,
        instance: Self::Instance,
        witness: Self::Witness,
    ) -> Result<(Self::OutputInstance, Self::OutputWitness), WARPError> {
        // (\gamma, (\alpha, \mu), \beta, \eta, (u_1, \dots, u_l))
        let (gamma, multi_constraints, codewords) = instance;
        let (multilinear_evals, beta, eta) = multi_constraints.get_constraints();
        let mu = multilinear_evals[0].1;

        let log_n = multilinear_evals[0].0.len();
        let n = log_n.pow(2);

        let u_mle = DenseMultilinearExtension::from_evaluations_slice(log_n, &witness);

        // commit to the rlc of the codeword
        let mt = MerkleTree::<MT>::new(
            &self.config.mt_leaf_hash_params,
            &self.config.mt_two_to_one_hash_params,
            &witness.chunks(1).collect::<Vec<_>>(),
        )?;

        // absorb commitment to the rlc of the codewords
        prover_state.add_scalars(&[mt.root()])?;
        prover_state.add_scalars(&[mu])?;
        prover_state.add_scalars(&[eta])?;

        // 7.1 step 2, get OOD challenges `alpha_i` for i in [S]
        let n_ood_samples = self.config.s * log_n;
        let mut ood_samples = vec![F::default(); n_ood_samples];

        prover_state.fill_challenge_scalars(&mut ood_samples)?;

        let ood_samples = ood_samples.chunks(log_n).collect::<Vec<_>>();

        // 7.1 step 3, compute OOD answers
        let eta_vec = ood_samples
            .iter()
            .map(|alpha| u_mle.fix_variables(alpha)[0])
            .collect::<Vec<_>>();

        // Absorb ood answers
        prover_state.add_scalars(&eta_vec)?;

        // 7.1 step 4, get shift query points `x_i` for i in [T]
        // Note that `x_i` should be in range 0..N, not in Fr
        let n_shift_queries = (self.config.t * log_n).div_ceil(8);
        let mut shift_queries = vec![F::default(); n_shift_queries];

        // NOTE: this should be binary
        // TODO: fix this
        prover_state.fill_challenge_scalars(&mut shift_queries)?;
        todo!()
    }

    fn verify() {
        todo!()
    }
}
