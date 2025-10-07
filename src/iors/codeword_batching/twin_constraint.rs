use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree},
};
use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_std::iterable::Iterable;
use spongefish::{
    codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField},
    ProofError, ProverState, Unit as SpongefishUnit,
};
use std::marker::PhantomData;

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
    MC: MultiConstrainedLinearCode<F, C, P>,
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
        MC: MultiConstrainedLinearCode<F, C, P>,
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
    ) -> Result<(Self::OutputInstance, Self::OutputWitness), WARPError>
    where
        ProverState: UnitToBytes,
    {
        // (\gamma, (\alpha, \mu), \beta, \eta, (u_1, \dots, u_l))
        let (gamma, multi_constraints, codewords) = instance;

        debug_assert!(gamma.len() == codewords.len());

        let constraints = multi_constraints.get_constraints();
        let (mut multilinear_evals, beta, eta) =
            (constraints.0.to_vec(), constraints.1, constraints.2);
        let mu = multilinear_evals[0].1;

        let l = codewords.len();
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
        // we return (\alpha, \hat{f}(\alpha), \hat{f}(\alpha)) for convenience, as we will below
        // extend the initial vector of multilinear evaluations and absorb the new claimed evaluations
        let (alpha_mu_ood_answers, mu): (Vec<(Vec<F>, F)>, Vec<F>) = ood_samples
            .iter()
            .map(|alpha| {
                let mu = u_mle.fix_variables(alpha)[0];
                ((alpha.to_vec(), mu), mu)
            })
            .unzip();

        // extend the multilinear evaluations with the new claimed ones
        multilinear_evals.extend(alpha_mu_ood_answers);

        // absorb ood answers
        prover_state.add_scalars(&mu)?;

        // 7.1 step 4, get shift query points `x_i` for i in [T]
        // Note that `x_i` should be in range 0..N, not in Fr
        let n_shift_queries = (self.config.t * log_n).div_ceil(8);
        let mut bytes_shift_queries = vec![0; n_shift_queries];

        // TODO: we shouldn't call `map_err`, there might be a trait missing on `ProverState`
        prover_state
            .fill_challenge_bytes(&mut bytes_shift_queries)
            .map_err(|d| ProofError::InvalidDomainSeparator(d))?;

        // build a vector of tuples where both are either 1 or 0, but where the first element is a
        // field element and the second element is a bool. we use it below to then store those new
        // evaluation claims
        let alpha_binary_shift_indexes = bytes_shift_queries
            .iter()
            .flat_map(|x| {
                (0..8)
                    .map(|i| {
                        let val = (x >> i) & 1 == 1;
                        // return in field element and in binary
                        (F::from(val), val)
                    })
                    .collect::<Vec<_>>()
            })
            .take(self.config.t * log_n)
            .collect::<Vec<(F, bool)>>();

        // we want to get (\alpha_k, \Sigma{\gamma_i \cdot f_i(x_k)})
        let alpha_mu_shift_queries: Vec<(Vec<F>, F)> = alpha_binary_shift_indexes
            .chunks(log_n)
            .map(|array_tuples| {
                let (alpha_as_field_elements, alpha_as_bool): (Vec<F>, Vec<bool>) =
                    array_tuples.to_vec().into_iter().unzip();
                let x_k = alpha_as_bool
                    .iter()
                    .fold(0usize, |acc, &b| (acc << 1) | b as usize);
                let mu = (0..l)
                    .map(|i| {
                        let gamma_i = gamma[i];
                        let f_i = &codewords[i];
                        gamma_i * f_i[x_k]
                    })
                    .sum::<F>();
                (alpha_as_field_elements, mu)
            })
            .collect();

        multilinear_evals.extend(alpha_mu_shift_queries);

        debug_assert!(multilinear_evals.len() == 1 + self.config.s + self.config.t);

        Ok((
            MC::new_with_constraint(
                self.config.code.config(),
                multilinear_evals,
                beta.clone(),
                eta,
            ),
            witness,
        ))
    }

    fn verify() {
        todo!()
    }
}
