use ark_codes::traits::LinearCode;
use ark_crypto_primitives::crh::blake3::GenericDigest;
use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::log2;
use rand::{CryptoRng, RngCore};
use spongefish::codecs::arkworks_algebra::{FieldToUnitDeserialize, FieldToUnitSerialize};
use spongefish::BytesToUnitSerialize;
use spongefish::{
    codecs::arkworks_algebra::{FieldDomainSeparator, UnitToField},
    ByteDomainSeparator, ProofError, ProverState, Unit, UnitToBytes,
};
use spongefish::{BytesToUnitDeserialize, DuplexSpongeInterface, ProofResult, VerifierState};

use crate::crypto::merkle::parameters::MerkleTreeParams;
use crate::utils::{DigestToUnitDeserialize, HintDeserialize, HintSerialize};
use crate::{
    relations::BundledPESAT,
    utils::{DigestDomainSeparator, DigestToUnitSerialize},
};

use crate::config::WARPConfig;

pub trait WARPDomainSeparator<F: Field + Unit, C: LinearCode<F>, MT: Config> {
    fn warp<P: BundledPESAT<F, Config = (usize, usize, usize)>>(
        self,
        config: WARPConfig<F, P>,
    ) -> Self;
}

impl<
        F: Field + Unit,
        C: LinearCode<F>,
        MT: Config,
        DomainSeparator: ByteDomainSeparator + FieldDomainSeparator<F> + DigestDomainSeparator<MT>,
    > WARPDomainSeparator<F, C, MT> for DomainSeparator
{
    fn warp<P: BundledPESAT<F, Config = (usize, usize, usize)>>(
        self,
        config: WARPConfig<F, P>,
    ) -> Self {
        assert!(config.n.is_power_of_two());
        assert!(config.l.is_power_of_two());
        let log_l = log2(config.l) as usize;
        let log_n = log2(config.n) as usize;
        let r = 1 + config.s + config.t;

        // WARNING: removing this for more flexibility, but this should be checked carefully
        //        assert!(r.is_power_of_two());

        let log_r = log2(r) as usize;
        #[allow(non_snake_case)]
        let (M, N, k) = config.p_conf;
        #[allow(non_snake_case)]
        let log_M = log2(M) as usize;
        let l2 = config.l - config.l1;
        let mut prover_state = self;
        for _ in 0..config.l1 {
            prover_state = prover_state.add_scalars(N - k, "instances");
        }

        if l2 > 0 {
            for i in 0..l2 {
                prover_state = prover_state.add_digest(&format!("l2_{i}_digest"))
            }

            prover_state = prover_state.add_scalars(log_n * l2, "l2_alphas");
            prover_state = prover_state.add_scalars(l2, "l2_mus");
            prover_state = prover_state.add_scalars(log_M * l2, "l2_taus");
            prover_state = prover_state.add_scalars((N - k) * l2, "l2_x");
            prover_state = prover_state.add_scalars(l2, "l2_etas");
        }

        prover_state = prover_state.add_digest("td_0");
        prover_state = prover_state.add_scalars(config.l1, "mus");

        for _ in 0..config.l1 {
            prover_state = prover_state.challenge_scalars(log_M, "tau_i");
        }

        prover_state = prover_state.challenge_scalars(1, "omega");
        prover_state = prover_state.challenge_scalars(log_l, "tau");

        // sumcheck twin constraints pseudo batching
        for i in 0..log_l {
            prover_state = prover_state
                .add_scalars(2 + (log_n as usize + 1).max(log_M + 2), &format!("h_{i}"))
                .challenge_scalars(1, &format!("challenge_{i}"));
        }

        prover_state = prover_state.add_digest("mt_linear_comb");
        prover_state = prover_state.add_scalars(2, "eta_nu0");
        prover_state = prover_state.challenge_scalars(config.s * log_n, "odd_samples");
        prover_state = prover_state.add_scalars(config.s, "odd_answers");
        prover_state =
            prover_state.challenge_bytes((config.t * log_n).div_ceil(8), "bytes_shift_queries");
        prover_state = prover_state.challenge_scalars(log_r, "xi");

        // sumcheck multilinear constraints batching
        for i in 0..log_n {
            prover_state = prover_state
                .add_scalars(3, &format!("h_{i}"))
                .challenge_scalars(1, &format!("challenge_{i}"));
        }

        prover_state
    }
}

pub fn absorb_instances<F: Field>(
    prover_state: &mut ProverState,
    instances: &[Vec<F>],
) -> Result<(), ProofError> {
    instances
        .iter()
        .try_for_each(|x| prover_state.add_scalars(x))
}

pub type AccInstances<F, MT> = (
    Vec<<MT as Config>::InnerDigest>, // rt
    Vec<Vec<F>>,                      // alpha
    Vec<F>,                           // mu
    (Vec<Vec<F>>, Vec<Vec<F>>),       // (tau, x)
    Vec<F>,                           // eta
);

pub fn absorb_accumulated_instances<F: Field, MT: Config>(
    prover_state: &mut ProverState,
    acc_instances: &AccInstances<F, MT>, // (rt, \alpha, \mu, \beta (\tau, x), \eta)
) -> Result<(), ProofError>
where
    ProverState: UnitToField<F> + UnitToBytes + DigestToUnitSerialize<MT>,
{
    acc_instances
        .0
        .clone()
        .into_iter()
        .try_for_each(|digest| prover_state.add_digest(digest))?;

    // alpha
    acc_instances
        .1
        .iter()
        .try_for_each(|alpha| prover_state.add_scalars(alpha))?;

    // mu
    prover_state.add_scalars(&acc_instances.2)?;

    //// taus
    acc_instances
        .3
         .0
        .iter()
        .try_for_each(|tau| prover_state.add_scalars(tau))?;

    //// xs
    acc_instances
        .3
         .1
        .iter()
        .try_for_each(|x| prover_state.add_scalars(x))?;

    //// etas
    prover_state.add_scalars(&acc_instances.4)?;

    Ok(())
}

pub fn parse_statement<
    'a,
    F: Field,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
>(
    verifier_state: &mut VerifierState<'a>,
    l1: usize,
    l2: usize,
    instance_len: usize,
    log_n: usize,
    #[allow(non_snake_case)] log_M: usize,
) -> Result<
    (
        Vec<Vec<F>>,
        (
            Vec<<MT as Config>::InnerDigest>,
            Vec<Vec<F>>,
            Vec<F>,
            (Vec<Vec<F>>, Vec<Vec<F>>),
            Vec<F>,
        ),
    ),
    ProofError,
>
where
    VerifierState<'a>: UnitToBytes
        + FieldToUnitDeserialize<F>
        + UnitToField<F>
        + DigestToUnitDeserialize<MT>
        + BytesToUnitDeserialize,
{
    // f. absorb parameters
    let mut l1_xs = vec![vec![F::default(); instance_len]; l1];
    l1_xs
        .iter_mut()
        .try_for_each(|inst| verifier_state.fill_next_scalars(inst))?;

    // l2 instances
    let l2_roots = (0..l2)
        .map(|_| verifier_state.read_digest())
        .collect::<Result<Vec<MT::InnerDigest>, ProofError>>()?;

    let mut l2_alphas = vec![vec![F::default(); log_n]; l2];
    l2_alphas
        .iter_mut()
        .try_for_each(|alpha| verifier_state.fill_next_scalars(alpha))?;

    let mut l2_mus = vec![F::default(); l2];
    verifier_state.fill_next_scalars(&mut l2_mus)?;

    let mut l2_taus = vec![vec![F::default(); log_M]; l2];
    l2_taus
        .iter_mut()
        .try_for_each(|tau| verifier_state.fill_next_scalars(tau))?;

    let mut l2_xs = vec![vec![F::default(); instance_len]; l2];
    l2_xs
        .iter_mut()
        .try_for_each(|x| verifier_state.fill_next_scalars(x))?;

    let mut l2_etas = vec![F::default(); l2];
    verifier_state.fill_next_scalars(&mut l2_etas)?;

    Ok((
        l1_xs,
        (l2_roots, l2_alphas, l2_mus, (l2_taus, l2_xs), l2_etas),
    ))
}

pub fn derive_randomness<
    'a,
    F: Field,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
>(
    verifier_state: &mut VerifierState<'a>,
    l1: usize,
    log_n: usize,
    log_l: usize,
    s: usize,
    t: usize,
    #[allow(non_snake_case)] log_M: usize,
) -> Result<
    (
        <MT as Config>::InnerDigest,
        Vec<F>,
        Vec<Vec<F>>,
        F,
        Vec<F>,
        Vec<F>,
        Vec<Vec<F>>,
        <MT as Config>::InnerDigest,
        F,
        Vec<F>,
        Vec<F>,
        Vec<u8>,
        Vec<F>,
        Vec<F>,
        Vec<[F; 3]>,
    ),
    ProofError,
>
where
    VerifierState<'a>: UnitToBytes
        + FieldToUnitDeserialize<F>
        + UnitToField<F>
        + DigestToUnitDeserialize<MT>
        + BytesToUnitDeserialize,
{
    let rt_0 = verifier_state.read_digest()?;
    let mut l1_mus = vec![F::default(); l1];
    verifier_state.fill_next_scalars(&mut l1_mus)?;

    let mut l1_taus = vec![vec![F::default(); log_M]; l1];

    for l1_tau in l1_taus.iter_mut().take(l1) {
        let mut tau_i = vec![F::default(); log_M];
        verifier_state.fill_challenge_scalars(&mut tau_i)?;
        *l1_tau = tau_i; // bundled evaluations
    }

    let [omega] = verifier_state.challenge_scalars::<1>()?;
    let mut tau = vec![F::default(); log_l];
    verifier_state.fill_challenge_scalars(&mut tau)?;

    // e. twin constraints sumcheck
    let mut gamma_sumcheck = Vec::new();
    let mut coeffs_twinc_sumcheck = Vec::new();
    for _ in 0..log_l {
        let mut h_coeffs = vec![F::zero(); 2 + (log_n + 1).max(log_M + 2) as usize];
        verifier_state.fill_next_scalars(&mut h_coeffs)?;
        let [c] = verifier_state.challenge_scalars::<1>()?;
        gamma_sumcheck.push(c);
        coeffs_twinc_sumcheck.push(h_coeffs);
    }

    let _td = verifier_state.read_digest()?;
    let [eta, nu_0] = verifier_state.next_scalars::<2>()?;
    let mut nus = vec![nu_0];

    // g. ood samples
    let n_ood_samples = s * log_n;
    let mut ood_samples = vec![F::default(); n_ood_samples];
    verifier_state.fill_challenge_scalars(&mut ood_samples)?;

    // h. ood answers
    let mut ood_answers = vec![F::default(); s];
    verifier_state.fill_next_scalars(&mut ood_answers)?;
    nus.extend(ood_answers);

    // i. shift queries and zero check
    let r = 1 + s + t;
    let log_r = log2(r) as usize;
    let n_shift_queries = (t * log_n).div_ceil(8);
    let mut bytes_shift_queries = vec![0u8; n_shift_queries];
    let mut xi = vec![F::default(); log_r];
    verifier_state.fill_challenge_bytes(&mut bytes_shift_queries)?;
    verifier_state.fill_challenge_scalars(&mut xi)?;

    // j. batching sumcheck
    let mut alpha_sumcheck = Vec::new();
    let mut sums_batching_sumcheck = Vec::new();
    for _ in 0..log_n {
        let [sum_00, sum_11, sum_0110]: [F; 3] = verifier_state.next_scalars()?;
        let [c] = verifier_state.challenge_scalars::<1>()?;
        alpha_sumcheck.push(c);
        sums_batching_sumcheck.push([sum_00, sum_11, sum_0110]);
    }

    Ok((
        rt_0,
        l1_mus,
        l1_taus,
        omega,
        tau,
        gamma_sumcheck,
        coeffs_twinc_sumcheck,
        _td,
        eta,
        nus,
        ood_samples,
        bytes_shift_queries,
        xi,
        alpha_sumcheck,
        sums_batching_sumcheck,
    ))
}

impl<F: Field, LeafH, CompressH, const N: usize>
    DigestToUnitSerialize<MerkleTreeParams<F, LeafH, CompressH, GenericDigest<N>>> for ProverState
where
    LeafH: CRHScheme<Input = [F], Output = GenericDigest<N>>,
    CompressH: TwoToOneCRHScheme<Input = GenericDigest<N>, Output = GenericDigest<N>>,
{
    fn add_digest(&mut self, digest: GenericDigest<N>) -> ProofResult<()> {
        self.add_bytes(&digest.0)
            .map_err(ProofError::InvalidDomainSeparator)
    }
}

impl<H, U, R> HintSerialize for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
    R: RngCore + CryptoRng,
{
    fn hint<T: CanonicalSerialize>(&mut self, hint: &T) -> ProofResult<()> {
        let mut bytes = Vec::new();
        hint.serialize_compressed(&mut bytes)?;
        self.hint_bytes(&bytes)?;
        Ok(())
    }
}

impl<F: Field, LeafH, CompressH, const N: usize>
    DigestToUnitDeserialize<MerkleTreeParams<F, LeafH, CompressH, GenericDigest<N>>>
    for VerifierState<'_>
where
    LeafH: CRHScheme<Input = [F], Output = GenericDigest<N>>,
    CompressH: TwoToOneCRHScheme<Input = GenericDigest<N>, Output = GenericDigest<N>>,
{
    fn read_digest(&mut self) -> ProofResult<GenericDigest<N>> {
        let mut digest = [0u8; N];
        self.fill_next_bytes(&mut digest)?;
        Ok(digest.into())
    }
}

impl<H, U> HintDeserialize for VerifierState<'_, H, U>
where
    U: Unit,
    H: DuplexSpongeInterface<U>,
{
    fn hint<T: CanonicalDeserialize>(&mut self) -> ProofResult<T> {
        let mut bytes = self.hint_bytes()?;
        Ok(T::deserialize_compressed(&mut bytes)?)
    }
}
