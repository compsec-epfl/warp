use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::Field;
use ark_std::log2;
use spongefish::{codecs::arkworks_algebra::FieldDomainSeparator, ByteDomainSeparator, Unit};

use crate::{
    accumulator::warp::WARPConfig,
    iors::{codeword_batching::PseudoBatchingIORConfig, pesat::TwinConstraintIORConfig},
    linear_code::LinearCode,
    relations::BundledPESAT,
    utils::DigestDomainSeparator,
};

// TODO
pub trait WARPDomainSeparator<F: Field + Unit, C: LinearCode<F>, MT: Config> {
    fn pesat_ior(self, conf: &TwinConstraintIORConfig<F, C, MT>) -> Self;
    fn pseudo_batching_ior(self, conf: &PseudoBatchingIORConfig<F, C, MT>) -> Self;
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
    fn pesat_ior(self, conf: &TwinConstraintIORConfig<F, C, MT>) -> Self {
        self.add_digest("root")
            .add_scalars(conf.l, "mu")
            .challenge_scalars(conf.log_m * conf.l, "tau")
    }

    fn pseudo_batching_ior(self, conf: &PseudoBatchingIORConfig<F, C, MT>) -> Self {
        self.add_scalars(1, "root")
            .add_scalars(1, "mu")
            .add_scalars(1, "eta")
            .challenge_scalars(conf.s * conf.log_n, "alpha")
            .add_scalars(conf.s, "mus")
            .challenge_bytes((conf.t * conf.log_n).div_ceil(8), "x")
    }

    fn warp<P: BundledPESAT<F, Config = (usize, usize, usize)>>(
        self,
        config: WARPConfig<F, P>,
    ) -> Self {
        assert!(config.n.is_power_of_two());
        assert!(config.l.is_power_of_two());
        let log_l = log2(config.l) as usize;
        let log_n = log2(config.n) as usize;
        let r = 1 + config.s + config.t;
        assert!(r.is_power_of_two());
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
