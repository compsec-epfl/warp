use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::Field;
use ark_std::log2;
use spongefish::{codecs::arkworks_algebra::FieldDomainSeparator, ByteDomainSeparator, Unit};

use crate::{
    iors::{codeword_batching::PseudoBatchingIORConfig, pesat::TwinConstraintIORConfig},
    linear_code::LinearCode,
    utils::DigestDomainSeparator,
};

// TODO
pub trait WARPDomainSeparator<F: Field + Unit, C: LinearCode<F>, MT: Config> {
    fn pesat_ior(self, conf: &TwinConstraintIORConfig<F, C, MT>) -> Self;
    fn pseudo_batching_ior(self, conf: &PseudoBatchingIORConfig<F, C, MT>) -> Self;
    fn warp(
        self,
        C: C,
        l1: usize,
        l2: usize,
        s: usize,
        t: usize,
        n: usize,
        k: usize,
        log_n: usize,
        log_m: usize,
        log_l: usize,
        log_r: usize,
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
            .challenge_scalars(conf.s * conf.log_n as usize, "alpha")
            .add_scalars(conf.s, "mus")
            .challenge_bytes((conf.t * conf.log_n).div_ceil(8), "x")
    }

    fn warp(
        self,
        code: C,
        l1: usize,
        l2: usize,
        s: usize,
        t: usize,
        #[allow(non_snake_case)] N: usize,
        k: usize,
        #[allow(non_snake_case)] log_N: usize,
        #[allow(non_snake_case)] log_M: usize,
        log_l: usize,
        log_r: usize,
    ) -> Self {
        let log_n = log2(code.code_len()) as usize;

        let mut prover_state = self;
        for _ in 0..l1 {
            prover_state = prover_state.add_scalars(N - k, "instances");
        }

        for _ in 0..l2 {
            prover_state = prover_state
                .add_digest("digest")
                .add_scalars(log_n, "alpha")
                .add_scalars(log_M + N, "beta")
                .add_scalars(2, "mu_eta");
        }

        prover_state = prover_state.add_digest("td_0");
        prover_state = prover_state.add_scalars(l1, "mus");
        for _ in 0..l1 {
            prover_state = prover_state.challenge_scalars(log_M, "tau_i");
        }
        prover_state = prover_state.challenge_scalars(1, "omega");
        prover_state = prover_state.challenge_scalars(log_l, "tau");
        prover_state = prover_state.add_digest("mt_linear_comb");
        prover_state = prover_state.add_scalars(2, "eta_nu0");
        prover_state = prover_state.challenge_scalars(s * log_n, "odd_samples");
        prover_state = prover_state.add_scalars(s, "odd_answers");
        prover_state = prover_state.challenge_bytes((t * log_n).div_ceil(8), "bytes_shift_queries");
        prover_state = prover_state.challenge_scalars(log_r, "xi");

        // sumcheck multilinear constraints batching
        for i in 0..log2(N) {
            prover_state = prover_state
                .add_scalars(3, &format!("h_{}", i))
                .challenge_scalars(1, &format!("challenge_{}", i));
        }

        prover_state
    }
}
