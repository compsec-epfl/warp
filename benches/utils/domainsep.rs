use spongefish::ProverState;

pub fn init_prover_state() -> ProverState {
    let domainsep = spongefish::domain_separator!("warp::rs");
    domainsep.instance(&0u32).std_prover()
}
