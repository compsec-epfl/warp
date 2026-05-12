/// Prover key — relation index plus dimensions `(M, N, k)`.
#[derive(Clone)]
pub struct WARPProverKey<P> {
    pub index: P,
    pub m_num_constraints: usize,
    pub n_num_variables: usize,
    pub k_num_witness_vars: usize,
}

/// Verifier key — dimensions only `(M, N, k)`.
#[derive(Clone, Copy)]
pub struct WARPVerifierKey {
    pub m_num_constraints: usize,
    pub n_num_variables: usize,
    pub k_num_witness_vars: usize,
}
