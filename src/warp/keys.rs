/// Prover key — relation index plus dimensions `(M, N, k)`.
#[derive(Clone)]
pub struct WARPProverKey<P> {
    pub index: P,
    pub m: usize,
    pub n: usize,
    pub k: usize,
}

/// Verifier key — dimensions only `(M, N, k)`.
#[derive(Clone, Copy)]
pub struct WARPVerifierKey {
    pub m: usize,
    pub n: usize,
    pub k: usize,
}
