use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_ff::Field;
use spongefish::{
    ByteDomainSeparator, BytesToUnitSerialize, DomainSeparator, ProofError, ProofResult,
    ProverState,
};
use whir::crypto::merkle_tree::{digest::GenericDigest, parameters::MerkleTreeParams};

use crate::utils::{DigestDomainSeparator, DigestToUnitSerialize};

// from whir
// https://github.com/WizardOfMenlo/whir/blob/3d627d31cec7d73a470a31a913229dd3128ee0cf/src/crypto/merkle_tree/parameters.rs#L63
impl<F: Field, LeafH, CompressH, const N: usize>
    DigestDomainSeparator<MerkleTreeParams<F, LeafH, CompressH, GenericDigest<N>>>
    for DomainSeparator
where
    LeafH: CRHScheme<Input = [F], Output = GenericDigest<N>>,
    CompressH: TwoToOneCRHScheme<Input = GenericDigest<N>, Output = GenericDigest<N>>,
{
    fn add_digest(self, label: &str) -> Self {
        self.add_bytes(N, label)
    }
}

// from whir
// https://github.com/WizardOfMenlo/whir/blob/3d627d31cec7d73a470a31a913229dd3128ee0cf/src/crypto/merkle_tree/parameters.rs#L76
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
