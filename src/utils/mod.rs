use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::Config,
};
use ark_ff::{Field, PrimeField};
use spongefish::{ByteDomainSeparator, BytesToUnitSerialize, DomainSeparator};
use spongefish::{ProofError, ProofResult, ProverState};
use whir::crypto::merkle_tree::digest::GenericDigest;
use whir::crypto::merkle_tree::parameters::MerkleTreeParams;

pub mod poly;
pub mod poseidon;

pub fn chunk_size<F: Field + PrimeField>() -> usize {
    let mut buf = Vec::new();
    F::zero().serialize_uncompressed(&mut buf).unwrap();

    buf.len()
}

pub fn bytes_to_vec_f<F: Field + PrimeField>(bytes: &[u8]) -> Vec<F> {
    bytes
        .chunks(chunk_size::<F>()) //TODO(z-tech): shouldn't need to call chunk_size() at runtime
        .map(|chunk| {
            F::from_le_bytes_mod_order(chunk)
            // let mut padded = Vec::with_capacity(chunk_size);
            // padded.extend_from_slice(chunk);
            // padded.resize(chunk_size, 0); // pad with zero bytes if necessary
            // let mut reader = Cursor::new(padded);
            // F::deserialize_uncompressed(&mut reader).unwrap()
        })
        .collect()
}

// we copy instead of import from whir since we would like to implement the `DigestDomainSeparator` trait
// as well on `DomainSeparator`
// https://github.com/WizardOfMenlo/whir/blob/22c675807fc9295fef68a11945713dc3e184e1c1/src/whir/domainsep.rs#L11
pub trait DigestDomainSeparator<MerkleConfig: Config> {
    #[must_use]
    fn add_digest(self, label: &str) -> Self;
}

// from whir
pub trait DigestToUnitSerialize<MerkleConfig: Config> {
    fn add_digest(&mut self, digest: MerkleConfig::InnerDigest) -> ProofResult<()>;
}

// from whir
pub trait DigestToUnitDeserialize<MerkleConfig: Config> {
    fn read_digest(&mut self) -> ProofResult<MerkleConfig::InnerDigest>;
}
