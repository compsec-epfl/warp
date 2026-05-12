use ark_ff::Field;
use ark_mt::MerkleHasher;
use ark_serialize::{CanonicalSerialize, Compress, SerializationError, Valid, Write};

use crate::crypto::merkle::WarpProof;
use crate::warp::{AccumulatorInstance, AccumulatorWitness, WARPProof};

// `AccumulatorInstance` and `WARPProof` carry generic associated types
// (`H::Digest`, `WarpProof<H>`) whose serializability is not implied by
// `H: MerkleHasher`. Putting the `CanonicalSerialize` bound in a
// separate `impl` block (rather than on the struct) keeps the bulk of
// the IOR / orchestrator code free of that dep — only the size-printing
// path pulls it in.

impl<F, H> CanonicalSerialize for AccumulatorInstance<F, H>
where
    F: Field + CanonicalSerialize,
    H: MerkleHasher,
    H::Digest: CanonicalSerialize,
{
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.rt_merkle_roots
            .serialize_with_mode(&mut writer, compress)?;
        self.alpha_fold_vectors
            .serialize_with_mode(&mut writer, compress)?;
        self.mu_claimed_evals
            .serialize_with_mode(&mut writer, compress)?;
        self.beta_twin_pairs
            .0
            .serialize_with_mode(&mut writer, compress)?;
        self.beta_twin_pairs
            .1
            .serialize_with_mode(&mut writer, compress)?;
        self.eta_predicate_evals
            .serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.rt_merkle_roots.serialized_size(compress)
            + self.alpha_fold_vectors.serialized_size(compress)
            + self.mu_claimed_evals.serialized_size(compress)
            + self.beta_twin_pairs.0.serialized_size(compress)
            + self.beta_twin_pairs.1.serialized_size(compress)
            + self.eta_predicate_evals.serialized_size(compress)
    }
}

impl<F, H> Valid for AccumulatorInstance<F, H>
where
    F: Field + CanonicalSerialize,
    H: MerkleHasher,
    H::Digest: CanonicalSerialize,
{
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl<F, H> CanonicalSerialize for WARPProof<F, H>
where
    F: Field + CanonicalSerialize,
    H: MerkleHasher,
    H::Digest: CanonicalSerialize,
    WarpProof<H>: CanonicalSerialize,
{
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.rt_0_fresh_merkle_root
            .serialize_with_mode(&mut writer, compress)?;
        self.mu_i_first_codeword_coords
            .serialize_with_mode(&mut writer, compress)?;
        self.nu_0_oracle_eval
            .serialize_with_mode(&mut writer, compress)?;
        self.nu_i_oracle_evals
            .serialize_with_mode(&mut writer, compress)?;
        self.auth_0.serialize_with_mode(&mut writer, compress)?;
        self.auth_j.serialize_with_mode(&mut writer, compress)?;
        self.shift_query_answers
            .serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.rt_0_fresh_merkle_root.serialized_size(compress)
            + self.mu_i_first_codeword_coords.serialized_size(compress)
            + self.nu_0_oracle_eval.serialized_size(compress)
            + self.nu_i_oracle_evals.serialized_size(compress)
            + self.auth_0.serialized_size(compress)
            + self.auth_j.serialized_size(compress)
            + self.shift_query_answers.serialized_size(compress)
    }
}

impl<F, H> Valid for WARPProof<F, H>
where
    F: Field + CanonicalSerialize,
    H: MerkleHasher,
    H::Digest: CanonicalSerialize,
    WarpProof<H>: CanonicalSerialize,
{
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

/// `AccumulatorWitness` deliberately drops `td` (the full Merkle tree)
/// from the serialized form: only `w` ships across the wire — the tree
/// is reconstructable by re-encoding `w`. Used for proof-size reporting,
/// not on-the-wire serialization.
pub fn acc_witness_size<F, H>(acc_witness: &AccumulatorWitness<F, H>, compress: Compress) -> usize
where
    F: Field + CanonicalSerialize,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    acc_witness.w_witnesses.serialized_size(compress)
}
