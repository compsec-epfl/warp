use ark_ff::Field;
use ark_serialize::{CanonicalSerialize, Compress, SerializationError, Valid, Write};
use ark_vc::mvc::MultiVectorCommitment;

use crate::warp::{AccumulatorInstance, AccumulatorWitness, WARPProof};

// `AccumulatorInstance` and `WARPProof` carry generic associated types
// (`V::Commitment`) whose serializability isn't implied by the trait
// itself. Putting the bound in a separate `impl` block (rather than on
// the struct) keeps the bulk of the IOR / orchestrator code free of that
// dep — only the size-printing path pulls it in.

impl<F, V> CanonicalSerialize for AccumulatorInstance<F, V>
where
    F: Field + CanonicalSerialize,
    V: MultiVectorCommitment<Alphabet = F>,
    V::Commitment: CanonicalSerialize,
{
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.rt_commitments
            .serialize_with_mode(&mut writer, compress)?;
        self.alpha_fold_vectors
            .serialize_with_mode(&mut writer, compress)?;
        self.mu_claimed_evals
            .serialize_with_mode(&mut writer, compress)?;
        let taus: Vec<&Vec<F>> = self.beta_twin_pairs.iter().map(|p| &p.tau).collect();
        let xs: Vec<&Vec<F>> = self.beta_twin_pairs.iter().map(|p| &p.x).collect();
        taus.serialize_with_mode(&mut writer, compress)?;
        xs.serialize_with_mode(&mut writer, compress)?;
        self.eta_predicate_evals
            .serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let taus: Vec<&Vec<F>> = self.beta_twin_pairs.iter().map(|p| &p.tau).collect();
        let xs: Vec<&Vec<F>> = self.beta_twin_pairs.iter().map(|p| &p.x).collect();
        self.rt_commitments.serialized_size(compress)
            + self.alpha_fold_vectors.serialized_size(compress)
            + self.mu_claimed_evals.serialized_size(compress)
            + taus.serialized_size(compress)
            + xs.serialized_size(compress)
            + self.eta_predicate_evals.serialized_size(compress)
    }
}

impl<F, V> Valid for AccumulatorInstance<F, V>
where
    F: Field + CanonicalSerialize,
    V: MultiVectorCommitment<Alphabet = F>,
    V::Commitment: CanonicalSerialize,
{
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl<F, V> CanonicalSerialize for WARPProof<F, V>
where
    F: Field + CanonicalSerialize,
    V: MultiVectorCommitment<Alphabet = F>,
    V::Commitment: CanonicalSerialize,
{
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.rt_0_fresh_commitment
            .serialize_with_mode(&mut writer, compress)?;
        self.mu_i_first_codeword_coords
            .serialize_with_mode(&mut writer, compress)?;
        self.nu_0_oracle_eval
            .serialize_with_mode(&mut writer, compress)?;
        self.nu_i_oracle_evals
            .serialize_with_mode(&mut writer, compress)?;
        self.shift_query_answers
            .serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.rt_0_fresh_commitment.serialized_size(compress)
            + self.mu_i_first_codeword_coords.serialized_size(compress)
            + self.nu_0_oracle_eval.serialized_size(compress)
            + self.nu_i_oracle_evals.serialized_size(compress)
            + self.shift_query_answers.serialized_size(compress)
    }
}

impl<F, V> Valid for WARPProof<F, V>
where
    F: Field + CanonicalSerialize,
    V: MultiVectorCommitment<Alphabet = F>,
    V::Commitment: CanonicalSerialize,
{
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

/// `AccumulatorWitness` deliberately drops `td` (the full Merkle tree)
/// from the serialized form: only `w` ships across the wire — the tree
/// is reconstructable by re-encoding `w`. Used for proof-size reporting,
/// not on-the-wire serialization.
pub fn acc_witness_size<F, V>(acc_witness: &AccumulatorWitness<F, V>, compress: Compress) -> usize
where
    F: Field + CanonicalSerialize,
    V: MultiVectorCommitment<Alphabet = F>,
{
    acc_witness.w_witnesses.serialized_size(compress)
}
