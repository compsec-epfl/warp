use ark_codes::traits::LinearCode;
use ark_crypto_primitives::{
    merkle_tree::{Config, MerkleTree, Path},
    Error,
};
use ark_ff::Field;

pub mod blake3;
pub mod parameters;
pub mod poseidon;

pub fn build_codeword_leaves<F: Field, C: LinearCode<F>>(
    code: &C,
    witnesses: &[Vec<F>],
    l1: usize,
) -> (Vec<Vec<F>>, Vec<F>) {
    let mut leaves = vec![F::default(); l1 * code.code_len()];
    let mut codewords = vec![vec![F::default(); code.code_len()]; l1];
    for (i, w) in witnesses.iter().enumerate() {
        let f_i = code.encode(w);
        // stacking codewords in flat array, which we chunk below
        // [[w_0[0], .., w_{N-1}[0]], .., [w_0[N-1], .., w_{N-1}[N-1]]] // L * N elements
        for (j, value) in f_i.iter().enumerate() {
            leaves[(j * l1) + i] = *value;
        }
        codewords[i] = f_i;
    }
    (codewords, leaves)
}

pub fn compute_auth_paths<P: Config>(
    td: &MerkleTree<P>,
    indexes: &[usize],
) -> Result<Vec<Path<P>>, Error> {
    let paths = indexes
        .iter()
        .map(|x_t| td.generate_proof(*x_t))
        .collect::<Result<Vec<Path<P>>, Error>>()?;
    Ok(paths)
}
