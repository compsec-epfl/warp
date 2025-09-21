use ark_std::marker::PhantomData;
use ark_std::rand::distributions::{Distribution, Standard};

use ark_ff::{FftField, Field, PrimeField};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, EvaluationDomain};
use ark_serialize::CanonicalSerialize;
use p3_brakedown::fast_registry;
use p3_brakedown::BrakedownCode;
use p3_code::{CodeOrFamily, SystematicCode};
use p3_field::{Field as P3Field, PrimeField64 as P3PrimeField64};
use p3_matrix::{dense::RowMajorMatrix, Matrix, MatrixRowSlices, MatrixRows};

mod convert;

use crate::linear_code::LinearCode;

fn brakedown_input<PF: P3Field>(message: &[PF]) -> RowMajorMatrix<PF> {
    // the smallest available message size I found was 16_384
    const MESSAGE_LEN: usize = 16_384;

    // each column is a message block of length (height in the matrix) MESSAGE_LEN
    let num_cols = (message.len() + MESSAGE_LEN - 1) / MESSAGE_LEN;

    // initialize a row-major matrix MESSAGE_LEN x num_cols
    let mut input_matrix = vec![PF::from_canonical_u32(0); MESSAGE_LEN * num_cols];

    // fill in the message blocks (the last gets padded automatically)
    for col_idx in 0..num_cols {
        let start = col_idx * MESSAGE_LEN;
        let end = core::cmp::min(start + MESSAGE_LEN, message.len());
        let col_slice = &message[start..end];
        for (row_idx, &value) in col_slice.iter().enumerate() {
            input_matrix[row_idx * num_cols + col_idx] = value;
        }
    }
    RowMajorMatrix::new(input_matrix, num_cols)
}

fn brakedown_output<PF: P3Field>(output_matrix: RowMajorMatrix<PF>) -> Vec<PF> {
    // Materialize and collect each column top-to-bottom.
    let codeword_len = output_matrix.height(); // MESSAGE_LEN + parity
    let num_output_cols = output_matrix.width(); // same as num_cols

    let mut out = Vec::with_capacity(codeword_len * num_output_cols);
    for col_idx in 0..num_output_cols {
        for row_idx in 0..codeword_len {
            out.push(output_matrix.row_slice(row_idx)[col_idx]);
        }
    }
    out
}

fn brakedown_encode<PF>(messages: &[PF]) -> Vec<PF>
where
    PF: P3Field,
    Standard: Distribution<PF>,
{
    // lil check
    if messages.is_empty() {
        return Vec::new();
    }

    // format the input
    let input_matrix = brakedown_input(messages);

    // encode
    let codewords = fast_registry::<PF, RowMajorMatrix<PF>>().encode_batch(input_matrix);

    // format and return
    let output_matrix = codewords.to_row_major_matrix();
    brakedown_output(output_matrix)
}

#[cfg(test)]
mod tests {
    use ark_ff::{Fp64, MontBackend, MontConfig};
    use p3_field::AbstractField;
    use p3_matrix::{Matrix, MatrixRowSlices};

    use super::*;

    use p3_goldilocks::Goldilocks as P3Goldilocks;

    #[derive(MontConfig)]
    #[modulus = "18446744069414584321"] // q = 2^64 - 2^32 + 1 Goldilocks
    #[generator = "2"]
    pub struct GoldilocksConfig;
    pub type Goldilocks = Fp64<MontBackend<GoldilocksConfig, 1>>;

    #[test]
    fn encode_sanity() {
        // NOTE(z-tech): I needed this to figure out how the succinct/plonky3
        // API works

        // get some random message
        let messages: Vec<Goldilocks> = (0..1024_u64).map(Goldilocks::from).collect();

        // convert to P3 fields
        let converted: Vec<P3Goldilocks> = convert::vec_ark_to_vec_p3_64(&messages);

        // resize to smallest available MESSAGE_LEN
        const MESSAGE_LEN: usize = 16_384;
        let mut resized = converted.clone();
        resized.resize(MESSAGE_LEN, P3Goldilocks::from_canonical_u32(0));

        // single-column matrix of height MESSAGE_LEN
        let input_matrix: RowMajorMatrix<P3Goldilocks> = RowMajorMatrix::new_col(resized);

        // encode
        let codewords = fast_registry::<P3Goldilocks, RowMajorMatrix<P3Goldilocks>>()
            .encode_batch(input_matrix);

        // get the first codeword in the list (there's only one)
        let codeword_len = codewords.height();
        let output_matrix = codewords.to_row_major_matrix();
        let codeword: Vec<P3Goldilocks> = (0..codeword_len)
            .map(|row_idx| output_matrix.row_slice(row_idx)[0])
            .collect();

        // verify the decoded message matches (trivially by reading first MESSAGE_LEN elements)
        let decoded_message: Vec<P3Goldilocks> = codeword[..messages.len()].to_vec();
        assert_eq!(decoded_message, converted);
    }

    #[test]
    fn encode_helper_sanity() {
        // NOTE(z-tech): this does the same as test "encode_sanity" but
        // handles the padding and input formatting provided a Vec<P3Field>

        // get a random message
        let message: Vec<Goldilocks> = (0..1024_u64).map(Goldilocks::from).collect();

        // convert it to P3 fields
        let converted: Vec<P3Goldilocks> = convert::vec_ark_to_vec_p3_64(&message);

        // get the codeword
        let codeword = brakedown_encode(&converted);

        // verify the decoded message matches <-- trivial by reading first message.len() elements
        let decoded_message: Vec<P3Goldilocks> = codeword[..message.len()].to_vec();
        assert_eq!(decoded_message, converted);
    }
}
