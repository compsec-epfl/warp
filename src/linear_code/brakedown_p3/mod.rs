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
use p3_matrix::{dense::RowMajorMatrix, MatrixRows, Matrix, MatrixRowSlices};
// use p3_code::LinearCode as P3LinearCode;

mod convert;

use crate::linear_code::LinearCode;

fn brakedown_encode<PF>(message: &[PF]) -> Vec<PF>
where
    PF: P3Field,
    Standard: Distribution<PF>,
{
    const K: usize = 16_384;
    if message.is_empty() {
        return Vec::new();
    }

    // Number of columns (each column is one message block of height K).
    let width = (message.len() + K - 1) / K;

    // Build a row-major matrix of size K x width.
    // data[r * width + c] holds row r, column c.
    let zero = PF::from_canonical_u32(0);
    let mut data = vec![zero; K * width];

    // Fill columns from the input (pad the last column with zeros).
    for c in 0..width {
        let start = c * K;
        let end = core::cmp::min(start + K, message.len());
        let col_slice = &message[start..end];
        for (r, &val) in col_slice.iter().enumerate() {
            data[r * width + c] = val;
        }
    }

    let input: RowMajorMatrix<PF> = RowMajorMatrix::new(data, width);

    // Encode with the fast Brakedown family.
    let family = fast_registry::<PF, RowMajorMatrix<PF>>();
    let encoded = family.encode_batch(input);

    // Materialize and collect each column top-to-bottom.
    let dense = encoded.to_row_major_matrix();
    let n = dense.height();   // total codeword length per column (K + parity)
    let w = dense.width();    // should equal `width`

    let mut out = Vec::with_capacity(n * w);
    for c in 0..w {
        for r in 0..n {
            out.push(dense.row_slice(r)[c]);
        }
    }
    out
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
    fn brakedown_roundtrip_sanity() {
        // get some random message
        let message: Vec<Goldilocks> = (0..1024_u64).map(Goldilocks::from).collect();

        // convert to P3 fields
        let converted: Vec<P3Goldilocks> = convert::vec_ark_to_vec_p3_64(&message);

        // resize to smallest available brakedown code
        let size = 16_384;
        let mut resized = converted.clone();
        resized.resize(size, P3Goldilocks::from_canonical_u32(0));
        let decoded_message = brakedown_encode(&resized);

        // // single-column matrix of height "size"
        // let input_matrix: RowMajorMatrix<P3Goldilocks> = RowMajorMatrix::new_col(resized);

        // // encode
        // let encoded = fast_registry::<P3Goldilocks, RowMajorMatrix<P3Goldilocks>>()
        //     .encode_batch(input_matrix);

        // // get the codeword
        // let codeword_len = encoded.height();
        // let output_matrix = encoded.to_row_major_matrix();
        // let codeword: Vec<P3Goldilocks> = (0..codeword_len)
        //     .map(|r| output_matrix.row_slice(r)[0]) // width == 1, so take [0]
        //     .collect();

        // // verify the decoded message matches (trivially by reading first "size" elements)
        // let decoded_message: Vec<P3Goldilocks> = codeword[..message.len()].to_vec();
        assert_eq!(decoded_message, resized);
    }
}
