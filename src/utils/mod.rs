use ark_ff::Field;
use ark_std::io::Cursor;

pub fn bytes_to_vec_f<F: Field>(bytes: &[u8]) -> Vec<F> {
    let mut buf = Vec::new();
    F::zero().serialize_uncompressed(&mut buf).unwrap();
    let chunk_size = buf.len();
    bytes
        .chunks(chunk_size)
        .map(|chunk| {
            let mut padded = Vec::with_capacity(chunk_size);
            padded.extend_from_slice(chunk);
            padded.resize(chunk_size, 0); // pad with zero bytes if necessary
            let mut reader = Cursor::new(padded);
            F::deserialize_uncompressed(&mut reader).unwrap()
        })
        .collect()
}
