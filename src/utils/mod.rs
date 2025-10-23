use ark_ff::{Field, PrimeField};

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
