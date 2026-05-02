use ark_ff::Field;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem, R1CS_PREDICATE_LABEL};
use serde::Serialize;

#[derive(Serialize)]
pub struct SerializableConstraintMatrices {
    pub num_instance_variables: usize,
    pub num_witness_variables: usize,
    pub num_constraints: usize,
    pub a: Vec<Vec<(Vec<u8>, usize)>>,
    pub b: Vec<Vec<(Vec<u8>, usize)>>,
    pub c: Vec<Vec<(Vec<u8>, usize)>>,
}

impl SerializableConstraintMatrices {
    pub fn serialize_nested_field<F: Field>(
        original: Vec<Vec<(F, usize)>>,
    ) -> Vec<Vec<(Vec<u8>, usize)>> {
        original
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|(coeff, col_idx)| {
                        let mut buf = Vec::new();
                        coeff.serialize_uncompressed(&mut buf).unwrap();
                        (buf, col_idx)
                    })
                    .collect()
            })
            .collect()
    }
    pub fn generate_description<F: Field>(
        constraint_synthesizer: impl ConstraintSynthesizer<F>,
    ) -> Vec<u8> {
        let constraint_system = ConstraintSystem::<F>::new_ref();
        constraint_synthesizer
            .generate_constraints(constraint_system.clone())
            .unwrap();
        constraint_system.finalize();

        let num_instance_variables = constraint_system.num_instance_variables();
        let num_witness_variables = constraint_system.num_witness_variables();
        let num_constraints = constraint_system.num_constraints();

        let mut matrices = constraint_system.to_matrices().unwrap();
        let mut r1cs = matrices.remove(R1CS_PREDICATE_LABEL).unwrap();
        let mut r1cs_iter = r1cs.drain(..);
        let a = r1cs_iter.next().unwrap();
        let b = r1cs_iter.next().unwrap();
        let c = r1cs_iter.next().unwrap();

        let serializable = SerializableConstraintMatrices {
            num_instance_variables,
            num_witness_variables,
            num_constraints,
            a: SerializableConstraintMatrices::serialize_nested_field(a),
            b: SerializableConstraintMatrices::serialize_nested_field(b),
            c: SerializableConstraintMatrices::serialize_nested_field(c),
        };
        let serialized = serde_json::to_string(&serializable).unwrap();
        serialized.into_bytes()
    }
}
