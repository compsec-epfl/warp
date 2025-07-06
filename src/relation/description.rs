use ark_ff::Field;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem};
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
    fn serialize_nested_field<F: Field>(
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
        let matrices: ConstraintMatrices<F> = constraint_system.to_matrices().unwrap();
        let serializable = SerializableConstraintMatrices::from(matrices);
        let serialized = serde_json::to_string(&serializable).unwrap();
        serialized.into_bytes()
    }
}

impl<F: Field> From<ConstraintMatrices<F>> for SerializableConstraintMatrices {
    fn from(m: ConstraintMatrices<F>) -> Self {
        Self {
            num_instance_variables: m.num_instance_variables,
            num_witness_variables: m.num_witness_variables,
            num_constraints: m.num_constraints,
            a: SerializableConstraintMatrices::serialize_nested_field(m.a),
            b: SerializableConstraintMatrices::serialize_nested_field(m.b),
            c: SerializableConstraintMatrices::serialize_nested_field(m.c),
        }
    }
}
