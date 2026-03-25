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

        let cs = constraint_system.into_inner().unwrap();
        let all_matrices = cs.to_matrices().unwrap();
        let r1cs_matrices = all_matrices
            .get(R1CS_PREDICATE_LABEL)
            .expect("R1CS predicate must exist");

        let num_constraints = cs
            .get_predicate_num_constraints(R1CS_PREDICATE_LABEL)
            .unwrap_or(0);

        let serializable = SerializableConstraintMatrices {
            num_instance_variables: cs.num_instance_variables(),
            num_witness_variables: cs.num_witness_variables(),
            num_constraints,
            a: Self::serialize_nested_field(r1cs_matrices[0].clone()),
            b: Self::serialize_nested_field(r1cs_matrices[1].clone()),
            c: Self::serialize_nested_field(r1cs_matrices[2].clone()),
        };
        let serialized = serde_json::to_string(&serializable).unwrap();
        serialized.into_bytes()
    }
}
