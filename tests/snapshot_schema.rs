//! ProtocolSchema snapshot test — locks the structural shape of WARP.
//!
//! Catches: IOR reorderings, IOR insertions/removals, MESSAGE_TAGS
//! changes (rename, reorder, add, remove), IOP::NAME changes.
//!
//! Does NOT depend on running the prover — pure function of the
//! protocol structure. Complements the FS-bytes snapshot in
//! `snapshot_fs.rs`.

use ark_bls12_381::Fr as BLS12_381;
use ark_codes::reed_solomon::ReedSolomon;
use ark_mt::{
    blake3::Blake3FieldHasher, hash_region::HashRegion, scheme::MerkleCommitment,
    shape::PerfectBinary,
};

use warp::relations::r1cs::R1CS;
use warp::WarpAccumulationScheme;

type VC = MerkleCommitment<HashRegion<Blake3FieldHasher<BLS12_381>>, PerfectBinary>;
type Scheme = WarpAccumulationScheme<BLS12_381, R1CS<BLS12_381>, ReedSolomon<BLS12_381>, VC>;

const EXPECTED_SCHEMA_HASH: Option<&str> =
    Some("3951519bee5a77b2fc5aeb8143c6597485bdd949cdaf9190dcd8337e4b0d2aad");

#[test]
fn warp_protocol_schema_snapshot() {
    let schema = Scheme::schema();
    let fingerprint = schema.fingerprint();
    let hex = fingerprint
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    println!("schema:\n{}", schema.display());
    println!("schema_hash = {}", hex);

    if let Some(expected) = EXPECTED_SCHEMA_HASH {
        assert_eq!(hex, expected, "ProtocolSchema fingerprint changed");
    }
}
