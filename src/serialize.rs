use ark_crypto_primitives::merkle_tree::{Config, MerkleTree, Path};
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;

#[derive(CanonicalSerialize)]
pub struct AccWitnessSerializer<
    F: Field + PrimeField,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
> {
    td: Vec<MT::LeafDigest>,
    f: Vec<F>,
    w: Vec<F>,
}

impl<F: Field + PrimeField, MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>>
    AccWitnessSerializer<F, MT>
{
    pub fn new(acc_witness: (Vec<MerkleTree<MT>>, Vec<Vec<F>>, Vec<Vec<F>>)) -> Self {
        assert_eq!(acc_witness.0.len(), 1);
        assert_eq!(acc_witness.1.len(), 1);
        assert_eq!(acc_witness.2.len(), 1);
        let f = acc_witness.1[0].clone();
        assert_eq!(f.len(), acc_witness.0[0].leaf_nodes.len());
        let w = acc_witness.2[0].clone();
        Self {
            td: acc_witness.0[0].clone().leaf_nodes,
            f,
            w,
        }
    }
}

#[derive(CanonicalSerialize)]
pub struct AccInstanceSerializer<
    F: Field + PrimeField,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
> {
    pub rt: MT::InnerDigest,
    pub alpha: Vec<F>,
    pub mu: F,
    pub beta: (Vec<F>, Vec<F>),
    pub eta: F,
}

impl<F: Field + PrimeField, MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>>
    AccInstanceSerializer<F, MT>
{
    pub fn new(
        acc_instance: (
            Vec<MT::InnerDigest>,
            Vec<Vec<F>>,
            Vec<F>,
            (Vec<Vec<F>>, Vec<Vec<F>>),
            Vec<F>,
        ),
    ) -> Self {
        assert_eq!(acc_instance.0.len(), 1);
        assert_eq!(acc_instance.1.len(), 1);
        assert_eq!(acc_instance.2.len(), 1);
        assert_eq!(acc_instance.3 .0.len(), 1);
        assert_eq!(acc_instance.3 .1.len(), 1);
        assert_eq!(acc_instance.4.len(), 1);
        let beta = (acc_instance.3 .0[0].clone(), acc_instance.3 .1[0].clone());
        Self {
            rt: acc_instance.0[0].clone(),
            alpha: acc_instance.1[0].clone(),
            mu: acc_instance.2[0],
            beta,
            eta: acc_instance.4[0],
        }
    }
}

#[derive(CanonicalSerialize)]
pub struct ProofSerializer<
    F: Field + PrimeField,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
> {
    rt_0: MT::InnerDigest,
    mu_i: Vec<F>,
    nu_0: F,
    nu_i: Vec<F>,
    auth_0: Vec<Path<MT>>,
    auth_j: Vec<Vec<Path<MT>>>,
    f_i_x_j: Vec<Vec<F>>,
}

impl<F: Field + PrimeField, MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>>
    ProofSerializer<F, MT>
{
    pub fn new(
        proof: (
            MT::InnerDigest,
            Vec<F>,
            F,
            Vec<F>,
            Vec<Path<MT>>,
            Vec<Vec<Path<MT>>>,
            Vec<Vec<F>>,
        ),
    ) -> Self {
        Self {
            rt_0: proof.0,
            mu_i: proof.1,
            nu_0: proof.2,
            nu_i: proof.3,
            auth_0: proof.4,
            auth_j: proof.5,
            f_i_x_j: proof.6,
        }
    }
}
