//! Thin re-export of the eq-polynomial helpers now provided by effsc.
//!
//! Kept at this path so existing warp imports (`crate::utils::poly::eq_poly`,
//! `eq_poly_non_binary`) continue to resolve. The library version of
//! `compute_hypercube_eq_evals` is also O(2^v) now — use it instead of the
//! per-point `eq_poly` whenever the full table is needed.
pub use effsc::hypercube::{eq_poly, eq_poly_non_binary};
