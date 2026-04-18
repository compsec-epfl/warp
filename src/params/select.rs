//! Soundness-driven parameter selection.
//!
//! Paired spec: `docs/paper-mods/mod4_parameter_selection.tex`.
//!
//! Computes the smallest `(s, t)` tuple that achieves the requested
//! security level under the chosen list-decoding regime. See the `.tex`
//! for the derivation and which bounds were used from the STIR / WHIR
//! literature.

use super::types::{ParamError, Params, Regime, SecurityLevel};

/// Minimum OOD samples. Covers the constant term used in the current
/// derivation; tightening this against the batching-sumcheck soundness
/// is deferred — see `mod4_parameter_selection.tex` §2.
const S_MIN: usize = 8;

/// Additive slack on the field-size admissibility check: we require
/// `log₂|F| ≥ λ + FIELD_EPSILON` so the polylog noise terms are
/// negligible at the target level.
pub const FIELD_EPSILON: u32 = 40;

/// Select the minimum `(s, t)` achieving `lambda` bits of soundness for
/// a Reed–Solomon code of rate `code_rate` over a field of `field_bits`,
/// under the chosen regime.
///
/// Returns `Err(ParamError::InvalidRate)` if `code_rate ∉ (0, 1)`, and
/// `Err(ParamError::FieldTooSmall)` if the field cannot cover the polylog
/// noise at the requested target (see §3 of the paper-mods spec).
pub fn select(
    lambda: SecurityLevel,
    field_bits: u32,
    code_rate: f64,
    regime: Regime,
) -> Result<Params, ParamError> {
    if !(0.0 < code_rate && code_rate < 1.0) {
        return Err(ParamError::InvalidRate);
    }
    if field_bits < lambda.bits() + FIELD_EPSILON {
        return Err(ParamError::FieldTooSmall {
            field_bits,
            lambda: lambda.bits(),
        });
    }

    let bits_per_query = match regime {
        Regime::Provable => 0.5 * (-code_rate.log2()),
        Regime::Conjectured => -code_rate.log2(),
    };
    debug_assert!(bits_per_query > 0.0);

    let t = (lambda.bits() as f64 / bits_per_query).ceil() as usize;

    Ok(Params { s: S_MIN, t })
}
