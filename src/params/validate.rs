//! Soundness validation — the inverse of [`super::select`].
//!
//! Given a `Params`, report how many bits of security it gives under the
//! chosen regime, and whether each component check passes.

use super::select::FIELD_EPSILON;
use super::types::{ParamError, Params, Regime, SecurityLevel, SoundnessBound};

const S_MIN: usize = 8;

/// Compute the soundness bound that `params` achieves on a rate-`code_rate`
/// Reed–Solomon code over a field of `field_bits`, under `regime`.
///
/// Returns `Err(ParamError::InvalidRate)` if the rate is outside `(0, 1)`.
/// `FieldTooSmall` is not returned here — field admissibility is surfaced
/// on the returned [`SoundnessBound`] so callers can reason about partial
/// failures.
pub fn validate(
    params: &Params,
    field_bits: u32,
    code_rate: f64,
    regime: Regime,
    target: SecurityLevel,
) -> Result<SoundnessBound, ParamError> {
    if !(0.0 < code_rate && code_rate < 1.0) {
        return Err(ParamError::InvalidRate);
    }

    let bits_per_query = match regime {
        Regime::Provable => 0.5 * (-code_rate.log2()),
        Regime::Conjectured => -code_rate.log2(),
    };

    let proximity_bits = (params.t as f64) * bits_per_query;
    let field_admissible = field_bits >= target.bits() + FIELD_EPSILON;
    let ood_admissible = params.s >= S_MIN;

    Ok(SoundnessBound {
        proximity_bits,
        field_admissible,
        ood_admissible,
    })
}
