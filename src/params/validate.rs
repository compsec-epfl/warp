use super::select::FIELD_EPSILON;
use super::types::{ParamError, Params, Regime, SecurityLevel, SoundnessBound, S_MIN};

/// Fail-closed soundness check. Returns `Ok(bound)` only when every
/// admissibility flag passes and proximity soundness meets the target.
///
/// For diagnostic output that returns the bound regardless of pass/fail,
/// use [`inspect`].
pub fn validate(
    params: &Params,
    field_bits: u32,
    code_rate: f64,
    regime: Regime,
    target: SecurityLevel,
) -> Result<SoundnessBound, ParamError> {
    let bound = inspect(params, field_bits, code_rate, regime, target)?;
    if !bound.field_admissible {
        return Err(ParamError::FieldTooSmall {
            field_bits,
            lambda: target.bits(),
        });
    }
    if !bound.ood_admissible {
        return Err(ParamError::OodSamplesTooFew {
            s: params.s,
            min: S_MIN,
        });
    }
    if bound.proximity_bits < target.bits() as f64 {
        return Err(ParamError::ProximitySoundnessBelowTarget {
            proximity_bits: bound.proximity_bits,
            target_bits: target.bits(),
        });
    }
    Ok(bound)
}

/// Diagnostic / non-failing variant of [`validate`]. Returns the full
/// [`SoundnessBound`] even when admissibility checks fail (only structural
/// errors like an invalid rate produce `Err`). Intended for CLI / debug
/// output; security-relevant callers must use [`validate`].
pub fn inspect(
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

    let _ = target;
    Ok(SoundnessBound {
        proximity_bits,
        field_admissible,
        ood_admissible,
    })
}
