use super::types::{ParamError, Params, Regime, SecurityLevel};

const S_MIN: usize = 8;

/// We require `log₂|F| ≥ λ + FIELD_EPSILON` so polylog noise is negligible.
pub const FIELD_EPSILON: u32 = 40;

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
