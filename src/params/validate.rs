use super::select::FIELD_EPSILON;
use super::types::{ParamError, Params, Regime, SecurityLevel, SoundnessBound};

const S_MIN: usize = 8;

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
