//! Soundness-driven `(s, t)` selection for WARP.
//! Paired spec: `docs/paper-mods/mod4_parameter_selection.tex`.

pub mod presets;
pub mod select;
pub mod types;
pub mod validate;

pub use presets::{lookup, Preset, PRESETS};
pub use select::select;
pub use types::{ParamError, Params, Regime, SecurityLevel, SoundnessBound};
pub use validate::{inspect, validate};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_validate_roundtrip_provable() {
        let lambda = SecurityLevel::STANDARD_128;
        let p = select(lambda, 254, 0.5, Regime::Provable).unwrap();
        assert!(
            p.t >= 256,
            "provable t at λ=128, ρ=1/2 should need ≥ 256 queries, got {}",
            p.t
        );
        let bound = validate(&p, 254, 0.5, Regime::Provable, lambda).unwrap();
        assert!(
            bound.meets(lambda),
            "selected params should self-validate: {bound:?}"
        );
    }

    #[test]
    fn select_validate_roundtrip_conjectured() {
        let lambda = SecurityLevel::STANDARD_128;
        let p = select(lambda, 254, 0.5, Regime::Conjectured).unwrap();
        // Conjectured halves the query count at ρ=0.5 (2 vs 1 bits per query).
        assert!(p.t >= 128 && p.t < 256);
        let bound = validate(&p, 254, 0.5, Regime::Conjectured, lambda).unwrap();
        assert!(bound.meets(lambda));
    }

    #[test]
    fn smaller_rate_needs_fewer_queries() {
        let lambda = SecurityLevel::STANDARD_128;
        let p_half = select(lambda, 254, 0.5, Regime::Provable).unwrap();
        let p_eighth = select(lambda, 254, 0.125, Regime::Provable).unwrap();
        assert!(
            p_eighth.t < p_half.t,
            "ρ=1/8 needs fewer queries than ρ=1/2: {} vs {}",
            p_eighth.t,
            p_half.t
        );
    }

    #[test]
    fn conjectured_needs_fewer_queries_than_provable() {
        let lambda = SecurityLevel::STANDARD_128;
        let p_prov = select(lambda, 254, 0.5, Regime::Provable).unwrap();
        let p_conj = select(lambda, 254, 0.5, Regime::Conjectured).unwrap();
        assert!(p_conj.t < p_prov.t);
    }

    #[test]
    fn field_too_small_is_rejected() {
        // 64-bit field, 128-bit target: should fail admissibility.
        assert!(matches!(
            select(SecurityLevel::STANDARD_128, 64, 0.5, Regime::Provable),
            Err(ParamError::FieldTooSmall { .. })
        ));
    }

    #[test]
    fn invalid_rate_is_rejected() {
        let lambda = SecurityLevel::STANDARD_80;
        assert_eq!(
            select(lambda, 254, 0.0, Regime::Provable),
            Err(ParamError::InvalidRate)
        );
        assert_eq!(
            select(lambda, 254, 1.0, Regime::Conjectured),
            Err(ParamError::InvalidRate)
        );
    }

    #[test]
    fn presets_self_validate() {
        // Every preset should achieve its claimed lambda under its regime.
        for preset in PRESETS {
            // Use 254-bit field so field_admissible passes at 128-bit.
            let bound = validate(
                &preset.params,
                254,
                preset.code_rate(),
                preset.regime,
                preset.lambda,
            )
            .unwrap();
            assert!(
                bound.meets(preset.lambda),
                "preset {:?} rate={:?} regime={:?} fails its own target: {:?}",
                preset.lambda,
                preset.code_rate(),
                preset.regime,
                bound
            );
        }
    }

    #[test]
    fn presets_match_select_output() {
        for preset in PRESETS {
            let recomputed = select(preset.lambda, 254, preset.code_rate(), preset.regime).unwrap();
            assert_eq!(
                recomputed,
                preset.params,
                "preset drift: {:?} rate={:?} regime={:?}",
                preset.lambda,
                preset.code_rate(),
                preset.regime
            );
        }
    }

    #[test]
    fn lookup_round_trips() {
        let p = lookup(SecurityLevel::STANDARD_128, 1, 2, Regime::Conjectured).unwrap();
        assert_eq!(p.params.t, 128);
    }

    #[test]
    fn lookup_misses_on_unknown_rate() {
        // We have 1/2 and 1/8 on file; 1/4 is not a preset.
        assert!(lookup(SecurityLevel::STANDARD_128, 1, 4, Regime::Provable).is_none());
    }
}
