//! Parameter-selection types.
//!
//! Paired spec: `docs/paper-mods/mod4_parameter_selection.tex`.

/// Target soundness, in bits. `SecurityLevel(128)` means the soundness
/// error should be at most 2⁻¹²⁸.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecurityLevel(pub u32);

impl SecurityLevel {
    pub const STANDARD_80: Self = Self(80);
    pub const STANDARD_100: Self = Self(100);
    pub const STANDARD_128: Self = Self(128);
    pub const STANDARD_192: Self = Self(192);
    pub const STANDARD_256: Self = Self(256);

    pub fn bits(self) -> u32 {
        self.0
    }
}

/// Which list-decoding regime to assume when bounding proximity-query
/// soundness. See `docs/paper-mods/mod4_parameter_selection.tex` §2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Regime {
    /// Johnson bound — radius `1 − √ρ`. Soundness error per query is
    /// `√ρ`; proven for Reed–Solomon in the STIR / WHIR lineage.
    Provable,
    /// Conjectured list-decodability up to radius `1 − ρ`. Soundness
    /// error per query is `ρ`; halves the required query count vs.
    /// provable at the same target.
    Conjectured,
}

/// Selected security-driven WARP parameters.
///
/// Workload parameters (`l`, `l1`) are *not* chosen here — they're caller-
/// supplied based on the batch size the application needs. This struct
/// carries only the choices whose minimum is dictated by soundness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// OOD samples.
    pub s: usize,
    /// Proximity / shift queries.
    pub t: usize,
}

/// Result of [`crate::params::validate`]. Reports the log₂ soundness error
/// achievable under the given `(params, rate, regime)`, together with the
/// field-size admissibility check.
#[derive(Clone, Copy, Debug)]
pub struct SoundnessBound {
    /// `-log₂` of the proximity-query soundness error contribution.
    pub proximity_bits: f64,
    /// Whether the field is large enough that the polylog-noise
    /// contributions are negligible at the target level.
    pub field_admissible: bool,
    /// Whether the selected `s` meets the minimum OOD sample count
    /// used in the current formulas. Currently always true with the
    /// hard-coded `S_MIN`; kept as a field so a future refinement can
    /// surface a failure.
    pub ood_admissible: bool,
}

impl SoundnessBound {
    /// `true` iff every component check passes at the caller's target.
    pub fn meets(&self, target: SecurityLevel) -> bool {
        self.field_admissible
            && self.ood_admissible
            && self.proximity_bits >= target.bits() as f64
    }
}

/// Reasons [`crate::params::select`] or [`crate::params::validate`] can
/// reject a configuration. Never panics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamError {
    /// Code rate was out of range `(0, 1)`.
    InvalidRate,
    /// Field is too small to support the target soundness even with
    /// infinite queries.
    FieldTooSmall {
        field_bits: u32,
        lambda: u32,
    },
}
