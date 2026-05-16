/// Minimum number of OOD samples — shared by `select` and `validate`.
pub const S_MIN: usize = 8;

/// Target soundness in bits: `SecurityLevel(128)` means error ≤ 2⁻¹²⁸.
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

/// Which list-decoding regime to assume. `Provable`: Johnson bound (radius
/// `1 − √ρ`). `Conjectured`: list-decoding to `1 − ρ`; halves `t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Regime {
    Provable,
    Conjectured,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub s: usize,
    pub t: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct SoundnessBound {
    pub proximity_bits: f64,
    pub field_admissible: bool,
    pub ood_admissible: bool,
}

impl SoundnessBound {
    pub fn meets(&self, target: SecurityLevel) -> bool {
        self.field_admissible && self.ood_admissible && self.proximity_bits >= target.bits() as f64
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ParamError {
    InvalidRate,
    FieldTooSmall {
        field_bits: u32,
        lambda: u32,
    },
    /// Returned by `validate()` when `params.s` is below the OOD-samples
    /// minimum required for the chosen target.
    OodSamplesTooFew {
        s: usize,
        min: usize,
    },
    /// Returned by `validate()` when proximity soundness is below target.
    ProximitySoundnessBelowTarget {
        proximity_bits: f64,
        target_bits: u32,
    },
}
