//! Pre-computed parameter tuples for common `(λ, code_rate)` points.
//!
//! Each entry is derived by [`super::select`] at the named regime and
//! stored here as a `const` lookup so tests and CLIs don't need to re-run
//! the derivation on every invocation. If you change the bounds in
//! `mod4_parameter_selection.tex`, regenerate this table via
//! `cargo run --bin warp-params -- table`.

use super::types::{Params, Regime, SecurityLevel};

/// One row of [`PRESETS`].
pub struct Preset {
    pub lambda: SecurityLevel,
    pub code_rate_num: u32,
    pub code_rate_den: u32,
    pub regime: Regime,
    pub params: Params,
}

impl Preset {
    pub fn code_rate(&self) -> f64 {
        self.code_rate_num as f64 / self.code_rate_den as f64
    }
}

/// Common `(λ, rate, regime) → (s, t)` selections. See module docstring
/// on regeneration.
///
/// All entries use the minimum `s = 8` (see
/// `mod4_parameter_selection.tex` §2); `t` is the smallest integer that
/// meets the target under the named regime.
pub const PRESETS: &[Preset] = &[
    // λ=80 @ rate 1/2
    Preset {
        lambda: SecurityLevel::STANDARD_80,
        code_rate_num: 1,
        code_rate_den: 2,
        regime: Regime::Provable,
        params: Params { s: 8, t: 160 },
    },
    Preset {
        lambda: SecurityLevel::STANDARD_80,
        code_rate_num: 1,
        code_rate_den: 2,
        regime: Regime::Conjectured,
        params: Params { s: 8, t: 80 },
    },
    // λ=80 @ rate 1/8 (three bits per query under provable)
    Preset {
        lambda: SecurityLevel::STANDARD_80,
        code_rate_num: 1,
        code_rate_den: 8,
        regime: Regime::Provable,
        params: Params { s: 8, t: 54 },
    },
    Preset {
        lambda: SecurityLevel::STANDARD_80,
        code_rate_num: 1,
        code_rate_den: 8,
        regime: Regime::Conjectured,
        params: Params { s: 8, t: 27 },
    },
    // λ=128 @ rate 1/2
    Preset {
        lambda: SecurityLevel::STANDARD_128,
        code_rate_num: 1,
        code_rate_den: 2,
        regime: Regime::Provable,
        params: Params { s: 8, t: 256 },
    },
    Preset {
        lambda: SecurityLevel::STANDARD_128,
        code_rate_num: 1,
        code_rate_den: 2,
        regime: Regime::Conjectured,
        params: Params { s: 8, t: 128 },
    },
    // λ=128 @ rate 1/8
    Preset {
        lambda: SecurityLevel::STANDARD_128,
        code_rate_num: 1,
        code_rate_den: 8,
        regime: Regime::Provable,
        params: Params { s: 8, t: 86 },
    },
    Preset {
        lambda: SecurityLevel::STANDARD_128,
        code_rate_num: 1,
        code_rate_den: 8,
        regime: Regime::Conjectured,
        params: Params { s: 8, t: 43 },
    },
];

/// Look up a preset by `(λ, num/den, regime)`. Exact-rational match —
/// callers that parsed the rate as a fraction preserve the exact form
/// and get a hit. Returns `None` if no exact row matches; use
/// [`super::select`] for arbitrary inputs.
pub fn lookup(
    lambda: SecurityLevel,
    num: u32,
    den: u32,
    regime: Regime,
) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| {
        p.lambda == lambda && p.code_rate_num == num && p.code_rate_den == den && p.regime == regime
    })
}
