//! Pre-computed `(λ, rate, regime) → (s, t)` rows. Regenerate via
//! `cargo run --bin warp-params -- table` after changing the bounds.

use super::types::{Params, Regime, SecurityLevel};

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

pub const PRESETS: &[Preset] = &[
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

/// Exact-rational match. `None` if the row isn't tabulated.
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
