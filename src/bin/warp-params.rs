//! `warp-params` — CLI for soundness-driven parameter selection.
//! Paired spec: `docs/paper-mods/mod4_parameter_selection.tex`.

use std::process::ExitCode;

use warp::params::{inspect, lookup, select, ParamError, Params, Regime, SecurityLevel, PRESETS};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("select") => cmd_select(&args[1..]),
        Some("validate") => cmd_validate(&args[1..]),
        Some("table") => cmd_table(),
        Some("-h") | Some("--help") | Some("help") | None => {
            print_usage();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("warp-params: unknown subcommand `{other}`");
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    eprintln!(
        "warp-params — pick soundness-driven WARP parameters.\n\
         \n\
         Usage:\n\
             warp-params select   --lambda N --rate NUM/DEN|FLOAT --field-bits N --regime provable|conjectured\n\
             warp-params validate --s N --t N --lambda N --rate ... --field-bits N --regime ...\n\
             warp-params table\n\
         \n\
         See docs/paper-mods/mod4_parameter_selection.tex for the derivation."
    );
}

fn cmd_select(args: &[String]) -> ExitCode {
    let flags = match parse_flags(args) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("warp-params select: {e}");
            return ExitCode::from(2);
        }
    };
    let (lambda, rate, field_bits, regime) =
        match (flags.lambda, flags.rate, flags.field_bits, flags.regime) {
            (Some(l), Some(r), Some(fb), Some(rg)) => (SecurityLevel(l), r, fb, rg),
            _ => {
                eprintln!("warp-params select: need --lambda, --rate, --field-bits, --regime");
                return ExitCode::from(2);
            }
        };
    match select(lambda, field_bits, rate.as_f64(), regime) {
        Ok(p) => {
            // Prefer a preset if we have an exact-rational match on file —
            // lets users see the canonical attested row, not just a
            // recomputed tuple. (Equal by `presets_match_select_output`.)
            let preset = rate.ratio().and_then(|(n, d)| lookup(lambda, n, d, regime));
            if let Some(preset) = preset {
                println!(
                    "λ={} rate={}/{} regime={:?} → s={} t={} (preset)",
                    preset.lambda.bits(),
                    preset.code_rate_num,
                    preset.code_rate_den,
                    preset.regime,
                    preset.params.s,
                    preset.params.t
                );
            } else {
                println!(
                    "λ={} rate={:.4} regime={:?} → s={} t={}",
                    lambda.bits(),
                    rate.as_f64(),
                    regime,
                    p.s,
                    p.t
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("warp-params select: {}", format_err(e));
            ExitCode::from(1)
        }
    }
}

fn cmd_validate(args: &[String]) -> ExitCode {
    let flags = match parse_flags(args) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("warp-params validate: {e}");
            return ExitCode::from(2);
        }
    };
    let (s, t, lambda, rate, field_bits, regime) = match (
        flags.s,
        flags.t,
        flags.lambda,
        flags.rate,
        flags.field_bits,
        flags.regime,
    ) {
        (Some(s), Some(t), Some(l), Some(r), Some(fb), Some(rg)) => {
            (s, t, SecurityLevel(l), r, fb, rg)
        }
        _ => {
            eprintln!(
                "warp-params validate: need --s, --t, --lambda, --rate, --field-bits, --regime"
            );
            return ExitCode::from(2);
        }
    };
    let params = Params { s, t };
    match inspect(&params, field_bits, rate.as_f64(), regime, lambda) {
        Ok(bound) => {
            println!(
                "proximity_bits={:.2} field_admissible={} ood_admissible={} meets_target={}",
                bound.proximity_bits,
                bound.field_admissible,
                bound.ood_admissible,
                bound.meets(lambda),
            );
            if bound.meets(lambda) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("warp-params validate: {}", format_err(e));
            ExitCode::from(1)
        }
    }
}

fn cmd_table() -> ExitCode {
    println!("lambda\trate\tregime\ts\tt");
    for preset in PRESETS {
        println!(
            "{}\t{}/{}\t{:?}\t{}\t{}",
            preset.lambda.bits(),
            preset.code_rate_num,
            preset.code_rate_den,
            preset.regime,
            preset.params.s,
            preset.params.t,
        );
    }
    ExitCode::SUCCESS
}

#[derive(Default)]
struct Flags {
    lambda: Option<u32>,
    rate: Option<Rate>,
    field_bits: Option<u32>,
    regime: Option<Regime>,
    s: Option<usize>,
    t: Option<usize>,
}

/// Parsed rate that remembers whether it was written as `num/den` or as
/// a decimal. Exact-rational form enables preset lookup.
#[derive(Clone, Copy)]
enum Rate {
    Ratio { num: u32, den: u32 },
    Float(f64),
}

impl Rate {
    fn as_f64(self) -> f64 {
        match self {
            Rate::Ratio { num, den } => num as f64 / den as f64,
            Rate::Float(x) => x,
        }
    }
    fn ratio(self) -> Option<(u32, u32)> {
        match self {
            Rate::Ratio { num, den } => Some((num, den)),
            Rate::Float(_) => None,
        }
    }
}

fn parse_flags(args: &[String]) -> Result<Flags, String> {
    let mut flags = Flags::default();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--lambda" => flags.lambda = Some(parse_u32(value)?),
            "--rate" => flags.rate = Some(parse_rate(value)?),
            "--field-bits" => flags.field_bits = Some(parse_u32(value)?),
            "--regime" => flags.regime = Some(parse_regime(value)?),
            "--s" => flags.s = Some(parse_u32(value)? as usize),
            "--t" => flags.t = Some(parse_u32(value)? as usize),
            other => return Err(format!("unknown flag: {other}")),
        }
    }
    Ok(flags)
}

fn parse_u32(s: &str) -> Result<u32, String> {
    s.parse()
        .map_err(|e| format!("expected u32, got `{s}`: {e}"))
}

fn parse_rate(s: &str) -> Result<Rate, String> {
    if let Some((num, den)) = s.split_once('/') {
        let n: u32 = num.parse().map_err(|e| format!("rate num `{num}`: {e}"))?;
        let d: u32 = den.parse().map_err(|e| format!("rate den `{den}`: {e}"))?;
        if d == 0 {
            return Err("rate denominator must be non-zero".into());
        }
        Ok(Rate::Ratio { num: n, den: d })
    } else {
        s.parse::<f64>()
            .map(Rate::Float)
            .map_err(|e| format!("rate `{s}`: {e}"))
    }
}

fn parse_regime(s: &str) -> Result<Regime, String> {
    match s.to_ascii_lowercase().as_str() {
        "provable" | "prov" => Ok(Regime::Provable),
        "conjectured" | "conj" => Ok(Regime::Conjectured),
        other => Err(format!(
            "unknown regime `{other}`, want `provable` or `conjectured`"
        )),
    }
}

fn format_err(e: ParamError) -> String {
    match e {
        ParamError::InvalidRate => "rate must be in (0, 1)".to_string(),
        ParamError::FieldTooSmall { field_bits, lambda } => {
            format!(
                "field is only {field_bits} bits; \
                 a target of {lambda} bits requires at least {} bits",
                lambda + warp::params::select::FIELD_EPSILON
            )
        }
        ParamError::OodSamplesTooFew { s, min } => {
            format!("OOD samples s = {s} is below minimum {min}")
        }
        ParamError::ProximitySoundnessBelowTarget {
            proximity_bits,
            target_bits,
        } => {
            format!(
                "proximity soundness {proximity_bits:.2} bits is below target {target_bits} bits"
            )
        }
    }
}
