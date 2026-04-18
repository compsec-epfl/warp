# Warp paper-mods

Living spec of notation and structural modifications we make to the Warp paper
so that the paper's IOR decomposition and the Rust implementation agree
exactly. This is **not** a paper in its own right — it is a working document
tracking deltas from the published construction, each paired with the code
module that realises it.

## Scope

Warp is framed as an **IOP** (Ben-Sasson–Chiesa–Spooner 2016), **not** as an
AHP. Oracles are functions `f: [n] → F` queried by index under the BCS
compiler, with multilinear-extension semantics layered on top for point
queries. See `notation.tex` for the shared preamble and rationale.

## Convention

- One `.tex` file per modification, paired with one Rust module.
- Shared preamble lives in `notation.tex`; every `.tex` file `\input`s it.
- **Authoring order**: the `.tex` file is written *before* the code module.
  Code doc comments cite the `.tex` filename; `.tex` files cite the Rust
  module path. Drift is caught in code review.
- No CI compilation. Build locally with `latexmk -pdf mod1_oracle.tex`.

## Modification numbering (reserved)

| File                              | Modification                             | Owning plan |
|-----------------------------------|------------------------------------------|-------------|
| `mod1_oracle.tex`                 | Oracle as first-class IOR output         | Plan 0      |
| `mod2_structured_sumcheck.tex`    | Structured-sumcheck primitive            | Plan B'     |
| `mod3_accumulator_state.tex`      | Accumulator as explicit IOR state        | Plan C      |
| `mod4_parameter_selection.tex`    | Soundness-driven parameter selection     | Plan P      |

Future modifications take the next free number in sequence.

## Cross-reference lint

Each phase module's doc comment must name a `.tex` file in this folder. Each
`.tex` must name at least one Rust module path it pairs with. A manual check
is in the Plan 0 verification list; automation is Plan T's job.
