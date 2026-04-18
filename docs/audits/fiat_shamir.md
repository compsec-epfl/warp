# Fiat–Shamir audit

Status: **v1 manual audit**, current as of commit `9bf4f43`. Automated
runtime-ordering enforcement is deferred (see bottom).

## What this document is

An ordered, line-for-line mapping of every `prover_message(…)` /
`prover_messages(…)` call on the prover side to its matching
`prover_message()` / `prover_messages_vec(…)` call on the verifier
side, and similarly for every `verifier_message(…)` /
`verifier_messages_vec(…)` challenge squeeze.

A Fiat–Shamir soundness flaw typically has a simple shape: a challenge
is squeezed **before** some prover message that should have influenced
it. This document lets a reviewer walk both sides in order and satisfy
themselves that every squeeze happens after every absorb that should
determine it. It is the compensating control for us not yet having a
runtime harness that asserts this automatically.

## Transcript ordering

| Step | Prover call | File:line | Verifier call | File:line |
|------|-------------|-----------|---------------|-----------|
| 1. Index — public params | `public_message(description)` | [src/lib.rs:113](../../src/lib.rs#L113) | (via `public_message` domain-sep, no explicit read) | — |
| 2. Index — `m` | `prover_message(m)` | [src/lib.rs:114](../../src/lib.rs#L114) | `prover_messages_vec` (absorbed as part of `vk`) | via `index()` |
| 3. Index — `n` | `prover_message(n)` | [src/lib.rs:115](../../src/lib.rs#L115) | " | " |
| 4. Index — `k` | `prover_message(k)` | [src/lib.rs:116](../../src/lib.rs#L116) | " | " |
| 5. Fresh instances `x_i` | `absorb_instances` → `prover_message` loop | [src/protocol/transcript/prover.rs:14](../../src/protocol/transcript/prover.rs#L14) | `prover_messages_vec(instance_len)` loop | [src/protocol/transcript/verifier.rs:25](../../src/protocol/transcript/verifier.rs#L25) |
| 6. Accumulator `rt[i]` | `prover_message(bytes)` | [src/protocol/transcript/prover.rs:28](../../src/protocol/transcript/prover.rs#L28) | `prover_message() -> [u8;32]` loop | [src/protocol/transcript/verifier.rs:49](../../src/protocol/transcript/verifier.rs#L49) |
| 7. Accumulator `α[i]` | `prover_message` loop | [src/protocol/transcript/prover.rs:33](../../src/protocol/transcript/prover.rs#L33) | `prover_messages_vec(log_n)` loop | [src/protocol/transcript/verifier.rs:55](../../src/protocol/transcript/verifier.rs#L55) |
| 8. Accumulator `μ[i]` | `prover_message` | [src/protocol/transcript/prover.rs:38](../../src/protocol/transcript/prover.rs#L38) | `prover_messages_vec(l2)` | [src/protocol/transcript/verifier.rs:58](../../src/protocol/transcript/verifier.rs#L58) |
| 9. Accumulator `τ[i]` | `prover_message` loop | [src/protocol/transcript/prover.rs:43](../../src/protocol/transcript/prover.rs#L43) | `prover_messages_vec(log_m)` loop | [src/protocol/transcript/verifier.rs:61](../../src/protocol/transcript/verifier.rs#L61) |
| 10. Accumulator `x[i]` | `prover_message` loop | [src/protocol/transcript/prover.rs:49](../../src/protocol/transcript/prover.rs#L49) | `prover_messages_vec(instance_len)` loop | [src/protocol/transcript/verifier.rs:65](../../src/protocol/transcript/verifier.rs#L65) |
| 11. Accumulator `η[i]` | `prover_message` | [src/protocol/transcript/prover.rs:54](../../src/protocol/transcript/prover.rs#L54) | `prover_messages_vec(l2)` | [src/protocol/transcript/verifier.rs:68](../../src/protocol/transcript/verifier.rs#L68) |
| 12. PESAT — `rt₀` | `prover_message(root_bytes)` | [src/protocol/phases/pesat.rs:78](../../src/protocol/phases/pesat.rs#L78) | `prover_message() -> [u8;32]` | [src/protocol/transcript/verifier.rs:111](../../src/protocol/transcript/verifier.rs#L111) |
| 13. PESAT — `μ_i` | `prover_messages(&mus)` | [src/protocol/phases/pesat.rs:79](../../src/protocol/phases/pesat.rs#L79) | `prover_messages_vec(l1)` | [src/protocol/transcript/verifier.rs:115](../../src/protocol/transcript/verifier.rs#L115) |
| 14. PESAT — τ squeeze | `verifier_messages_vec::<F>(log_m)` × l1 | [src/protocol/phases/pesat.rs:82](../../src/protocol/phases/pesat.rs#L82) | `verifier_message::<F>()` × (l1 · log_m) | [src/protocol/transcript/verifier.rs:121](../../src/protocol/transcript/verifier.rs#L121) |
| 15. Twin-constraint — ω | `verifier_message()` | [src/protocol/phases/twin_constraint.rs:160](../../src/protocol/phases/twin_constraint.rs#L160) | `verifier_message::<F>()` | [src/protocol/transcript/verifier.rs:126](../../src/protocol/transcript/verifier.rs#L126) |
| 16. Twin-constraint — τ | `verifier_messages_vec::<F>(log_l)` | [src/protocol/phases/twin_constraint.rs:161](../../src/protocol/phases/twin_constraint.rs#L161) | `verifier_message::<F>()` × log_l | [src/protocol/transcript/verifier.rs:128](../../src/protocol/transcript/verifier.rs#L128) |
| 17. Twin-constraint — sumcheck | per round: coeffs absorbed, γ squeezed (inside `coefficient_sumcheck`) | [src/protocol/phases/twin_constraint.rs:202](../../src/protocol/phases/twin_constraint.rs#L202) | per round: `prover_messages_vec` coeffs, `verifier_message` γ | [src/protocol/transcript/verifier.rs:136](../../src/protocol/transcript/verifier.rs#L136) |
| 18. Post-TC — new root | `prover_message(td_root_bytes)` | [src/lib.rs:213](../../src/lib.rs#L213) | `prover_message() -> [u8;32]` | [src/protocol/transcript/verifier.rs:143](../../src/protocol/transcript/verifier.rs#L143) |
| 19. Post-TC — η | `prover_message(&eta)` | [src/lib.rs:214](../../src/lib.rs#L214) | `prover_message() -> F` | [src/protocol/transcript/verifier.rs:147](../../src/protocol/transcript/verifier.rs#L147) |
| 20. Post-TC — ν₀ | `prover_message(&nu_0)` | [src/lib.rs:215](../../src/lib.rs#L215) | `prover_message() -> F` | [src/protocol/transcript/verifier.rs:148](../../src/protocol/transcript/verifier.rs#L148) |
| 21. OOD — sample points | `verifier_messages_vec::<F>(s·log_n)` | [src/protocol/phases/ood.rs:35](../../src/protocol/phases/ood.rs#L35) | `verifier_message::<F>()` × (s · log_n) | [src/protocol/transcript/verifier.rs:154](../../src/protocol/transcript/verifier.rs#L154) |
| 22. OOD — answers | `prover_messages(&answers)` | [src/protocol/phases/ood.rs:41](../../src/protocol/phases/ood.rs#L41) | `prover_messages_vec(s)` | [src/protocol/transcript/verifier.rs:158](../../src/protocol/transcript/verifier.rs#L158) |
| 23. Proximity — query bytes | `verifier_messages_vec::<[u8;1]>(num_bytes)` via `QueryIndices::sample` | [src/protocol/query.rs:18](../../src/protocol/query.rs#L18) | `verifier_message::<[u8;1]>()` × num_bytes | [src/protocol/transcript/verifier.rs:166](../../src/protocol/transcript/verifier.rs#L166) |
| 24. Batching — ξ | `verifier_messages_vec::<F>(log_r)` | [src/protocol/phases/batching.rs:61](../../src/protocol/phases/batching.rs#L61) | `verifier_message::<F>()` × log_r | [src/protocol/transcript/verifier.rs:169](../../src/protocol/transcript/verifier.rs#L169) |
| 25. Batching — sumcheck | per round: `[a, b]` absorbed, α squeezed (inside `inner_product_sumcheck`) | [src/protocol/phases/batching.rs:93](../../src/protocol/phases/batching.rs#L93) | per round: `prover_messages() -> [F;2]`, `verifier_message()` α | [src/protocol/transcript/verifier.rs:176](../../src/protocol/transcript/verifier.rs#L176) |

## What every reviewer should spot-check

For each challenge squeeze, confirm that every prover message that
**defines** that challenge's semantic purpose has already been absorbed
above it. Examples:

- **τ challenges (step 14).** Squeezed after the PESAT root and fresh
  μ_i (steps 12–13). ✓ Both values determine which witness the prover
  committed to; binding τ to them is required so the prover can't pick
  τ after learning which witness is rejected.
- **ω challenge (step 15).** Squeezed after all prior PESAT state and
  after τ. ✓ ω linearly combines two claims; if the prover could pick
  ω *before* τ, they could cancel the two terms against a dishonest
  witness.
- **Shift-query bytes (step 23).** Squeezed after the new commitment
  `td_root_bytes`, η, ν₀, and the OOD answers (steps 18–22). ✓ The
  query index must be unpredictable relative to the committed oracle.
- **Batching-sumcheck α challenges (step 25).** Squeezed per round
  after each `[a, b]` is absorbed (inside the sumcheck). ✓ Standard.

## What is **not** in this table

- `domain_separator!("…")` invocations: those are audited via the
  domain-sep macro's own per-call string matching; if the same
  domainsep string is used on prover and verifier, the transcripts
  align. Rotate the string if the layout changes.
- `AccumulatorInstance::empty()` / `AccumulatorWitness::empty()`
  paths: these do nothing to the transcript, so they are
  unaudited here.

## Deferred — a runtime Fiat–Shamir harness

Plan T originally proposed a test that captures the ordered list of
`prover_message` / `verifier_message` calls during a prove, and
asserts it matches a golden sequence. That would make drift between
prover and verifier impossible to land undetected. Implementing it
requires instrumenting `spongefish::ProverState` (external crate), so
it's deferred. The current table is the compensating control; it is
*manually* regenerated when any file above changes.
