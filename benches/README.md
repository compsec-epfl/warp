# Warp benches

Two bench suites with different roles:

| Bench                    | Signal                   | Scope                      | Cost             |
|--------------------------|--------------------------|----------------------------|------------------|
| `warp_rs` (criterion)    | Wall time, noisy         | Whole `prove` at 5 sizes   | Fast, informational |
| `iai_phases` (iai-callgrind) | Instruction count, deterministic | Whole `prove` at 1 size (v1)    | Slow, CI gate       |

The criterion suite is for local feedback — it reports wall time in
milliseconds, which is human-intuitive but varies across machines and
loads. It runs natively on any host.

The iai-callgrind suite is for **regression detection**. Callgrind counts
executed instructions, so the number is reproducible across CI runs. A
1% change is real signal. Plan B uses it as the PR gate.

## Running

### Criterion (works on macOS, Linux, Windows)

```bash
make bench-wall
# or
cargo bench --bench warp_rs
```

### iai-callgrind (native — requires valgrind)

```bash
cargo install iai-callgrind-runner --version 0.14.0
make bench-ci
# or
cargo bench --bench iai_phases
```

### iai-callgrind (macOS via Docker)

Valgrind hasn't worked on macOS since Big Sur, so on a Mac host run the
bench inside a Linux container:

```bash
make bench-ci-local
```

This builds `benches/docker/Dockerfile.iai` (cached after the first
run), mounts the repo read-write, and caches cargo registry + git in
`target/iai-docker-cache/` so subsequent runs don't re-download
arkworks. First run: ~5 min build + ~5 min bench. Later runs: ~30 s
build check + bench time.

## v1 scope

`iai_phases` currently benches **one** prove configuration
(`l1=4, s=2, t=7, hashchain=10`). Larger parameter points and
per-phase attribution are deferred — see the docstring at the top of
`iai_phases.rs` for why.

Baseline instruction counts are not yet committed; the plan is to
capture them in a follow-up once the CI workflow is wired up. See
`~/.claude/plans/nested-conjuring-scott.md` → Plan B for the full
roadmap, and the TODO about a GitHub Actions workflow.
