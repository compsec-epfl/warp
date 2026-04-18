# Convenience targets for Plan B (benchmarking + regression detection).
# Plan 0 / O deliverables are consumed via cargo directly — no make target
# needed.

.PHONY: help test clippy bench-wall bench-ci bench-ci-local bench-docker-build

help:
	@echo "Targets:"
	@echo "  test              cargo test (both feature configs)"
	@echo "  clippy            cargo clippy --all-targets --all-features"
	@echo "  bench-wall        criterion wall-time benches (runs anywhere)"
	@echo "  bench-ci          iai-callgrind instruction-count benches (Linux native)"
	@echo "  bench-ci-local    iai-callgrind benches inside Docker (macOS-friendly)"

test:
	cargo test
	cargo test --features profile

clippy:
	cargo clippy --all-targets -- -D warnings
	cargo clippy --all-targets --all-features -- -D warnings

bench-wall:
	cargo bench --bench warp_rs

# Native iai-callgrind bench. Requires valgrind + iai-callgrind-runner
# installed on the host. Will fail on macOS (valgrind is unsupported
# since Big Sur) — use `bench-ci-local` instead.
bench-ci:
	cargo bench --bench iai_phases

IAI_IMAGE := warp-iai-bench
IAI_CACHE := $(CURDIR)/target/iai-docker-cache

bench-docker-build:
	docker build -f benches/docker/Dockerfile.iai -t $(IAI_IMAGE) .

# Run the iai bench inside a Linux container. Mounts the repo read-write
# so the target/ dir (including bench output) is reused across runs.
# Caches cargo registry + git + target in host-side directories to avoid
# re-downloading arkworks on every invocation.
bench-ci-local: bench-docker-build
	mkdir -p $(IAI_CACHE)/registry $(IAI_CACHE)/git
	docker run --rm \
		-v $(CURDIR):/workspace \
		-v $(IAI_CACHE)/registry:/usr/local/cargo/registry \
		-v $(IAI_CACHE)/git:/usr/local/cargo/git \
		$(IAI_IMAGE)
