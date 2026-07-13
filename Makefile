# TrustGrant Protocol — Dev Commands
# ====================================
# Common targets for local development.
# `make ci` runs the same checks as GitHub Actions CI.

TOOLCHAIN ?= stable
PACKAGES := trustgrant-domain trustgrant-document trustgrant-error \
            trustgrant-issue trustgrant-evaluate trustgrant-verify \
            trustgrant-ownership trustgrant-discovery trustgrant-revocation \
            trustgrant-ports trustgrant

.PHONY: all build check test clippy fmt bench coverage audit fuzz ci \
        interop clean docs example-hot example-cold help

all: check test clippy fmt

# ── Build ──────────────────────────────────────────────────────────

build:
	cargo build --workspace

build-release:
	cargo build --release --workspace

check:
	cargo check --workspace --all-targets

# ── Test ───────────────────────────────────────────────────────────

test:
	cargo test --workspace

test-release:
	cargo test --workspace -- --include-ignored

test-failures:
	cargo test --workspace -- --show-output 2>&1 | grep -E "FAILED|panicked" || true

# ── Lint ───────────────────────────────────────────────────────────

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all -- --check

fmt-fix:
	cargo fmt --all

# ── Coverage ───────────────────────────────────────────────────────

coverage:
	cargo tarpaulin --packages $(PACKAGES) --skip-clean --out lcov

coverage-html:
	cargo tarpaulin --packages $(PACKAGES) --skip-clean --out html --output-dir target/coverage

# ── Benchmarks ─────────────────────────────────────────────────────

bench:
	cargo bench --workspace --exclude trustgrant-fuzz

bench-parse:
	cargo bench --bench trustgrant_core -- trustgrant_parse

bench-verify:
	cargo bench --bench trustgrant_core -- trustgrant_verification

bench-eval:
	cargo bench --bench trustgrant_core -- trustgrant_evaluation

# ── Profiles ───────────────────────────────────────────────────────

profile-build:
	cargo build --profile profiling --examples --benches

# Evaluate hot path: default 100M iterations, 10M is enough for profiling.
profile-eval: profile-build
	perf record --call-graph fp -F 999 \
		./target/profiling/examples/evaluate_hot_path-* 10000000

profile-canonicalize: profile-build
	perf record --call-graph fp -F 999 \
		./target/profiling/examples/canonicalize_cold_path-* 10000

profile-bench: profile-build
	perf record --call-graph fp -F 999 \
		./target/profiling/deps/trustgrant_core-* --bench

flamegraph:
	perf script | inferno-flamegraph > flamegraph.svg

# ── Fuzz ───────────────────────────────────────────────────────────

fuzz:
	cargo fuzz build --all

fuzz-run-%:
	cargo fuzz run $* -- -max_total_time=30

# ── Audit ──────────────────────────────────────────────────────────

audit:
	cargo audit

# ── Interop ─────────────────────────────────────────────────────────

interop:
	cargo test --test interop -p trustgrant -- --nocapture
	cargo test --test conformance_vectors -p trustgrant -- --nocapture
	cargo test --test conformance -p trustgrant -- --nocapture

# ── CI (matches GitHub Actions) ────────────────────────────────────

ci: check clippy fmt test bench
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  All CI checks passed!"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

ci-full: ci coverage audit fuzz
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  Full CI suite passed!"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Examples ───────────────────────────────────────────────────────

example-hot:
	cargo run --release --example evaluate_hot_path -- 1000000

example-cold:
	cargo run --release --example canonicalize_cold_path -- 1000

# ── Clean ──────────────────────────────────────────────────────────

clean:
	cargo clean

clean-deep:
	cargo clean
	rm -rf perf.data* flamegraph.svg target/coverage

# ── Docs ───────────────────────────────────────────────────────────

docs:
	cargo doc --workspace --no-deps

docs-open:
	cargo doc --workspace --no-deps --open

# ── Help ───────────────────────────────────────────────────────────

help:
	@echo "TrustGrant Protocol — Dev Commands"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  make build        — Build workspace"
	@echo "  make check        — Cargo check all targets"
	@echo "  make test         — Run all tests"
	@echo "  make clippy       — Lint with clippy"
	@echo "  make fmt          — Check formatting"
	@echo "  make fmt-fix      — Fix formatting"
	@echo "  make bench        — Run benchmarks"
	@echo "  make coverage     — Run tarpaulin (lcov)"
	@echo "  make ci           — check + clippy + fmt + test + bench"
	@echo "  make ci-full      — ci + coverage + audit + fuzz"
	@echo "  make audit        — Cargo audit"
	@echo "  make fuzz         — Build fuzz targets"
	@echo "  make profile-eval — Perf profile evaluate hot path"
	@echo "  make flamegraph   — Generate flamegraph from perf.data"
	@echo "  make docs         — Build docs"
	@echo "  make clean        — Clean build artifacts"
