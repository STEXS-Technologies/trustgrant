# Contributing to TrustGrant

## Scope

This repository contains the TrustGrant protocol core — document types,
validation, evaluation engine, verification pipeline, and ownership
transitions. It does not contain HTTP backends, database adapters, or
application-specific logic.

## Pull requests

- PRs should target the `main` branch
- Every PR must pass CI: `make ci` (check, clippy, fmt, test, bench)
- For interop-impacting changes: `make interop` (vectors + conformance)
- For WASM-impacting changes: `cargo check --target wasm32-unknown-unknown`
- Commit messages follow conventional format:
  `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`, `refactor:`, `perf:`

## Testing

- `cargo test` — all unit + integration tests
- `cargo test --test interop` — 29 evaluation scenario vectors
- `cargo test --test conformance_vectors` — 37 validation vectors
- `cargo test --test conformance` — 54 spec section tests
- `cargo test --test property_tests` — 14 formal properties
- `cargo kani -p kani-proofs` — formal verification harnesses
- `cargo tarpaulin --packages ...` — coverage analysis

## Architecture

The protocol core is organized into crates under `crates/`:

- **trustgrant-domain** — Core domain types (AuthorityId, SelectorKind, etc.)
- **trustgrant-document** — JSON document parsing, validation, normalization
- **trustgrant-evaluate** — Hot-path evaluation engine
- **trustgrant-verify** — Cold-path verification pipeline
- **trustgrant-issue** — Draft and signable document construction
- **trustgrant-discovery** — Discovery document parsing and signer binding
- **trustgrant-revocation** — Revocation state management
- **trustgrant-ownership** — Ownership authority transition verification
- **trustgrant-ports** — Backend-agnostic trait boundaries
- **trustgrant-error** — Error types

The facade crate `trustgrant` re-exports all types for convenience.
Depend on individual crates for granular dependency management.

## Interop vectors

Language-agnostic test vectors live under `tests/interop/vectors/` and
`tests/conformance/vectors/`. These are JSON files that any implementation
can parse. Adding a new vector requires:
1. A JSON file with the test scenario
2. The Rust runner (`tests/interop.rs` or `tests/conformance_vectors.rs`)
   should automatically discover and validate it

## Style

- No `unsafe` code (enforced by `#![forbid(unsafe_code)]`)
- No `unwrap` or `expect` in production code (enforced by clippy)
- All public API surface documented with doc comments
- Error variants annotated with retry classification
