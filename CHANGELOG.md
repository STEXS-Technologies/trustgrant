# Changelog

All notable changes to the TrustGrant protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-07-13

### Added

- TrustGrant v0 wire format (JSON + JCS canonicalization)
- Raw document parsing and validation
- Normalized grant types with scope, capability, and constraint validation
- Evaluation engine (recognize, mint, custom operations with scope+capability model)
- Authority and principal scope evaluation with selector expressions
- RFC 8785 JSON canonicalization for deterministic signing payloads
- Verification pipeline (parse → validate → canonicalize → signer binding → revocation → signature verification)
- Proof bundle assembly and resolution (discovery, revocation, ownership transitions)
- Ownership authority transition verification and chain validation
- Persistent verified grant records (serialization + rehydration + consistency checks)
- Revocation source policy (online/cached/offline posture, freshness windows)
- Discovery document parsing (authority keys, delegation, revocation policy)
- Delegated principal key resolution
- Backend-agnostic port traits: `DiscoverySource`, `RevocationSource`, `StorageSource`
- `tracing` instrumentation at key verification and evaluation decision points
- Selector-based matching with built-in kinds (authority, namespace, actor)
- Custom operation scope with allow/deny lists
- Audience scope with authority and principal constraints
- Mint constraints (max total, max per user)
- Compact string storage for optimized heap allocation (`compact-str`)
- UTF-16 code-unit ordering for canonical map keys (`Utf16Key`)
- 29 interop test vectors covering all 19 evaluation outcomes
- 37 conformance test vectors covering spec validation rules (§2.5–§12)
- 54 Rust conformance tests (spec sections)
- 14 formal property-based tests (deny subtractive, allow explicit, fail-closed, etc.)
- 2 Kani proof harnesses verifying selector matching core algorithm
- End-to-end test with real ed25519 signatures (full pipeline: draft → canonicalize → sign → verify → evaluate)
- 12 integration tests covering P1/P2/P3 gaps (capabilities, origin authority, edge cases, boundaries)
- Real signature verification e2e test
- Malformed vector test for runner defensive paths
- WASM build target (`wasm32-unknown-unknown`)
- Profiling infrastructure (frame pointers, profiling profile, flamegraph cargo-make targets)
- CI pipeline (check, clippy, fmt, test, bench, interop, audit, fuzz, smoke, coverage)

### Changed

- **Spec fix**: canonical example target scope kind `"authority_id"` → `"authority"` (Section 4)
- **Infrastructure-agnostic endpoints**: `revocation_endpoint` from `Url` to `CompactString` across all types, removing the `url` dependency from document and verify crates
- **Discovery endpoints**: `status_endpoint`, `principal_key_endpoint` from `Url` to `CompactString`
- **Performance**: direct datetime buffer write (−55% canonicalize), Utf16Key newtype (−55% canonicalize), compact_str for raw documents (−33% parse)
- **Origin authority constraint**: spec §13 step 3 now enforced in evaluation engine
- **Docs simplified**: README now concise with quick example, all P-number jargon removed
- **P0 protocol hardening (all 8 items)**:
  - Origin binding mandatory via `ResourceBinding` — every evaluation request binds to a resource
  - Atomic execution boundary (`MutationRequest`, `intent_id`, `expected_version`, `EvaluationOutcome`)
  - Race-safe mint quotas — authoritative counters injected by executor, `pub(crate)` API
  - Mint idempotency + supply semantics — `MintContext.with_quantity()`, engine checks `current + quantity > max`
  - Typed transaction envelope — `MutationRequest.actor`, `envelope_expires_at`, `intent_id` required
  - Selector provenance — `verify_selectors()` required before engine evaluation for mint ops
  - Post-revocation effect — `PostRevocationEffect` enum (`BlockAll`/`BlockMintingOnly`), wire-format optional
  - Remove implicit mint authorization — `operations=null` no longer allows mint, explicit `"create"` required
  - Remove `operations.all` wildcard — all operations must be explicitly listed in allow/deny
  - Reject duplicate audience authorities — `DuplicateAudienceAuthority` error on duplicate `authority_id`

### Fixed

- Spec canonical example: `"authority_id"` → `"authority"` in target scope selector
- EvaluationDenyReason Display impl: all 20 variants now tested
- Pre-existing clippy violations: 69 violations fixed across workspace
- Epoch timestamp test: multi-line JSON parsing quirk fixed
- All doc-tests: `rust,ignore` blocks made compilable or replaced with text

### Removed

- `url` dependency from `trustgrant-document`, `trustgrant-discovery`, `trustgrant-verify`
- Go interop harness (vectors remain, scaffolding gone — no Go TrustGrant library)
- Empty `[dev-dependencies]` section from `trustgrant-evaluate`

### Documentation

- `ERROR_BOUNDARIES.md` — classification of fatal vs recoverable errors
- `TRACING_GUIDE.md` — spans, events, and subscriber setup
- `IMPLEMENTATION_GUIDE.md` (interop) — cross-impl implementation order
- `AUDIT.md` — deep audit report (local-only)
- 17 Markdown documents and 2 schemas covering the specification, architecture,
  integration, and interoperability
