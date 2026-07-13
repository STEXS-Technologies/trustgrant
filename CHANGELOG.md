# Changelog

All notable changes to the TrustGrant protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — Unreleased

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
- Selector-based matching with built-in kinds (authority, namespace, player_id)
- Custom operation scope with allow/deny lists
- Audience scope with authority and principal constraints
- Mint constraints (max total, max per user)
- Compact string storage for optimized heap allocation (`compact-str`)
- UTF-16 code-unit ordering for canonical map keys (`Utf16Key`)
- 380+ unit and integration tests with 96.6% coverage
- 0 clippy warnings, 0 unsound patterns
- Profiling infrastructure (frame pointers, profiling profile, flamegraph Makefile targets)
- CI pipeline (GitHub Actions: check, clippy, fmt, test, bench, audit, fuzz, smoke)
