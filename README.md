# TrustGrant

A **selector-based, certificate-driven protocol** for decentralized delegation
of authority over resources and operations across independent systems.

One authority issues a signed grant allowing another authority to recognize
or mint resources under specific scopes, for specific audiences, under specific
constraints. Grants are revocable, time-bound, and verifiable offline.

## Quick example

This is a conceptual excerpt, not a complete signed v0 document. The full required wire
shape is in the [protocol spec](docs/TRUSTGRANT_V0_SPEC.md).

```json
{
  "trustgrant_id": "tg_550e8400-e29b-41d4-a716-446655440000",
  "issuer_authority": "https://issuer.example.com",
  "target_scope": { "allow": [{"kind": "authority", "values": ["https://partner.example.com"]}] },
  "capabilities": { "recognize": true, "mint": false },
  "signature": "base64(signature)"
}
```

## Repository structure

```
crates/
  trustgrant/               — Facade crate (re-exports everything)
  trustgrant-domain/        — Core domain types
  trustgrant-document/      — Document parsing, validation, normalization
  trustgrant-evaluate/      — Evaluation engine
  trustgrant-verify/        — Verification pipeline
  trustgrant-issue/         — Draft and issuance
  trustgrant-ownership/     — Ownership authority transitions
  trustgrant-discovery/     — Discovery document parsing
  trustgrant-revocation/    — Revocation state types
  trustgrant-ports/         — Backend-agnostic port traits
  trustgrant-error/         — Error types
tests/                      — Integration tests
  interop/vectors/          — Language-agnostic test vectors (29)
  conformance/vectors/      — Spec validation vectors (37)
docs/                       — Cross-implementation guide, use cases, tracing
kani-proofs/                — Kani formal verification harnesses
```

## Documentation

| Doc | What it covers |
|-----|----------------|
| [Protocol spec](docs/TRUSTGRANT_V0_SPEC.md) | Full specification, 14 sections |
| [Documentation index](docs/README.md) | Complete protocol, integration, and interoperability documentation |
| [Use cases](docs/USE_CASES.md) | What problems TrustGrant solves |
| [Implementation guide](docs/IMPLEMENTATION_GUIDE.md) | Implementing in other languages |
| [Error boundaries](docs/ERROR_BOUNDARIES.md) | Fatal vs recoverable errors |
| [Tracing guide](docs/TRACING_GUIDE.md) | Observability setup |
| [Crate README](crates/trustgrant/README.md) | Rust crate overview |

## Status

**v0.1.0** — Experimental. The protocol is intentionally expressive to explore
real-world needs before stabilizing v1.

## License

MIT OR Apache-2.0
