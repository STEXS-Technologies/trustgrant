# TrustGrant

A **selector-based, certificate-driven protocol** for decentralized delegation
of authority over resources and operations across independent systems.

One authority issues a signed grant allowing another authority to recognize
or mint resources under specific scopes, for specific audiences, under specific
constraints. Grants are revocable, time-bound, and verifiable offline.

## Quick example

This is a conceptual excerpt, not a complete signed v0 document. The full required wire
shape is in the [protocol spec](../../docs/TRUSTGRANT_V0_SPEC.md).

```json
{
  "trustgrant_id": "tg_550e8400-e29b-41d4-a716-446655440000",
  "issuer_authority": "https://issuer.example.com",
  "target_scope": { "allow": [{"kind": "authority", "values": ["https://partner.example.com"]}] },
  "capabilities": { "recognize": true, "mint": false },
  "resource_scope": { "types": { "item": { "allow": [{"kind": "namespace", "values": ["weapons"]}] }}},
  "signature": "base64(signature)"
}
```

## Protocol scope

This crate owns:
- Document types, validation, canonicalization
- Scope and capability evaluation
- Signature verification interfaces (trait-based, PQ-extensible)
- Discovery and revocation types
- Ownership authority transitions

It does not own:
- HTTP routing, database adapters, streaming

## Documentation

- [Protocol spec](../../docs/TRUSTGRANT_V0_SPEC.md) — full specification
- [Use cases](../../docs/USE_CASES.md) — what problems TrustGrant solves
- [Implementation guide](../../docs/IMPLEMENTATION_ARCHITECTURE.md) — crate architecture
- [Integration guide](../../docs/INTEGRATION_GUIDE.md) — how to use the Rust crate
- [Error boundaries](../../docs/ERROR_BOUNDARIES.md) — which errors are retryable
- [Tracing guide](../../docs/TRACING_GUIDE.md) — observability with tracing
- [Cross-impl interop](../../docs/IMPLEMENTATION_GUIDE.md) — implementing in Go, TS, etc.
