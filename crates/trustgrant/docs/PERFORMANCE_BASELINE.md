**Document Version:** 0.2\
**Last Updated:** 2026-07-13\
**Status:** Stable\
**Related Documents:**
[TrustGrant v0 Spec](TRUSTGRANT_V0_SPEC.md),
[TrustGrant Integration Guide](INTEGRATION_GUIDE.md)

# TrustGrant Performance Baseline

Current benchmark results for the v0 protocol core. All measurements are
median time per operation on an x86_64 Linux system with Rust 1.94.

## Benchmark scope

`cargo bench -p trustgrant --bench trustgrant_core` covers parsing,
validation, canonicalization, verification, and evaluation.

## Current numbers

### Parse

| Benchmark | Time |
|-----------|------|
| `raw_document_parse` | 2.19 µs |
| `authority_discovery_parse` | 1.36 µs |
| `delegated_principal_parse` | 665 ns |
| `revocation_proof_parse` | 186 ns |

### Verification

| Benchmark | Time |
|-----------|------|
| `validate_raw_document` | 965 ns |
| `canonicalize_document` | 736 ns |
| `verify_with_metadata` | 5.26 µs |
| `verify_with_proof_bundle` | 5.12 µs |
| `verify_with_ownership_chain` | 6.51 µs |
| `verify_ownership_transition` | 3.08 µs |

### Evaluation

| Benchmark | Time |
|-----------|------|
| `evaluate_verified_grant` | 23.3 ns |

### Selector parsing

| Benchmark | Time |
|-----------|------|
| `selector_expression_parse` | 173 ns |

## Hardware

Run on a modern x86_64 processor. Results will vary by hardware and
operating system. For precise comparisons, run the benchmarks on your
target hardware:

```bash
cargo bench -p trustgrant --bench trustgrant_core
```
