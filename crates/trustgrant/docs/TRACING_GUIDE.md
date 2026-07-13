# TrustGrant Tracing Guide

## Overview

The protocol core emits `tracing` events and spans at key decision points.
These are always compiled in but zero-cost when no subscriber is registered.

## Spans

| Span name | Location | Fields | When |
|-----------|----------|--------|------|
| `verify` | `verify_impl()` | `trustgrant_id` | Per verification call |
| `evaluate` | `evaluate()` | `trustgrant_id`, `operation` | Per evaluation call |

## Events

| Event name / level | Location | Fields | Meaning |
|-------------------|----------|--------|---------|
| `info!("verified")` | pipeline.rs | `trustgrant_id` | Grant verification succeeded |
| `debug!("canonicalized")` | pipeline.rs | `trustgrant_id` | Document canonicalized |
| `debug!("metadata_consistent")` | pipeline.rs | `trustgrant_id` | Metadata checks passed |
| `debug!("signature_verified")` | pipeline.rs | `trustgrant_id` | Cryptographic signature passed |
| `debug!("allowed")` | engine.rs | `trustgrant_id`, `operation` | Evaluation allowed |
| `debug!(reason = ?Revoked)` | engine.rs | `trustgrant_id`, `operation`, `reason` | Grant is revoked |
| `debug!(reason = ?NotYetValid)` | engine.rs | `trustgrant_id`, `operation`, `reason` | Evaluation before window start |
| `debug!(reason = ?Expired)` | engine.rs | `trustgrant_id`, `operation`, `reason` | Evaluation after window end |
| `debug!(reason = ?ResourceTypeNotGranted)` | engine.rs | `trustgrant_id`, `operation`, `reason` | Resource type not in grant |
| `debug!(?reason)` | engine.rs | `trustgrant_id`, `operation`, `reason` | Scope or resource evaluation denied |
| `trace!(kind, "matched")` | engine.rs | `kind` | Selector comparison matched |
| `trace!(kind, "not_matched")` | engine.rs | `kind` | Selector comparison did not match |

## Subscribing

Example subscriber setup (add to your application's main):

```rust,ignore
use tracing_subscriber;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("trustgrant=debug")
        .init();
    // ...
}
```

## Filtering

- `trustgrant=debug` — verification steps and evaluation decisions
- `trustgrant=trace` — selector-level matching details (very verbose)
- `trustgrant=info` — successful verification completions only
- `off` — disable all trustgrant tracing
