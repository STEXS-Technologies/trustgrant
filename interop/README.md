# TrustGrant Interop Test Harness

Cross-implementation test vectors for the TrustGrant protocol.

## Structure

```
interop/
  go/           — Go test harness (reads same vectors)
  vectors/      — shared JSON test vectors (symlinked from tests/interop/vectors/)
tests/
  interop/
    vectors/    — canonical vector location
    interop.rs  — Rust test runner
```

The canonical vector location is `tests/interop/vectors/`.
Go and other languages read from `interop/vectors/` (or reference the canonical path).

## Adding a vector

Create a new JSON file in `tests/interop/vectors/` with:

```json
{
  "description": "Human-readable name",
  "trustgrant": { /* full RawTrustGrantDocument */ },
  "evaluations": [
    {
      "description": "Scenario description",
      "request": {
        "operation": "recognize|mint|custom:name",
        "target_authority": "https://...",
        "audience_authority": "https://...",
        "resource_type": "item",
        "resource_selectors": { "namespace": ["weapons"] },
        "evaluated_at": "2026-06-15T12:00:00Z",
        "mint_context": { "total_minted": 0, "user_minted": 0 }
      },
      "expected": "Allowed" | { "Denied": "DenyReason" }
    }
  ]
}
```

## Running

Rust:
```
cargo test --test interop
```

Go (once impl exists):
```
cd interop/go && go test ./...
```
