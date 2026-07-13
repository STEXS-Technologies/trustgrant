# TrustGrant Interop Test Harness

Cross-implementation test vectors for the TrustGrant protocol.

## Structure

```
tests/
  interop/
    vectors/    — JSON test vectors (canonical location)
    interop.rs  — Rust test runner
  conformance/
    vectors/    — JSON conformance vectors
```

## Running

```bash
make interop
```

This runs:
- 29 interop vectors (evaluation scenarios, full Rust verification pipeline)
- 37 conformance vectors (spec validation rules)
- 54 conformance tests (Rust, spec sections §2.5–§12)

## Adding a vector

Create a new JSON file in `tests/interop/vectors/`. See existing vectors for format.
