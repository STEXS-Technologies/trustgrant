# TrustGrant Implementation Guide (for non-Rust languages)

This guide explains how to implement the TrustGrant protocol in another language
(Go, TypeScript, Python, etc.) using the interop and conformance test vectors.

## Overview

TrustGrant is a signed, selector-based delegation protocol. A minimal implementation
needs three components:

1. **Document parser** — parse the RawTrustGrantDocument JSON into native types
2. **Document validator** — validate structural rules (spec Sections 4-12)
3. **Evaluation engine** — evaluate authorization requests against a verified grant
   (spec Section 13)

The test vectors validate each component independently.

## Test vectors

```
tests/interop/vectors/      — 28 evaluation scenario vectors (language-agnostic)
tests/conformance/vectors/  — 36 spec validation rule vectors (language-agnostic)
```

### Conformance vectors (validation rules)

These test that the document parser + validator reject malformed documents
and accept valid ones. Format:

```json
{
  "spec_section": "5",
  "description": "target_scope all=true with non-null allow should be rejected",
  "overrides": {
    "target_scope": { "all": true, "allow": [...] }
  },
  "assert": { "validation": "rejected" }
}
```

To use them:
1. Start from a minimal valid document (see `Base document` below)
2. Apply the `overrides` to produce the test document
3. Parse and validate it
4. Assert the result matches `assert.validation`

The base document all conformance vectors inherit from:

```json
{
  "trustgrant_id": "tg_11111111-1111-4111-8111-111111111001",
  "version": 0,
  "grant_series_id": "tgs_11111111-1111-4111-8111-111111111001",
  "revision": 1,
  "supersedes": null,
  "supersession_policy": "coexist",
  "issuer_authority": "https://issuer.example.com",
  "origin_authority": "https://issuer.example.com",
  "active_owning_authority": "https://issuer.example.com",
  "key_id": "root-key-1",
  "target_scope": {
    "all": false,
    "allow": [{"kind": "authority", "all": false, "values": ["https://target.example.com"], "expressions": null}],
    "deny": null
  },
  "capabilities": { "recognize": true, "mint": false },
  "default_audience_scope": null,
  "resource_scope": {
    "types": {
      "item": {
        "all": false,
        "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
        "deny": null,
        "capabilities": { "recognize": null, "mint": null },
        "constraints": { "minting": { "max_total": null, "max_per_user": null }, "audience_scope": null },
        "operations": null
      }
    }
  },
  "global_constraints": {
    "time": { "not_before": "2026-04-07T12:00:00Z", "not_after": "2027-04-08T12:00:00Z" }
  },
  "revocation": {
    "revocable": true,
    "revocation_endpoint": "https://issuer.example.com/revocation"
  },
  "issued_at": "2026-04-07T12:00:00Z",
  "signature": "base64-signature",
  "issuer_principal": { "kind": "service", "id": "issuer-worker" }
}
```

### Interop vectors (evaluation scenarios)

These test that the evaluation engine produces correct authorization decisions.
Format:

```json
{
  "description": "matching recognize request — should be allowed",
  "trustgrant": { ... },
  "revocation_override": null,
  "evaluations": [
    {
      "description": "...",
      "request": {
        "operation": "recognize",
        "target_authority": "https://target.example.com",
        "audience_authority": "https://audience.example.com",
        "resource_type": "item",
        "resource_selectors": { "namespace": ["weapons"] },
        "evaluated_at": "2026-06-15T12:00:00Z",
        "mint_context": null
      },
      "setup": null,
      "expected": "Allowed"
    }
  ]
}
```

To use them:
1. Parse the trustgrant document and verify it (establish signer binding, check
   revocation, canonicalize, check signature)
2. For each evaluation, build an `EvaluationRequest` from the JSON
3. Run your evaluation engine
4. Assert the result matches `expected`

The `revocation_override` field tells you what revocation state to set:
- `null` or absent: grant is Active
- `"revoked"`: grant is Revoked
- `"non_revocable"`: grant is NonRevocable

The `setup` field on evaluations tells you to inject additional context:
- `null` or absent: no special setup
- `"add_audience_principal"`: before evaluating, insert audience principal
  selectors matching the grant's principal_scope

### Expression vectors

Conformance vectors with `"expression"` test predicate parsing:

```json
{
  "spec_section": "8",
  "description": "equals predicate matches exact string",
  "expression": {
    "predicate": "equals(\"foo\")",
    "match": ["foo"],
    "no_match": ["bar"]
  }
}
```

### Selector kind vectors

Conformance vectors with `"selector_kind"` test kind equality:

```json
{
  "spec_section": "7",
  "description": "built-in authority is case-insensitive",
  "selector_kind": { "a": "authority", "b": "AUTHORITY", "expect_equal": true }
}
```

## Implementation order

| Step | What | Tested by |
|------|------|-----------|
| 1 | Document JSON parser + type definitions | Conformance vectors (validation) |
| 2 | Document validation rules (§4-12) | Conformance vectors (validation) |
| 3 | Expression predicates (equals, startsWith, endsWith, contains) | Expression vectors |
| 4 | SelectorKind matching (built-in case-insensitive, others case-sensitive) | Selector kind vectors |
| 5 | Evaluation engine (spec §13 steps 1-11) | Interop vectors |
| 6 | Signature verification | Interop vectors (mock verifier) |

## Reference: Go harness

The reference implementation in `interop/go/interop_test.go` shows the minimal
scaffolding: read vector files, parse JSON, validate structure.

For a full implementation, write a test that — for each interop vector —
parses the trustgrant, runs the evaluation scenarios, and asserts the expected
outcomes. The Go test currently only validates structure because no Go
TrustGrant library exists yet. When one does, the evaluation assertions
slot directly into the existing test.

## Running your tests

```
# Rust (reference implementation)
make interop

# Go (structural validation only)
cd interop/go && go test ./...

# TypeScript (when impl exists)
cd interop/typescript && npx jest

# Validate that all three agree
make interop  # runs Rust + Go
```
