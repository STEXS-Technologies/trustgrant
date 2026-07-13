**Document Version:** 0.1\
**Last Updated:** 2026-04-08\
**Status:** Draft\
**Owner:** CTO (Wladimir Trubizin)\
**Related Documents:** [TrustGrant v0 Spec](TRUSTGRANT_V0_SPEC.md),
[TrustGrant Interoperability and Proof Models](INTEROPERABILITY_AND_PROOF_MODELS.md),
[TrustGrant Integration Guide](INTEGRATION_GUIDE.md)

# TrustGrant Baseline Interoperability Profile

## 1. Purpose

TrustGrant v0 keeps selector kinds, principal kinds, and service-defined operation names
open.

That makes the core expressive, but it also means two independent deployments will not
automatically interoperate unless they agree on exact token conventions.

This document defines one baseline interoperability profile for adopters that want
portable behavior without inventing a private vocabulary from scratch.

It is intentionally narrow:
- exact tokens only
- lowercase `snake_case` for shared selector and principal-kind names
- no general aliasing
- no case-folded matching

## 2. Profile Name

Recommended profile name:

```text
trustgrant-baseline-v0
```

Deployments may publish or negotiate another profile name, but if they claim this
baseline profile they should keep the exact token set below.

## 3. Authority and Audience Tokens

### 3.1 Authority Selector

Canonical profile token:

```text
authority_id
```

Semantics:
- target authority selector
- audience authority selector
- exact `authority_id` string comparison

Current v0 helper note:
- `EvaluationRequest::new(...)` also populates `authority`
- that alias exists as a narrow compatibility helper for common v0 issuers
- baseline-profile documents should still prefer `authority_id`

### 3.2 Audience Entry

Audience entries use the machine-contract field:

```text
authority_id
```

That field is already part of the signed wire shape and should not be renamed or
profiled into another field name.

## 4. Resource Selector Tokens

Recommended shared resource selector kinds:

- `id`
- `namespace`
- `project`
- `tag`

Semantics:
- all are exact validated tokens
- values are exact string matches unless expressions are used
- if deployments want portable meaning for these selectors, they should use the exact
  spellings above

## 5. Audience Principal Tokens

Recommended shared principal-scope selector kinds:

- `player_id`
- `user_id`
- `service_id`
- `organization_id`

These are selector kinds used inside `principal_scope`, not a closed subject taxonomy
for every deployment.

If a deployment wants a narrower contract, it should publish that explicitly as its own
profile variant.

## 6. Delegated Signer Principal Kinds

Recommended shared delegated signer `issuer_principal.kind` values:

- `service`
- `project`
- `tenant`
- `organization`

Rules:
- exact lowercase tokens
- no case-folding
- no general aliasing such as `Service`, `svc`, or `org`

## 7. Operation Naming

Built-in names remain:
- `recognize`
- `create`

Custom operations in this baseline profile should use one of:
- lowercase `snake_case`
- lowercase dotted namespaces such as `asset.download`

Examples:
- `asset.download`
- `asset.preview`
- `item.transfer`
- `order.refund`

Non-examples:
- `Asset.Download`
- `assetDownload`
- `downloadAsset`

The core treats those as different exact tokens.

## 8. Signature and Canonicalization

Recommended shared signing profile:

```text
format           = jcs+ed25519
canonicalization = RFC8785
```

Deployments that want this baseline profile should not silently mix other
canonicalization or signing-profile identifiers.

## 9. Verification Posture Expectations

Recommended baseline verifier posture expectations:
- `Online` may use live revocation evidence from the active source profile
- `Cached` requires non-live evidence with bounded freshness
- `Offline` requires non-live evidence and fail-closed behavior on stale proof

These posture rules are already aligned with the current v0 core.

## 10. Non-Goals

This baseline profile does not standardize:
- one universal subject taxonomy
- one non-HTTP authority resolver format
- multisig or threshold signer proof formats
- one marketplace or asset schema
- one global operation registry

Those remain deployment or ecosystem profile concerns.

## 11. Adoption Guidance

If two independent systems want predictable interoperability, they should agree in
writing on:
- the profile name
- exact selector tokens they will emit
- exact principal kinds they will emit
- exact custom operation names they will honor
- exact signature profile they expect

If they do not, the TrustGrant core will still verify documents, but runtime
authorization may fail closed because exact token matching will not line up.

## Review & Maintenance

- **Last Reviewed:** 2026-04-08
- **Next Review:** When a second concrete interoperability profile is added
- **Change Log:**
  - v0.1 (2026-04-08): Added a concrete baseline interoperability profile with exact
    selector, principal-kind, operation, and signature-profile conventions
