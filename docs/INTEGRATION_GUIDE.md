**Document Version:** 0.2\
**Last Updated:** 2026-07-14\
**Status:** Draft\
**Related Documents:** [TrustGrant v0 Spec](TRUSTGRANT_V0_SPEC.md),
[TrustGrant Authority Discovery](TRUSTGRANT_AUTHORITY_DISCOVERY.md),
[TrustGrant Ownership Authority Transitions](OWNERSHIP_AUTHORITY_TRANSITIONS.md),
[TrustGrant Implementation Architecture](IMPLEMENTATION_ARCHITECTURE.md)

# TrustGrant Integration Guide

This guide explains the intended TrustGrant crate integration path for one adopter.

The design goal is:
- issue one TrustGrant without handcrafting large JSON payloads
- verify one TrustGrant once
- persist one normalized verified record
- evaluate that verified record many times without reparsing JSON

TrustGrant stays runtime-agnostic:
- no required HTTP transport
- no required storage engine
- no required cryptography backend
- no required networked discovery backend inside the crate

Those deployment concerns stay in adapters around the protocol core.

* * *

## 1. Happy Path Overview

Recommended integration flow:

1. Build one issuer-side draft with `TrustGrantDraft`
2. Canonicalize the signable draft bytes
3. Sign those canonical bytes with deployment-selected cryptography
4. Finalize one signed raw TrustGrant document
5. Verify it with `VerificationPipeline`
6. Convert the verified result into `VerifiedTrustGrantRecord`
7. Persist that record in the adopter's verified-grant registry
8. Rehydrate `VerifiedTrustGrant` from the record for hot-path evaluation
9. Evaluate requests with `EvaluationEngine`

Cold path:
- draft creation
- canonicalization
- signature verification
- discovery / revocation / ownership proof resolution
- persistence serialization

Hot path:
- load one previously verified record
- rehydrate normalized verified state
- evaluate one request

The hot path must not reparse raw JSON.

Current v0 core note:
- `EvaluationRequest::new(...)` populates both `authority` and `authority_id` selector
  aliases for target and audience authority contexts
- this is a compatibility helper for common v0 issuer vocabularies, not a global
  selector registry
- outside that narrow helper, operation names and principal kinds remain exact validated
  tokens with no general aliasing or case-folding; the built-in selector kinds
  `authority`, `namespace`, and `actor` are case-insensitive

* * *

## 2. Issue One TrustGrant

Use `TrustGrantDraft` for issuer-side assembly.

`TrustGrantDraft` is intended for:
- protocol ID generation
- lineaged v0 issuance
- canonical signable payload construction

It is not intended to replace a full product-side issuance workflow.
It is the crate-level primitive for compliant issuer tooling.

The draft helper rejects several invalid issuer-side states early instead of waiting
until later validation, including:
- first revision combined with `supersedes`
- self-supersession
- inverted global time windows

Example:

```rust
use std::collections::BTreeMap;

use chrono::Utc;
use trustgrant::{
    TrustGrantDraft, TrustGrantDraftAuthorities,
};
use trustgrant::document::raw::{
    RawCapabilities, RawMintingConstraints, RawResourceScope, RawResourceType, RawScope,
    RawSelector, RawTypeCapabilities, RawTypeConstraints,
};
use trustgrant::domain::Utf16Key;

let mut resource_types = BTreeMap::new();
resource_types.insert(
    Utf16Key::new("item"),
    RawResourceType::new(
        false,
        Some(vec![RawSelector::values(
            "namespace",
            vec!["weapons".into()],
        )]),
        None,
        RawTypeCapabilities::new(Some(true), Some(false)),
        RawTypeConstraints::new(
            RawMintingConstraints::new(Some(10), Some(1)),
            None,
        ),
        None,
    ),
);

let draft = TrustGrantDraft::new(
    TrustGrantDraftAuthorities::self_owned("https://issuer.example.com")?,
    "root-key-1",
    RawScope::allow(vec![RawSelector::values(
        "authority",
        vec!["https://target.example.com".into()],
    )]),
    RawCapabilities::new(true, false),
    RawResourceScope::new(resource_types),
    Utc::now(),
)?;
```

What this gives the issuer:
- generated `trustgrant_id`
- generated `grant_series_id`
- revision `1`
- a typed draft that can become canonical signable bytes

* * *

## 3. Canonicalize And Sign

Protocol rule:
- the `signature` field is excluded from the signed canonical payload

Current crate-level draft tooling represents that signable payload as one raw TrustGrant
document whose `signature` field is empty before finalization.
That empty field is an issuance-helper representation, not the protocol rule itself.

Use:
- `draft.signable_document()?`
- `draft.canonical_bytes()?`

Example:

```rust
let canonical_bytes = draft.canonical_bytes()?;
let signature = sign_with_ed25519(canonical_bytes.as_slice());
let signed_document = draft.into_signed_document(signature)?;
let json = signed_document.to_json_string()?;
```

Important rule:
- issuers sign the canonical bytes, not arbitrary pretty-printed JSON
- verifiers recompute canonical bytes under the same exclusion rule and verify the
  published `signature` against those bytes

If issuer tooling wants to publish or transport JSON, it should serialize the finalized
signed raw document after signing.

* * *

## 4. Verify One TrustGrant

TrustGrant supports two main verification styles.

### 4.1 Metadata-Driven Verification

Use this when the adopter already resolved:
- signer binding
- ownership verification state
- revocation verification state

Example:

```rust
use trustgrant::{
    VerificationMetadata, VerificationPipeline,
};

let artifacts = VerificationPipeline::new()
    .verify_json_bytes(document_bytes, &signature_verifier, verification_metadata)?;

let verified_grant = artifacts.verified_grant();
```

This is useful when:
- the surrounding system already manages discovery caches
- revocation checks happen elsewhere
- ownership proof chains were already resolved

### 4.2 Source-Driven Verification

Use this when the pipeline should resolve proof inputs through adapter-facing ports.

Example:

```rust
use trustgrant::{
    VerificationContext, VerificationPipeline, VerificationPosture,
    VerificationSources,
};

let artifacts = VerificationPipeline::new().verify_json_bytes_with_sources(
    document_bytes,
    &signature_verifier,
    VerificationSources::new(discovery_source, revocation_source, ownership_source),
    VerificationContext::new(verified_at, VerificationPosture::Online),
)?;
```

Important rule:
- `VerificationSources::new(...)` expects one already-selected proof-source set
- it does not merge multiple discovery mirrors or reconcile conflicting proof inputs
- if the adopter has several possible sources, adapter code must arbitrate first and
  then pass the final source set into the TrustGrant core

### 4.3 Proof-Bundle Convenience Path

Use this when one shared bundle object can act as:
- discovery source
- revocation source
- ownership-transition source

Example:

```rust
use trustgrant::{
    TrustGrantProofBundle, VerificationContext, VerificationPipeline,
    VerificationPosture,
};

let mut bundle = TrustGrantProofBundle::new();
bundle.insert_discovery_document(discovery_document)?;
bundle.insert_revocation_proof(revocation_proof)?;
bundle.insert_ownership_transition_chain(trustgrant_id, transition_chain)?;

let artifacts = VerificationPipeline::new().verify_json_bytes_with_bundle(
    document_bytes,
    &signature_verifier,
    &bundle,
    VerificationContext::new(verified_at, VerificationPosture::Online),
)?;
```

This is the simplest crate-level end-to-end integration path for one adopter.

The same bundle can also be passed explicitly as sources:

```rust
let artifacts = VerificationPipeline::new().verify_json_bytes_with_sources(
    document_bytes,
    &signature_verifier,
    bundle.as_sources(),
    VerificationContext::new(verified_at, VerificationPosture::Online),
)?;
```

* * *

## 5. Persist Verified State

Do not persist raw JSON as the hot-path authorization representation.

Recommended persistence split:
- optional raw signed JSON for audit / re-export
- `VerifiedTrustGrantRecord` for runtime loading and repeated evaluation

`VerifiedTrustGrantRecord` carries an explicit persistence format version.
Treat it as a versioned storage contract, not as an ad hoc serde blob.

Important lifecycle rule:
- rehydrating `VerifiedTrustGrantRecord` is not a blind deserialize
- the current core re-checks normalized document and metadata consistency on import
- tampered signer binding, ownership metadata, or posture/revocation combinations fail
  closed during rehydrate
- unknown persisted-record fields are rejected during deserialize/import

Example:

```rust
use trustgrant::VerifiedTrustGrantRecord;

let record = VerifiedTrustGrantRecord::from(artifacts.verified_grant());
persist_verified_record(&record)?;
```

`VerifiedTrustGrantRecord` is intended to be:
- serialization-friendly
- detached from transport-specific concerns
- reconstructible into `VerifiedTrustGrant`
- treated as one opaque persisted record, not as a tree of public helper DTOs
- versioned explicitly for durable storage and future migration handling

It is not STEXS-specific.
It is the generic persistence-facing verified-record contract for TrustGrant adopters.

* * *

## 6. Rehydrate And Evaluate

Runtime evaluation should load the persisted verified record, rehydrate it, and evaluate
directly on normalized verified state.

Example:

```rust
use trustgrant::{
    EvaluationEngine, EvaluationRequest, RequestedCapability, RequestedOperation,
    ResourceBinding, ResourceContext, ResourceRef, VerifiedTrustGrantRecord,
};

let record: VerifiedTrustGrantRecord = load_verified_record()?;
let verified_grant = record.try_into_verified_grant()?;

let resource = ResourceContext::new("item")?;
let request = EvaluationRequest::new(
    RequestedOperation::Capability(RequestedCapability::Recognize),
    ResourceBinding::Existing(ResourceRef::new(
        origin_authority,
        "resource-42".to_owned(),
    )),
    target_authority,
    audience_authority,
    resource,
    evaluation_time,
)?;

let decision = EvaluationEngine::new().evaluate(&verified_grant, &request);
```

This is the key architectural payoff:
- no raw JSON parsing on the hot path
- no signature verification on the hot path
- no discovery lookups on the hot path
- no revocation fetches on the hot path

The verifier does the expensive work once.
The evaluator consumes normalized state many times.

* * *

## 7. Minimal Adapter Responsibilities

Every adopter must still provide:

- one signature verifier implementation
- one policy for online / cached / offline posture
- one storage strategy for verified records

If source-driven verification is used, the adopter must also provide:
- one authority discovery source
- one revocation proof source
- one ownership-transition proof source

Posture rule:
- `Online` may use live revocation evidence from the active source profile
- `Cached` and `Offline` must use non-live revocation evidence such as signed snapshots,
  proof bundles, or other trusted cached material

Current v0 core note:
- snapshot-like evidence is represented explicitly through source kinds such as
  `snapshot` and `proof_bundle`
- direct live resolver evidence, including live API or live chain-state style inputs, is
  treated as live-source evidence and is rejected for `Cached` and `Offline`

The crate intentionally does not hardcode:
- HTTP clients
- database choices
- caching choices
- job scheduling
- service discovery

That keeps TrustGrant portable across deployments.

* * *

## 8. Recommended First Integration

For a first adoption pass, the simplest path is:

1. build grants with `TrustGrantDraft`
2. sign canonical bytes with one deployment-specific signing backend
3. verify with `VerificationPipeline`
4. persist `VerifiedTrustGrantRecord`
5. evaluate with `EvaluationEngine`

Only after that should an adopter add:
- discovery fetch adapters
- revocation refresh schedulers
- ownership-transition chain stores
- registry indexing and lineage projections

This keeps the first integration understandable and hard to misuse.

* * *

## Review & Maintenance

- **Last Reviewed:** 2026-07-14
- **Next Review:** When the issuer or persistence-facing TrustGrant API changes
  materially
- **Change Log:**
  - v0.2 (2026-07-14): Corrected the issuer-side example imports and raw resource-map
    key type, and documented built-in selector-kind matching precisely.
  - v0.1 (2026-04-08): Added the first crate-local integration guide covering issue,
    verify, persist, and hot-path evaluation
