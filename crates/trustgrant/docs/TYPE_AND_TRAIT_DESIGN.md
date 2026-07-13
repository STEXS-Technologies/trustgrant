**Document Version:** 0.7\
**Last Updated:** 2026-04-08\
**Status:** Draft\
**Owner:** CTO (Wladimir Trubizin)\
**Related Documents:** [TrustGrant Crate Docs](README.md),
[TrustGrant v0 Spec](TRUSTGRANT_V0_SPEC.md),
[TrustGrant Interoperability and Proof Models](INTEROPERABILITY_AND_PROOF_MODELS.md),
[TrustGrant Implementation Architecture](IMPLEMENTATION_ARCHITECTURE.md)

# TrustGrant Type and Port Design

## 1. Purpose

This document translates the TrustGrant protocol requirements into the concrete type and
port surfaces the `trustgrant` crate exposes and the nearby surfaces it should grow
next.

It exists to keep the implementation boundary precise now that parser, verifier, and
evaluation logic are already present in the crate.

## 2. Design Rules

The crate should follow these rules:
- exact document identity and logical lineage must be separate types
- verifier logic must consume validated and verified protocol state, not raw JSON
- transport-specific concerns must stay outside the crate
- proof-source resolution must be abstracted from transport
- typed subjects and authorities must replace loose strings where practical
- exact `trustgrant_id` evaluation must remain the default runtime rule
- owning-authority lineage must be representable separately from exact grant lineage
- raw parsing should prefer borrowed representations until normalization requires
  ownership
- hot-path evaluation should prefer concrete types and compact normalized state over
  flexible but allocation-heavy representations

For the first v0 implementation, owned raw-wire parsing is still acceptable when it
keeps the protocol pipeline simpler and more auditable.
Borrowed/raw-buffer parsing should be adopted only when benchmarks justify the added
complexity and the canonicalization path remains straightforward.

## 3. Core Value Types

The first implementation pass should introduce value objects at least for:

- `TrustGrantId`
  - exact signed document identity
- `GrantSeriesId`
  - stable lineage identity across revisions
- `Revision`
  - monotonic revision number inside one lineage
- `AuthorityId`
  - globally unique authority identifier
- `OwnershipAuthorityTransitionId`
  - identity of one ownership-authority transition record
- `KeyId`
  - signing-key identifier
- `ResourceType`
  - protocol-visible resource category
- `OperationName`
  - protocol-visible operation identifier
- `PrincipalKind`
  - typed delegated-principal category
- `PrincipalId`
  - delegated-principal identifier

These should be newtypes or explicit enums, not loose strings in downstream logic.

Where performance matters, these types should also be chosen to:
- minimize repeated allocation
- make equality and lookup cheap
- avoid hidden clones in hot-path evaluation

## 4. Authority Model Types

The type system should distinguish:
- authority identity
- authority scheme
- authority discovery material
- signer proof material
- ownership authority over a canonical resource lineage

Suggested conceptual types:

```rust
struct AuthorityId;

enum AuthorityScheme {
    Https,
    Did,
    Chain,
    Other,
}

struct AuthorityDiscoveryDocument;
struct AuthorityKeyRecord;
struct SignatureProfile;
struct OwnershipAuthorityRef;
```

The key point is that `AuthorityId` is not "just an HTTPS URL", even if HTTPS remains
the common case.

The type should also make the scheme inspectable without forcing reparsing in every
hot-path check.

The model should also make it possible to distinguish:
- original issuing authority for a historic grant
- currently active owning authority for the canonical lineage
- successor authority after a valid transfer

## 5. Subject Model Types

Cross-runtime interoperability requires a typed subject model.

Current v0 core directly models:
- delegated signer identity through `PrincipalKind` and `PrincipalId`
- issuer-defined selector kinds for resource and audience filtering

Future conceptual types may widen that into:

```rust
struct SubjectRef {
    kind: SubjectKind,
    id: SubjectId,
    authority_id: Option<AuthorityId>,
}

enum SubjectKind {
    Standard(StandardSubjectKind),
    Custom(Box<str>),
}

enum StandardSubjectKind {
    User,
    Wallet,
    Contract,
    Service,
    Organization,
    Group,
}
```

The protocol must still allow issuer-defined subject kinds, but the current v0 core does
not yet ship one standardized cross-profile subject taxonomy.

Raw parsed subject data may borrow from the input document.
Verified normalized subject data should own only what is needed for repeated evaluation.

## 6. Document Lifecycle Types

The implementation should encode stage transitions explicitly:

```rust
struct RawTrustGrantDocument;
struct ValidatedTrustGrantDocument;
struct VerifiedTrustGrant;
```

And the verified form should preserve:
- `trustgrant_id`
- `grant_series_id`
- `revision`
- `supersedes`
- `supersession_policy`
- `origin_authority`
- `active_owning_authority`
- normalized scopes, constraints, and operations
- signature/discovery/revocation metadata needed for audit and cache freshness

## 7. Supersession Types

The lineage model should be explicit in types rather than spread across ad hoc fields.

Suggested conceptual types:

```rust
enum SupersessionPolicy {
    Coexist,
    SupersedePrevious,
}

struct GrantLineage {
    series_id: GrantSeriesId,
    revision: Revision,
    supersedes: Option<TrustGrantId>,
    supersession_policy: SupersessionPolicy,
}
```

Lineage metadata should be normalized once and then reused rather than re-derived during
hot-path evaluation.

Ownership-authority lineage should also be modeled explicitly rather than hidden inside
ad hoc metadata.

Suggested conceptual types:

```rust
struct OwnershipAuthorityTransition {
    transition_id: OwnershipAuthorityTransitionId,
    canonical_lineage_id: GrantSeriesId,
    from_authority: AuthorityId,
    to_authority: AuthorityId,
}
```

The exact final type names may change, but the implementation should make ownership
transfer a first-class concept rather than a side-effect buried in platform code.

## 8. Proof-Source Types

The crate should model proof-source categories without binding them to one transport.

Suggested conceptual types:

```rust
enum ProofSourceKind {
    Api,
    Snapshot,
    ProofBundle,
    ChainState,
    Other,
}

struct FreshnessPolicy;
struct FinalityRequirement;
struct VerificationPosture;
```

These types should let consumers express:
- online verification
- cached verification
- offline verification
- proof freshness requirements
- chain or distributed-state finality requirements

They should also make it explicit whether a verifier is allowed to proceed without
network access or fresh proof acquisition.

## 9. Trait Surface Principles

The crate should expose traits for protocol inputs, not for application-layer
orchestration.

The important port categories are:
- authority resolution
- discovery retrieval
- delegated principal key resolution
- signer proof resolution
- revocation proof resolution
- ownership-authority transition proof resolution
- clock/time access
- finality evaluation

The exact async representation is still an implementation choice.
It may use async traits, associated futures, or another zero-cost design that fits the
repo standards. That choice should be made when implementation starts, not guessed here.

The performance rule is:
- proof acquisition may use flexible adapter boundaries
- evaluation over `VerifiedTrustGrant` should avoid paying dynamic-dispatch cost unless
  that tradeoff is explicitly chosen

## 10. Conceptual Traits

The expected responsibilities are:

```rust
trait AuthorityDiscoverySource {
    // Return authenticated discovery material for an authority.
}

trait RevocationProofSource {
    // Resolve revocation state from the active proof source model.
}

trait OwnershipTransitionProofSource {
    // Resolve and validate ownership-authority transition proofs for canonical lineages.
}

trait Clock {
    // Supply current time for deterministic verification.
}

trait FinalityPolicy {
    // Decide whether proof freshness/finality is sufficient.
}
```

These ports should not:
- own HTTP clients
- own SQL access
- own cache implementations
- assume chain access is "just another HTTP GET"

Current v0 core directly exposes:
- `AuthorityDiscoverySource`
- `RevocationProofSource`
- `OwnershipTransitionProofSource`
- `SignatureVerifier`
- `DiscoverySource` — raw fetch layer for discovery documents (application-level, optional)
- `RevocationSource` — raw revocation status check (application-level, optional)
- `StorageSource` — persist and load verified grants (application-level, optional)

The three application-level traits (`DiscoverySource`, `RevocationSource`, `StorageSource`)
are optional — the protocol core never calls them directly. They exist so that applications
fetching from authority endpoints have a standard interface instead of each one inventing
their own `trait MyHttpFetcher`.

It does not yet expose separate built-in ports for:
- non-HTTP authority resolution
- native multisig or contract-signer proof aggregation

## 11. Evaluation Types

The runtime evaluation engine should be driven by explicit request/decision types.

Suggested conceptual shapes:

```rust
struct EvaluationRequest;

enum EvaluationDecision {
    Allow,
    Deny(EvaluationDenyReason),
}

enum EvaluationDenyReason {
    GrantNotFound,
    GrantInactive,
    Revoked,
    TargetMismatch,
    AudienceMismatch,
    CapabilityDenied,
    OperationDenied,
    ResourceMismatch,
    ConstraintViolation,
    ProofInsufficient,
}
```

The deny reason type is important because distributed and offline verification failures
need to be distinguishable from ordinary scope denial.

It is also useful for fast-fail behavior and performance-sensitive observability.

## 12. Normalized Verified State

`VerifiedTrustGrant` should be designed as the canonical hot-path input.

It should be:
- serializable for persistence
- stable enough for local caching
- rich enough for exact-document evaluation
- explicit enough for lineage-aware management
- independent from raw JSON representation
- compact enough for repeated in-memory reads without avoidable copying

## 13. Persistence Expectations

The crate must not own persistence, but its types should support:
- verified-grant storage keyed by `trustgrant_id`
- optional lineage index keyed by `grant_series_id`
- signer/discovery metadata caching
- revocation-proof freshness tracking
- audit linkage for provenance-backed consumer systems

The type surface should avoid forcing consumers to persist large raw blobs when compact
normalized records are sufficient.

## 14. Security and Correctness Requirements

The type and trait layer should make these mistakes hard to write:
- evaluating raw documents directly
- confusing `version` with `revision`
- replacing exact `trustgrant_id` evaluation with implicit "latest revision"
- treating subject identifiers as untyped strings everywhere
- baking HTTPS or API-only assumptions into proof resolution
- accepting stale or non-final proof state silently
- re-parsing or re-allocating data in the hot path that should already be normalized

## Review & Maintenance

- **Last Reviewed:** 2026-04-08
- **Next Review:** When the first concrete TrustGrant Rust modules are introduced
- **Change Log:**
  - v0.7 (2026-04-08): Aligned the type/port document with the current implemented core
    by centering `PrincipalKind`/`PrincipalId`, clarifying that broader subject-taxonomy
    and richer signer-profile support remain future profile-layer growth
  - v0.6 (2026-04-08): Updated wording to reflect the current `ports/verification.rs`
    boundary and current crate terminology
  - v0.5 (2026-04-06): Added explicit `origin_authority` preservation to the
    verified-state model and kept the crate docs generic instead of platform-specific
  - v0.4 (2026-04-06): Added canonical ownership-lineage and ownership-transition proof
    concepts to the type and trait design
  - v0.2 (2026-04-06): Added zero-copy, normalized-state, and hot-path performance
    guidance to the type and trait design
  - v0.1 (2026-04-06): Initial type and trait design for the runtime-agnostic TrustGrant
    crate
