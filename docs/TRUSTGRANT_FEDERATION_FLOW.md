**Document Version:** 0.7\
**Last Updated:** 2026-04-08\
**Status:** Draft\
**Related Documents:** [TrustGrant Crate Docs](README.md),
[TrustGrant v0 Spec](TRUSTGRANT_V0_SPEC.md),
[TrustGrant Authority Discovery](TRUSTGRANT_AUTHORITY_DISCOVERY.md)

# TrustGrant Federation Flow

## 1. Overview

This document describes the end-to-end flow of TrustGrant across independent services,
from issuance to runtime enforcement.

Actors:

- Issuer Authority
- Target Authority
- Audience Authority
- User / Client

* * *

## 2. High-Level Architecture

- each authority runs its own TrustGrant control plane
- each authority exposes authenticated discovery material through a resolver profile
- each authority maintains a local trust registry of accepted external authorities
- TrustGrants are exchanged explicitly between authorities

There is no central registry and no central coordinator.

For HTTPS-hosted authorities, the resolver profile is typically
`/.well-known/trustgrant.json`. For blockchain-backed, DID-style, or offline
authorities, the resolver profile may use another authenticated proof source.

Current v0 core note:
- the core consumes already-resolved authenticated discovery material
- non-HTTP resolution remains adapter/profile responsibility
- exact current guarantees are tracked in
  [TrustGrant Authority Discovery](TRUSTGRANT_AUTHORITY_DISCOVERY.md) and
  [TrustGrant Interoperability and Proof Models](INTEROPERABILITY_AND_PROOF_MODELS.md)

* * *

## 3. Issuance Flow

1. Issuer Authority decides to delegate authority to Target Authority
2. Issuer constructs a TrustGrant document:
   - `issuer_authority = IA`
   - `origin_authority = OA`
   - `active_owning_authority = AOA`
   - `target_scope` includes `TA`
   - `resource_scope` defines resources
   - `audience_scope` defines allowed audiences
3. Issuer signs the TrustGrant with its private key
4. Issuer sends the TrustGrant to Target Authority

### 3.x Issuance by Delegated Principals

An authority may delegate TrustGrant signing authority to internal principals such as
tenants or projects.

In this model:

- `issuer_authority` identifies the signer of the exact grant
- `origin_authority` identifies the immutable canonical origin of the referenced
  resources
- `active_owning_authority` identifies the authority currently empowered to issue
  owner-level grants for the lineage
- `issuer_principal` identifies the delegated signer
- the TrustGrant is signed using a delegated principal key

Example:

```json
{
  "issuer_authority": "https://platform.example.com",
  "origin_authority": "https://platform.example.com",
  "active_owning_authority": "https://platform.example.com",
  "issuer_principal": {
    "kind": "tenant",
    "id": "tenant_a"
  },
  "key_id": "tenant-a-2026",
  "signature": "..."
}
```

The target side must:

1. resolve authenticated root discovery material through the active authority-resolution
   profile
2. discover the delegated-principal resolution mechanism for that profile
3. resolve delegated principal signing keys
4. verify that the signing key is bound to the asserted principal
5. apply local policy to decide whether this principal is trusted

Current v0 core note:
- the verifier consumes one already-resolved effective signer binding per verification
  call
- richer signer models are normalized by the surrounding profile before entering the
  core
- the authoritative detail lives in
  [TrustGrant Authority Discovery](TRUSTGRANT_AUTHORITY_DISCOVERY.md) and
  [TrustGrant Interoperability and Proof Models](INTEROPERABILITY_AND_PROOF_MODELS.md)

* * *

## 4. Registration Flow

1. Target Authority receives a TrustGrant
2. Target verifies schema, protocol version, and lineage metadata
3. Target validates structural safety:
   - reject duplicate selectors
   - validate `grant_series_id`, `revision`, `supersedes`, and `supersession_policy`
4. Target checks `issuer_authority` against its trust registry
5. Target validates the relationship between `origin_authority`,
   `active_owning_authority`, and the referenced resources
6. Target resolves issuer discovery material through the active authority-resolution
   profile
   - if the deployment uses mirrored, cached, chain-backed, or relayed proof inputs, it
     must reconcile them into one selected proof-source set before calling the
     TrustGrant verifier
7. Target verifies signature
8. Target checks time validity
9. Target stores the TrustGrant under its canonical protocol `trustgrant_id`
10. Target indexes the grant by `grant_series_id` and `revision` for lineage-aware
    management
11. Target may additionally assign a local `registration_id` or storage handle for
    persistence
12. Target applies `supersession_policy` to older revisions in the same lineage
13. Target returns the canonical `trustgrant_id` and, if needed, the local
    `registration_id` to internal systems

Only registered TrustGrants may be used at runtime.

### 4.x Update and Supersession Flow

When an issuer updates an existing logical delegation:

1. issuer keeps the same `grant_series_id`
2. issuer issues a new unique `trustgrant_id`
3. issuer increments `revision`
4. issuer may set `supersedes` to the previous `trustgrant_id`
5. issuer declares `supersession_policy`

Allowed outcomes:
- `coexist`: old and new revisions remain active simultaneously until one expires, is
  revoked, or is retired by local policy
- `supersede_previous`: the accepted new revision supersedes older active revisions in
  the same lineage

Supersession does not replace revocation:
- a superseded older revision may still need explicit revocation later
- an invalid updated revision may itself be revoked

### 4.y Ownership Authority Transition Flow

When a canonical resource lineage moves from one authority to another:

1. current owning authority prepares an ownership-authority transition record
2. transition record identifies:
   - origin authority
   - current owning authority
   - successor authority
   - explicit canonical resource scope
   - activation timing
3. current owning authority signs the transition
4. successor authority countersigns acceptance
5. verifier or platform registry checks:
   - predecessor is the current active owning authority
   - successor acceptance is valid
   - no conflicting active transition exists
6. once accepted and active, successor authority becomes the active owning authority for
   future TrustGrant issuance on that lineage

This is not the same as issuing a broad operational TrustGrant.

See [TrustGrant Ownership Authority Transitions](OWNERSHIP_AUTHORITY_TRANSITIONS.md).

* * *

## 5. Runtime Usage Flow

For each request:

1. caller includes:

```text
X-TrustGrant-ID: <trustgrant_id>
```

2. control plane loads the TrustGrant from cache or storage
3. verification pipeline runs:
   - check TrustGrant exists and is active
   - check not-before / not-after
   - check revocation status using the active proof source, cached state, and background
     refresh where applicable
   - check current authority matches `target_scope`
   - check capability allows operation
   - check resource matches `resource_scope`
   - check audience matches `audience_scope`
   - check minting constraints
4. if all checks pass, approve the operation
5. otherwise reject

Runtime evaluation should use the exact referenced `trustgrant_id`.

Lineage-aware lookup such as "latest active revision for this `grant_series_id`" may
exist as a management or convenience feature, but it must remain explicit and must not
silently replace exact-document evaluation.

Interoperability note:
- operation names, selector kinds, and principal kinds remain open in v0
- independent systems that want portable meaning across authorities should standardize
  named interoperability profiles rather than rely on ad hoc strings alone

### 5.x Runtime Flow with Delegated Principals

If `issuer_principal` is present, runtime verification extends with:

- resolve delegated principal key via root discovery
- verify delegated key validity and binding
- enforce local policy for delegated principals

If a deployment has multiple candidate proof sources for the same grant, the deployment
must choose one final authoritative source set before verification.
The current TrustGrant core does not merge or arbitrate competing proof sources during
one verification call.

* * *

## 6. Cross-Authority Resource Flow Example

Scenario:

- Authority A issues shared resources
- Authority B mints on behalf of Authority A
- Authority C accepts those resources

Flow:

1. Authority A issues a TrustGrant to Authority B with mint capability
2. Authority A includes audience scope allowing Authority C
3. Authority B mints a resource with:
   - `origin_authority = Authority A`
   - `active_owning_authority = Authority A`
4. A client presents that resource to Authority C
5. Authority C verifies:
   - issuer is Authority A
   - TrustGrant allows recognition
   - audience allows Authority C
6. the resource is accepted and usable under Authority C's local policy

* * *

## 7. Trust Boundaries

Each authority enforces:

- which issuers it trusts
- which TrustGrants it registers
- which audiences it accepts
- which operations it allows

No authority is forced to accept any TrustGrant.
Federation is strictly opt-in.

* * *

## 8. Failure Modes

Hard failures:

- unknown issuer
- invalid signature
- revoked TrustGrant
- target not allowed
- audience not allowed
- predecessor is not the currently active owning authority
- successor acceptance missing or invalid
- overlapping active transition claims for the same lineage
- successor-issued grant presented without the required active transition proof chain

Soft failures:

- key rotation delay
- cache miss
- revocation proof source degraded while still within bounded staleness or finality
  policy

* * *

## 9. Caching Strategy

Recommended:

- cache TrustGrant by `trustgrant_id` in-process
- keep optional lineage indexes by `grant_series_id`
- cache authority keys by `authority_id`
- cache revocation state separately from grant payload
- use short TTL for non-revoked state and longer TTL for revoked state
- add jitter to refresh timing to avoid synchronized spikes
- use async background refresh plus a circuit breaker for revocation endpoint calls
- enforce a maximum staleness window after which requests fail closed

Suggested baseline profile:

- non-revoked cache TTL: 60-300 seconds
- revoked cache TTL: until `not_after`
- background refresh interval: around 50% of TTL with jitter
- circuit behavior: stop synchronous revocation calls during repeated failure, rely on
  cache until max staleness

This profile reduces revocation-proof-source denial-of-service blast radius while
preserving fail-closed semantics.

* * *

## 10. Design Philosophy

TrustGrant federation is:

- decentralized
- explicit
- fail-closed
- cryptographically verifiable
- incrementally adoptable

There is no global authority.
Trust emerges from explicit bilateral agreements.

* * *

## 11. v1 Hardening Notes

For production v1 rollouts, strongly prefer:

- short-lived grants plus refresh as the main lifecycle model
- revocation as a kill switch, not routine lifecycle churn
- duplicate selector rejection
- restricted expression surface or no expressions
- deterministic canonical signing profile across all participants

## Review & Maintenance

- **Last Reviewed:** 2026-04-08
- **Next Review:** When authority-resolution or proof-source modeling changes materially
- **Change Log:**
  - v0.7 (2026-04-08): Distinguished protocol-level federation openness from the current
    core guarantees for non-HTTP authority resolution, effective signer bindings, and
    interoperability-profile responsibility
  - v0.6 (2026-04-08): Clarified that multi-source proof reconciliation happens before
    the TrustGrant verifier and is not performed inside one verification call
  - v0.5 (2026-04-06): Added `origin_authority` and `active_owning_authority` to the
    generic federation model and kept `issuer_authority` as the signer of the exact
    grant
  - v0.4 (2026-04-06): Added explicit ownership-authority transition flow and failure
    modes for successor-authority issuance
  - v0.3 (2026-04-06): Generalized federation flow wording from HTTPS-only discovery and
    revocation endpoints to authenticated resolver and proof-source profiles
  - v0.2 (2026-04-06): Added lineage-aware registration, supersession behavior, and
    exact-document runtime evaluation rules
