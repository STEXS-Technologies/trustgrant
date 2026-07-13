**Document Version:** 0.3\
**Last Updated:** 2026-04-08\
**Status:** Draft\
**Owner:** CTO (Wladimir Trubizin)\
**Related Documents:** [TrustGrant Crate Docs](README.md),
[TrustGrant v0 Spec](TRUSTGRANT_V0_SPEC.md),
[TrustGrant Authority Discovery](TRUSTGRANT_AUTHORITY_DISCOVERY.md),
[TrustGrant Federation Flow](TRUSTGRANT_FEDERATION_FLOW.md),
[TrustGrant Implementation Architecture](IMPLEMENTATION_ARCHITECTURE.md)

# TrustGrant Interoperability and Proof Models

## 1. Purpose

TrustGrant is intended to work across:
- centralized services
- offline verifiers
- blockchain-backed or other distributed systems

This document defines the interoperability requirements that keep the protocol usable
across those environments without coupling the core protocol to one transport or one
proof source.

## 2. Interoperability Baseline

TrustGrant must not assume that every participating authority is:
- an HTTPS service
- able to host a `/.well-known` document
- able to answer live revocation HTTP calls
- represented by a single conventional asymmetric key

The protocol must remain compatible with authorities whose trust material comes from:
- hosted web discovery
- DID-style or profile-specific resolvers
- blockchain-backed contract or account state
- signed offline bundles or mirrored snapshots

## 3. Authority Identity Schemes

`authority_id` must be treated as a globally unique authority identifier, not as "always
an HTTPS URL".

The protocol should support authority identifiers such as:
- HTTPS service authorities
- DID-style authorities
- blockchain-network authorities
- other globally unique authority schemes accepted by the consumer profile

For HTTPS-hosted authorities, `/.well-known/trustgrant.json` remains the default
discovery form.

For non-HTTP authorities, the consuming profile must define how equivalent discovery
material is resolved.

Current v0 core guarantee:
- `AuthorityId` classifies scheme names such as `https`, `did`, `chain`, or other custom
  schemes
- known scheme classification is ASCII-case-insensitive, but the original `authority_id`
  string remains exact and is not rewritten by the core
- the crate parses authenticated discovery material once it is provided
- the crate does not ship built-in DID, chain, or other non-HTTP resolver adapters

## 4. Discovery and Proof Sources

TrustGrant needs a generalized proof-source model.

The verifier may obtain authority metadata, signer metadata, and revocation state from
sources such as:
- live API endpoints
- cached snapshots
- signed proof bundles
- blockchain-backed state resolvers
- relayed or mirrored trust material validated by signature or local trust policy

The core protocol requirement is not "use HTTP". The requirement is:
- resolve authoritative verification material
- authenticate it
- apply freshness/finality policy
- fail closed if the proof source is insufficient

For the current v0 core, one verification call consumes one already-selected
proof-source set:
- one discovery source
- one revocation source
- one ownership-transition source

The core does not merge mirrored sources, vote between conflicting sources, or reconcile
disagreement automatically.
If a deployment uses relays, mirrors, multiple caches, chain-backed resolvers, or
API-plus-snapshot comparison, that reconciliation must happen in adapters or
verifier-profile policy before the final source set is handed to the TrustGrant core.

## 5. Signer Models

TrustGrant should support multiple signer models, including:
- single-key authority signing
- delegated-principal signing
- multisig or threshold-managed authority signing
- contract-wallet or contract-managed signing authority
- blockchain-backed signer ownership proven by finalized state

The verifier must be able to distinguish:
- who the authority is
- who the asserted signer is
- how signer authority is proven

The protocol must not assume one signer proof model for all deployments.

Current v0 core guarantee:
- the core directly models one resolved signer binding at verification time
- that binding carries one effective key record, one signature profile, and optional
  delegated-principal attribution
- richer signer models such as multisig, threshold, contract-managed, or
  blockchain-proven ownership must be collapsed by adapters or consumer profile policy
  into one effective signer binding before the TrustGrant core verifies the payload

## 6. Subject Identity Model

Cross-runtime interoperability requires a typed subject model.

Resource ownership and audience principals should support subjects such as:
- user
- wallet or account
- contract
- service principal
- organization
- group
- other issuer-defined subject kinds

Opaque strings such as a plain `user_id` are not enough for a protocol that must bridge
application users, service identities, and blockchain-native accounts.

Current v0 core guarantee:
- authority identity is typed through `AuthorityId`
- delegated signer identity is typed through `PrincipalKind` and `PrincipalId`
- selector and audience principal kinds remain issuer-defined validated names
- the crate does not yet ship one standardized cross-profile subject taxonomy

## 7. Operation Interoperability

Service-defined operations are intentionally open in v0, but independent systems still
need a way to agree on shared meaning.

TrustGrant should therefore support interoperability profiles that define:
- shared operation names
- shared capability expectations
- shared subject/selector conventions
- shared proof and freshness requirements

The protocol should remain open-ended, but deployments that want reliable cross-runtime
interoperability should standardize named profiles rather than rely on ad hoc operation
strings alone.

One concrete starting point is documented in
[TrustGrant Baseline Interoperability Profile](BASELINE_INTEROPERABILITY_PROFILE.md).

Current v0 core guarantee:
- operation names are validated but otherwise opaque
- selector kinds and principal kinds are validated but otherwise opaque
- the core does not apply general case-folding or alias expansion to those tokens;
  interoperable deployments should standardize exact token strings in their profile
- the crate does not ship a built-in interoperability-profile registry, shared operation
  catalog, or subject-kind catalog

## 8. Revocation and Finality

Revocation must be modeled as a proof problem, not only as an HTTP status-endpoint
problem.

The protocol should support revocation evidence sourced from:
- online API status checks
- cached signed snapshots
- blockchain-backed finalized state
- signed proof bundles

Distributed or blockchain-backed revocation requires explicit finality/freshness policy:
- what state root or block height was trusted
- what freshness window is acceptable
- whether probabilistic or economic finality is acceptable
- when the verifier must fail closed

Offline verification must never silently upgrade stale or unfinalized revocation
evidence into success.

When multiple revocation candidates exist, consumer policy must define:
- how the candidates are authenticated
- how disagreement is detected
- how one final source set is selected
- when disagreement forces fail-closed rejection

The current v0 core expects that selection step to be complete before verification
begins.

## 9. Presentation and Proof Bundles

To support offline, mirrored, or chain-assisted verification, TrustGrant should support
a proof-bundle model that can carry:
- the TrustGrant document
- authority discovery material or a reference to it
- signer proof material
- revocation proof material or revocation snapshot metadata
- optional resource provenance or mint-proof linkage

The exact bundle format can evolve, but the implementation should leave room for this
model from the start.

## 10. Implementation Consequences

The `trustgrant` crate should therefore be designed around abstractions for:
- authority resolution, not only HTTP discovery fetching
- signer proof resolution, not only simple key lookup
- revocation proof resolution, not only HTTP status polling
- finality and freshness policy
- typed subject matching
- optional interoperability profiles

Current v0 core implementation today provides:
- authority scheme inspection
- discovery and delegated-principal document parsing
- one resolved signer binding
- posture-aware revocation policy
- issuer-defined selector and principal-kind matching

It does not yet provide:
- built-in non-HTTP resolver adapters
- native multisig or threshold signer aggregation logic
- contract-wallet or chain-state signer adapters
- a built-in interoperability-profile registry

This keeps the crate usable in:
- centralized deployments
- hybrid centralized-plus-chain deployments
- fully offline verification paths
- future extracted SDKs and tooling

## Review & Maintenance

- **Last Reviewed:** 2026-04-08
- **Next Review:** When verifier traits or authority-resolution design begins
- **Change Log:**
  - v0.3 (2026-04-08): Distinguished current v0 core guarantees from broader protocol
    compatibility goals for authority schemes, signer models, subject typing, and
    interoperability profiles
  - v0.2 (2026-04-08): Clarified single-source-set verification semantics and pushed
    multi-source reconciliation responsibility to adapters and verifier profiles
  - v0.1 (2026-04-06): Initial interoperability and proof-model requirements for
    centralized, offline, and blockchain-backed TrustGrant deployments
