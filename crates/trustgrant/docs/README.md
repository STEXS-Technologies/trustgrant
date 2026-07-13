**Document Version:** 0.9\
**Last Updated:** 2026-04-08\
**Status:** Draft\
**Owner:** CTO (Wladimir Trubizin)\
**Related Documents:** [TrustGrant v0 Spec](TRUSTGRANT_V0_SPEC.md),
[TrustGrant Use Cases](USE_CASES.md),
[TrustGrant Integration Guide](INTEGRATION_GUIDE.md),
[TrustGrant Federation Flow](TRUSTGRANT_FEDERATION_FLOW.md),
[TrustGrant Type and Trait Design](TYPE_AND_TRAIT_DESIGN.md),
[TrustGrant Implementation Architecture](IMPLEMENTATION_ARCHITECTURE.md),
[TrustGrant Performance Baseline](PERFORMANCE_BASELINE.md),
[TrustGrant Canonicalization Specialization](CANONICALIZATION_SPECIALIZATION.md)

# TrustGrant Crate Docs

This folder contains the protocol-level technical documentation for the TrustGrant
crate.

Platform-specific semantics and deployment-profile design belong outside this
crate-local documentation set.
This crate-local doc set stays focused on:
- protocol mechanics
- document structure
- discovery and federation flow
- implementation architecture of the runtime-agnostic crate
- machine-readable schema artifacts

## Documentation Boundary

**Root `docs/` covers platform semantics:**
- authority ownership model in the platform
- integration with inventory and auth
- platform-level revocation and provenance rules

**`crates/trustgrant/docs/` covers protocol mechanics:**
- TrustGrant v0 document model
- authority discovery
- federation flow
- implementation architecture of the core crate
- machine-readable schema

## Current Docs

- [TrustGrant v0 Spec](TRUSTGRANT_V0_SPEC.md)
- [TrustGrant Use Cases](USE_CASES.md)
- [TrustGrant Integration Guide](INTEGRATION_GUIDE.md)
- [TrustGrant Authority Discovery](TRUSTGRANT_AUTHORITY_DISCOVERY.md)
- [TrustGrant Federation Flow](TRUSTGRANT_FEDERATION_FLOW.md)
- [TrustGrant Ownership Authority Transitions](OWNERSHIP_AUTHORITY_TRANSITIONS.md)
- [TrustGrant Interoperability and Proof Models](INTEROPERABILITY_AND_PROOF_MODELS.md)
- [TrustGrant Baseline Interoperability Profile](BASELINE_INTEROPERABILITY_PROFILE.md)
- [TrustGrant Type and Trait Design](TYPE_AND_TRAIT_DESIGN.md)
- [TrustGrant Implementation Architecture](IMPLEMENTATION_ARCHITECTURE.md)
- [TrustGrant Performance Baseline](PERFORMANCE_BASELINE.md)
- [TrustGrant Canonicalization Specialization](CANONICALIZATION_SPECIALIZATION.md)
- [TrustGrant v0 Schema](TRUSTGRANT_V0_SCHEMA_FINAL_WITH_KEY_ID.json)
- [TrustGrant Ownership Authority Transition v0 Schema](TRUSTGRANT_OWNERSHIP_AUTHORITY_TRANSITION_V0_SCHEMA.json)

## Status

These documents are derived from the current TrustGrant source materials provided for
protocol documentation work.
They are kept here so the protocol specification, federation flow, discovery rules, and
schema stay close to the crate that will implement them.

## Review & Maintenance

- **Last Reviewed:** 2026-04-08
- **Next Review:** When the protocol schema or technical flow changes materially
- **Change Log:**
  - v1.5 (2026-04-08): Hardened proof-bundle insertion against silent conflicts and
    overgrowth, and revalidated persisted verified-grant records against bounded
    cardinality on rehydrate
  - v1.4 (2026-04-08): Hardened the core against hostile input with explicit
    document-size, selector-count, request-context, and ownership-chain bounds, plus new
    regression tests and fuzz coverage
  - v1.3 (2026-04-08): Added proof-source lookup profiling guidance and recorded the
    accepted delegated-signer lookup optimization plus the reverted ownership-chain
    experiment
  - v1.2 (2026-04-08): Updated crate-local performance documentation to include accepted
    verified-record rehydrate and issuer-side finalization optimization passes
  - v1.1 (2026-04-08): Added canonicalization-specialization design constraints and
    rollout guidance for measured cold-path optimization work
  - v1.0 (2026-04-08): Added a benchmark baseline and explicit A/B performance workflow
    for TrustGrant optimization passes
  - v0.9 (2026-04-08): Added an integration guide for issuing, verifying, persisting,
    and evaluating TrustGrants
  - v0.8 (2026-04-08): Added a protocol-level use-case catalog for TrustGrant beyond one
    deployment profile
  - v0.7 (2026-04-07): Froze the TrustGrant v0 machine-contract baseline further by
    aligning the main schema with origin/active ownership fields and adding the
    ownership-transition schema
  - v0.6 (2026-04-06): Removed platform-specific framing and kept the crate docs focused
    on generic TrustGrant protocol mechanics
  - v0.5 (2026-04-06): Added concrete ownership-authority transition profile
    documentation for successor-authority issuance and transfer verification
  - v0.4 (2026-04-06): Added type-and-trait design guidance and brought the TrustGrant
    crate into normal workspace verification
  - v0.3 (2026-04-06): Added interoperability and proof-model guidance for centralized,
    offline, and blockchain-backed TrustGrant deployments
  - v0.2 (2026-04-06): Added implementation-architecture coverage and aligned crate docs
    boundary with deployment-profile separation
  - v0.1 (2026-04-06): Reworked crate-local docs to hold protocol-only technical
    material and schema artifacts
