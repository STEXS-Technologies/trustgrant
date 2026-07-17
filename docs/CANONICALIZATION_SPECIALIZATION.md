**Document Version:** 0.2\
**Last Updated:** 2026-07-14\
**Status:** Draft\
**Related Documents:** [TrustGrant v0 Spec](TRUSTGRANT_V0_SPEC.md),
[TrustGrant Implementation Architecture](IMPLEMENTATION_ARCHITECTURE.md),
[TrustGrant Performance Baseline](PERFORMANCE_BASELINE.md)

# TrustGrant Canonicalization Specialization

## 1. Purpose

This document defines the safe optimization boundary for TrustGrant v0 canonicalization.

The current implementation uses fixed TrustGrant-specific canonical writers to produce
RFC 8785-equivalent signing bytes. `serde_jcs` remains the equivalence oracle in tests.
Profiling shows that canonicalization is a material cold-path cost in TrustGrant
verification.

This document exists so performance work does not drift the protocol semantics.

## 2. Current State

The current TrustGrant v0 canonicalization path:
- builds a signable projection of the raw TrustGrant document
- excludes the `signature` field from the signed payload
- emits RFC 8785-equivalent canonical JSON through a TrustGrant-specific canonical
  writer
- uses the previous `serde_jcs` path as the correctness oracle in unit tests

The ownership-transition canonicalization path now follows the same discipline:
- proposal and acceptance payloads use fixed ownership-transition canonical writers
- predecessor and successor signature exclusion rules remain explicit
- the previous `serde_jcs` path remains the oracle in unit tests

Measured current state from [TrustGrant Performance Baseline](PERFORMANCE_BASELINE.md):
- full verify path: about `5.26 µs`
- TrustGrant canonicalization alone: about `0.736 µs`
- ownership-transition verify path: about `3.08 µs`

The performance baseline records current measurements, not a durable comparison against
the pre-specialization implementation.

Current audit posture:
- the specialization is accepted
- the semantic risk is controlled by oracle tests and canonicalization fuzz coverage
- any later change to the canonical writer must preserve the same safeguards

## 3. Non-Negotiable Semantic Invariants

Any specialized TrustGrant canonicalization path must preserve all of these:

1. Output bytes must be RFC 8785-equivalent to the current implementation.
2. `signature` must remain excluded from the signed payload.
3. Field presence and omission rules must remain identical to v0 wire behavior.
4. Numeric rendering must remain RFC 8785-correct.
5. String escaping must remain RFC 8785-correct.
6. Object key ordering must remain RFC 8785-correct.
7. Array ordering must remain input-order preserving.
8. Unsupported future fields must not be silently dropped if the raw wire type evolves
   and the specialization is not updated accordingly.
9. Ownership-transition canonicalization must not drift from the main TrustGrant
   canonicalization discipline.

If any optimization threatens one of these invariants, it is rejected.

## 4. What Specialization Is Allowed

The following are allowed optimization directions:

1. Specialized signable writer for the fixed TrustGrant v0 wire shape.
2. Pre-sized or segmented output buffering when measured and justified.
3. Reduced intermediate allocation when constructing canonical bytes.
4. Direct field emission in already-known protocol field order.
5. Specialized canonicalization for the ownership-transition wire documents under the
   same equivalence rules.

The following are not allowed:

1. Changing the canonicalization profile away from RFC 8785.
2. Introducing a "mostly equivalent" fast path.
3. Reordering arrays or selector lists.
4. Using heuristic escaping that is not byte-for-byte equivalent.
5. Optimizing only the benchmark fixture while weakening general v0 behavior.

## 5. Safe Specialization Strategy

If TrustGrant moves away from generic `serde_jcs` for canonicalization, the safe shape
is:

1. Keep the raw wire structs unchanged.
2. Keep the public `canonicalize_trustgrant(...)` entrypoint unchanged.
3. Introduce a dedicated TrustGrant v0 canonical writer behind that entrypoint.
4. Emit canonical bytes directly for the fixed TrustGrant v0 wire shape.
5. Keep the generic `serde_jcs` path as the oracle during rollout and testing.

This means the specialization should be:
- internal
- profile-specific
- heavily regression-tested
- replaceable if it fails equivalence or maintenance checks

## 6. Recommended Rollout

The recommended rollout order is:

1. Add oracle tests comparing specialized output against current `serde_jcs` output for
   TrustGrant v0.
2. Add the same oracle tests for ownership-transition canonicalization.
3. Add fuzz/property coverage that compares both implementations over bounded valid raw
   documents.
4. Only after equivalence coverage exists, implement the specialized writer.
5. Benchmark again on:
   - canonicalization-only harness
   - full verify cold path
   - ownership-transition verification
6. Reject the specialization if the wall-time gain is not meaningful.

## 7. Acceptance Criteria

A specialized TrustGrant canonicalizer is acceptable only if all of the following hold:

1. All existing tests still pass.
2. New oracle-equivalence tests pass.
3. Fuzzing comparing old and new canonicalization passes cleanly.
4. Canonicalization wall time improves materially on the dedicated harness.
5. Full verify cold-path wall time also improves materially.
6. Hot-path evaluation is not regressed by any collateral structural changes.
7. The implementation remains understandable enough for future audits.

For TrustGrant v0, "materially" should mean:
- clearly outside run-to-run noise
- visible in repeated `perf stat` and benchmark runs
- not purchased with substantially more maintenance risk than the gain

## 8. Initial Candidate Scope

The initial specialization was deliberately narrow:

1. main TrustGrant document canonicalization only
2. no parser changes
3. no verified-state redesign in the same pass

That kept the experiment attributable. Ownership-transition canonicalization followed as
a separate pass under the same oracle-equivalence safeguards.


## 9. Audit Checklist For The Future Pass

Before accepting a specialized canonical writer, review all of the following:

- every v0 field is emitted in the correct order
- omitted optional fields match the current implementation exactly
- UTF-8 and escaping behavior match the generic canonicalizer
- ownership fields are preserved exactly:
  - `issuer_authority`
  - `origin_authority`
  - `active_owning_authority`
- selector arrays preserve order
- resource type objects preserve RFC 8785 key ordering
- audience entries preserve order
- `signature` remains excluded
- no production `unsafe`
- no Clippy silencing
- code remains auditable and small enough to reason about

## 10. Current Recommendation

The current recommendation is:

- keep the specialized writers as the main canonicalization paths for the fixed v0
  TrustGrant and ownership-transition wire shapes
- do not widen either writer without new measurements and oracle coverage
- evaluate any later cold-path optimization in a separate pass under the same
  equivalence discipline

The important rule remains the same: semantic equivalence is mandatory, and performance
work that cannot prove equivalence is rejected.

## Review & Maintenance

- **Last Reviewed:** 2026-07-14
- **Next Review:** When the v0 wire shape or canonicalization implementation changes
  materially
- **Change Log:**
  - v0.2 (2026-07-14): Corrected the implementation description and synchronized current
    benchmark figures and specialization status with the code and performance baseline.
  - v0.1 (2026-04-08): Defined the original safety boundary and rollout criteria for
    TrustGrant-specific canonicalization.
