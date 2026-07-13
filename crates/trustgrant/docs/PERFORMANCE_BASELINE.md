**Document Version:** 0.1\
**Last Updated:** 2026-04-08\
**Status:** Draft\
**Owner:** CTO (Wladimir Trubizin)\
**Related Documents:**
[TrustGrant Implementation Architecture](IMPLEMENTATION_ARCHITECTURE.md),
[TrustGrant Type and Trait Design](TYPE_AND_TRAIT_DESIGN.md),
[TrustGrant Integration Guide](INTEGRATION_GUIDE.md)

# TrustGrant Performance Baseline

This document records the current TrustGrant v0 protocol-core benchmark baseline before
dedicated performance optimization work begins.

The purpose of this baseline is:
- establish one reproducible starting point
- separate cold-path cost from hot-path cost
- prevent accidental regressions during optimization work
- force every performance change to be justified by measured results

TrustGrant performance policy:
- optimize correctness-preserving code only
- measure first
- change one layer at a time
- compare every optimization against a saved baseline
- reject changes that improve one path while causing unacceptable regression in another

* * *

## Benchmark Scope

Current benchmark target:

- `cargo bench -p trustgrant --bench trustgrant_core -- --noplot`

This benchmark covers:
- raw TrustGrant parse
- authority discovery parse
- delegated principal parse
- revocation proof parse
- raw document validation
- TrustGrant canonicalization
- verification with pre-resolved metadata
- verification with one proof bundle
- verification with one ownership chain
- ownership-transition verification
- hot-path evaluation of one previously verified grant

Criterion output artifacts are written under:

- `target/criterion/`

The current baseline values below were read from Criterion `estimates.json` median point
estimates after a clean benchmark run on the current branch.

## Current Accepted Metrics

Current accepted hot-path progression:

| Stage | Median | Change vs previous | Change vs baseline |
| --- | ---: | ---: | ---: |
| Baseline | `~26 ns` | `-` | `-` |
| Pass 1: request-side selector context compaction | `~20 ns` | `-21.9%` | `-21.9%` |
| Pass 2: selector kind classification | `~18 ns` | `-7.7%` | `-27.9%` |

Rejected passes so far:
- inline single-value selector storage: about `19.475 ns`
- forced `#[inline(always)]` on `selector_matches_context`: about `23.6 ns`

These rejected passes were reverted immediately and are not part of the current runtime
state.

Current accepted cold-path progression:

| Stage | Canonicalize | Verify | Change vs previous verify | Change vs baseline verify |
| --- | ---: | ---: | ---: | ---: |
| Baseline | `12.73 µs` | `17.35 µs` | `-` | `-` |
| Pass 3: specialized canonical writer | `0.825 µs` | `5.23 µs` | `-69.9%` | `-69.9%` |

The accepted canonicalization pass was also differential-fuzzed against the previous
`serde_jcs` oracle path for more than 10 minutes with no crash, assertion failure, or
output mismatch.

Current accepted ownership-transition cold-path progression:

| Stage | Canonicalize proposal + acceptance | Verify transition | Change vs previous verify | Change vs baseline verify |
| --- | ---: | ---: | ---: | ---: |
| Baseline | `11.95 µs` | `15.50 µs` | `-` | `-` |
| Pass 4: specialized ownership-transition canonical writer | `0.917 µs` | `2.97 µs` | `-80.8%` | `-80.8%` |

The accepted ownership-transition pass was also differential-fuzzed against the previous
`serde_jcs` oracle path for 601 seconds with no crash, assertion failure, or output
mismatch.

Current accepted persistence rehydrate progression:

| Stage | Rehydrate verified record | Change vs previous | Change vs borrowed baseline |
| --- | ---: | ---: | ---: |
| Borrowed baseline | `2.47 µs` | `-` | `-` |
| Pass 5: direct record-to-normalized rehydrate | `1.47 µs` | `-40.5%` | `-40.5%` |

This accepted pass removed the raw -> validated -> normalized reconstruction hop during
verified-record rehydration and rebuilt normalized verified state directly from the
persisted record.

Current accepted issuance progression:

| Stage | Build signed document | Change vs previous | Change vs baseline |
| --- | ---: | ---: | ---: |
| Baseline | `0.514 µs` | `-` | `-` |
| Pass 6: consuming signed finalization | `0.298 µs` | `-42.0%` | `-42.0%` |

This accepted pass removed the borrowed signable reconstruction hop from
`into_signed_document(self, ...)` and rebuilt the signed raw document directly from the
consuming draft.

Current measured proof-source lookup progression:

| Lookup path | Baseline | Accepted state | Change |
| --- | ---: | ---: | ---: |
| Delegated signer lookup | `~106 ns` | `~105 ns` | `-1.8%` |
| Revocation lookup | `~11 ns` | `~11 ns` | `-` |
| Ownership-chain lookup | `~107 ns` | `~107 ns` | `-` |

Notes:
- delegated signer lookup improved after removing cloned tuple-key assembly in
  `TrustGrantProofBundle`
- revocation lookup is already negligible on the current fixture
- one ownership-chain source-contract pass using shared slices regressed to about
  `113 ns` and was reverted immediately

* * *

## Current Baseline

### Parse

| Benchmark | Median |
| --- | ---: |
| `trustgrant_parse/raw_document_parse` | `2.092 µs` |
| `trustgrant_parse/authority_discovery_parse` | `1.314 µs` |
| `trustgrant_parse/delegated_principal_parse` | `617.27 ns` |
| `trustgrant_parse/revocation_proof_parse` | `170.16 ns` |

### Verification

| Benchmark | Median |
| --- | ---: |
| `trustgrant_verification/validate_raw_document` | `844.88 ns` |
| `trustgrant_verification/canonicalize_document` | `800.41 ns` |
| `trustgrant_verification/verify_with_metadata` | `5.250 µs` |
| `trustgrant_verification/verify_with_proof_bundle` | `6.689 µs` |
| `trustgrant_verification/verify_with_ownership_chain` | `8.027 µs` |
| `trustgrant_verification/verify_ownership_transition` | `3.370 µs` |

### Evaluation

| Benchmark | Median |
| --- | ---: |
| `trustgrant_evaluation/evaluate_verified_grant` | `~18 ns` |

* * *

## Interpretation

Current performance shape confirms the intended TrustGrant architecture:

- JSON parsing is cold-path work, not the runtime authorization hot path
- canonicalization and verification dominate cold-path cost
- hot-path evaluation over normalized verified state is already extremely cheap

This means:
- parser replacement is not the first optimization priority
- hot-path work should focus on memory layout, branch behavior, and selector lookup
  shape
- cold-path work should focus on clone reduction, allocation reduction, and
  normalized-state construction cost

Recent hardening impact:
- hostile-input and deserialization hardening did not erase the major accepted wins
- hot-path evaluation remains about `18 ns`
- canonicalization remains about `0.8 µs`
- full verify with metadata remains about `5.25 µs`
- the latest audit pass introduced small measured regressions in
  `validate_raw_document`, `verify_with_metadata`, and `verify_with_ownership_chain`,
  but they remain far below the original pre-specialization baseline and do not change
  the overall performance shape

The next likely optimization targets are:
- remaining evaluator comparison pressure, if a future measured pass justifies the added
  complexity
- delegated proof-source resolution internals, but only if a stronger signal appears
  than the current low-single-digit gain
- cold-path data movement outside canonicalization, but only where a dedicated harness
  shows real cost

* * *

## Accepted Optimization Passes

### Pass 1: Request-Side Selector Context

Status:
- accepted

Change:
- replaced request-side selector storage in `SelectorContext` from
  `BTreeMap<SelectorKind, BTreeSet<String>>` to a compact
  `Vec<(SelectorKind, Vec<String>)>`-style layout
- kept the verified-grant layout unchanged in this pass
- updated exact selector matching to use the new compact request context

Reason:
- symbolized `perf record` profiling on the hot-path evaluator showed the dominant cost
  centered on:
  - `trustgrant::evaluate::engine::EvaluationEngine::evaluate`
  - `trustgrant::evaluate::engine::selector_matches_context`
  - `__memcmp_evex_movbe`
- the evaluated request shape in the benchmark uses very small selector sets, so
  tree-based request containers were paying pointer-chasing and comparison overhead that
  did not buy anything for the hot path

Measured result:
- baseline `trustgrant_evaluation/evaluate_verified_grant`: about `26 ns`
- after pass 1: about `20 ns`
- observed improvement: about `15%`

Rejected follow-up in this area:
- one additional micro-optimization pass inside `selector_matches_context` was
  benchmarked and then reverted because it did not produce a statistically meaningful
  improvement

Profiling note:
- `perf stat` hardware counters were unavailable in the current environment because
  supported counter events were blocked
- hot-path profiling therefore used:

```bash
cargo rustc -p trustgrant --profile bench --bench trustgrant_core -- \
  -C strip=none -C debuginfo=2 -C force-frame-pointers=yes

perf record -F 999 -g --call-graph dwarf -o /tmp/trustgrant-eval.perf.data -- \
  target/release/deps/trustgrant_core-<hash> evaluate_verified_grant --bench --noplot
```

The next likely hot-path targets remain:
- `selector_matches_context`
- `EvaluationEngine::evaluate`
- string-compare pressure visible through `__memcmp_evex_movbe`

### Evaluator-Only Profiling Harness

Status:
- available

Purpose:
- isolate the `EvaluationEngine::evaluate(...)` hot path from Criterion output,
  benchmark-group setup, and stderr writes that can pollute `perf report`
- keep the same verified-grant and evaluation-request fixture shape as the existing
  benchmark while measuring only the repeated evaluator loop

Harness:
- `cargo run --release -p trustgrant --example evaluate_hot_path -- <iterations>`

Example smoke check:

```bash
cargo run --release -p trustgrant --example evaluate_hot_path -- 1000
```

Recommended profiling flow:

```bash
cargo rustc -p trustgrant --example evaluate_hot_path --release -- \
  -C strip=none -C debuginfo=2 -C force-frame-pointers=yes

perf stat -r 5 \
  -e cycles,instructions,branches,branch-misses,cache-references,cache-misses \
  target/release/examples/evaluate_hot_path 100000000

perf record -F 999 -g --call-graph dwarf \
  -o /tmp/trustgrant-evaluate-hot-path.perf.data -- \
  target/release/examples/evaluate_hot_path 100000000

perf report --stdio -i /tmp/trustgrant-evaluate-hot-path.perf.data --percent-limit 0.5
```

Use this harness when:
- profiling the evaluator hot path specifically
- trying to separate actual evaluator cost from benchmark harness overhead
- validating whether a suspected improvement still shows up without Criterion's
  stderr/reporting path in the sample set

### Proof-Source Lookup Harness

Status:
- available

Purpose:
- isolate proof-source lookup cost from parse, validation, canonicalization, and
  signature verification
- measure delegated signer, revocation, and ownership-chain lookup separately

Harness:
- `cargo run --release -p trustgrant --example proof_source_lookup_cold_path -- <mode> <iterations>`

Modes:
- `delegated-signer`
- `revocation`
- `ownership-chain`

Example commands:

```bash
cargo build -p trustgrant --release --example proof_source_lookup_cold_path

perf stat -r 5 \
  -e cycles,instructions,branches,branch-misses,cache-references,cache-misses \
  target/release/examples/proof_source_lookup_cold_path delegated-signer 10000000

perf stat -r 5 \
  -e cycles,instructions,branches,branch-misses,cache-references,cache-misses \
  target/release/examples/proof_source_lookup_cold_path revocation 10000000

perf stat -r 5 \
  -e cycles,instructions,branches,branch-misses,cache-references,cache-misses \
  target/release/examples/proof_source_lookup_cold_path ownership-chain 1000000
```

Observed benefit:
- the evaluator-only harness removes Criterion's stderr write path from the dominant
  sample set, which makes later source-level profiling decisions much easier to trust

### Verification Cold-Path Profiling Harness

Status:
- available

Purpose:
- isolate parse, validate, canonicalize, verify, and normalize work without Criterion
  reporting noise
- keep the same fixture stable across repeated `perf` and allocator runs
- make cold-path CPU and allocation decisions benchmarkable before touching protocol
  code

Harness:
- `cargo run --release -p trustgrant --example verify_cold_path -- <iterations>`

Example smoke check:

```bash
cargo run --release -p trustgrant --example verify_cold_path -- 100
```

Recommended profiling flow:

```bash
cargo rustc -p trustgrant --example verify_cold_path --release -- \
  -C strip=none -C debuginfo=2 -C force-frame-pointers=yes

perf stat -r 5 \
  -e cycles,instructions,branches,branch-misses,cache-references,cache-misses \
  target/release/examples/verify_cold_path 100000

perf record -F 999 -g --call-graph dwarf \
  -o /tmp/trustgrant-verify-cold.perf.data -- \
  target/release/examples/verify_cold_path 100000

perf report --stdio -i /tmp/trustgrant-verify-cold.perf.data --percent-limit 0.5
```

Observed baseline before pass 3:
- about `1.7349 s` for `100000` full verify iterations
- about `17.35 µs` per verification

Observed accepted state after pass 3:
- about `0.523 s` for `100000` full verify iterations
- about `5.23 µs` per verification

Observed profile shape:
- canonicalization is the dominant cold-path cost center
- whole-document validation cloning is measurable but not the primary wall-time driver
- allocator work is still visible in the full verify path, but the majority of
  actionable cost sits under canonical serialization

Rejected follow-up in this area:
- validating from a borrowed raw document instead of cloning the parsed raw document
  slightly changed counters but did not improve wall time enough to justify the added
  code surface
- that change was reverted immediately

### Verified-Record Rehydrate Profiling Harness

Status:
- available

Purpose:
- isolate verified-record rehydrate cost from persistence-facing normalized state back
  into one `VerifiedTrustGrant`
- benchmark cold-path reconstruction work without including parse, validate,
  canonicalize, or signature verification
- make record-shape and normalization changes A/B testable before touching protocol
  integration code

Harness:
- `cargo run --release -p trustgrant --example rehydrate_verified_record_cold_path -- <iterations>`

Example smoke check:

```bash
cargo run --release -p trustgrant --example rehydrate_verified_record_cold_path -- 1000
```

Recommended profiling flow:

```bash
cargo rustc -p trustgrant --example rehydrate_verified_record_cold_path --release -- \
  -C strip=none -C debuginfo=2 -C force-frame-pointers=yes

perf stat -r 5 \
  -e cycles,instructions,branches,branch-misses,cache-references,cache-misses \
  target/release/examples/rehydrate_verified_record_cold_path 1000000
```

Observed borrowed baseline before pass 5:
- about `2.471 s` for `1000000` rehydrate iterations
- about `2.47 µs` per rehydrate

Observed accepted state after pass 5:
- about `1.4686 s` for `1000000` rehydrate iterations
- about `1.47 µs` per rehydrate

Interpretation:
- the previous raw -> validated -> normalized reconstruction hop was real wasted compute
  on the persistence rehydrate path
- direct record-to-normalized reconstruction is worth keeping because it removes that
  work while preserving validation and keeping the API shape straightforward

### Issuance Cold-Path Profiling Harnesses

Status:
- available

Purpose:
- isolate issuer-side draft materialization work from canonicalization and signature
  verification
- measure the borrowed signable-document path separately from the consuming
  signed-finalization path

Harnesses:
- `cargo run --release -p trustgrant --example issue_signable_cold_path -- <iterations>`
- `cargo run --release -p trustgrant --example issue_signed_cold_path -- <iterations>`

Observed borrowed signable baseline:
- about `0.24491 s` for `1000000` iterations
- about `0.245 µs` per signable document build

Observed signed-document baseline before pass 6:
- about `0.51419 s` for `1000000` iterations
- about `0.514 µs` per finalized signed document build

Observed accepted state after pass 6:
- about `0.29777 s` for `1000000` iterations
- about `0.298 µs` per finalized signed document build

Interpretation:
- borrowed signable construction was already small
- the real avoidable waste was the consuming finalization path rebuilding through the
  borrowed signable flow and cloning fields it could move

### Proof-Bundle Assembly Profiling Harness

Status:
- available

Purpose:
- isolate bundle assembly over already-parsed proof documents so lookup and wiring
  overhead can be measured separately from JSON parsing

Harness:
- `cargo run --release -p trustgrant --example proof_bundle_assembly_cold_path -- <iterations>`

Observed baseline:
- about `0.44881 s` for `1000000` iterations
- about `0.449 µs` per proof-bundle assembly

Interpretation:
- proof-bundle assembly is measurable but already small
- no optimization is accepted here yet because the current measurement does not show a
  compelling enough payoff for structural churn

### Raw-Parse Profiling Harness

Status:
- available

Purpose:
- isolate raw JSON parse cost from validation, canonicalization, verification, and
  normalization
- compare the current `parse_json_str(...)` and `parse_json_bytes(...)` entrypoints
  under the same fixture

Harness:
- `cargo run --release -p trustgrant --example parse_raw_document_cold_path -- <mode> <iterations>`

Supported modes:
- `str`
- `bytes`

Observed baselines:
- `str`: about `2.112 µs` per parse
- `bytes`: about `2.537 µs` per parse

Interpretation:
- raw parsing is already a small cold-path cost compared with the pre-specialization
  canonicalization and verification costs that were previously dominating
- `parse_json_bytes(...)` is slower than `parse_json_str(...)` on the current fixture,
  so there is no accepted parser-side optimization here yet
- parser churn is not justified until profiling shows a larger share of total cold-path
  CPU or a materially better parser path

### Canonicalization-Only Profiling Harness

Status:
- available

Purpose:
- isolate RFC 8785 canonicalization from the rest of the verification path
- determine whether further cold-path work belongs in TrustGrant code or at the
  `serde_jcs` dependency boundary

Harness:
- `cargo run --release -p trustgrant --example canonicalize_cold_path -- <iterations>`

Example smoke check:

```bash
cargo run --release -p trustgrant --example canonicalize_cold_path -- 100
```

Recommended profiling flow:

```bash
cargo rustc -p trustgrant --example canonicalize_cold_path --release -- \
  -C strip=none -C debuginfo=2 -C force-frame-pointers=yes

perf stat -r 5 \
  -e cycles,instructions,branches,branch-misses,cache-references,cache-misses \
  target/release/examples/canonicalize_cold_path 100000

perf record -F 999 -g --call-graph dwarf \
  -o /tmp/trustgrant-canonicalize-cold.perf.data -- \
  target/release/examples/canonicalize_cold_path 100000

perf report --stdio -i /tmp/trustgrant-canonicalize-cold.perf.data --percent-limit 0.5
```

Observed baseline before pass 3:
- about `1.2730 s` for `100000` canonicalization iterations
- about `12.73 µs` per canonicalization
- canonicalization alone is therefore roughly `73%` of the measured full verification
  wall time on the current fixture

Observed accepted state after pass 3:
- about `0.0825 s` for `100000` canonicalization iterations
- about `0.825 µs` per canonicalization

Observed profile shape:
- the dominant cost is inside `serde_jcs` and supporting allocation work
- notable hotspots:
  - `alloc::raw_vec::RawVecInner<A>::finish_grow`
  - `realloc`
  - `std::io::Write::write_all`
  - `serde_jcs::Utf16Key::new`
  - `serde_json::ser::format_escaped_str_contents`
  - `serde_json::SerializeMap::serialize_key`

Interpretation:
- further cold-path gains are unlikely to come from small verifier refactors
- the next serious cold-path optimization would need to target canonicalization more
  directly, most likely through a more specialized serializer path or a
  TrustGrant-specific canonical writer

Rejected follow-up in this area:
- replacing `serde_jcs::to_vec` with `serde_jcs::to_writer` over a manually pre-sized
  `Vec<u8>` changed some counters but did not improve wall time enough to justify
  keeping an arbitrary capacity knob in protocol code
- that change was reverted immediately

### Pass 3: Specialized TrustGrant Canonical Writer

Status:
- accepted

Change:
- replaced generic `serde_jcs` canonicalization for the main TrustGrant v0 document with
  a TrustGrant-specific canonical writer behind the existing
  `canonicalize_trustgrant(...)` entrypoint
- kept the public API unchanged
- kept string escaping delegated to `serde_json` so escaping semantics remain correct
  and auditable
- kept dynamic resource-type key ordering RFC 8785-equivalent by sorting with UTF-16 key
  comparison
- added oracle tests comparing the specialized output against the previous `serde_jcs`
  path
- added a dedicated differential fuzz target that compares both implementations over
  fuzzed raw documents

Reason:
- cold-path profiling showed canonicalization alone consuming about `73%` of end-to-end
  verification wall time
- previous surrounding micro-optimizations did not move wall time enough to be worth
  keeping
- the only measured remaining cold-path opportunity was specializing the canonical
  writer itself

Measured result:
- canonicalization baseline: `12.73 µs`
- canonicalization after pass 3: `0.825 µs`
- verification baseline: `17.35 µs`
- verification after pass 3: `5.23 µs`
- observed verification improvement over baseline: about `69.9%`

Correctness guardrails:
- oracle-equivalence unit tests against the previous `serde_jcs` path
- differential fuzzing for more than 10 minutes with:
  - deterministic output assertion
  - byte-for-byte equality against the oracle path
  - explicit `signature` exclusion assertion

Acceptance note:
- this pass is intentionally limited to the main TrustGrant v0 document canonicalization
  path
- ownership-transition canonicalization is still on the generic path and can be
  optimized later in a separate measured pass

### Ownership-Transition Cold-Path Profiling Harnesses

Status:
- available

Purpose:
- isolate ownership-transition proposal and acceptance canonicalization
- isolate full ownership-transition verification from the main TrustGrant document path
- keep transition A/B work attributable

Harnesses:
- `cargo run --release -p trustgrant --example ownership_transition_canonicalize_cold_path -- <iterations>`
- `cargo run --release -p trustgrant --example ownership_transition_verify_cold_path -- <iterations>`

Recommended profiling flow:

```bash
cargo rustc -p trustgrant --example ownership_transition_canonicalize_cold_path --release -- \
  -C strip=none -C debuginfo=2 -C force-frame-pointers=yes

cargo rustc -p trustgrant --example ownership_transition_verify_cold_path --release -- \
  -C strip=none -C debuginfo=2 -C force-frame-pointers=yes

perf stat -r 5 \
  -e cycles,instructions,branches,branch-misses,cache-references,cache-misses \
  target/release/examples/ownership_transition_canonicalize_cold_path 100000

perf stat -r 5 \
  -e cycles,instructions,branches,branch-misses,cache-references,cache-misses \
  target/release/examples/ownership_transition_verify_cold_path 100000
```

Observed baseline before pass 4:
- canonicalize proposal + acceptance: about `1.1949 s` for `100000` iterations
- about `11.95 µs` per iteration
- verify transition: about `1.5501 s` for `100000` iterations
- about `15.50 µs` per verification

Observed accepted state after pass 4:
- canonicalize proposal + acceptance: about `0.0917 s` for `100000` iterations
- about `0.917 µs` per iteration
- verify transition: about `0.2966 s` for `100000` iterations
- about `2.97 µs` per verification

### Pass 4: Specialized Ownership-Transition Canonical Writer

Status:
- accepted

Change:
- replaced generic `serde_jcs` canonicalization for ownership-transition proposal and
  acceptance payloads with a fixed ownership-transition canonical writer behind the
  existing public API
- kept the public entrypoints unchanged:
  - `canonicalize_transition_proposal(...)`
  - `canonicalize_transition_acceptance(...)`
- added oracle tests comparing specialized output against the previous `serde_jcs` path
- added a dedicated differential fuzz target for transition canonicalization

Reason:
- ownership-transition verification was still substantially more expensive than the
  optimized main TrustGrant path
- the main document canonicalization pass had already demonstrated that the generic
  `serde_jcs` path was the real cold-path cost center
- transition canonicalization was the next highest-payoff remaining protocol
  optimization target

Measured result:
- transition canonicalization baseline: `11.95 µs`
- transition canonicalization after pass 4: `0.917 µs`
- transition verification baseline: `15.50 µs`
- transition verification after pass 4: `2.97 µs`
- observed verification improvement over baseline: about `80.8%`

Correctness guardrails:
- oracle-equivalence unit tests for proposal and acceptance payloads
- dedicated differential fuzzing for 601 seconds with:
  - deterministic output assertion
  - byte-for-byte equality against the previous oracle path
  - explicit predecessor/successor signature exclusion assertions

Acceptance note:
- this pass stays limited to ownership-transition proposal and acceptance
  canonicalization
- it does not widen the transition protocol or change verification semantics

### Pass 2: Selector Kind Classification

Status:
- accepted

Change:
- changed `SelectorKind` from a plain normalized string wrapper to a validated value
  that also carries a small internal classification for the currently hot built-in
  selector kinds:
  - `authority`
  - `namespace`
  - `player_id`
- added `SelectorKind::same_kind(...)` so request-side selector lookup can avoid
  repeating full string equality for these built-ins
- kept `Other` selector kinds exact and fully comparable so protocol semantics did not
  change

Reason:
- post-pass-1 symbolized profiling still showed substantial self time under:
  - `trustgrant::evaluate::engine::EvaluationEngine::evaluate`
  - `trustgrant::evaluate::engine::selector_matches_context`
  - `__memcmp_evex_movbe`
- for the measured request shapes, a noticeable portion of the remaining hot cost came
  from repeated selector-kind string comparisons, especially for the built-in selector
  kinds that dominate current evaluation requests

Measured result:
- pass-1 `trustgrant_evaluation/evaluate_verified_grant`: about `20 ns`
- after pass 2: about `18 ns`
- observed improvement over pass 1: about `7.7%`

Rejected follow-up in this area:
- one narrower pass tried to inline the common single-value selector storage on the
  request side
- benchmark result regressed to about `19.475 ns`
- that change was reverted immediately instead of being kept as complexity debt

Profiling note:
- after pass 2, `perf record` still showed the main remaining hotspots under:
  - `trustgrant::evaluate::engine::EvaluationEngine::evaluate`
  - `trustgrant::evaluate::engine::selector_matches_context`
  - `__memcmp_evex_movbe`
- the share attributable to selector-kind comparison pressure dropped, which is why this
  pass was accepted

* * *

## Remaining Optimization Opportunities

These are the remaining protocol-level optimization candidates after the accepted
hot-path and canonicalization passes.

They are ordered by expected payoff relative to complexity and semantic risk.

### 1. Verified-Record Rehydrate and Cold-Path Reconstruction

Priority:
- medium

Expected payoff:
- moderate throughput and cloud CPU improvement under high registry or revalidation
  volume

Why it still matters:
- persistence rehydrate and reconstruction still do more data movement than the hot path
  needs
- this is not on the main authorization path, but it still costs CPU in background
  refresh and registration flows

Guardrails:
- measure with the cold-path harness first
- prefer reducing copies over broad type redesign
- keep the persistence-facing surface stable unless a measured gain justifies a change

### 2. Issuance Draft Finalization and Signable Construction

Priority:
- medium

Expected payoff:
- modest cold-path win for issuer tooling and bulk issuance flows

Why it still matters:
- draft finalization is still a cold-path construction phase that can perform avoidable
  allocation and copying
- this matters more for batch issuance than for single-grant latency

Guardrails:
- only optimize if issuance volume is a real expected workload
- keep the issuer API simple and auditable

### 3. Remaining Evaluator Comparison Pressure

Priority:
- low to medium

Expected payoff:
- incremental hot-path wins, likely in small single-digit nanoseconds

Why it still matters:
- profiling still points at `EvaluationEngine::evaluate`, `selector_matches_context`,
  and string-compare pressure
- however, the current hot path is already very fast at about `18 ns`

Guardrails:
- expect diminishing returns
- reject complexity that does not buy a clear measured win
- do not broaden data-structure refactors without direct profiling evidence

### 4. Proof-Bundle and Source-Assembly Overhead

Priority:
- low

Expected payoff:
- small cold-path ergonomics and throughput improvement

Why it still matters:
- bundle construction and source assembly are not free
- these costs matter in repeated verification environments

Guardrails:
- optimize only after core verification-path costs are clearly smaller than the assembly
  overhead
- avoid weakening the clean adapter boundary

### 5. Parser and Raw-Document Allocation Behavior

Priority:
- low

Expected payoff:
- probably limited under the current architecture

Why it is lower priority:
- parse is already cheap relative to verification
- the major cold-path bottleneck was canonicalization and that has now been addressed
- parser replacement or large raw-document redesigns are likely to buy less than they
  cost in complexity

Guardrails:
- do not replace the parser without proof
- do not add complexity to the raw-wire layer for speculative wins

* * *

## Required A/B Workflow

Every performance change must follow this process:

1. save a named baseline before the change
2. make one logically grouped optimization
3. rerun the same benchmark set
4. compare changed results against the saved baseline
5. reject or revise the change if it causes unacceptable regression

Recommended command flow:

```bash
cargo bench -p trustgrant --bench trustgrant_core -- --save-baseline pre_opt
# make one optimization pass
cargo bench -p trustgrant --bench trustgrant_core -- --baseline pre_opt --noplot
```

If a saved-baseline workflow is not available in the current local Criterion toolchain,
the fallback is:

1. run the benchmark target
2. capture `target/criterion/**/new/estimates.json`
3. compare medians and confidence intervals against the previous committed baseline

Optimization acceptance rules:
- no correctness regression
- no benchmark removal to hide regressions
- no cold-path win that materially harms hot-path latency
- no hot-path win that explodes cold-path CPU or allocation cost without explicit
  justification

Every accepted optimization should update this document or a follow-up change log with:
- what changed
- which benchmarks improved
- which benchmarks regressed, if any
- why the tradeoff was accepted

* * *

## Measurement Discipline

Performance work on TrustGrant must stay disciplined:

- do not optimize from intuition alone
- do not merge “cleanup + optimization + redesign” in one pass
- keep benchmark fixtures stable when comparing
- prefer structural wins before micro-tuning
- re-measure after every meaningful optimization layer

TrustGrant is intended for high-volume, latency-sensitive deployments, but those
deployments still pay for cold-path CPU in cloud environments.
The performance goal is therefore:

- cheap verification ingress
- very cheap repeated evaluation
- predictable scaling under high concurrency
