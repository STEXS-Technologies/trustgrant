use std::collections::BTreeMap;
use std::hint::black_box;
use std::process::abort;

use chrono::{TimeZone, Utc};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use trustgrant::document::raw::{
    RawCapabilities, RawMintingConstraints, RawResourceScope, RawResourceType, RawScope,
    RawSelector, RawTypeCapabilities, RawTypeConstraints,
};
use trustgrant::domain::Utf16Key;
use trustgrant::{
    AuthorityId, AuthorityKeyRecord, BundleRevocationProof, CanonicalizationProfile,
    EvaluationEngine, EvaluationRequest, GrantRevision, OwnershipChainVerifier, OwnershipProofKind,
    OwnershipResourceScope, OwnershipSelector, OwnershipTransitionLineage,
    OwnershipTransitionParties, OwnershipTransitionRecord, OwnershipTransitionVerifier,
    OwnershipVerificationRecord, ProofFinality, RawOwnershipTransitionDocument,
    RawTrustGrantDocument, RequestedCapability, RequestedOperation, ResolvedSignerBinding,
    ResourceBinding, ResourceContext, ResourceRef, ResourceTypeName, RevocationFreshnessPolicy,
    RevocationRecord, RevocationSourceKind, RevocationStatus, SelectorExpression, SignatureProfile,
    SignatureVerificationRequest, SignatureVerifier, TransitionId, TransitionSeriesId,
    TrustGrantDraft, TrustGrantDraftAuthorities, TrustGrantError, TrustGrantProofBundle,
    ValidatedTrustGrantDocument, VerificationContext, VerificationMetadata, VerificationPipeline,
    VerificationPosture, VerifiedRevocationState, ensure_metadata_matches_document,
    parse_authority_discovery_document, parse_delegated_principal_key_document,
    parse_revocation_status_proof,
};

const VALID_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
  "version":0,
  "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
  "revision":1,
  "supersedes":null,
  "supersession_policy":"coexist",
  "issuer_authority":"https://issuer.example.com",
  "origin_authority":"https://issuer.example.com",
  "active_owning_authority":"https://issuer.example.com",
  "key_id":"root-key-1",
  "target_scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}],"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":null}],
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

const DELEGATED_ROOT_DISCOVERY_JSON: &str = r#"{
  "authority_id":"https://issuer.example.com",
  "keys":[
    {
      "key_id":"root-key-1",
      "algorithm":"ed25519",
      "public_key":"base64-root-public-key",
      "not_before":"2026-01-01T00:00:00Z",
      "not_after":"2027-01-01T00:00:00Z"
    }
  ],
  "signature_profile":{
    "format":"jcs+ed25519",
    "canonicalization":"RFC8785"
  },
  "revocation_policy":{
    "status_endpoint":"https://issuer.example.com/revocation",
    "non_revoked_ttl_seconds":120,
    "max_stale_seconds":900
  },
  "issued_at":"2026-04-07T12:00:00Z",
  "delegation":{
    "principals_supported":true,
    "principal_key_endpoint":"https://issuer.example.com/delegation/principals"
  }
}"#;

const DELEGATED_PRINCIPAL_KEYS_JSON: &str = r#"{
  "authority_id":"https://issuer.example.com",
  "principal":{"kind":"service","id":"issuer-worker"},
  "keys":[
    {
      "key_id":"root-key-1",
      "algorithm":"ed25519",
      "public_key":"base64-delegated-public-key",
      "not_before":"2026-01-01T00:00:00Z",
      "not_after":"2027-01-01T00:00:00Z",
      "revoked":false
    }
  ]
}"#;

const REVOCATION_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
  "status":"active",
  "checked_at":"2026-04-07T12:00:00Z"
}"#;

const ORIGIN_DISCOVERY_JSON: &str = r#"{
  "authority_id":"https://origin.example.com",
  "keys":[
    {
      "key_id":"origin-key-1",
      "algorithm":"ed25519",
      "public_key":"base64-origin-public-key",
      "not_before":"2026-01-01T00:00:00Z",
      "not_after":"2027-01-01T00:00:00Z"
    }
  ],
  "signature_profile":{
    "format":"jcs+ed25519",
    "canonicalization":"RFC8785"
  },
  "issued_at":"2026-04-07T12:00:00Z"
}"#;

const SUCCESSOR_DISCOVERY_JSON: &str = r#"{
  "authority_id":"https://successor.example.com",
  "keys":[
    {
      "key_id":"successor-key-1",
      "algorithm":"ed25519",
      "public_key":"base64-successor-public-key",
      "not_before":"2026-01-01T00:00:00Z",
      "not_after":"2027-01-01T00:00:00Z"
    }
  ],
  "signature_profile":{
    "format":"jcs+ed25519",
    "canonicalization":"RFC8785"
  },
  "issued_at":"2026-04-07T12:00:00Z"
}"#;

const SUCCESSOR_OWNERSHIP_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174100",
  "version":0,
  "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174101",
  "revision":1,
  "supersedes":null,
  "supersession_policy":"coexist",
  "issuer_authority":"https://successor.example.com",
  "origin_authority":"https://origin.example.com",
  "active_owning_authority":"https://successor.example.com",
  "key_id":"successor-key-1",
  "target_scope":{"all":true,"allow":null,"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":null,
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["custom:use"],"deny":null}}}},
  "global_constraints":null,
  "revocation":{"revocable":true,"revocation_endpoint":"https://successor.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":null
}"#;

const SUCCESSOR_REVOCATION_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174100",
  "status":"active",
  "checked_at":"2026-04-07T12:30:00Z"
}"#;

const OWNERSHIP_TRANSITION_JSON: &str = r#"{
  "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174200",
  "version":0,
  "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174201",
  "revision":1,
  "supersedes_transition_id":null,
  "origin_authority":"https://origin.example.com",
  "from_authority":"https://origin.example.com",
  "to_authority":"https://successor.example.com",
  "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T11:00:00Z","not_after":"2026-04-07T13:00:00Z"}},
  "effective_at":"2026-04-07T12:00:00Z",
  "predecessor_signature":{"key_id":"origin-key-1","signature":"origin-signature"},
  "successor_acceptance":{"accepted_at":"2026-04-07T11:30:00Z","key_id":"successor-key-1","signature":"successor-signature"}
}"#;

#[derive(Debug, Default)]
struct BenchSignatureVerifier;

impl SignatureVerifier for BenchSignatureVerifier {
    fn verify_signature(
        &self,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), TrustGrantError> {
        let has_payload = !request.canonical_bytes().is_empty();
        let matches_signature = matches!(
            (request.key_id().as_str(), request.signature()),
            ("root-key-1", "base64-signature")
                | ("origin-key-1", "origin-signature")
                | ("successor-key-1", "successor-signature")
                | ("successor-key-1", "base64-signature")
        );

        if has_payload && matches_signature {
            Ok(())
        } else {
            Err(TrustGrantError::SignatureVerificationFailed)
        }
    }
}

fn trustgrant_benchmarks(criterion: &mut Criterion) {
    let verifier = BenchSignatureVerifier;
    let pipeline = VerificationPipeline::new();
    let ownership_transition_verifier = OwnershipTransitionVerifier::new();

    let raw_document = must(
        RawTrustGrantDocument::parse_json_str(VALID_TRUSTGRANT_JSON)
            .map_err(|_error| TrustGrantError::InvalidJsonDocument),
        "benchmark fixture should parse",
    );
    let verification_metadata = verification_metadata();
    let delegated_bundle = delegated_proof_bundle();
    let delegated_context = VerificationContext::new(
        fixed_timestamp(2026, 4, 7, 12, 0, 0),
        VerificationPosture::Online,
    );
    let ownership_bundle = ownership_proof_bundle();
    let ownership_context = VerificationContext::new(
        fixed_timestamp(2026, 4, 7, 12, 30, 0),
        VerificationPosture::Online,
    );
    let evaluation_request = recognize_request();
    let verified_for_evaluation = must(
        pipeline
            .verify_json_str(
                VALID_TRUSTGRANT_JSON,
                &verifier,
                verification_metadata.clone(),
            )
            .map(|artifacts| artifacts.verified_grant().clone()),
        "benchmark verification should succeed",
    );

    let mut parse_group = criterion.benchmark_group("trustgrant_parse");
    parse_group.bench_function("raw_document_parse", |bench| {
        bench.iter(|| {
            must(
                RawTrustGrantDocument::parse_json_str(black_box(VALID_TRUSTGRANT_JSON))
                    .map_err(|_error| TrustGrantError::InvalidJsonDocument),
                "raw parse should succeed",
            )
        });
    });
    parse_group.bench_function("authority_discovery_parse", |bench| {
        bench.iter(|| {
            must(
                parse_authority_discovery_document(black_box(DELEGATED_ROOT_DISCOVERY_JSON)),
                "discovery parse should succeed",
            )
        });
    });
    parse_group.bench_function("delegated_principal_parse", |bench| {
        bench.iter(|| {
            must(
                parse_delegated_principal_key_document(black_box(DELEGATED_PRINCIPAL_KEYS_JSON)),
                "delegated parse should succeed",
            )
        });
    });
    parse_group.bench_function("revocation_proof_parse", |bench| {
        bench.iter(|| {
            must(
                parse_revocation_status_proof(black_box(REVOCATION_JSON)),
                "revocation parse should succeed",
            )
        });
    });
    parse_group.finish();

    let mut verification_group = criterion.benchmark_group("trustgrant_verification");
    verification_group.bench_function("validate_raw_document", |bench| {
        bench.iter_batched(
            || raw_document.clone(),
            |raw| {
                must(
                    ValidatedTrustGrantDocument::try_from(black_box(raw)),
                    "validation should succeed",
                )
            },
            BatchSize::SmallInput,
        );
    });
    verification_group.bench_function("canonicalize_document", |bench| {
        bench.iter(|| {
            must(
                trustgrant::canonicalize_trustgrant(
                    black_box(&raw_document),
                    CanonicalizationProfile::Rfc8785,
                ),
                "canonicalization should succeed",
            )
        });
    });
    verification_group.bench_function("verify_with_metadata", |bench| {
        bench.iter(|| {
            must(
                pipeline.verify_json_str(
                    black_box(VALID_TRUSTGRANT_JSON),
                    &verifier,
                    black_box(verification_metadata.clone()),
                ),
                "verification should succeed",
            )
        });
    });
    verification_group.bench_function("verify_with_proof_bundle", |bench| {
        bench.iter(|| {
            must(
                pipeline.verify_json_str_with_sources(
                    black_box(VALID_TRUSTGRANT_JSON),
                    &verifier,
                    black_box(delegated_bundle.as_sources()),
                    delegated_context,
                ),
                "source-driven verification should succeed",
            )
        });
    });
    verification_group.bench_function("verify_with_ownership_chain", |bench| {
        bench.iter(|| {
            must(
                pipeline.verify_json_str_with_sources(
                    black_box(SUCCESSOR_OWNERSHIP_TRUSTGRANT_JSON),
                    &verifier,
                    black_box(ownership_bundle.as_sources()),
                    ownership_context,
                ),
                "ownership verification should succeed",
            )
        });
    });
    verification_group.bench_function("verify_ownership_transition", |bench| {
        bench.iter(|| {
            must(
                ownership_transition_verifier.verify_json_str(
                    black_box(OWNERSHIP_TRANSITION_JSON),
                    &verifier,
                    black_box(&ownership_bundle),
                    ownership_context,
                ),
                "ownership transition verify should succeed",
            )
        });
    });
    verification_group.finish();

    let mut evaluation_group = criterion.benchmark_group("trustgrant_evaluation");
    evaluation_group.bench_function("evaluate_verified_grant", |bench| {
        let engine = EvaluationEngine::new();

        bench.iter(|| {
            black_box(
                engine.evaluate(
                    black_box(&verified_for_evaluation),
                    black_box(&evaluation_request),
                )
            )
        });
    });
    evaluation_group.finish();

    // -- Selector expression parse benchmarks --

    let mut selector_group = criterion.benchmark_group("trustgrant_selector");
    selector_group.bench_function("selector_expression_parse", |bench| {
        bench.iter(|| {
            let e1 = SelectorExpression::parse(black_box(r#"contains("candidate-id")"#));
            let e2 = SelectorExpression::parse(black_box(r#"startsWith("auth:")"#));
            let e3 = SelectorExpression::parse(black_box(r#"endsWith(":suffix")"#));
            let e4 = SelectorExpression::parse(black_box(r#"equals("vip_user")"#));
            black_box((e1, e2, e3, e4))
        });
    });
    selector_group.finish();

    // -- Ownership chain verification benchmark --

    let successor_raw = must(
        RawTrustGrantDocument::parse_json_str(SUCCESSOR_OWNERSHIP_TRUSTGRANT_JSON)
            .map_err(|_error| TrustGrantError::InvalidJsonDocument),
        "successor trustgrant should parse",
    );
    let successor_validated = must(
        ValidatedTrustGrantDocument::try_from(successor_raw),
        "successor document should validate",
    );

    let transition_id = must(
        "tgt_123e4567-e89b-12d3-a456-426614174200".parse::<TransitionId>(),
        "transition id should parse",
    );
    let transition_series_id = must(
        "tgts_123e4567-e89b-12d3-a456-426614174201".parse::<TransitionSeriesId>(),
        "transition series id should parse",
    );
    let revision = must(GrantRevision::new(1), "revision should be valid");

    let lineage = must(
        OwnershipTransitionLineage::new(transition_id, transition_series_id, revision, None),
        "lineage should be valid",
    );

    let origin_authority = must(
        AuthorityId::new("https://origin.example.com"),
        "origin authority should be valid",
    );
    let predecessor_authority = must(
        AuthorityId::new("https://origin.example.com"),
        "predecessor authority should be valid",
    );
    let successor_authority = must(
        AuthorityId::new("https://successor.example.com"),
        "successor authority should be valid",
    );
    let parties = must(
        OwnershipTransitionParties::new(
            origin_authority,
            predecessor_authority,
            successor_authority,
        ),
        "parties should be valid",
    );

    let resource_type = must(
        ResourceTypeName::new("item"),
        "resource type should be valid",
    );
    let ownership_selector = must(
        OwnershipSelector::new("id", vec!["canonical_item_1".to_owned()]),
        "ownership selector should be valid",
    );
    let ownership_resource_scope = must(
        OwnershipResourceScope::new(vec![ownership_selector]),
        "ownership resource scope should be valid",
    );

    let scope_map = BTreeMap::from([(resource_type, ownership_resource_scope)]);

    let transition = must(
        OwnershipTransitionRecord::new(
            lineage,
            parties,
            scope_map,
            None,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        ),
        "transition record should be valid",
    );

    let transitions = vec![transition];
    let chain_verifier = OwnershipChainVerifier::new();

    let mut chain_group = criterion.benchmark_group("trustgrant_ownership_chain");
    chain_group.bench_function("ownership_chain_verify", |bench| {
        bench.iter_batched(
            || (successor_validated.clone(), transitions.clone()),
            |(document, txs)| {
                chain_verifier.verify_document_ownership(
                    black_box(&document),
                    black_box(&txs),
                    fixed_timestamp(2026, 4, 7, 12, 30, 0),
                )
            },
            BatchSize::SmallInput,
        );
    });
    chain_group.finish();

    // -- Ensure metadata matches document benchmark --

    let validated_for_consistency = must(
        ValidatedTrustGrantDocument::try_from(raw_document.clone()),
        "validation for consistency should succeed",
    );

    let mut consistency_group = criterion.benchmark_group("trustgrant_consistency");
    consistency_group.bench_function("ensure_metadata_matches_document", |bench| {
        bench.iter_batched(
            || {
                (
                    verification_metadata.clone(),
                    validated_for_consistency.clone(),
                )
            },
            |(meta, doc)| {
                ensure_metadata_matches_document(
                    black_box(&meta),
                    black_box(&doc),
                    CanonicalizationProfile::Rfc8785,
                )
            },
            BatchSize::SmallInput,
        );
    });
    consistency_group.finish();

    // -- TrustGrant draft signable benchmark --

    let draft = must(
        TrustGrantDraft::new(
            must(
                TrustGrantDraftAuthorities::self_owned("https://issuer.example.com"),
                "authorities should be valid",
            ),
            "root-key-1",
            RawScope::allow(vec![RawSelector::values(
                "authority",
                vec!["https://target.example.com".into()],
            )]),
            RawCapabilities::new(true, false),
            resource_scope_for_draft(),
            fixed_timestamp(2026, 4, 8, 12, 0, 0),
        ),
        "draft should be valid",
    );

    let mut draft_group = criterion.benchmark_group("trustgrant_draft");
    draft_group.bench_function("draft_signable", |bench| {
        bench.iter_batched(
            || draft.clone(),
            |draft| {
                must(
                    draft.signable_document(),
                    "signable document should be valid",
                )
            },
            BatchSize::SmallInput,
        );
    });
    draft_group.finish();
}

fn verification_metadata() -> VerificationMetadata {
    VerificationMetadata::new(
        fixed_timestamp(2026, 4, 7, 12, 0, 0),
        VerificationPosture::Online,
        signer_binding(),
        ownership_record(),
        VerifiedRevocationState::Checked(must(
            RevocationRecord::new(
                RevocationStatus::Active,
                RevocationSourceKind::Api,
                ProofFinality::Observed,
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                fixed_timestamp(2026, 4, 7, 12, 5, 0),
            ),
            "revocation record should be valid",
        )),
    )
}

fn signer_binding() -> ResolvedSignerBinding {
    ResolvedSignerBinding::new(
        must(
            AuthorityId::new("https://issuer.example.com"),
            "issuer authority should be valid",
        ),
        must(
            AuthorityKeyRecord::new(
                "root-key-1",
                "ed25519",
                "base64-public-key",
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                fixed_timestamp(2026, 4, 8, 12, 0, 0),
            ),
            "key record should be valid",
        ),
        must(
            SignatureProfile::new("jcs+ed25519", "RFC8785"),
            "signature profile should be valid",
        ),
        Some(must(
            trustgrant::DelegatedPrincipalRef::new("service", "issuer-worker"),
            "delegated principal should be valid",
        )),
    )
}

fn ownership_record() -> OwnershipVerificationRecord {
    OwnershipVerificationRecord::new(
        must(
            AuthorityId::new("https://issuer.example.com"),
            "origin authority should be valid",
        ),
        must(
            AuthorityId::new("https://issuer.example.com"),
            "active owner should be valid",
        ),
        fixed_timestamp(2026, 4, 7, 12, 0, 0),
        OwnershipProofKind::StaticOwner,
        None,
    )
}

fn delegated_proof_bundle() -> TrustGrantProofBundle {
    let discovery_document = must(
        parse_authority_discovery_document(DELEGATED_ROOT_DISCOVERY_JSON),
        "discovery fixture should parse",
    );
    let delegated_document = must(
        parse_delegated_principal_key_document(DELEGATED_PRINCIPAL_KEYS_JSON),
        "delegated fixture should parse",
    );
    let revocation_proof = must(
        parse_revocation_status_proof(REVOCATION_JSON),
        "revocation fixture should parse",
    );

    let mut bundle = TrustGrantProofBundle::new();
    must(
        bundle.insert_discovery_document(discovery_document),
        "discovery document should insert",
    );
    must(
        bundle.insert_delegated_principal_document(delegated_document),
        "delegated principal document should insert",
    );
    must(
        bundle.insert_revocation_proof(BundleRevocationProof::new(
            revocation_proof,
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            must(
                RevocationFreshnessPolicy::new(120, 900),
                "freshness policy should be valid",
            ),
        )),
        "revocation proof should insert",
    );

    bundle
}

fn ownership_proof_bundle() -> TrustGrantProofBundle {
    let origin_discovery = must(
        parse_authority_discovery_document(ORIGIN_DISCOVERY_JSON),
        "origin discovery should parse",
    );
    let successor_discovery = must(
        parse_authority_discovery_document(SUCCESSOR_DISCOVERY_JSON),
        "successor discovery should parse",
    );
    let revocation_proof = must(
        parse_revocation_status_proof(SUCCESSOR_REVOCATION_JSON),
        "successor revocation should parse",
    );
    let transition = must(
        RawOwnershipTransitionDocument::parse_json_str(OWNERSHIP_TRANSITION_JSON)
            .map_err(|_error| TrustGrantError::InvalidOwnershipTransitionDocument),
        "transition fixture should parse",
    );
    let trustgrant_id = must(
        "tg_123e4567-e89b-12d3-a456-426614174100".parse(),
        "trustgrant id should be valid",
    );

    let mut bundle = TrustGrantProofBundle::new();
    must(
        bundle.insert_discovery_document(origin_discovery),
        "origin discovery should insert",
    );
    must(
        bundle.insert_discovery_document(successor_discovery),
        "successor discovery should insert",
    );
    must(
        bundle.insert_revocation_proof(BundleRevocationProof::new(
            revocation_proof,
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            must(
                RevocationFreshnessPolicy::new(120, 900),
                "freshness policy should be valid",
            ),
        )),
        "revocation proof should insert",
    );
    must(
        bundle.insert_ownership_transition_chain(trustgrant_id, vec![transition]),
        "ownership transition chain should insert",
    );

    bundle
}

fn recognize_request() -> EvaluationRequest {
    let mut resource = must(
        ResourceContext::new("item"),
        "resource context should be valid",
    );
    must(
        resource.insert_selector("namespace", "weapons"),
        "resource selector should be valid",
    );

    must(
        EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(
                must(
                    AuthorityId::new("https://issuer.example.com"),
                    "origin authority should be valid",
                ),
                "resource-42".to_string(),
            )),
            must(
                AuthorityId::new("https://target.example.com"),
                "target authority should be valid",
            ),
            must(
                AuthorityId::new("https://audience.example.com"),
                "audience authority should be valid",
            ),
            resource,
            fixed_timestamp(2026, 4, 7, 13, 0, 0),
        ),
        "evaluation request should be valid",
    )
}

fn resource_scope_for_draft() -> RawResourceScope {
    let mut types = BTreeMap::new();
    types.insert(
        Utf16Key::new("item"),
        RawResourceType::new(
            false,
            Some(vec![RawSelector::values(
                "namespace",
                vec!["weapons".into()],
            )]),
            None,
            RawTypeCapabilities::new(Some(true), Some(false)),
            RawTypeConstraints::new(RawMintingConstraints::new(None, None), None),
            None,
        ),
    );
    RawResourceScope::new(types)
}

fn fixed_timestamp(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        .single()
        .unwrap_or_else(|| abort_with("fixed timestamp should be valid"))
}

fn must<T>(result: Result<T, TrustGrantError>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => abort_with_error(context, &error),
    }
}

fn abort_with(context: &str) -> ! {
    eprintln!("{context}");
    abort()
}

fn abort_with_error(context: &str, error: &TrustGrantError) -> ! {
    eprintln!("{context}: {error}");
    abort()
}

criterion_group!(benches, trustgrant_benchmarks);
criterion_main!(benches);
