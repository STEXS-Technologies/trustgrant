use crate::{
    EvaluationEngine, EvaluationRequest, RequestedCapability, RequestedOperation, ResourceBinding,
    ResourceContext, ResourceRef,
};
use chrono::{TimeZone, Utc};
use std::hint::black_box;
use trustgrant_discovery::{AuthorityKeyRecord, ResolvedSignerBinding, SignatureProfile};
use trustgrant_document::ValidatedTrustGrantDocument;
use trustgrant_domain::{AuthorityId, OwnershipProofKind, OwnershipVerificationRecord};
use trustgrant_revocation::{
    ProofFinality, RevocationRecord, RevocationSourceKind, RevocationStatus,
    VerifiedRevocationState,
};
use trustgrant_verify::{VerificationMetadata, VerificationPosture, VerifiedTrustGrant};

fn ts() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 4, 7, 12, 0, 0)
        .single()
        .unwrap_or(Utc::now())
}

fn signer_binding() -> ResolvedSignerBinding {
    ResolvedSignerBinding::new(
        AuthorityId::new("https://issuer.example.com").unwrap(),
        AuthorityKeyRecord::new("root-key-1", "ed25519", "base64-public-key", ts(), ts()).unwrap(),
        SignatureProfile::new("jcs+ed25519", "RFC8785").unwrap(),
        None,
    )
}

fn build_verified_grant() -> VerifiedTrustGrant {
    let json = r#"{
        "trustgrant_id":"tg_11111111-1111-4111-8111-111111111001",
        "version":0,
        "grant_series_id":"tgs_11111111-1111-4111-8111-111111111001",
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
        "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":null},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"allow":["recognize"],"deny":null}}}},
        "global_constraints":{"time":{"not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z"}},
        "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
        "issued_at":"2026-06-01T12:00:00Z",
        "signature":"valid-signature",
        "issuer_principal":{"kind":"service","id":"issuer-worker"}
    }"#;
    let raw = trustgrant_document::RawTrustGrantDocument::parse_json_str(json).unwrap();
    let validated = ValidatedTrustGrantDocument::try_from(raw).unwrap();
    VerifiedTrustGrant::new(
        validated,
        VerificationMetadata::new(
            ts(),
            VerificationPosture::Online,
            signer_binding(),
            OwnershipVerificationRecord::new(
                AuthorityId::new("https://issuer.example.com").unwrap(),
                AuthorityId::new("https://issuer.example.com").unwrap(),
                ts(),
                OwnershipProofKind::StaticOwner,
                None,
            ),
            VerifiedRevocationState::Checked(
                RevocationRecord::new(
                    RevocationStatus::Active,
                    RevocationSourceKind::Api,
                    ProofFinality::Observed,
                    ts(),
                    ts(),
                )
                .unwrap(),
            ),
        ),
    )
}

#[kani::proof]
#[kani::unwind(500)]
fn verify_evaluate_basic() {
    let engine = EvaluationEngine::new();
    let grant = black_box(build_verified_grant());
    let mut resource = ResourceContext::new("item").unwrap();
    resource.insert_selector("namespace", "weapons").unwrap();
    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(ResourceRef::new(
            AuthorityId::new("https://issuer.example.com").unwrap(),
            "resource-42".to_string(),
        )),
        AuthorityId::new("https://target.example.com").unwrap(),
        AuthorityId::new("https://audience.example.com").unwrap(),
        resource,
        ts(),
    )
    .unwrap();
    let outcome = engine.evaluate(&grant, &request);
    black_box(outcome);
}
