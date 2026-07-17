use std::hint::black_box;
use std::num::ParseIntError;
use std::process::ExitCode;

use chrono::{TimeZone, Utc};
use thiserror::Error;
use trustgrant::{
    AuthorityId, AuthorityKeyRecord, DelegatedPrincipalRef, EvaluationEngine, EvaluationRequest,
    OwnershipProofKind, OwnershipVerificationRecord, ProofFinality, RawTrustGrantDocument,
    RequestedCapability, RequestedOperation, ResolvedSignerBinding, ResourceBinding,
    ResourceContext, ResourceRef, RevocationRecord, RevocationSourceKind, RevocationStatus,
    SignatureProfile, TrustGrantError, ValidatedTrustGrantDocument, VerificationMetadata,
    VerificationPosture, VerifiedRevocationState, VerifiedTrustGrant,
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
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

#[derive(Debug, Error)]
enum EvaluateHotPathError {
    #[error(transparent)]
    TrustGrant(#[from] TrustGrantError),
    #[error("iterations must be one valid u64")]
    InvalidIterations(#[source] ParseIntError),
    #[error("example fixture timestamp must be valid")]
    InvalidFixtureTimestamp,
}

fn main() -> ExitCode {
    match run() {
        Ok(allowed_count) => {
            println!("{allowed_count}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u64, EvaluateHotPathError> {
    let iterations = parse_iterations(std::env::args().skip(1))?;
    let engine = EvaluationEngine::new();
    let verified_grant = verified_grant()?;
    let evaluation_request = recognize_request()?;

    let mut allowed_count = 0_u64;

    for _ in 0..iterations {
        let outcome =
            black_box(engine.evaluate(black_box(&verified_grant), black_box(&evaluation_request)));

        if outcome.decision().is_allowed() {
            allowed_count = allowed_count.saturating_add(1);
        }
    }

    Ok(allowed_count)
}

fn parse_iterations(arguments: impl Iterator<Item = String>) -> Result<u64, EvaluateHotPathError> {
    let Some(argument) = arguments.into_iter().next() else {
        return Ok(100_000_000);
    };

    argument
        .parse::<u64>()
        .map_err(EvaluateHotPathError::InvalidIterations)
}

fn verified_grant() -> Result<VerifiedTrustGrant, EvaluateHotPathError> {
    let raw = RawTrustGrantDocument::parse_json_str(VALID_TRUSTGRANT_JSON)
        .map_err(|_error| TrustGrantError::InvalidJsonDocument)?;
    let validated = ValidatedTrustGrantDocument::try_from(raw)?;

    Ok(VerifiedTrustGrant::new(validated, verification_metadata()?))
}

fn verification_metadata() -> Result<VerificationMetadata, EvaluateHotPathError> {
    Ok(VerificationMetadata::new(
        fixed_timestamp(2026, 4, 7, 12, 0, 0)?,
        VerificationPosture::Online,
        signer_binding()?,
        ownership_record()?,
        VerifiedRevocationState::Checked(RevocationRecord::new(
            RevocationStatus::Active,
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            fixed_timestamp(2026, 4, 7, 12, 0, 0)?,
            fixed_timestamp(2026, 4, 7, 12, 5, 0)?,
        )?),
    ))
}

fn signer_binding() -> Result<ResolvedSignerBinding, EvaluateHotPathError> {
    Ok(ResolvedSignerBinding::new(
        AuthorityId::new("https://issuer.example.com")?,
        AuthorityKeyRecord::new(
            "root-key-1",
            "ed25519",
            "base64-public-key",
            fixed_timestamp(2026, 4, 7, 12, 0, 0)?,
            fixed_timestamp(2026, 4, 8, 12, 0, 0)?,
        )?,
        SignatureProfile::new("jcs+ed25519", "RFC8785")?,
        Some(DelegatedPrincipalRef::new("service", "issuer-worker")?),
    ))
}

fn ownership_record() -> Result<OwnershipVerificationRecord, EvaluateHotPathError> {
    Ok(OwnershipVerificationRecord::new(
        AuthorityId::new("https://issuer.example.com")?,
        AuthorityId::new("https://issuer.example.com")?,
        fixed_timestamp(2026, 4, 7, 12, 0, 0)?,
        OwnershipProofKind::StaticOwner,
        None,
    ))
}

fn recognize_request() -> Result<EvaluationRequest, EvaluateHotPathError> {
    let mut resource = ResourceContext::new("item")?;
    resource.insert_selector("namespace", "weapons")?;

    Ok(EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(ResourceRef::new(
            AuthorityId::new("https://issuer.example.com")?,
            "resource-42".to_owned(),
        )),
        AuthorityId::new("https://target.example.com")?,
        AuthorityId::new("https://audience.example.com")?,
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0)?,
    )?)
}

fn fixed_timestamp(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Result<chrono::DateTime<Utc>, EvaluateHotPathError> {
    Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        .single()
        .ok_or(EvaluateHotPathError::InvalidFixtureTimestamp)
}
