use std::hint::black_box;
use std::num::ParseIntError;
use std::process::ExitCode;

use chrono::{TimeZone, Utc};
use thiserror::Error;
use trustgrant::{
    AuthorityId, AuthorityKeyRecord, DelegatedPrincipalRef, OwnershipProofKind,
    OwnershipVerificationRecord, ProofFinality, ResolvedSignerBinding, RevocationRecord,
    RevocationSourceKind, RevocationStatus, SignatureProfile, SignatureVerificationRequest,
    SignatureVerifier, TrustGrantError, VerificationMetadata, VerificationPipeline,
    VerificationPosture, VerifiedRevocationState,
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

#[derive(Debug, Error)]
enum VerifyColdPathError {
    #[error(transparent)]
    TrustGrant(#[from] TrustGrantError),
    #[error("iterations must be one valid u64")]
    InvalidIterations(#[source] ParseIntError),
    #[error("example fixture timestamp must be valid")]
    InvalidFixtureTimestamp,
}

#[derive(Debug, Default)]
struct ExampleSignatureVerifier;

impl SignatureVerifier for ExampleSignatureVerifier {
    fn verify_signature(
        &self,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), TrustGrantError> {
        let has_payload = !request.canonical_bytes().is_empty();
        let matches_signature =
            request.key_id().as_str() == "root-key-1" && request.signature() == "base64-signature";

        if has_payload && matches_signature {
            Ok(())
        } else {
            Err(TrustGrantError::SignatureVerificationFailed)
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(verified_count) => {
            println!("{verified_count}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u64, VerifyColdPathError> {
    let iterations = parse_iterations(std::env::args().skip(1))?;
    let pipeline = VerificationPipeline::new();
    let verifier = ExampleSignatureVerifier;
    let metadata = verification_metadata()?;

    let mut verified_count = 0_u64;

    for _ in 0..iterations {
        let artifacts = black_box(pipeline.verify_json_str(
            black_box(VALID_TRUSTGRANT_JSON),
            &verifier,
            black_box(metadata.clone()),
        )?);

        black_box(artifacts.verified_grant());
        verified_count = verified_count.saturating_add(1);
    }

    Ok(verified_count)
}

fn parse_iterations(arguments: impl Iterator<Item = String>) -> Result<u64, VerifyColdPathError> {
    let Some(argument) = arguments.into_iter().next() else {
        return Ok(10_000);
    };

    argument
        .parse::<u64>()
        .map_err(VerifyColdPathError::InvalidIterations)
}

fn verification_metadata() -> Result<VerificationMetadata, VerifyColdPathError> {
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

fn signer_binding() -> Result<ResolvedSignerBinding, VerifyColdPathError> {
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

fn ownership_record() -> Result<OwnershipVerificationRecord, VerifyColdPathError> {
    Ok(OwnershipVerificationRecord::new(
        AuthorityId::new("https://issuer.example.com")?,
        AuthorityId::new("https://issuer.example.com")?,
        fixed_timestamp(2026, 4, 7, 12, 0, 0)?,
        OwnershipProofKind::StaticOwner,
        None,
    ))
}

fn fixed_timestamp(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Result<chrono::DateTime<Utc>, VerifyColdPathError> {
    Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        .single()
        .ok_or(VerifyColdPathError::InvalidFixtureTimestamp)
}
