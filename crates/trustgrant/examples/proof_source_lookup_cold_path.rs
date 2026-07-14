use std::hint::black_box;
use std::num::ParseIntError;
use std::process::ExitCode;

use chrono::{TimeZone, Utc};
use thiserror::Error;
use trustgrant::{
    AuthorityDiscoverySource, OwnershipTransitionProofSource, ProofFinality,
    RawOwnershipTransitionDocument, RawTrustGrantDocument, RevocationFreshnessPolicy,
    RevocationProofSource, RevocationSourceKind, TrustGrantError, TrustGrantProofBundle,
    ValidatedTrustGrantDocument, VerificationContext, VerificationPosture,
    parse_authority_discovery_document, parse_delegated_principal_key_document,
    parse_revocation_status_proof,
};

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
      "key_id":"project-key-1",
      "algorithm":"ed25519",
      "public_key":"base64-delegated-public-key",
      "not_before":"2026-01-01T00:00:00Z",
      "not_after":"2027-01-01T00:00:00Z",
      "revoked":false
    }
  ]
}"#;

const DELEGATED_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
  "version":0,
  "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
  "revision":1,
  "supersedes":null,
  "supersession_policy":"coexist",
  "issuer_authority":"https://issuer.example.com",
  "origin_authority":"https://issuer.example.com",
  "active_owning_authority":"https://issuer.example.com",
  "key_id":"project-key-1",
  "target_scope":{"all":true,"allow":null,"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":null,
  "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
  "global_constraints":null,
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

const DELEGATED_REVOCATION_JSON: &str = r#"{
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LookupMode {
    DelegatedSigner,
    Revocation,
    OwnershipChain,
}

#[derive(Debug, Error)]
enum ProofSourceLookupColdPathError {
    #[error(transparent)]
    TrustGrant(#[from] TrustGrantError),
    #[error("iterations must be one valid u64")]
    InvalidIterations(#[source] ParseIntError),
    #[error("mode must be one of: delegated-signer, revocation, ownership-chain")]
    InvalidMode,
    #[error("example fixture timestamp must be valid")]
    InvalidFixtureTimestamp,
}

fn main() -> ExitCode {
    match run() {
        Ok(resolution_count) => {
            println!("{resolution_count}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u64, ProofSourceLookupColdPathError> {
    let (mode, iterations) = parse_arguments(std::env::args().skip(1))?;
    let delegated_document = validated_document(DELEGATED_TRUSTGRANT_JSON)?;
    let successor_document = validated_document(SUCCESSOR_OWNERSHIP_TRUSTGRANT_JSON)?;
    let delegated_bundle = delegated_bundle()?;
    let ownership_bundle = ownership_bundle()?;
    let delegated_context = VerificationContext::new(
        fixed_timestamp(2026, 4, 7, 12, 0, 0)?,
        VerificationPosture::Online,
    );
    let ownership_context = VerificationContext::new(
        fixed_timestamp(2026, 4, 7, 12, 30, 0)?,
        VerificationPosture::Online,
    );
    let signer_binding = delegated_bundle.resolve_signer_binding(
        delegated_document.issuer_authority(),
        delegated_document.key_id(),
        delegated_document.issuer_principal(),
        delegated_context,
    )?;
    let mut resolution_count = 0_u64;

    for _ in 0..iterations {
        match mode {
            LookupMode::DelegatedSigner => {
                let resolved = black_box(delegated_bundle.resolve_signer_binding(
                    delegated_document.issuer_authority(),
                    delegated_document.key_id(),
                    delegated_document.issuer_principal(),
                    delegated_context,
                )?);
                black_box(resolved);
            }
            LookupMode::Revocation => {
                let resolved = black_box(delegated_bundle.resolve_revocation_record(
                    &delegated_document,
                    &signer_binding,
                    delegated_context,
                )?);
                black_box(resolved);
            }
            LookupMode::OwnershipChain => {
                let resolved =
                    black_box(ownership_bundle.resolve_ownership_transition_chain(
                        &successor_document,
                        ownership_context,
                    )?);
                black_box(resolved);
            }
        }

        resolution_count = resolution_count.saturating_add(1);
    }

    Ok(resolution_count)
}

fn parse_arguments(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(LookupMode, u64), ProofSourceLookupColdPathError> {
    let mode = match arguments.next().as_deref() {
        None => LookupMode::DelegatedSigner,
        Some("delegated-signer") => LookupMode::DelegatedSigner,
        Some("revocation") => LookupMode::Revocation,
        Some("ownership-chain") => LookupMode::OwnershipChain,
        Some(_) => return Err(ProofSourceLookupColdPathError::InvalidMode),
    };

    let Some(argument) = arguments.next() else {
        return Ok((mode, 1_000_000));
    };

    Ok((
        mode,
        argument
            .parse::<u64>()
            .map_err(ProofSourceLookupColdPathError::InvalidIterations)?,
    ))
}

fn delegated_bundle() -> Result<TrustGrantProofBundle, ProofSourceLookupColdPathError> {
    let mut bundle = TrustGrantProofBundle::new();
    bundle.insert_discovery_document(parse_authority_discovery_document(
        DELEGATED_ROOT_DISCOVERY_JSON,
    )?)?;
    bundle.insert_delegated_principal_document(parse_delegated_principal_key_document(
        DELEGATED_PRINCIPAL_KEYS_JSON,
    )?)?;
    bundle.insert_revocation_proof(trustgrant::BundleRevocationProof::new(
        parse_revocation_status_proof(DELEGATED_REVOCATION_JSON)?,
        RevocationSourceKind::Api,
        ProofFinality::Observed,
        RevocationFreshnessPolicy::new(86400, 86400)?,
    ))?;
    Ok(bundle)
}

fn ownership_bundle() -> Result<TrustGrantProofBundle, ProofSourceLookupColdPathError> {
    let trustgrant_id = "tg_123e4567-e89b-12d3-a456-426614174100".parse()?;
    let mut bundle = TrustGrantProofBundle::new();
    bundle.insert_discovery_document(parse_authority_discovery_document(ORIGIN_DISCOVERY_JSON)?)?;
    bundle.insert_discovery_document(parse_authority_discovery_document(
        SUCCESSOR_DISCOVERY_JSON,
    )?)?;
    bundle.insert_ownership_transition_chain(
        trustgrant_id,
        vec![
            RawOwnershipTransitionDocument::parse_json_str(OWNERSHIP_TRANSITION_JSON)
                .map_err(|_error| TrustGrantError::InvalidOwnershipTransitionDocument)?,
        ],
    )?;
    Ok(bundle)
}

fn validated_document(
    json: &str,
) -> Result<ValidatedTrustGrantDocument, ProofSourceLookupColdPathError> {
    let raw_document = RawTrustGrantDocument::parse_json_str(json)
        .map_err(|_error| TrustGrantError::InvalidJsonDocument)?;
    Ok(ValidatedTrustGrantDocument::try_from(raw_document)?)
}

fn fixed_timestamp(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Result<chrono::DateTime<Utc>, ProofSourceLookupColdPathError> {
    Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        .single()
        .ok_or(ProofSourceLookupColdPathError::InvalidFixtureTimestamp)
}
