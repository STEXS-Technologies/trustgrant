use std::hint::black_box;
use std::num::ParseIntError;
use std::process::ExitCode;

use chrono::{TimeZone, Utc};
use thiserror::Error;
use trustgrant::{
    AuthorityDiscoverySource, AuthorityId, AuthorityKeyRecord, KeyId, OwnershipTransitionVerifier,
    ResolvedSignerBinding, SignatureProfile, SignatureVerificationRequest, SignatureVerifier,
    TrustGrantError, ValidatedPrincipal, VerificationContext, VerificationPosture,
};

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

#[derive(Debug, Error)]
enum OwnershipTransitionVerifyColdPathError {
    #[error(transparent)]
    TrustGrant(#[from] TrustGrantError),
    #[error("iterations must be one valid u64")]
    InvalidIterations(#[source] ParseIntError),
    #[error("example fixture timestamp must be valid")]
    InvalidFixtureTimestamp,
    #[error("example discovery fixture must contain one signing key")]
    MissingFixtureKey,
}

#[derive(Debug, Default)]
struct ExampleSignatureVerifier;

impl SignatureVerifier for ExampleSignatureVerifier {
    fn verify_signature(
        &self,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), TrustGrantError> {
        let has_payload = !request.canonical_bytes().is_empty();
        let matches_signature = matches!(
            (request.key_id().as_str(), request.signature()),
            ("origin-key-1", "origin-signature") | ("successor-key-1", "successor-signature")
        );

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

fn run() -> Result<u64, OwnershipTransitionVerifyColdPathError> {
    let iterations = parse_iterations(std::env::args().skip(1))?;
    let verifier = ExampleSignatureVerifier;
    let transition_verifier = OwnershipTransitionVerifier::new();
    let discovery_source = ExampleDiscoverySource::new()?;
    let context = VerificationContext::new(
        fixed_timestamp(2026, 4, 7, 12, 30, 0)?,
        VerificationPosture::Online,
    );
    let mut verified_count = 0_u64;

    for _ in 0..iterations {
        let verified_transition = black_box(transition_verifier.verify_json_str(
            black_box(OWNERSHIP_TRANSITION_JSON),
            &verifier,
            &discovery_source,
            black_box(context),
        )?);
        black_box(verified_transition.record());
        verified_count = verified_count.saturating_add(1);
    }

    Ok(verified_count)
}

fn parse_iterations(
    arguments: impl Iterator<Item = String>,
) -> Result<u64, OwnershipTransitionVerifyColdPathError> {
    let Some(argument) = arguments.into_iter().next() else {
        return Ok(10_000);
    };

    argument
        .parse::<u64>()
        .map_err(OwnershipTransitionVerifyColdPathError::InvalidIterations)
}

fn fixed_timestamp(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Result<chrono::DateTime<Utc>, OwnershipTransitionVerifyColdPathError> {
    Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        .single()
        .ok_or(OwnershipTransitionVerifyColdPathError::InvalidFixtureTimestamp)
}

#[derive(Debug)]
struct ExampleDiscoverySource {
    origin_authority: AuthorityId,
    origin_key: AuthorityKeyRecord,
    successor_authority: AuthorityId,
    successor_key: AuthorityKeyRecord,
    signature_profile: SignatureProfile,
}

impl ExampleDiscoverySource {
    fn new() -> Result<Self, OwnershipTransitionVerifyColdPathError> {
        let origin = trustgrant::parse_authority_discovery_document(ORIGIN_DISCOVERY_JSON)?;
        let successor = trustgrant::parse_authority_discovery_document(SUCCESSOR_DISCOVERY_JSON)?;
        let origin_key = origin
            .keys()
            .first()
            .cloned()
            .ok_or(OwnershipTransitionVerifyColdPathError::MissingFixtureKey)?;
        let successor_key = successor
            .keys()
            .first()
            .cloned()
            .ok_or(OwnershipTransitionVerifyColdPathError::MissingFixtureKey)?;

        Ok(Self {
            origin_authority: origin.authority_id().clone(),
            origin_key,
            successor_authority: successor.authority_id().clone(),
            successor_key,
            signature_profile: origin.signature_profile().clone(),
        })
    }
}

impl AuthorityDiscoverySource for ExampleDiscoverySource {
    fn resolve_signer_binding(
        &self,
        issuer_authority: &AuthorityId,
        key_id: &KeyId,
        issuer_principal: Option<&ValidatedPrincipal>,
        _context: VerificationContext,
    ) -> Result<ResolvedSignerBinding, TrustGrantError> {
        if issuer_principal.is_some() {
            return Err(TrustGrantError::IssuerPrincipalMismatch);
        }

        if issuer_authority == &self.origin_authority && key_id == self.origin_key.key_id() {
            return Ok(ResolvedSignerBinding::new(
                self.origin_authority.clone(),
                self.origin_key.clone(),
                self.signature_profile.clone(),
                None,
            ));
        }

        if issuer_authority == &self.successor_authority && key_id == self.successor_key.key_id() {
            return Ok(ResolvedSignerBinding::new(
                self.successor_authority.clone(),
                self.successor_key.clone(),
                self.signature_profile.clone(),
                None,
            ));
        }

        Err(TrustGrantError::SignatureVerificationFailed)
    }
}
