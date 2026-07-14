use std::hint::black_box;
use std::num::ParseIntError;
use std::process::ExitCode;

use thiserror::Error;
use trustgrant::{
    BundleRevocationProof, ProofFinality, RawOwnershipTransitionDocument,
    RevocationFreshnessPolicy, RevocationSourceKind, TrustGrantError, TrustGrantId,
    TrustGrantProofBundle, parse_authority_discovery_document,
    parse_delegated_principal_key_document, parse_revocation_status_proof,
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
  "delegation":{
    "principals_supported":true,
    "principal_key_endpoint":"https://issuer.example.com/.well-known/trustgrant/principals/{kind}/{id}"
  },
  "issued_at":"2026-04-07T12:00:00Z"
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

const REVOCATION_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
  "status":"active",
  "checked_at":"2026-04-07T12:00:00Z"
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
enum ProofBundleAssemblyColdPathError {
    #[error(transparent)]
    TrustGrant(#[from] TrustGrantError),
    #[error("iterations must be one valid u64")]
    InvalidIterations(#[source] ParseIntError),
}

fn main() -> ExitCode {
    match run() {
        Ok(bundle_count) => {
            println!("{bundle_count}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u64, ProofBundleAssemblyColdPathError> {
    let iterations = parse_iterations(std::env::args().skip(1))?;
    let discovery_document = parse_authority_discovery_document(DELEGATED_ROOT_DISCOVERY_JSON)?;
    let delegated_document = parse_delegated_principal_key_document(DELEGATED_PRINCIPAL_KEYS_JSON)?;
    let revocation_proof = parse_revocation_status_proof(REVOCATION_JSON)?;
    let transition = RawOwnershipTransitionDocument::parse_json_str(OWNERSHIP_TRANSITION_JSON)
        .map_err(|_error| TrustGrantError::InvalidOwnershipTransitionDocument)?;
    let trustgrant_id = "tg_123e4567-e89b-12d3-a456-426614174000".parse::<TrustGrantId>()?;
    let freshness_policy = RevocationFreshnessPolicy::new(86400, 86400)?;
    let mut bundle_count = 0_u64;

    for _ in 0..iterations {
        let mut bundle = TrustGrantProofBundle::new();
        bundle.insert_discovery_document(discovery_document.clone())?;
        bundle.insert_delegated_principal_document(delegated_document.clone())?;
        bundle.insert_revocation_proof(BundleRevocationProof::new(
            revocation_proof,
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            freshness_policy,
        ))?;
        bundle.insert_ownership_transition_chain(trustgrant_id, vec![transition.clone()])?;
        let bundle = black_box(bundle);

        black_box(bundle);
        bundle_count = bundle_count.saturating_add(1);
    }

    Ok(bundle_count)
}

fn parse_iterations(
    arguments: impl Iterator<Item = String>,
) -> Result<u64, ProofBundleAssemblyColdPathError> {
    let Some(argument) = arguments.into_iter().next() else {
        return Ok(100_000);
    };

    argument
        .parse::<u64>()
        .map_err(ProofBundleAssemblyColdPathError::InvalidIterations)
}
