use std::hint::black_box;
use std::num::ParseIntError;
use std::process::ExitCode;

use thiserror::Error;
use trustgrant::{
    CanonicalizationProfile, RawOwnershipTransitionDocument, TrustGrantError,
    canonicalize_transition_acceptance, canonicalize_transition_proposal,
};

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
enum OwnershipTransitionCanonicalizeColdPathError {
    #[error(transparent)]
    TrustGrant(#[from] TrustGrantError),
    #[error("iterations must be one valid u64")]
    InvalidIterations(#[source] ParseIntError),
}

fn main() -> ExitCode {
    match run() {
        Ok(byte_count) => {
            println!("{byte_count}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u64, OwnershipTransitionCanonicalizeColdPathError> {
    let iterations = parse_iterations(std::env::args().skip(1))?;
    let raw_document = RawOwnershipTransitionDocument::parse_json_str(OWNERSHIP_TRANSITION_JSON)
        .map_err(|_error| TrustGrantError::InvalidOwnershipTransitionDocument)?;
    let mut total_bytes = 0_u64;

    for _ in 0..iterations {
        let proposal_bytes = black_box(canonicalize_transition_proposal(
            black_box(&raw_document),
            CanonicalizationProfile::Rfc8785,
        )?);
        let acceptance_bytes = black_box(canonicalize_transition_acceptance(
            black_box(&raw_document),
            CanonicalizationProfile::Rfc8785,
        )?);

        total_bytes = total_bytes
            .saturating_add(proposal_bytes.as_slice().len() as u64)
            .saturating_add(acceptance_bytes.as_slice().len() as u64);
    }

    Ok(total_bytes)
}

fn parse_iterations(
    arguments: impl Iterator<Item = String>,
) -> Result<u64, OwnershipTransitionCanonicalizeColdPathError> {
    let Some(argument) = arguments.into_iter().next() else {
        return Ok(10_000);
    };

    argument
        .parse::<u64>()
        .map_err(OwnershipTransitionCanonicalizeColdPathError::InvalidIterations)
}
