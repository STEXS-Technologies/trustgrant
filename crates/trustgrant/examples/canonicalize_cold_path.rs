use std::hint::black_box;
use std::num::ParseIntError;
use std::process::ExitCode;

use thiserror::Error;
use trustgrant::{
    CanonicalizationProfile, RawTrustGrantDocument, TrustGrantError, canonicalize_trustgrant,
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
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":null},"operations":{"allow":["recognize"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

#[derive(Debug, Error)]
enum CanonicalizeColdPathError {
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

fn run() -> Result<u64, CanonicalizeColdPathError> {
    let iterations = parse_iterations(std::env::args().skip(1))?;
    let raw_document = RawTrustGrantDocument::parse_json_str(VALID_TRUSTGRANT_JSON)
        .map_err(|_error| TrustGrantError::InvalidJsonDocument)?;
    let mut total_bytes = 0_u64;

    for _ in 0..iterations {
        let canonical_bytes = black_box(canonicalize_trustgrant(
            black_box(&raw_document),
            CanonicalizationProfile::Rfc8785,
        )?);
        total_bytes = total_bytes.saturating_add(canonical_bytes.as_slice().len() as u64);
    }

    Ok(total_bytes)
}

fn parse_iterations(
    arguments: impl Iterator<Item = String>,
) -> Result<u64, CanonicalizeColdPathError> {
    let Some(argument) = arguments.into_iter().next() else {
        return Ok(10_000);
    };

    argument
        .parse::<u64>()
        .map_err(CanonicalizeColdPathError::InvalidIterations)
}
