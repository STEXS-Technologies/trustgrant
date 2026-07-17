use std::hint::black_box;
use std::num::ParseIntError;
use std::process::ExitCode;

use thiserror::Error;
use trustgrant::{RawTrustGrantDocument, TrustGrantError};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseMode {
    Str,
    Bytes,
}

#[derive(Debug, Error)]
enum ParseRawDocumentColdPathError {
    #[error(transparent)]
    TrustGrant(#[from] TrustGrantError),
    #[error("iterations must be one valid u64")]
    InvalidIterations(#[source] ParseIntError),
    #[error("mode must be one of: str, bytes")]
    InvalidMode,
}

fn main() -> ExitCode {
    match run() {
        Ok(parsed_count) => {
            println!("{parsed_count}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u64, ParseRawDocumentColdPathError> {
    let (mode, iterations) = parse_arguments(std::env::args().skip(1))?;
    let json_bytes = VALID_TRUSTGRANT_JSON.as_bytes();
    let mut parsed_count = 0_u64;

    for _ in 0..iterations {
        let document = match mode {
            ParseMode::Str => {
                RawTrustGrantDocument::parse_json_str(black_box(VALID_TRUSTGRANT_JSON))?
            }
            ParseMode::Bytes => RawTrustGrantDocument::parse_json_bytes(black_box(json_bytes))?,
        };

        black_box(document);
        parsed_count = parsed_count.saturating_add(1);
    }

    Ok(parsed_count)
}

fn parse_arguments(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(ParseMode, u64), ParseRawDocumentColdPathError> {
    let mode = match arguments.next().as_deref() {
        None => ParseMode::Str,
        Some("str") => ParseMode::Str,
        Some("bytes") => ParseMode::Bytes,
        Some(_) => return Err(ParseRawDocumentColdPathError::InvalidMode),
    };

    let Some(argument) = arguments.next() else {
        return Ok((mode, 1_000_000));
    };

    Ok((
        mode,
        argument
            .parse::<u64>()
            .map_err(ParseRawDocumentColdPathError::InvalidIterations)?,
    ))
}
