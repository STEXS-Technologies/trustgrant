use std::collections::BTreeMap;
use std::hint::black_box;
use std::num::ParseIntError;
use std::process::ExitCode;

use chrono::{TimeZone, Utc};
use thiserror::Error;
use trustgrant::document::raw::{
    RawCapabilities, RawMintingConstraints, RawResourceScope, RawResourceType, RawScope,
    RawSelector, RawTypeCapabilities, RawTypeConstraints,
};
use trustgrant::domain::Utf16Key;
use trustgrant::{TrustGrantDraft, TrustGrantDraftAuthorities, TrustGrantError};

#[derive(Debug, Error)]
enum IssueSignedColdPathError {
    #[error(transparent)]
    TrustGrant(#[from] TrustGrantError),
    #[error("iterations must be one valid u64")]
    InvalidIterations(#[source] ParseIntError),
    #[error("example fixture timestamp must be valid")]
    InvalidFixtureTimestamp,
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

fn run() -> Result<u64, IssueSignedColdPathError> {
    let iterations = parse_iterations(std::env::args().skip(1))?;
    let draft = trustgrant_draft()?;
    let mut total_bytes = 0_u64;

    for _ in 0..iterations {
        let document =
            black_box(black_box(draft.clone()).into_signed_document("base64-signature")?);
        total_bytes = total_bytes
            .saturating_add(document.signature.len() as u64)
            .saturating_add(document.trustgrant_id.len() as u64);
    }

    Ok(total_bytes)
}

fn parse_iterations(
    arguments: impl Iterator<Item = String>,
) -> Result<u64, IssueSignedColdPathError> {
    let Some(argument) = arguments.into_iter().next() else {
        return Ok(100_000);
    };

    argument
        .parse::<u64>()
        .map_err(IssueSignedColdPathError::InvalidIterations)
}

fn trustgrant_draft() -> Result<TrustGrantDraft, IssueSignedColdPathError> {
    Ok(TrustGrantDraft::new(
        TrustGrantDraftAuthorities::self_owned("https://issuer.example.com")?,
        "root-key-1",
        RawScope::allow(vec![RawSelector::values(
            "authority",
            vec!["https://target.example.com".into()],
        )]),
        RawCapabilities::new(true, false),
        resource_scope(),
        fixed_timestamp(2026, 4, 8, 12, 0, 0)?,
    )?)
}

fn resource_scope() -> RawResourceScope {
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
            RawTypeConstraints::new(RawMintingConstraints::new(Some(10), Some(1)), None),
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
) -> Result<chrono::DateTime<Utc>, IssueSignedColdPathError> {
    Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        .single()
        .ok_or(IssueSignedColdPathError::InvalidFixtureTimestamp)
}
