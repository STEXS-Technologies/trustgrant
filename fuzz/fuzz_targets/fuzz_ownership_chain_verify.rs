#![no_main]
use std::collections::BTreeMap;

use chrono::Utc;
use libfuzzer_sys::fuzz_target;

use trustgrant::{
    OwnershipChainVerifier, TrustGrantError, ValidatedOwnershipTransitionDocument,
    ValidatedTrustGrantDocument,
    document::{
        RawOwnershipTransitionDocument,
        raw::{
            RawCapabilities, RawMintingConstraints, RawOperationScope, RawResourceScope,
            RawResourceType, RawScope, RawSelector, RawSupersessionPolicy, RawTrustGrantDocument,
            RawTypeCapabilities, RawTypeConstraints,
        },
    },
    domain::Utf16Key,
};

fn build_matching_document(
    raw: &RawOwnershipTransitionDocument,
    validated: &ValidatedOwnershipTransitionDocument,
) -> Result<ValidatedTrustGrantDocument, TrustGrantError> {
    let mut types = BTreeMap::new();

    for (type_name, scope) in validated.resource_scope() {
        let raw_selectors: Vec<RawSelector> = scope
            .selectors()
            .iter()
            .map(|selector| RawSelector {
                kind: selector.kind().as_str().into(),
                all: false,
                values: Some(selector.values().iter().cloned().map(Into::into).collect()),
                expressions: None,
            })
            .collect();

        if raw_selectors.is_empty() {
            continue;
        }

        types.insert(
            Utf16Key::new(type_name.as_str()),
            RawResourceType {
                all: false,
                allow: Some(raw_selectors),
                deny: None,
                capabilities: RawTypeCapabilities {
                    recognize: Some(true),
                    mint: Some(false),
                },
                constraints: RawTypeConstraints {
                    minting: RawMintingConstraints {
                        max_total: None,
                        max_per_user: None,
                    },
                    audience_scope: None,
                },
                operations: Some(RawOperationScope {
                    all: false,
                    allow: Some(vec!["custom:use".into()]),
                    deny: None,
                }),
            },
        );
    }

    let raw_doc = RawTrustGrantDocument {
        trustgrant_id: "tg_123e4567-e89b-12d3-a456-426614174000".to_owned().into(),
        version: 0,
        grant_series_id: "tgs_123e4567-e89b-12d3-a456-426614174001".to_owned().into(),
        revision: 1,
        supersedes: None,
        supersession_policy: RawSupersessionPolicy::Coexist,
        issuer_authority: "https://issuer.example.com".to_owned().into(),
        origin_authority: raw.origin_authority.clone(),
        active_owning_authority: raw.to_authority.clone(),
        key_id: "root-key-1".to_owned().into(),
        target_scope: RawScope {
            all: true,
            allow: None,
            deny: None,
        },
        capabilities: RawCapabilities {
            recognize: true,
            mint: false,
        },
        default_audience_scope: None,
        resource_scope: RawResourceScope { types },
        global_constraints: None,
        revocation: None,
        issued_at: raw.effective_at,
        signature: "valid-signature".to_owned().into(),
        issuer_principal: None,
        interoperability_profile: None,
    };

    ValidatedTrustGrantDocument::try_from(raw_doc)
}

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = RawOwnershipTransitionDocument::parse_json_bytes(data) else {
        return;
    };

    let Ok(validated) = ValidatedOwnershipTransitionDocument::try_from(raw.clone()) else {
        return;
    };

    let Ok(record) = validated.to_record() else {
        return;
    };

    let Ok(document) = build_matching_document(&raw, &validated) else {
        return;
    };

    let verifier = OwnershipChainVerifier::new();
    let checked_at = Utc::now();

    // Core invariant: the verifier must never panic regardless of input.
    // All failures surface as Result::Err, never as unwinding panics.
    let _result = verifier.verify_document_ownership(&document, &[record], checked_at);
});
