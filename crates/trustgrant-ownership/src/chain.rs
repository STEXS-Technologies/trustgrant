use std::collections::{BTreeMap, HashSet};

use chrono::{DateTime, Utc};

use trustgrant_document::{ValidatedResourceType, ValidatedSelector, ValidatedTrustGrantDocument};
use trustgrant_domain::{
    OwnershipProofKind, OwnershipResourceScope, OwnershipSelector, OwnershipTransitionRecord,
    OwnershipVerificationRecord, ResourceTypeName,
};
use trustgrant_error::TrustGrantError;
use trustgrant_error::limits::{MAX_OWNERSHIP_CHAIN_LENGTH, ensure_collection_limit};

/// Verifies the ownership-transition chain for a TrustGrant document.
///
/// Checks that the resolved chain of ownership transitions is consistent,
/// covers the document's resource scope, and terminates at the document's
/// declared active owning authority. Returns a normalized
/// [`OwnershipVerificationRecord`] that captures the verified ownership
/// state.
#[derive(Debug, Default, Clone, Copy)]
pub struct OwnershipChainVerifier;

impl OwnershipChainVerifier {
    #[must_use = "ownership chain verifier should be reused by adapters and the verification pipeline"]
    pub const fn new() -> Self {
        Self
    }

    /// Verifies the resolved ownership-transition chain for one validated
    /// TrustGrant and returns normalized ownership state.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use chrono::Utc;
    /// use trustgrant_document::ValidatedTrustGrantDocument;
    /// use trustgrant_domain::OwnershipTransitionRecord;
    /// use trustgrant_ownership::OwnershipChainVerifier;
    ///
    /// let document: ValidatedTrustGrantDocument = /* parse from JSON */;
    /// let transitions: Vec<OwnershipTransitionRecord> = /* load transitions */;
    ///
    /// let result = OwnershipChainVerifier::new()
    ///     .verify_document_ownership(&document, &transitions, Utc::now());
    ///
    /// match result {
    ///     Ok(record) => println!("owner: {}", record.active_owning_authority().as_str()),
    ///     Err(error) => eprintln!("ownership verification failed: {error}"),
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the resolved chain is missing,
    /// inconsistent, not yet active, or does not cover the document resource
    /// scope.
    pub fn verify_document_ownership(
        self,
        document: &ValidatedTrustGrantDocument,
        transitions: &[OwnershipTransitionRecord],
        checked_at: DateTime<Utc>,
    ) -> Result<OwnershipVerificationRecord, TrustGrantError> {
        let ownership = document.ownership_authority_state();
        ensure_collection_limit(
            "ownership_transition.chain",
            transitions.len(),
            MAX_OWNERSHIP_CHAIN_LENGTH,
        )?;

        if transitions.is_empty() {
            return if ownership.origin_authority() == ownership.active_owning_authority() {
                Ok(OwnershipVerificationRecord::new(
                    ownership.origin_authority().clone(),
                    ownership.active_owning_authority().clone(),
                    checked_at,
                    OwnershipProofKind::StaticOwner,
                    None,
                ))
            } else {
                Err(TrustGrantError::MissingOwnershipTransitionChain)
            };
        }

        let mut current_owner = ownership.origin_authority().clone();
        let mut seen_transition_ids = HashSet::with_capacity(transitions.len());
        let mut current_series_id = None;
        let mut current_revision = None;
        let mut previous_effective_at = None;
        let mut tip = None;

        for transition in transitions {
            if transition.origin_authority() != ownership.origin_authority() {
                return Err(TrustGrantError::OwnershipTransitionOriginMismatch);
            }

            if !seen_transition_ids.insert(transition.lineage().transition_id()) {
                return Err(TrustGrantError::InvalidOwnershipTransitionChain);
            }

            if let Some(current_series_id) = current_series_id {
                if transition.lineage().transition_series_id() != current_series_id {
                    return Err(TrustGrantError::InvalidOwnershipTransitionChain);
                }
            } else {
                current_series_id = Some(transition.lineage().transition_series_id());
            }

            if let Some(current_revision) = current_revision {
                if transition.lineage().revision().get() <= current_revision {
                    return Err(TrustGrantError::InvalidOwnershipTransitionChain);
                }

                if transition.lineage().supersedes_transition_id() != tip {
                    return Err(TrustGrantError::InvalidOwnershipTransitionChain);
                }
            } else if transition.lineage().revision().get() != 1 {
                return Err(TrustGrantError::InvalidOwnershipTransitionChain);
            }

            // Permanent invariant from ownership-transition fuzzing: the first
            // accepted transition in one lineage must begin at the current
            // active owner, which is the origin authority before any transfer.
            if transition.predecessor_authority() != &current_owner {
                return Err(TrustGrantError::InvalidOwnershipTransitionChain);
            }

            if checked_at < transition.effective_at() {
                return Err(TrustGrantError::InvalidOwnershipTransitionChain);
            }

            if let Some(time_window) = transition.time_window()
                && !time_window.contains(checked_at)
            {
                return Err(TrustGrantError::InvalidOwnershipTransitionChain);
            }

            if let Some(previous_effective_at) = previous_effective_at
                && transition.effective_at() < previous_effective_at
            {
                return Err(TrustGrantError::InvalidOwnershipTransitionChain);
            }

            ensure_transition_scope_covers_document(
                document.resource_scope(),
                transition.resource_scope(),
            )?;

            current_owner = transition.successor_authority().clone();
            current_revision = Some(transition.lineage().revision().get());
            previous_effective_at = Some(transition.effective_at());
            tip = Some(transition.lineage().transition_id());
        }

        if &current_owner != ownership.active_owning_authority() {
            return Err(TrustGrantError::OwnershipTransitionActiveOwnerMismatch);
        }

        Ok(OwnershipVerificationRecord::new(
            ownership.origin_authority().clone(),
            current_owner,
            checked_at,
            OwnershipProofKind::TransitionChain,
            tip,
        ))
    }
}

fn ensure_transition_scope_covers_document(
    document_scope: &BTreeMap<ResourceTypeName, ValidatedResourceType>,
    transition_scope: &BTreeMap<ResourceTypeName, OwnershipResourceScope>,
) -> Result<(), TrustGrantError> {
    for (resource_type, document_resource_type) in document_scope {
        let Some(transition_resource_scope) = transition_scope.get(resource_type) else {
            return Err(TrustGrantError::OwnershipTransitionScopeMismatch);
        };

        ensure_resource_type_scope_covered(document_resource_type, transition_resource_scope)?;
    }

    Ok(())
}

fn ensure_resource_type_scope_covered(
    document_resource_type: &ValidatedResourceType,
    transition_resource_scope: &OwnershipResourceScope,
) -> Result<(), TrustGrantError> {
    if document_resource_type.all() || !document_resource_type.deny().is_empty() {
        return Err(TrustGrantError::OwnershipTransitionScopeMismatch);
    }

    // `allow()` is guaranteed non-empty when `all()` is false
    // (ValidatedResourceType invariant enforced at construction).
    for selector in document_resource_type.allow() {
        ensure_selector_covered(selector, transition_resource_scope.selectors())?;
    }

    Ok(())
}

fn ensure_selector_covered(
    document_selector: &ValidatedSelector,
    transition_selectors: &[OwnershipSelector],
) -> Result<(), TrustGrantError> {
    if document_selector.all()
        || !document_selector.expressions().is_empty()
        || document_selector.values().is_empty()
    {
        return Err(TrustGrantError::OwnershipTransitionScopeMismatch);
    }

    // Aggregate all values from every transition selector whose kind matches
    // the document selector.  Coverage is satisfied when every document value
    // appears in at least one matching transition selector — the values need
    // not all come from the same selector.
    let all_transition_values: Vec<&String> = transition_selectors
        .iter()
        .filter(|ts| ts.kind() == document_selector.kind())
        .flat_map(|ts| ts.values().iter())
        .collect();

    let is_covered = document_selector
        .values()
        .iter()
        .all(|value| all_transition_values.contains(&value));

    if is_covered {
        Ok(())
    } else {
        Err(TrustGrantError::OwnershipTransitionScopeMismatch)
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{TimeZone, Utc};

    use super::OwnershipChainVerifier;
    use trustgrant_document::ValidatedTrustGrantDocument;
    use trustgrant_document::raw::{
        RawCapabilities, RawMintingConstraints, RawOperationScope, RawResourceScope,
        RawResourceType, RawScope, RawSelector, RawSupersessionPolicy, RawTrustGrantDocument,
        RawTypeCapabilities, RawTypeConstraints,
    };
    use trustgrant_domain::{
        AuthorityId, GrantRevision, OwnershipProofKind, OwnershipResourceScope, OwnershipSelector,
        OwnershipTimeWindow, OwnershipTransitionLineage, OwnershipTransitionParties,
        OwnershipTransitionRecord, ResourceTypeName, TransitionId, TransitionSeriesId, Utf16Key,
    };
    use trustgrant_error::TrustGrantError;
    use trustgrant_error::limits::MAX_OWNERSHIP_CHAIN_LENGTH;

    #[test]
    fn ownership_chain_verifier_accepts_empty_chain_when_owner_matches_origin() {
        let document = validated_document("https://origin.example.com");
        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[],
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );

        let record =
            result.unwrap_or_else(|error| panic!("static owner should be accepted: {error}"));
        assert_eq!(record.proof_kind(), OwnershipProofKind::StaticOwner);
    }

    #[test]
    fn ownership_chain_verifier_accepts_matching_transition_chain() {
        let document = validated_document("https://successor.example.com");
        let record = transition_record(
            "https://origin.example.com",
            "https://origin.example.com",
            "https://successor.example.com",
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[record],
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn ownership_chain_verifier_rejects_missing_chain_when_owner_changed() {
        let document = validated_document("https://successor.example.com");

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[],
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::MissingOwnershipTransitionChain)
        );
    }

    #[test]
    fn ownership_chain_verifier_rejects_scope_mismatch() {
        let document = validated_document("https://successor.example.com");
        let record = transition_record_for_resource(
            "https://origin.example.com",
            "https://origin.example.com",
            "https://successor.example.com",
            "other",
        );

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[record],
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::OwnershipTransitionScopeMismatch)
        );
    }

    #[test]
    fn ownership_chain_verifier_rejects_partial_resource_type_coverage() {
        // Document requires coverage for two resource types: "item" and "user".
        let document = ValidatedTrustGrantDocument::try_from(RawTrustGrantDocument {
            trustgrant_id: "tg_123e4567-e89b-12d3-a456-426614174000".into(),
            version: 0,
            grant_series_id: "tgs_123e4567-e89b-12d3-a456-426614174001".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://origin.example.com".into(),
            active_owning_authority: "https://successor.example.com".into(),
            key_id: "root-key-1".into(),
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
            resource_scope: RawResourceScope {
                types: BTreeMap::from([
                    (
                        Utf16Key::new("item"),
                        RawResourceType {
                            all: false,
                            allow: Some(vec![RawSelector {
                                kind: "id".into(),
                                all: false,
                                values: Some(vec!["canonical_item_1".into()]),
                                expressions: None,
                            }]),
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
                    ),
                    (
                        Utf16Key::new("user"),
                        RawResourceType {
                            all: false,
                            allow: Some(vec![RawSelector {
                                kind: "id".into(),
                                all: false,
                                values: Some(vec!["canonical_user_1".into()]),
                                expressions: None,
                            }]),
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
                    ),
                ]),
            },
            global_constraints: None,
            revocation: None,
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "valid-signature".into(),
            issuer_principal: None,
        })
        .unwrap_or_else(|error| panic!("validated document should be valid: {error}"));

        // Transition only covers "item", not "user"
        let record = transition_record(
            "https://origin.example.com",
            "https://origin.example.com",
            "https://successor.example.com",
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[record],
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::OwnershipTransitionScopeMismatch)
        );
    }

    #[test]
    fn ownership_chain_verifier_accepts_split_selector_union() {
        // Document requires two values: "item_a" and "item_b" for resource type "item".
        let document = ValidatedTrustGrantDocument::try_from(RawTrustGrantDocument {
            trustgrant_id: "tg_123e4567-e89b-12d3-a456-426614174000".into(),
            version: 0,
            grant_series_id: "tgs_123e4567-e89b-12d3-a456-426614174001".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://origin.example.com".into(),
            active_owning_authority: "https://successor.example.com".into(),
            key_id: "root-key-1".into(),
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
            resource_scope: RawResourceScope {
                types: BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "id".into(),
                            all: false,
                            values: Some(vec!["item_a".into(), "item_b".into()]),
                            expressions: None,
                        }]),
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
                )]),
            },
            global_constraints: None,
            revocation: None,
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "valid-signature".into(),
            issuer_principal: None,
        })
        .unwrap_or_else(|error| panic!("validated document should be valid: {error}"));

        // Transition covers "item" with two selectors: ["item_a"] and ["item_b"].
        // Together they cover both document values, but individually neither is
        // sufficient.
        let record = OwnershipTransitionRecord::new(
            OwnershipTransitionLineage::new(
                "tgt_123e4567-e89b-12d3-a456-426614174010"
                    .parse::<TransitionId>()
                    .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                "tgts_123e4567-e89b-12d3-a456-426614174011"
                    .parse::<TransitionSeriesId>()
                    .unwrap_or_else(|error| panic!("transition series id should parse: {error}")),
                GrantRevision::new(1)
                    .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
                None,
            )
            .unwrap_or_else(|error| panic!("lineage should be valid: {error}")),
            OwnershipTransitionParties::new(
                authority("https://origin.example.com"),
                authority("https://origin.example.com"),
                authority("https://successor.example.com"),
            )
            .unwrap_or_else(|error| panic!("parties should be valid: {error}")),
            BTreeMap::from([(
                ResourceTypeName::new("item")
                    .unwrap_or_else(|error| panic!("resource type should be valid: {error}")),
                OwnershipResourceScope::new(vec![
                    OwnershipSelector::new("id", vec!["item_a".into()])
                        .unwrap_or_else(|error| panic!("selector should be valid: {error}")),
                    OwnershipSelector::new("id", vec!["item_b".into()])
                        .unwrap_or_else(|error| panic!("selector should be valid: {error}")),
                ])
                .unwrap_or_else(|error| panic!("resource scope should be valid: {error}")),
            )]),
            None,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        )
        .unwrap_or_else(|error| panic!("transition record should be valid: {error}"));

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[record],
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn ownership_chain_verifier_rejects_excessive_chain_length() {
        let document = validated_document("https://successor.example.com");
        let transitions = (0..=MAX_OWNERSHIP_CHAIN_LENGTH)
            .map(|index| {
                let successor = format!("https://successor-{index}.example.com");
                let predecessor = if index == 0 {
                    "https://origin.example.com".into()
                } else {
                    format!("https://successor-{}.example.com", index - 1)
                };

                transition_record(
                    "https://origin.example.com",
                    &predecessor,
                    &successor,
                    fixed_timestamp(2026, 4, 7, 12, 0, 0),
                )
            })
            .collect::<Vec<_>>();

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &transitions,
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::CollectionTooLarge {
                field: "ownership_transition.chain",
                max_items: MAX_OWNERSHIP_CHAIN_LENGTH,
            })
        );
    }

    #[test]
    fn ownership_chain_verifier_rejects_first_transition_when_predecessor_differs_from_origin() {
        let document = validated_document("https://successor.example.com");
        let record = transition_record(
            "https://different-origin.example.com",
            "https://origin.example.com",
            "https://successor.example.com",
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[record],
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::OwnershipTransitionOriginMismatch)
        );
    }

    #[test]
    fn ownership_chain_verifier_rejects_duplicate_transition_ids() {
        let document = validated_document("https://final.example.com");
        let first = transition_record(
            "https://origin.example.com",
            "https://origin.example.com",
            "https://first.example.com",
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );
        // Second transition uses the SAME transition_id as the first,
        // different successor, different predecessor.
        // Must use a supersedes value that is not its own transition_id to avoid SelfSupersession.
        let second = OwnershipTransitionRecord::new(
            OwnershipTransitionLineage::new(
                "tgt_123e4567-e89b-12d3-a456-426614174010"
                    .parse::<TransitionId>()
                    .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                "tgts_123e4567-e89b-12d3-a456-426614174011"
                    .parse::<TransitionSeriesId>()
                    .unwrap_or_else(|error| panic!("transition series id should parse: {error}")),
                GrantRevision::new(2)
                    .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
                Some(
                    "tgt_123e4567-e89b-12d3-a456-426614174099"
                        .parse::<TransitionId>()
                        .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                ),
            )
            .unwrap_or_else(|error| panic!("lineage should be valid: {error}")),
            OwnershipTransitionParties::new(
                authority("https://origin.example.com"),
                authority("https://first.example.com"),
                authority("https://final.example.com"),
            )
            .unwrap_or_else(|error| panic!("parties should be valid: {error}")),
            BTreeMap::from([(
                ResourceTypeName::new("item")
                    .unwrap_or_else(|error| panic!("resource type should be valid: {error}")),
                OwnershipResourceScope::new(vec![
                    OwnershipSelector::new("id", vec!["canonical_item_1".into()])
                        .unwrap_or_else(|error| panic!("selector should be valid: {error}")),
                ])
                .unwrap_or_else(|error| panic!("resource scope should be valid: {error}")),
            )]),
            None,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        )
        .unwrap_or_else(|error| panic!("transition record should be valid: {error}"));

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[first, second],
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionChain)
        );
    }

    #[test]
    fn ownership_chain_verifier_rejects_non_increasing_revision() {
        let document = validated_document("https://second.example.com");
        let first = transition_record(
            "https://origin.example.com",
            "https://origin.example.com",
            "https://first.example.com",
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );
        // Second transition has revision 1 (same as first) — non-increasing.
        let second = OwnershipTransitionRecord::new(
            OwnershipTransitionLineage::new(
                "tgt_123e4567-e89b-12d3-a456-426614174020"
                    .parse::<TransitionId>()
                    .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                "tgts_123e4567-e89b-12d3-a456-426614174011"
                    .parse::<TransitionSeriesId>()
                    .unwrap_or_else(|error| panic!("transition series id should parse: {error}")),
                GrantRevision::new(1)
                    .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
                None,
            )
            .unwrap_or_else(|error| panic!("lineage should be valid: {error}")),
            OwnershipTransitionParties::new(
                authority("https://origin.example.com"),
                authority("https://first.example.com"),
                authority("https://second.example.com"),
            )
            .unwrap_or_else(|error| panic!("parties should be valid: {error}")),
            BTreeMap::from([(
                ResourceTypeName::new("item")
                    .unwrap_or_else(|error| panic!("resource type should be valid: {error}")),
                OwnershipResourceScope::new(vec![
                    OwnershipSelector::new("id", vec!["canonical_item_1".into()])
                        .unwrap_or_else(|error| panic!("selector should be valid: {error}")),
                ])
                .unwrap_or_else(|error| panic!("resource scope should be valid: {error}")),
            )]),
            None,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        )
        .unwrap_or_else(|error| panic!("transition record should be valid: {error}"));

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[first, second],
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionChain)
        );
    }

    #[test]
    fn ownership_chain_verifier_rejects_series_id_mismatch() {
        let document = validated_document("https://final.example.com");
        let first = transition_record(
            "https://origin.example.com",
            "https://origin.example.com",
            "https://first.example.com",
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );
        // Second transition uses a DIFFERENT transition_series_id.
        let second = OwnershipTransitionRecord::new(
            OwnershipTransitionLineage::new(
                "tgt_123e4567-e89b-12d3-a456-426614174030"
                    .parse::<TransitionId>()
                    .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                "tgts_123e4567-e89b-12d3-a456-426614174099"
                    .parse::<TransitionSeriesId>()
                    .unwrap_or_else(|error| panic!("transition series id should parse: {error}")),
                GrantRevision::new(2)
                    .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
                Some(
                    "tgt_123e4567-e89b-12d3-a456-426614174010"
                        .parse::<TransitionId>()
                        .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                ),
            )
            .unwrap_or_else(|error| panic!("lineage should be valid: {error}")),
            OwnershipTransitionParties::new(
                authority("https://origin.example.com"),
                authority("https://first.example.com"),
                authority("https://final.example.com"),
            )
            .unwrap_or_else(|error| panic!("parties should be valid: {error}")),
            BTreeMap::from([(
                ResourceTypeName::new("item")
                    .unwrap_or_else(|error| panic!("resource type should be valid: {error}")),
                OwnershipResourceScope::new(vec![
                    OwnershipSelector::new("id", vec!["canonical_item_1".into()])
                        .unwrap_or_else(|error| panic!("selector should be valid: {error}")),
                ])
                .unwrap_or_else(|error| panic!("resource scope should be valid: {error}")),
            )]),
            None,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        )
        .unwrap_or_else(|error| panic!("transition record should be valid: {error}"));

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[first, second],
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionChain)
        );
    }

    fn validated_document(active_owning_authority: &str) -> ValidatedTrustGrantDocument {
        ValidatedTrustGrantDocument::try_from(RawTrustGrantDocument {
            trustgrant_id: "tg_123e4567-e89b-12d3-a456-426614174000".into(),
            version: 0,
            grant_series_id: "tgs_123e4567-e89b-12d3-a456-426614174001".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://origin.example.com".into(),
            active_owning_authority: active_owning_authority.into(),
            key_id: "root-key-1".into(),
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
            resource_scope: RawResourceScope {
                types: BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "id".into(),
                            all: false,
                            values: Some(vec!["canonical_item_1".into()]),
                            expressions: None,
                        }]),
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
                )]),
            },
            global_constraints: None,
            revocation: None,
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "valid-signature".into(),
            issuer_principal: None,
        })
        .unwrap_or_else(|error| panic!("validated document should be valid: {error}"))
    }

    fn transition_record(
        origin_authority: &str,
        predecessor_authority: &str,
        successor_authority: &str,
        effective_at: chrono::DateTime<Utc>,
    ) -> OwnershipTransitionRecord {
        transition_record_for_resource_with_time(
            origin_authority,
            predecessor_authority,
            successor_authority,
            "item",
            effective_at,
        )
    }

    fn transition_record_for_resource(
        origin_authority: &str,
        predecessor_authority: &str,
        successor_authority: &str,
        resource_type: &str,
    ) -> OwnershipTransitionRecord {
        transition_record_for_resource_with_time(
            origin_authority,
            predecessor_authority,
            successor_authority,
            resource_type,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        )
    }

    fn transition_record_for_resource_with_time(
        origin_authority: &str,
        predecessor_authority: &str,
        successor_authority: &str,
        resource_type: &str,
        effective_at: chrono::DateTime<Utc>,
    ) -> OwnershipTransitionRecord {
        OwnershipTransitionRecord::new(
            OwnershipTransitionLineage::new(
                "tgt_123e4567-e89b-12d3-a456-426614174010"
                    .parse::<TransitionId>()
                    .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                "tgts_123e4567-e89b-12d3-a456-426614174011"
                    .parse::<TransitionSeriesId>()
                    .unwrap_or_else(|error| panic!("transition series id should parse: {error}")),
                GrantRevision::new(1)
                    .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
                None,
            )
            .unwrap_or_else(|error| panic!("lineage should be valid: {error}")),
            OwnershipTransitionParties::new(
                authority(origin_authority),
                authority(predecessor_authority),
                authority(successor_authority),
            )
            .unwrap_or_else(|error| panic!("parties should be valid: {error}")),
            BTreeMap::from([(
                ResourceTypeName::new(resource_type)
                    .unwrap_or_else(|error| panic!("resource type should be valid: {error}")),
                OwnershipResourceScope::new(vec![
                    OwnershipSelector::new("id", vec!["canonical_item_1".into()])
                        .unwrap_or_else(|error| panic!("selector should be valid: {error}")),
                ])
                .unwrap_or_else(|error| panic!("resource scope should be valid: {error}")),
            )]),
            None,
            effective_at,
        )
        .unwrap_or_else(|error| panic!("transition record should be valid: {error}"))
    }

    #[test]
    fn ownership_chain_verifier_rejects_chain_with_gap() {
        // Two transitions: the second's predecessor_authority does NOT match
        // the first's successor_authority, creating a gap in the chain.
        let document = validated_document("https://third-b.example.com");

        // First transition: origin→origin → successor=first
        let first = transition_record(
            "https://origin.example.com",
            "https://origin.example.com",
            "https://first.example.com",
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );

        // Second transition: predecessor=third (NOT first), successor=third-b
        // This creates a gap because current_owner after first is "first",
        // but second expects predecessor "third".
        let second = OwnershipTransitionRecord::new(
            OwnershipTransitionLineage::new(
                "tgt_123e4567-e89b-12d3-a456-426614174020"
                    .parse::<TransitionId>()
                    .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                "tgts_123e4567-e89b-12d3-a456-426614174011"
                    .parse::<TransitionSeriesId>()
                    .unwrap_or_else(|error| panic!("transition series id should parse: {error}")),
                GrantRevision::new(2)
                    .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
                Some(
                    "tgt_123e4567-e89b-12d3-a456-426614174010"
                        .parse::<TransitionId>()
                        .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                ),
            )
            .unwrap_or_else(|error| panic!("lineage should be valid: {error}")),
            OwnershipTransitionParties::new(
                authority("https://origin.example.com"),
                authority("https://third.example.com"),
                authority("https://third-b.example.com"),
            )
            .unwrap_or_else(|error| panic!("parties should be valid: {error}")),
            BTreeMap::from([(
                ResourceTypeName::new("item")
                    .unwrap_or_else(|error| panic!("resource type should be valid: {error}")),
                OwnershipResourceScope::new(vec![
                    OwnershipSelector::new("id", vec!["canonical_item_1".into()])
                        .unwrap_or_else(|error| panic!("selector should be valid: {error}")),
                ])
                .unwrap_or_else(|error| panic!("resource scope should be valid: {error}")),
            )]),
            None,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        )
        .unwrap_or_else(|error| panic!("transition record should be valid: {error}"));

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[first, second],
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionChain)
        );
    }

    fn authority(value: &str) -> AuthorityId {
        AuthorityId::new(value).unwrap_or_else(|error| panic!("authority should be valid: {error}"))
    }

    fn fixed_timestamp(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
            .single()
            .unwrap_or_else(|| panic!("fixed timestamp should be valid"))
    }

    // -----------------------------------------------------------------
    // Time-window invariants
    // -----------------------------------------------------------------

    #[test]
    fn ownership_chain_verifier_rejects_check_before_effective_at() {
        let document = validated_document("https://successor.example.com");
        // Transition effective at 12:30, but checked_at is 12:00 (before)
        let record = transition_record(
            "https://origin.example.com",
            "https://origin.example.com",
            "https://successor.example.com",
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[record],
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionChain)
        );
    }

    #[test]
    fn ownership_chain_verifier_rejects_check_after_time_window_not_after() {
        let document = validated_document("https://successor.example.com");
        let time_window = OwnershipTimeWindow::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            fixed_timestamp(2026, 4, 7, 13, 0, 0),
        )
        .unwrap_or_else(|error| panic!("time window should be valid: {error}"));

        // effective_at = 12:30 falls inside not_before..not_after
        let record = OwnershipTransitionRecord::new(
            OwnershipTransitionLineage::new(
                "tgt_123e4567-e89b-12d3-a456-426614174010"
                    .parse::<TransitionId>()
                    .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                "tgts_123e4567-e89b-12d3-a456-426614174011"
                    .parse::<TransitionSeriesId>()
                    .unwrap_or_else(|error| panic!("transition series id should parse: {error}")),
                GrantRevision::new(1)
                    .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
                None,
            )
            .unwrap_or_else(|error| panic!("lineage should be valid: {error}")),
            OwnershipTransitionParties::new(
                authority("https://origin.example.com"),
                authority("https://origin.example.com"),
                authority("https://successor.example.com"),
            )
            .unwrap_or_else(|error| panic!("parties should be valid: {error}")),
            BTreeMap::from([(
                ResourceTypeName::new("item")
                    .unwrap_or_else(|error| panic!("resource type should be valid: {error}")),
                OwnershipResourceScope::new(vec![
                    OwnershipSelector::new("id", vec!["canonical_item_1".into()])
                        .unwrap_or_else(|error| panic!("selector should be valid: {error}")),
                ])
                .unwrap_or_else(|error| panic!("resource scope should be valid: {error}")),
            )]),
            Some(time_window),
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        )
        .unwrap_or_else(|error| panic!("transition record should be valid: {error}"));

        // checked_at = 14:00 is after not_after (13:00)
        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[record],
            fixed_timestamp(2026, 4, 7, 14, 0, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionChain)
        );
    }

    #[test]
    fn ownership_chain_verifier_rejects_non_monotonic_effective_at() {
        let document = validated_document("https://second.example.com");

        // First transition effective at 12:30
        let first = transition_record(
            "https://origin.example.com",
            "https://origin.example.com",
            "https://first.example.com",
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        // Second transition has effective_at 12:00, which is before first's 12:30
        let second = OwnershipTransitionRecord::new(
            OwnershipTransitionLineage::new(
                "tgt_123e4567-e89b-12d3-a456-426614174020"
                    .parse::<TransitionId>()
                    .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                "tgts_123e4567-e89b-12d3-a456-426614174011"
                    .parse::<TransitionSeriesId>()
                    .unwrap_or_else(|error| panic!("transition series id should parse: {error}")),
                GrantRevision::new(2)
                    .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
                Some(
                    "tgt_123e4567-e89b-12d3-a456-426614174010"
                        .parse::<TransitionId>()
                        .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                ),
            )
            .unwrap_or_else(|error| panic!("lineage should be valid: {error}")),
            OwnershipTransitionParties::new(
                authority("https://origin.example.com"),
                authority("https://first.example.com"),
                authority("https://second.example.com"),
            )
            .unwrap_or_else(|error| panic!("parties should be valid: {error}")),
            BTreeMap::from([(
                ResourceTypeName::new("item")
                    .unwrap_or_else(|error| panic!("resource type should be valid: {error}")),
                OwnershipResourceScope::new(vec![
                    OwnershipSelector::new("id", vec!["canonical_item_1".into()])
                        .unwrap_or_else(|error| panic!("selector should be valid: {error}")),
                ])
                .unwrap_or_else(|error| panic!("resource scope should be valid: {error}")),
            )]),
            None,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        )
        .unwrap_or_else(|error| panic!("transition record should be valid: {error}"));

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[first, second],
            fixed_timestamp(2026, 4, 7, 13, 0, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionChain)
        );
    }

    #[test]
    fn ownership_chain_verifier_rejects_supersedes_mismatch() {
        let document = validated_document("https://second.example.com");

        // First transition: transition_id = "tgt_..010", revision=1, supersedes=None
        let first = transition_record(
            "https://origin.example.com",
            "https://origin.example.com",
            "https://first.example.com",
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );

        // Second transition: supersedes points to a different transition_id,
        // NOT the first's transition_id.
        let second = OwnershipTransitionRecord::new(
            OwnershipTransitionLineage::new(
                "tgt_123e4567-e89b-12d3-a456-426614174020"
                    .parse::<TransitionId>()
                    .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                "tgts_123e4567-e89b-12d3-a456-426614174011"
                    .parse::<TransitionSeriesId>()
                    .unwrap_or_else(|error| panic!("transition series id should parse: {error}")),
                GrantRevision::new(2)
                    .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
                Some(
                    "tgt_123e4567-e89b-12d3-a456-426614174099"
                        .parse::<TransitionId>()
                        .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                ),
            )
            .unwrap_or_else(|error| panic!("lineage should be valid: {error}")),
            OwnershipTransitionParties::new(
                authority("https://origin.example.com"),
                authority("https://first.example.com"),
                authority("https://second.example.com"),
            )
            .unwrap_or_else(|error| panic!("parties should be valid: {error}")),
            BTreeMap::from([(
                ResourceTypeName::new("item")
                    .unwrap_or_else(|error| panic!("resource type should be valid: {error}")),
                OwnershipResourceScope::new(vec![
                    OwnershipSelector::new("id", vec!["canonical_item_1".into()])
                        .unwrap_or_else(|error| panic!("selector should be valid: {error}")),
                ])
                .unwrap_or_else(|error| panic!("resource scope should be valid: {error}")),
            )]),
            None,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        )
        .unwrap_or_else(|error| panic!("transition record should be valid: {error}"));

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[first, second],
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionChain)
        );
    }

    #[test]
    fn ownership_chain_verifier_rejects_single_transition_with_revision_two_and_no_tip() {
        // A single transition with revision=2 and a valid supersedes will still
        // fail because tip is None and the supersedes does not match the tip
        // (line 86-87: transition.lineage().supersedes_transition_id() != tip).
        let document = validated_document("https://successor.example.com");
        let record = OwnershipTransitionRecord::new(
            OwnershipTransitionLineage::new(
                "tgt_123e4567-e89b-12d3-a456-426614174010"
                    .parse::<TransitionId>()
                    .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                "tgts_123e4567-e89b-12d3-a456-426614174011"
                    .parse::<TransitionSeriesId>()
                    .unwrap_or_else(|error| panic!("transition series id should parse: {error}")),
                GrantRevision::new(2)
                    .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
                Some(
                    "tgt_123e4567-e89b-12d3-a456-426614174099"
                        .parse::<TransitionId>()
                        .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                ),
            )
            .unwrap_or_else(|error| panic!("lineage should be valid: {error}")),
            OwnershipTransitionParties::new(
                authority("https://origin.example.com"),
                authority("https://origin.example.com"),
                authority("https://successor.example.com"),
            )
            .unwrap_or_else(|error| panic!("parties should be valid: {error}")),
            BTreeMap::from([(
                ResourceTypeName::new("item")
                    .unwrap_or_else(|error| panic!("resource type should be valid: {error}")),
                OwnershipResourceScope::new(vec![
                    OwnershipSelector::new("id", vec!["canonical_item_1".into()])
                        .unwrap_or_else(|error| panic!("selector should be valid: {error}")),
                ])
                .unwrap_or_else(|error| panic!("resource scope should be valid: {error}")),
            )]),
            None,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        )
        .unwrap_or_else(|error| panic!("transition record should be valid: {error}"));

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[record],
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionChain)
        );
    }

    #[test]
    fn ownership_chain_verifier_rejects_active_owner_mismatch() {
        // Document expects active_owning_authority = "final" but chain ends at "intermediate".
        let document = validated_document("https://final.example.com");
        let record = transition_record(
            "https://origin.example.com",
            "https://origin.example.com",
            "https://intermediate.example.com",
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[record],
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::OwnershipTransitionActiveOwnerMismatch)
        );
    }

    #[test]
    fn ownership_chain_verifier_rejects_resource_type_with_all_true() {
        // Document resource type has all=true, which the chain verifier rejects.
        let document = ValidatedTrustGrantDocument::try_from(RawTrustGrantDocument {
            trustgrant_id: "tg_123e4567-e89b-12d3-a456-426614174000".into(),
            version: 0,
            grant_series_id: "tgs_123e4567-e89b-12d3-a456-426614174001".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://origin.example.com".into(),
            active_owning_authority: "https://successor.example.com".into(),
            key_id: "root-key-1".into(),
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
            resource_scope: RawResourceScope {
                types: BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: true, // <-- all=true triggers rejection at line 161
                        allow: None,
                        deny: None,
                        capabilities: RawTypeCapabilities::new(Some(true), Some(false)),
                        constraints: RawTypeConstraints::new(
                            RawMintingConstraints::new(None, None),
                            None,
                        ),
                        operations: None,
                    },
                )]),
            },
            global_constraints: None,
            revocation: None,
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "valid-signature".into(),
            issuer_principal: None,
        })
        .unwrap_or_else(|error| panic!("document should be valid: {error}"));

        let record = transition_record(
            "https://origin.example.com",
            "https://origin.example.com",
            "https://successor.example.com",
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[record],
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::OwnershipTransitionScopeMismatch)
        );
    }

    #[test]
    fn ownership_chain_verifier_rejects_selector_all_true_in_document() {
        // Document has a selector with all=true, which the chain verifier rejects.
        let document = ValidatedTrustGrantDocument::try_from(RawTrustGrantDocument {
            trustgrant_id: "tg_123e4567-e89b-12d3-a456-426614174000".into(),
            version: 0,
            grant_series_id: "tgs_123e4567-e89b-12d3-a456-426614174001".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://origin.example.com".into(),
            active_owning_authority: "https://successor.example.com".into(),
            key_id: "root-key-1".into(),
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
            resource_scope: RawResourceScope {
                types: BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "id".into(),
                            all: true, // <-- all=true on selector triggers rejection
                            values: None,
                            expressions: None,
                        }]),
                        deny: None,
                        capabilities: RawTypeCapabilities::new(Some(true), Some(false)),
                        constraints: RawTypeConstraints::new(
                            RawMintingConstraints::new(None, None),
                            None,
                        ),
                        operations: Some(RawOperationScope {
                            all: false,
                            allow: Some(vec!["custom:use".into()]),
                            deny: None,
                        }),
                    },
                )]),
            },
            global_constraints: None,
            revocation: None,
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "valid-signature".into(),
            issuer_principal: None,
        })
        .unwrap_or_else(|error| panic!("document should be valid: {error}"));

        let record = transition_record(
            "https://origin.example.com",
            "https://origin.example.com",
            "https://successor.example.com",
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[record],
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::OwnershipTransitionScopeMismatch)
        );
    }

    #[test]
    fn ownership_chain_verifier_rejects_uncovered_selector_value() {
        // Document requires values ["item_a", "item_b"] but transition only covers ["item_a"].
        let document = ValidatedTrustGrantDocument::try_from(RawTrustGrantDocument {
            trustgrant_id: "tg_123e4567-e89b-12d3-a456-426614174000".into(),
            version: 0,
            grant_series_id: "tgs_123e4567-e89b-12d3-a456-426614174001".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://origin.example.com".into(),
            active_owning_authority: "https://successor.example.com".into(),
            key_id: "root-key-1".into(),
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
            resource_scope: RawResourceScope {
                types: BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "id".into(),
                            all: false,
                            values: Some(vec!["item_a".into(), "item_b".into()]),
                            expressions: None,
                        }]),
                        deny: None,
                        capabilities: RawTypeCapabilities::new(Some(true), Some(false)),
                        constraints: RawTypeConstraints::new(
                            RawMintingConstraints::new(None, None),
                            None,
                        ),
                        operations: Some(RawOperationScope {
                            all: false,
                            allow: Some(vec!["custom:use".into()]),
                            deny: None,
                        }),
                    },
                )]),
            },
            global_constraints: None,
            revocation: None,
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "valid-signature".into(),
            issuer_principal: None,
        })
        .unwrap_or_else(|error| panic!("document should be valid: {error}"));

        // Transition covers only "item_a", not "item_b".
        let record = OwnershipTransitionRecord::new(
            OwnershipTransitionLineage::new(
                "tgt_123e4567-e89b-12d3-a456-426614174010"
                    .parse::<TransitionId>()
                    .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
                "tgts_123e4567-e89b-12d3-a456-426614174011"
                    .parse::<TransitionSeriesId>()
                    .unwrap_or_else(|error| panic!("transition series id should parse: {error}")),
                GrantRevision::new(1)
                    .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
                None,
            )
            .unwrap_or_else(|error| panic!("lineage should be valid: {error}")),
            OwnershipTransitionParties::new(
                authority("https://origin.example.com"),
                authority("https://origin.example.com"),
                authority("https://successor.example.com"),
            )
            .unwrap_or_else(|error| panic!("parties should be valid: {error}")),
            BTreeMap::from([(
                ResourceTypeName::new("item")
                    .unwrap_or_else(|error| panic!("resource type should be valid: {error}")),
                OwnershipResourceScope::new(vec![
                    OwnershipSelector::new("id", vec!["item_a".into()])
                        .unwrap_or_else(|error| panic!("selector should be valid: {error}")),
                ])
                .unwrap_or_else(|error| panic!("resource scope should be valid: {error}")),
            )]),
            None,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        )
        .unwrap_or_else(|error| panic!("transition record should be valid: {error}"));

        let result = OwnershipChainVerifier::new().verify_document_ownership(
            &document,
            &[record],
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::OwnershipTransitionScopeMismatch)
        );
    }
}
