use chrono::{DateTime, Utc};
use compact_str::CompactString;

use trustgrant_document::RawTrustGrantDocument;
use trustgrant_document::raw::{
    InteroperabilityProfile, RawAudienceEntry, RawCapabilities, RawGlobalConstraints, RawPrincipal,
    RawResourceScope, RawRevocation, RawScope, RawSupersessionPolicy, RawTimeWindow,
};
use trustgrant_domain::{
    AuthorityId, CanonicalizationProfile, GrantRevision, GrantSeriesId, KeyId, SupersessionPolicy,
    TrustGrantId,
};
use trustgrant_error::TrustGrantError;
use trustgrant_verify::{CanonicalTrustGrantBytes, canonicalize_trustgrant};

/// One validated set of authority identifiers for a TrustGrant draft.
///
/// Contains the issuer, origin, and active owning authority that together
/// define the authority boundary for a [`TrustGrantDraft`]. Use
/// [`Self::self_owned`] when all three authorities are the same (common
/// for first-party issuance), or [`Self::new`] when they differ (ownership
/// transfer scenarios).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustGrantDraftAuthorities {
    issuer_authority: AuthorityId,
    origin_authority: AuthorityId,
    active_owning_authority: AuthorityId,
}

impl TrustGrantDraftAuthorities {
    /// Creates one validated authority set where issuer, origin, and active
    /// owning authority are all the same authority.
    ///
    /// This is the common case for first-party issuance without ownership
    /// transfer.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the authority identifier is invalid.
    pub fn self_owned(authority: impl Into<String>) -> Result<Self, TrustGrantError> {
        let authority = AuthorityId::new(authority)?;

        Ok(Self {
            issuer_authority: authority.clone(),
            origin_authority: authority.clone(),
            active_owning_authority: authority,
        })
    }

    /// Creates one validated authority set for issuer-side TrustGrant drafts.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when one of the authority identifiers is
    /// invalid.
    pub fn new(
        issuer_authority: impl Into<String>,
        origin_authority: impl Into<String>,
        active_owning_authority: impl Into<String>,
    ) -> Result<Self, TrustGrantError> {
        Ok(Self {
            issuer_authority: AuthorityId::new(issuer_authority)?,
            origin_authority: AuthorityId::new(origin_authority)?,
            active_owning_authority: AuthorityId::new(active_owning_authority)?,
        })
    }
}

/// One issuer-side TrustGrant draft before cryptographic signing.
///
/// A draft carries the full grant payload with auto-generated protocol
/// identifiers ([`TrustGrantId`], [`GrantSeriesId`]). Builder-pattern
/// methods let you refine the draft (lineage, time window, audience,
/// revocation, principal) before producing a signable document.
///
/// # Lifecycle
///
/// 1. **Draft** — [`TrustGrantDraft::new`] creates the initial draft.
/// 2. **Refine** — use `with_*` methods to customise the draft.
/// 3. **Signable** — [`signable_document`](Self::signable_document)
///    or [`canonical_bytes`](Self::canonical_bytes) produces the payload
///    to be signed.
/// 4. **Signed** — [`into_signed_document`](Self::into_signed_document)
///    attaches the cryptographic signature and yields the final
///    [`RawTrustGrantDocument`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustGrantDraft {
    trustgrant_id: TrustGrantId,
    grant_series_id: GrantSeriesId,
    revision: GrantRevision,
    supersedes: Option<TrustGrantId>,
    supersession_policy: SupersessionPolicy,
    issuer_authority: AuthorityId,
    origin_authority: AuthorityId,
    active_owning_authority: AuthorityId,
    key_id: KeyId,
    target_scope: RawScope,
    capabilities: RawCapabilities,
    default_audience_scope: Vec<RawAudienceEntry>,
    resource_scope: RawResourceScope,
    global_time_window: Option<RawTimeWindow>,
    revocation: Option<RawRevocation>,
    issued_at: DateTime<Utc>,
    issuer_principal: Option<RawPrincipal>,
    interoperability_profile: Option<InteroperabilityProfile>,
}

impl TrustGrantDraft {
    /// Creates one issuer-side TrustGrant draft with generated protocol IDs.
    ///
    /// # Examples
    ///
    /// Basic draft → signable → signed flow:
    ///
    /// ```rust
    /// # use std::collections::BTreeMap;
    /// # use chrono::{TimeZone, Utc};
    /// # use trustgrant_document::raw::{
    /// #     RawCapabilities, RawResourceScope, RawScope,
    /// # };
    /// # use trustgrant_issue::{TrustGrantDraft, TrustGrantDraftAuthorities};
    /// let authorities = TrustGrantDraftAuthorities::self_owned(
    ///     "https://issuer.example.com",
    /// )
    /// .expect("valid authorities");
    ///
    /// let draft = TrustGrantDraft::new(
    ///     authorities,
    ///     "root-key-1",
    ///     RawScope::all(),
    ///     RawCapabilities::new(true, false),
    ///     RawResourceScope::new(BTreeMap::new()),
    ///     Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
    ///         .single()
    ///         .expect("valid timestamp"),
    /// )
    /// .expect("valid draft");
    ///
    /// // Draft → signable document (borrows the draft)
    /// let signable = draft.signable_document().expect("signable document");
    /// assert!(signable.signature.is_empty());
    ///
    /// // Signable → signed document (consumes the draft)
    /// let signed = draft
    ///     .into_signed_document("valid-signature-v1")
    ///     .expect("signed document");
    /// assert_eq!(signed.signature, "valid-signature-v1");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when one of the authority or key identity
    /// fields is invalid.
    pub fn new(
        authorities: TrustGrantDraftAuthorities,
        key_id: impl Into<String>,
        target_scope: RawScope,
        capabilities: RawCapabilities,
        resource_scope: RawResourceScope,
        issued_at: DateTime<Utc>,
    ) -> Result<Self, TrustGrantError> {
        Ok(Self {
            trustgrant_id: TrustGrantId::generate(),
            grant_series_id: GrantSeriesId::generate(),
            revision: GrantRevision::new(1)?,
            supersedes: None,
            supersession_policy: SupersessionPolicy::Coexist,
            issuer_authority: authorities.issuer_authority,
            origin_authority: authorities.origin_authority,
            active_owning_authority: authorities.active_owning_authority,
            key_id: KeyId::new(key_id)?,
            target_scope,
            capabilities,
            default_audience_scope: Vec::new(),
            resource_scope,
            global_time_window: None,
            revocation: None,
            issued_at,
            issuer_principal: None,
            interoperability_profile: None,
        })
    }

    /// Generated trustgrant id should be used for publication or signing.
    pub const fn trustgrant_id(&self) -> TrustGrantId {
        self.trustgrant_id
    }

    /// Generated grant series id should be used for lineage-aware issuance.
    #[must_use]
    pub const fn grant_series_id(&self) -> GrantSeriesId {
        self.grant_series_id
    }

    /// Applies one explicit lineage override to the draft.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the requested supersession policy
    /// cannot be represented by the TrustGrant v0 wire contract.
    pub fn with_lineage(
        mut self,
        grant_series_id: GrantSeriesId,
        revision: GrantRevision,
        supersedes: Option<TrustGrantId>,
        supersession_policy: SupersessionPolicy,
    ) -> Result<Self, TrustGrantError> {
        if matches!(
            supersession_policy,
            SupersessionPolicy::ExplicitRevocationRequired
        ) {
            return Err(TrustGrantError::UnsupportedV0WireSupersessionPolicy);
        }

        if revision.get() == 1 && supersedes.is_some() {
            return Err(TrustGrantError::InvalidSupersedesForFirstRevision);
        }

        if supersedes == Some(self.trustgrant_id) {
            return Err(TrustGrantError::SelfSupersession);
        }

        self.grant_series_id = grant_series_id;
        self.revision = revision;
        self.supersedes = supersedes;
        self.supersession_policy = supersession_policy;
        Ok(self)
    }

    /// Draft updates should be chained into the final signable draft.
    pub fn with_default_audience_scope(mut self, audience_scope: Vec<RawAudienceEntry>) -> Self {
        self.default_audience_scope = audience_scope;
        self
    }

    /// Draft updates should be chained into the final signable draft.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the provided time window is inverted.
    pub fn with_global_time_window(
        mut self,
        time_window: RawTimeWindow,
    ) -> Result<Self, TrustGrantError> {
        if time_window.not_before > time_window.not_after {
            return Err(TrustGrantError::InvalidTimeWindow);
        }

        self.global_time_window = Some(time_window);
        Ok(self)
    }

    /// Draft updates should be chained into the final signable draft.
    pub fn with_revocation(mut self, revocation: RawRevocation) -> Self {
        self.revocation = Some(revocation);
        self
    }

    /// Draft updates should be chained into the final signable draft.
    #[must_use]
    pub fn with_issuer_principal(mut self, issuer_principal: RawPrincipal) -> Self {
        self.issuer_principal = Some(issuer_principal);
        self
    }

    /// Sets the interoperability profile for this draft grant.
    #[must_use]
    pub fn with_interoperability_profile(
        mut self,
        interoperability_profile: InteroperabilityProfile,
    ) -> Self {
        self.interoperability_profile = Some(interoperability_profile);
        self
    }

    /// Builds one raw TrustGrant document suitable for canonical signing.
    ///
    /// Protocol rule:
    /// - the `signature` field is excluded from the signed canonical payload
    ///
    /// Current draft tooling represents that signable payload with an empty
    /// `signature` field before finalization. That empty value is an internal
    /// issuance-helper representation, not the protocol rule itself.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the current draft cannot be expressed
    /// by the TrustGrant v0 wire contract.
    pub fn signable_document(&self) -> Result<RawTrustGrantDocument, TrustGrantError> {
        let supersession_policy = match self.supersession_policy {
            SupersessionPolicy::Coexist => RawSupersessionPolicy::Coexist,
            SupersessionPolicy::SupersedePrevious => RawSupersessionPolicy::SupersedePrevious,
            SupersessionPolicy::ExplicitRevocationRequired => {
                return Err(TrustGrantError::UnsupportedV0WireSupersessionPolicy);
            }
        };

        Ok(RawTrustGrantDocument {
            trustgrant_id: self.trustgrant_id.to_string().into(),
            version: 0,
            grant_series_id: self.grant_series_id.to_string().into(),
            revision: self.revision.get(),
            supersedes: self.supersedes.map(|value| value.to_string().into()),
            supersession_policy,
            issuer_authority: self.issuer_authority.to_string().into(),
            origin_authority: self.origin_authority.to_string().into(),
            active_owning_authority: self.active_owning_authority.to_string().into(),
            key_id: self.key_id.as_str().to_owned().into(),
            target_scope: self.target_scope.clone(),
            capabilities: self.capabilities,
            default_audience_scope: (!self.default_audience_scope.is_empty())
                .then(|| self.default_audience_scope.clone()),
            resource_scope: self.resource_scope.clone(),
            global_constraints: self
                .global_time_window
                .as_ref()
                .map(|time| RawGlobalConstraints::new(Some(time.clone()))),
            revocation: self.revocation.clone(),
            issued_at: self.issued_at,
            signature: CompactString::new(""),
            issuer_principal: self.issuer_principal.clone(),
            interoperability_profile: self.interoperability_profile.clone(),
        })
    }

    fn into_signable_document(self) -> Result<RawTrustGrantDocument, TrustGrantError> {
        let Self {
            trustgrant_id,
            grant_series_id,
            revision,
            supersedes,
            supersession_policy,
            issuer_authority,
            origin_authority,
            active_owning_authority,
            key_id,
            target_scope,
            capabilities,
            default_audience_scope,
            resource_scope,
            global_time_window,
            revocation,
            issued_at,
            issuer_principal,
            interoperability_profile,
        } = self;

        let supersession_policy = match supersession_policy {
            SupersessionPolicy::Coexist => RawSupersessionPolicy::Coexist,
            SupersessionPolicy::SupersedePrevious => RawSupersessionPolicy::SupersedePrevious,
            SupersessionPolicy::ExplicitRevocationRequired => {
                return Err(TrustGrantError::UnsupportedV0WireSupersessionPolicy);
            }
        };

        Ok(RawTrustGrantDocument {
            trustgrant_id: trustgrant_id.to_string().into(),
            version: 0,
            grant_series_id: grant_series_id.to_string().into(),
            revision: revision.get(),
            supersedes: supersedes.map(|value| value.to_string().into()),
            supersession_policy,
            issuer_authority: issuer_authority.to_string().into(),
            origin_authority: origin_authority.to_string().into(),
            active_owning_authority: active_owning_authority.to_string().into(),
            key_id: key_id.as_str().to_owned().into(),
            target_scope,
            capabilities,
            default_audience_scope: (!default_audience_scope.is_empty())
                .then_some(default_audience_scope),
            resource_scope,
            global_constraints: global_time_window
                .map(|time| RawGlobalConstraints::new(Some(time))),
            revocation,
            issued_at,
            signature: CompactString::new(""),
            issuer_principal,
            interoperability_profile,
        })
    }

    /// Canonicalizes the current signable draft for signing under the TrustGrant
    /// rule that excludes `signature` from the signed payload.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when canonicalization fails.
    pub fn canonical_bytes(&self) -> Result<CanonicalTrustGrantBytes, TrustGrantError> {
        canonicalize_trustgrant(&self.signable_document()?, CanonicalizationProfile::Rfc8785)
    }

    /// Finalizes the draft into one signed raw TrustGrant document.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the provided signature is empty after
    /// trimming.
    pub fn into_signed_document(
        self,
        signature: impl Into<CompactString>,
    ) -> Result<RawTrustGrantDocument, TrustGrantError> {
        let signature = signature.into();

        if signature.trim().is_empty() {
            return Err(TrustGrantError::EmptyStringField("signature"));
        }

        let mut document = self.into_signable_document()?;
        document.signature = signature;
        Ok(document)
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{TimeZone, Utc};

    use super::{TrustGrantDraft, TrustGrantDraftAuthorities};
    use trustgrant_document::raw::{
        RawAudienceEntry, RawCapabilities, RawMintingConstraints, RawPrincipal, RawResourceScope,
        RawResourceType, RawRevocation, RawScope, RawSelector, RawTimeWindow, RawTypeCapabilities,
        RawTypeConstraints,
    };
    use trustgrant_domain::{GrantRevision, SupersessionPolicy, TrustGrantId, Utf16Key};
    use trustgrant_error::TrustGrantError;

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
                RawTypeConstraints::new(RawMintingConstraints::new(None, None), None),
                None,
            ),
        );
        RawResourceScope::new(types)
    }

    #[test]
    fn draft_generates_ids_and_produces_signable_document() {
        let draft = TrustGrantDraft::new(
            TrustGrantDraftAuthorities::self_owned("https://issuer.example.com")
                .unwrap_or_else(|error| panic!("authorities should be valid: {error}")),
            "root-key-1",
            RawScope::allow(vec![RawSelector::values(
                "authority",
                vec!["https://target.example.com".into()],
            )]),
            RawCapabilities::new(true, false),
            resource_scope(),
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        )
        .unwrap_or_else(|error| panic!("draft should be valid: {error}"));

        assert!(draft.trustgrant_id().to_string().starts_with("tg_"));
        assert!(draft.grant_series_id().to_string().starts_with("tgs_"));

        let signable = draft
            .signable_document()
            .unwrap_or_else(|error| panic!("signable document should be valid: {error}"));

        assert!(signable.signature.is_empty());
        assert_eq!(signable.version, 0);
    }

    #[test]
    fn draft_rejects_empty_signature_when_finalizing() {
        let draft = TrustGrantDraft::new(
            TrustGrantDraftAuthorities::self_owned("https://issuer.example.com")
                .unwrap_or_else(|error| panic!("authorities should be valid: {error}")),
            "root-key-1",
            RawScope::all(),
            RawCapabilities::new(true, false),
            resource_scope(),
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        )
        .unwrap_or_else(|error| panic!("draft should be valid: {error}"));

        assert!(draft.into_signed_document(" ").is_err());
    }

    #[test]
    fn draft_rejects_first_revision_with_supersedes() {
        let draft = TrustGrantDraft::new(
            TrustGrantDraftAuthorities::self_owned("https://issuer.example.com")
                .unwrap_or_else(|error| panic!("authorities should be valid: {error}")),
            "root-key-1",
            RawScope::all(),
            RawCapabilities::new(true, false),
            resource_scope(),
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        )
        .unwrap_or_else(|error| panic!("draft should be valid: {error}"));
        let grant_series_id = draft.grant_series_id();
        let trustgrant_id = draft.trustgrant_id();

        let result = draft.with_lineage(
            grant_series_id,
            GrantRevision::new(1)
                .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
            Some(trustgrant_id),
            SupersessionPolicy::Coexist,
        );

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidSupersedesForFirstRevision)
        );
    }

    #[test]
    fn draft_rejects_self_supersession() {
        let draft = TrustGrantDraft::new(
            TrustGrantDraftAuthorities::self_owned("https://issuer.example.com")
                .unwrap_or_else(|error| panic!("authorities should be valid: {error}")),
            "root-key-1",
            RawScope::all(),
            RawCapabilities::new(true, false),
            resource_scope(),
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        )
        .unwrap_or_else(|error| panic!("draft should be valid: {error}"));
        let grant_series_id = draft.grant_series_id();
        let trustgrant_id = draft.trustgrant_id();

        let result = draft.with_lineage(
            grant_series_id,
            GrantRevision::new(2)
                .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
            Some(trustgrant_id),
            SupersessionPolicy::Coexist,
        );

        assert_eq!(result, Err(TrustGrantError::SelfSupersession));
    }

    #[test]
    fn draft_rejects_inverted_global_time_window() {
        let draft = TrustGrantDraft::new(
            TrustGrantDraftAuthorities::self_owned("https://issuer.example.com")
                .unwrap_or_else(|error| panic!("authorities should be valid: {error}")),
            "root-key-1",
            RawScope::all(),
            RawCapabilities::new(true, false),
            resource_scope(),
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        )
        .unwrap_or_else(|error| panic!("draft should be valid: {error}"));

        let result = draft.with_global_time_window(RawTimeWindow::new(
            Utc.with_ymd_and_hms(2026, 4, 9, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        ));

        assert_eq!(result, Err(TrustGrantError::InvalidTimeWindow));
    }

    #[test]
    fn canonical_bytes_produces_non_empty_deterministic_output() {
        let draft = TrustGrantDraft::new(
            TrustGrantDraftAuthorities::self_owned("https://issuer.example.com")
                .unwrap_or_else(|error| panic!("authorities should be valid: {error}")),
            "root-key-1",
            RawScope::allow(vec![RawSelector::values(
                "authority",
                vec!["https://target.example.com".into()],
            )]),
            RawCapabilities::new(true, false),
            resource_scope(),
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        )
        .unwrap_or_else(|error| panic!("draft should be valid: {error}"));

        let bytes1 = draft
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("canonical bytes should succeed: {error}"));
        assert!(
            !bytes1.as_slice().is_empty(),
            "canonical bytes should be non-empty"
        );

        let bytes2 = draft
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("second canonical_bytes should succeed: {error}"));
        assert_eq!(
            bytes1, bytes2,
            "canonical_bytes should produce deterministic output"
        );
    }

    #[test]
    fn authorities_new_stores_distinct_authorities() {
        let authorities = TrustGrantDraftAuthorities::new(
            "https://issuer.example.com",
            "https://origin.example.com",
            "https://owner.example.com",
        )
        .unwrap_or_else(|error| panic!("authorities should be valid: {error}"));

        let draft = TrustGrantDraft::new(
            authorities,
            "root-key-1",
            RawScope::all(),
            RawCapabilities::new(true, false),
            resource_scope(),
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        )
        .unwrap_or_else(|error| panic!("draft should be valid: {error}"));

        let signable = draft
            .signable_document()
            .unwrap_or_else(|error| panic!("signable document should be valid: {error}"));

        assert_eq!(signable.issuer_authority, "https://issuer.example.com");
        assert_eq!(signable.origin_authority, "https://origin.example.com");
        assert_eq!(
            signable.active_owning_authority,
            "https://owner.example.com"
        );
    }

    #[test]
    fn into_signed_document_produces_document_with_valid_signature() {
        let draft = TrustGrantDraft::new(
            TrustGrantDraftAuthorities::self_owned("https://issuer.example.com")
                .unwrap_or_else(|error| panic!("authorities should be valid: {error}")),
            "root-key-1",
            RawScope::all(),
            RawCapabilities::new(true, false),
            resource_scope(),
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        )
        .unwrap_or_else(|error| panic!("draft should be valid: {error}"));

        let signed = draft
            .into_signed_document("valid-signature-v1")
            .unwrap_or_else(|error| panic!("into_signed_document should succeed: {error}"));

        assert_eq!(signed.signature, "valid-signature-v1");
        assert!(
            signed.trustgrant_id.starts_with("tg_"),
            "signed document should have a valid trustgrant id"
        );
        assert_eq!(signed.version, 0);
    }

    #[test]
    fn with_default_audience_scope_sets_audience_on_draft() {
        let draft = TrustGrantDraft::new(
            TrustGrantDraftAuthorities::self_owned("https://issuer.example.com")
                .unwrap_or_else(|error| panic!("authorities should be valid: {error}")),
            "root-key-1",
            RawScope::all(),
            RawCapabilities::new(true, false),
            resource_scope(),
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        )
        .unwrap_or_else(|error| panic!("draft should be valid: {error}"))
        .with_default_audience_scope(vec![RawAudienceEntry::new(
            "https://audience.example.com",
            RawScope::allow(vec![RawSelector::values(
                "principal",
                vec!["user-1".into()],
            )]),
            None,
        )]);

        let signable = draft
            .signable_document()
            .unwrap_or_else(|error| panic!("signable document should be valid: {error}"));

        let audience = signable
            .default_audience_scope
            .as_ref()
            .unwrap_or_else(|| panic!("default_audience_scope should be set"));
        assert_eq!(audience.len(), 1);
        assert_eq!(
            audience
                .first()
                .unwrap_or_else(|| panic!("audience should have at least one entry"))
                .authority_id,
            "https://audience.example.com"
        );
    }

    #[test]
    fn with_revocation_sets_revocation_on_draft() {
        let revocation: RawRevocation = serde_json::from_value(serde_json::json!({
            "revocable": true,
            "revocation_endpoint": "https://example.com/revoke",
            "post_revocation_effect": "block_all"
        }))
        .unwrap_or_else(|error| panic!("revocation should deserialize: {error}"));

        let draft = TrustGrantDraft::new(
            TrustGrantDraftAuthorities::self_owned("https://issuer.example.com")
                .unwrap_or_else(|error| panic!("authorities should be valid: {error}")),
            "root-key-1",
            RawScope::all(),
            RawCapabilities::new(true, false),
            resource_scope(),
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        )
        .unwrap_or_else(|error| panic!("draft should be valid: {error}"))
        .with_revocation(revocation);

        let signable = draft
            .signable_document()
            .unwrap_or_else(|error| panic!("signable document should be valid: {error}"));

        let signable_revocation = signable
            .revocation
            .as_ref()
            .unwrap_or_else(|| panic!("revocation should be set"));
        assert!(signable_revocation.revocable);
        assert_eq!(
            signable_revocation.revocation_endpoint.as_str(),
            "https://example.com/revoke"
        );
    }

    #[test]
    fn with_issuer_principal_sets_principal_on_draft() {
        let draft = TrustGrantDraft::new(
            TrustGrantDraftAuthorities::self_owned("https://issuer.example.com")
                .unwrap_or_else(|error| panic!("authorities should be valid: {error}")),
            "root-key-1",
            RawScope::all(),
            RawCapabilities::new(true, false),
            resource_scope(),
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        )
        .unwrap_or_else(|error| panic!("draft should be valid: {error}"))
        .with_issuer_principal(RawPrincipal::new("service", "svc-123"));

        let signable = draft
            .signable_document()
            .unwrap_or_else(|error| panic!("signable document should be valid: {error}"));

        let principal = signable
            .issuer_principal
            .as_ref()
            .unwrap_or_else(|| panic!("issuer_principal should be set"));
        assert_eq!(principal.kind, "service");
        assert_eq!(principal.id, "svc-123");
    }

    #[test]
    fn draft_rejects_explicit_revocation_required_by_lineage() {
        let draft = TrustGrantDraft::new(
            TrustGrantDraftAuthorities::self_owned("https://issuer.example.com")
                .unwrap_or_else(|error| panic!("authorities should be valid: {error}")),
            "root-key-1",
            RawScope::all(),
            RawCapabilities::new(true, false),
            resource_scope(),
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        )
        .unwrap_or_else(|error| panic!("draft should be valid: {error}"));
        let grant_series_id = draft.grant_series_id();

        let result = draft.with_lineage(
            grant_series_id,
            GrantRevision::new(2)
                .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
            None,
            SupersessionPolicy::ExplicitRevocationRequired,
        );

        assert_eq!(
            result,
            Err(TrustGrantError::UnsupportedV0WireSupersessionPolicy)
        );
    }

    #[test]
    fn draft_with_lineage_accepts_revision_two() {
        let draft = TrustGrantDraft::new(
            TrustGrantDraftAuthorities::self_owned("https://issuer.example.com")
                .unwrap_or_else(|error| panic!("authorities should be valid: {error}")),
            "root-key-1",
            RawScope::all(),
            RawCapabilities::new(true, false),
            resource_scope(),
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        )
        .unwrap_or_else(|error| panic!("draft should be valid: {error}"));

        let series_id = draft.grant_series_id();
        // Use a different generated trustgrant id to avoid self-supersession.
        let prev_id = TrustGrantId::generate();

        // with_lineage should succeed for revision > 1
        let result = draft.with_lineage(
            series_id,
            GrantRevision::new(2)
                .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
            Some(prev_id),
            SupersessionPolicy::Coexist,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn draft_with_global_time_window_success() {
        let draft = TrustGrantDraft::new(
            TrustGrantDraftAuthorities::self_owned("https://issuer.example.com")
                .unwrap_or_else(|error| panic!("authorities should be valid: {error}")),
            "root-key-1",
            RawScope::all(),
            RawCapabilities::new(true, false),
            resource_scope(),
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        )
        .unwrap_or_else(|error| panic!("draft should be valid: {error}"));

        let result = draft.with_global_time_window(RawTimeWindow::new(
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
            Utc.with_ymd_and_hms(2026, 4, 9, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        ));

        assert!(result.is_ok());
    }

    #[test]
    fn signable_document_rejects_explicit_revocation_required() {
        // The signable_document() method also rejects
        // ExplicitRevocationRequired (line 214-216), but with_lineage() blocks
        // it first.  To exercise that path we must set the private field
        // directly — the test module has access because it is a child of the
        // defining module.
        let mut draft = TrustGrantDraft::new(
            TrustGrantDraftAuthorities::self_owned("https://issuer.example.com")
                .unwrap_or_else(|error| panic!("authorities should be valid: {error}")),
            "root-key-1",
            RawScope::all(),
            RawCapabilities::new(true, false),
            resource_scope(),
            Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid")),
        )
        .unwrap_or_else(|error| panic!("draft should be valid: {error}"));

        draft.supersession_policy = SupersessionPolicy::ExplicitRevocationRequired;

        let result = draft.signable_document();
        assert_eq!(
            result,
            Err(TrustGrantError::UnsupportedV0WireSupersessionPolicy)
        );
    }
}
