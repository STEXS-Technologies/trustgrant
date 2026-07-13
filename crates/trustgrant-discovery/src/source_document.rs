use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use url::Url;

use super::{AuthorityKeyRecord, DelegatedPrincipalRef, ResolvedSignerBinding, SignatureProfile};
use trustgrant_document::ValidatedPrincipal;
use trustgrant_domain::{AuthorityId, KeyId};
use trustgrant_error::TrustGrantError;
use trustgrant_error::limits::{
    MAX_DELEGATED_PRINCIPAL_JSON_BYTES, MAX_DISCOVERY_JSON_BYTES, MAX_DISCOVERY_KEYS,
    MAX_REVOCATION_ENDPOINTS, ensure_collection_limit, ensure_json_size,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRevocationPolicy {
    status_endpoint: Url,
    non_revoked_ttl_seconds: u64,
    max_stale_seconds: u64,
}

impl DiscoveryRevocationPolicy {
    /// Creates one validated discovery-side revocation policy.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when one of the TTL values is zero.
    pub fn new(
        status_endpoint: Url,
        non_revoked_ttl_seconds: u64,
        max_stale_seconds: u64,
    ) -> Result<Self, TrustGrantError> {
        if non_revoked_ttl_seconds == 0 || max_stale_seconds == 0 {
            return Err(TrustGrantError::InvalidRevocationPolicy);
        }

        Ok(Self {
            status_endpoint,
            non_revoked_ttl_seconds,
            max_stale_seconds,
        })
    }

    #[must_use = "status endpoint participates in revocation resolution"]
    pub const fn status_endpoint(&self) -> &Url {
        &self.status_endpoint
    }

    #[must_use = "non-revoked ttl participates in freshness normalization"]
    pub const fn non_revoked_ttl_seconds(&self) -> u64 {
        self.non_revoked_ttl_seconds
    }

    #[must_use = "max stale seconds participates in freshness normalization"]
    pub const fn max_stale_seconds(&self) -> u64 {
        self.max_stale_seconds
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryDelegation {
    principal_key_endpoint: Url,
}

impl DiscoveryDelegation {
    #[must_use = "principal key endpoint participates in delegated key resolution"]
    pub const fn new(principal_key_endpoint: Url) -> Self {
        Self {
            principal_key_endpoint,
        }
    }

    #[must_use = "principal key endpoint participates in delegated key resolution"]
    pub const fn principal_key_endpoint(&self) -> &Url {
        &self.principal_key_endpoint
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityDiscoveryDocument {
    authority_id: AuthorityId,
    keys: Vec<AuthorityKeyRecord>,
    signature_profile: SignatureProfile,
    revocation_policy: Option<DiscoveryRevocationPolicy>,
    revocation_endpoints: Vec<Url>,
    issued_at: DateTime<Utc>,
    delegation: Option<DiscoveryDelegation>,
}

impl AuthorityDiscoveryDocument {
    /// Resolves one root-authority signer binding from discovery material.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when authority mismatch occurs or the
    /// requested key is absent.
    pub fn resolve_root_signer_binding(
        &self,
        issuer_authority: &AuthorityId,
        key_id: &KeyId,
    ) -> Result<ResolvedSignerBinding, TrustGrantError> {
        if &self.authority_id != issuer_authority {
            return Err(TrustGrantError::DiscoveryAuthorityMismatch);
        }

        let key_record = self
            .keys
            .iter()
            .find(|record| record.key_id() == key_id)
            .cloned()
            .ok_or(TrustGrantError::MissingSigningKey)?;

        Ok(ResolvedSignerBinding::new(
            self.authority_id.clone(),
            key_record,
            self.signature_profile.clone(),
            None,
        ))
    }

    #[must_use = "authority id participates in issuer discovery validation"]
    pub const fn authority_id(&self) -> &AuthorityId {
        &self.authority_id
    }

    #[must_use = "keys participate in signing-key lookup"]
    pub fn keys(&self) -> &[AuthorityKeyRecord] {
        &self.keys
    }

    #[must_use = "signature profile participates in canonical verification"]
    pub const fn signature_profile(&self) -> &SignatureProfile {
        &self.signature_profile
    }

    #[must_use = "revocation policy participates in proof-source defaults"]
    pub const fn revocation_policy(&self) -> Option<&DiscoveryRevocationPolicy> {
        self.revocation_policy.as_ref()
    }

    #[must_use = "revocation endpoints participate in source-specific resolution"]
    pub fn revocation_endpoints(&self) -> &[Url] {
        &self.revocation_endpoints
    }

    #[must_use = "issued_at participates in discovery audit"]
    pub const fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    #[must_use = "delegation metadata participates in delegated-key routing"]
    pub const fn delegation(&self) -> Option<&DiscoveryDelegation> {
        self.delegation.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedPrincipalKeyDocument {
    authority_id: AuthorityId,
    principal: DelegatedPrincipalRef,
    keys: Vec<AuthorityKeyRecord>,
}

impl DelegatedPrincipalKeyDocument {
    /// Resolves one delegated signer binding from principal-key material.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when authority or principal mismatch occurs,
    /// or when the requested key is absent.
    pub fn resolve_signer_binding(
        &self,
        issuer_authority: &AuthorityId,
        issuer_principal: &ValidatedPrincipal,
        key_id: &KeyId,
        signature_profile: &SignatureProfile,
    ) -> Result<ResolvedSignerBinding, TrustGrantError> {
        if &self.authority_id != issuer_authority {
            return Err(TrustGrantError::DelegatedDiscoveryAuthorityMismatch);
        }

        if self.principal.kind().as_str() != issuer_principal.kind().as_str()
            || self.principal.id().as_str() != issuer_principal.id().as_str()
        {
            return Err(TrustGrantError::DelegatedPrincipalMismatch);
        }

        let key_record = self
            .keys
            .iter()
            .find(|record| record.key_id() == key_id)
            .cloned()
            .ok_or(TrustGrantError::MissingSigningKey)?;

        Ok(ResolvedSignerBinding::new(
            self.authority_id.clone(),
            key_record,
            signature_profile.clone(),
            Some(self.principal.clone()),
        ))
    }

    #[must_use = "authority id participates in delegated-key routing"]
    pub const fn authority_id(&self) -> &AuthorityId {
        &self.authority_id
    }

    #[must_use = "principal participates in delegated-key routing"]
    pub const fn principal(&self) -> &DelegatedPrincipalRef {
        &self.principal
    }

    #[must_use = "keys participate in delegated key lookup"]
    pub fn keys(&self) -> &[AuthorityKeyRecord] {
        &self.keys
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuthorityDiscoveryDocument {
    authority_id: String,
    keys: Vec<RawDiscoveryKeyRecord>,
    signature_profile: RawSignatureProfile,
    revocation_policy: Option<RawRevocationPolicy>,
    revocation_endpoints: Option<Vec<Url>>,
    issued_at: DateTime<Utc>,
    delegation: Option<RawDelegation>,
}

impl RawAuthorityDiscoveryDocument {
    fn parse_json_str(json: &str) -> Result<Self, TrustGrantError> {
        ensure_json_size("authority_discovery", json.len(), MAX_DISCOVERY_JSON_BYTES)?;
        serde_json::from_str(json).map_err(|_error| TrustGrantError::InvalidDiscoveryDocument)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignatureProfile {
    format: String,
    canonicalization: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDiscoveryKeyRecord {
    key_id: String,
    algorithm: String,
    public_key: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRevocationPolicy {
    status_endpoint: Url,
    non_revoked_ttl_seconds: u64,
    max_stale_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDelegation {
    principals_supported: bool,
    principal_key_endpoint: Url,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDelegatedPrincipalKeyDocument {
    authority_id: String,
    principal: RawDelegatedPrincipal,
    keys: Vec<RawDelegatedKeyRecord>,
}

impl RawDelegatedPrincipalKeyDocument {
    fn parse_json_str(json: &str) -> Result<Self, TrustGrantError> {
        ensure_json_size(
            "delegated_principal_key",
            json.len(),
            MAX_DELEGATED_PRINCIPAL_JSON_BYTES,
        )?;
        serde_json::from_str(json)
            .map_err(|_error| TrustGrantError::InvalidDelegatedPrincipalDocument)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDelegatedPrincipal {
    kind: String,
    id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDelegatedKeyRecord {
    key_id: String,
    algorithm: String,
    public_key: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    revoked: bool,
}

impl TryFrom<RawAuthorityDiscoveryDocument> for AuthorityDiscoveryDocument {
    type Error = TrustGrantError;

    fn try_from(raw: RawAuthorityDiscoveryDocument) -> Result<Self, Self::Error> {
        ensure_collection_limit("discovery.keys", raw.keys.len(), MAX_DISCOVERY_KEYS)?;
        let authority_id = AuthorityId::new(raw.authority_id)?;
        let keys = collect_unique_key_records(raw.keys)?;
        let signature_profile = SignatureProfile::new(
            raw.signature_profile.format,
            raw.signature_profile.canonicalization,
        )?;
        let revocation_policy = raw
            .revocation_policy
            .map(|policy| {
                DiscoveryRevocationPolicy::new(
                    policy.status_endpoint,
                    policy.non_revoked_ttl_seconds,
                    policy.max_stale_seconds,
                )
            })
            .transpose()?;
        let revocation_endpoints = raw.revocation_endpoints.unwrap_or_default();
        ensure_collection_limit(
            "discovery.revocation_endpoints",
            revocation_endpoints.len(),
            MAX_REVOCATION_ENDPOINTS,
        )?;
        let delegation = match raw.delegation {
            Some(delegation) if delegation.principals_supported => {
                Some(DiscoveryDelegation::new(delegation.principal_key_endpoint))
            }
            Some(_delegation) => return Err(TrustGrantError::InvalidDiscoveryDocument),
            None => None,
        };

        Ok(Self {
            authority_id,
            keys,
            signature_profile,
            revocation_policy,
            revocation_endpoints,
            issued_at: raw.issued_at,
            delegation,
        })
    }
}

impl TryFrom<RawDelegatedPrincipalKeyDocument> for DelegatedPrincipalKeyDocument {
    type Error = TrustGrantError;

    fn try_from(raw: RawDelegatedPrincipalKeyDocument) -> Result<Self, Self::Error> {
        ensure_collection_limit(
            "delegated_principal.keys",
            raw.keys.len(),
            MAX_DISCOVERY_KEYS,
        )?;
        let authority_id = AuthorityId::new(raw.authority_id)?;
        let principal = DelegatedPrincipalRef::new(raw.principal.kind, raw.principal.id)?;
        let keys =
            collect_unique_key_records(raw.keys.into_iter().filter(|record| !record.revoked))?;

        Ok(Self {
            authority_id,
            principal,
            keys,
        })
    }
}

/// Parses and normalizes one authority discovery document.
///
/// # Errors
///
/// Returns [`TrustGrantError`] when the JSON or normalized discovery state is
/// invalid.
pub fn parse_authority_discovery_document(
    json: &str,
) -> Result<AuthorityDiscoveryDocument, TrustGrantError> {
    RawAuthorityDiscoveryDocument::parse_json_str(json)?.try_into()
}

/// Parses and normalizes one delegated-principal key document.
///
/// # Errors
///
/// Returns [`TrustGrantError`] when the JSON or normalized delegated-principal
/// key state is invalid.
pub fn parse_delegated_principal_key_document(
    json: &str,
) -> Result<DelegatedPrincipalKeyDocument, TrustGrantError> {
    RawDelegatedPrincipalKeyDocument::parse_json_str(json)?.try_into()
}

fn collect_unique_key_records(
    raw_records: impl IntoIterator<Item = impl Into<RawKeyRecordLike>>,
) -> Result<Vec<AuthorityKeyRecord>, TrustGrantError> {
    let mut seen_key_ids = HashSet::new();
    let mut keys = Vec::new();

    for raw_record in raw_records {
        let raw_record: RawKeyRecordLike = raw_record.into();
        let key = AuthorityKeyRecord::new(
            raw_record.key_id,
            raw_record.algorithm,
            raw_record.public_key,
            raw_record.not_before,
            raw_record.not_after,
        )?;

        if !seen_key_ids.insert(key.key_id().as_str().to_owned()) {
            return Err(TrustGrantError::DuplicateKeyId);
        }

        keys.push(key);
    }

    Ok(keys)
}

struct RawKeyRecordLike {
    key_id: String,
    algorithm: String,
    public_key: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

impl From<RawDiscoveryKeyRecord> for RawKeyRecordLike {
    fn from(value: RawDiscoveryKeyRecord) -> Self {
        Self {
            key_id: value.key_id,
            algorithm: value.algorithm,
            public_key: value.public_key,
            not_before: value.not_before,
            not_after: value.not_after,
        }
    }
}

impl From<RawDelegatedKeyRecord> for RawKeyRecordLike {
    fn from(value: RawDelegatedKeyRecord) -> Self {
        Self {
            key_id: value.key_id,
            algorithm: value.algorithm,
            public_key: value.public_key,
            not_before: value.not_before,
            not_after: value.not_after,
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::SignatureProfile;
    use super::{
        DiscoveryDelegation, DiscoveryRevocationPolicy, parse_authority_discovery_document,
        parse_delegated_principal_key_document,
    };
    use trustgrant_document::{ValidatedPrincipal, raw::RawPrincipal};
    use trustgrant_domain::{AuthorityId, KeyId};
    use trustgrant_error::TrustGrantError;
    use trustgrant_error::limits::MAX_DISCOVERY_KEYS;

    #[test]
    fn discovery_document_parses_and_resolves_root_signer() {
        let document = match parse_authority_discovery_document(
            r#"{
              "authority_id":"https://issuer.example.com",
              "keys":[
                {
                  "key_id":"root-key-1",
                  "algorithm":"ed25519",
                  "public_key":"base64-public-key",
                  "not_before":"2026-04-07T12:00:00Z",
                  "not_after":"2026-04-08T12:00:00Z"
                }
              ],
              "signature_profile":{
                "format":"jcs+ed25519",
                "canonicalization":"RFC8785"
              },
              "revocation_policy":{
                "status_endpoint":"https://issuer.example.com/trustgrant/revoke",
                "non_revoked_ttl_seconds":120,
                "max_stale_seconds":900
              },
              "issued_at":"2026-04-07T12:00:00Z"
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("discovery document should parse: {error}"),
        };

        assert_eq!(document.keys().len(), 1);
        assert!(document.revocation_policy().is_some());

        let signer = match document.resolve_root_signer_binding(
            &authority("https://issuer.example.com"),
            &key_id("root-key-1"),
        ) {
            Ok(value) => value,
            Err(error) => panic!("root signer binding should resolve: {error}"),
        };

        assert_eq!(signer.key_record().key_id().as_str(), "root-key-1");
    }

    #[test]
    fn delegated_principal_document_rejects_principal_mismatch() {
        let document = match parse_delegated_principal_key_document(
            r#"{
              "authority_id":"https://issuer.example.com",
              "principal":{"kind":"project","id":"alpha"},
              "keys":[
                {
                  "key_id":"project-key-1",
                  "algorithm":"ed25519",
                  "public_key":"base64-public-key",
                  "not_before":"2026-04-07T12:00:00Z",
                  "not_after":"2026-04-08T12:00:00Z",
                  "revoked":false
                }
              ]
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("delegated principal document should parse: {error}"),
        };

        let result = document.resolve_signer_binding(
            &authority("https://issuer.example.com"),
            &validated_principal("project", "beta"),
            &key_id("project-key-1"),
            &signature_profile(),
        );

        assert_eq!(result, Err(TrustGrantError::DelegatedPrincipalMismatch));
    }

    #[test]
    fn delegated_principal_document_resolves_matching_principal() {
        let document = match parse_delegated_principal_key_document(
            r#"{
              "authority_id":"https://issuer.example.com",
              "principal":{"kind":"project","id":"alpha"},
              "keys":[
                {
                  "key_id":"project-key-1",
                  "algorithm":"ed25519",
                  "public_key":"base64-public-key",
                  "not_before":"2026-04-07T12:00:00Z",
                  "not_after":"2026-04-08T12:00:00Z",
                  "revoked":false
                }
              ]
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("delegated principal document should parse: {error}"),
        };

        let signer = match document.resolve_signer_binding(
            &authority("https://issuer.example.com"),
            &validated_principal("project", "alpha"),
            &key_id("project-key-1"),
            &signature_profile(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("delegated signer binding should resolve: {error}"),
        };

        assert_eq!(
            signer
                .delegated_principal()
                .map(|principal| principal.id().as_str()),
            Some("alpha")
        );
    }

    #[test]
    fn discovery_document_rejects_duplicate_key_ids() {
        let result = parse_authority_discovery_document(
            r#"{
              "authority_id":"https://issuer.example.com",
              "keys":[
                {
                  "key_id":"root-key-1",
                  "algorithm":"ed25519",
                  "public_key":"base64-public-key-1",
                  "not_before":"2026-04-07T12:00:00Z",
                  "not_after":"2026-04-08T12:00:00Z"
                },
                {
                  "key_id":"root-key-1",
                  "algorithm":"ed25519",
                  "public_key":"base64-public-key-2",
                  "not_before":"2026-04-07T12:00:00Z",
                  "not_after":"2026-04-08T12:00:00Z"
                }
              ],
              "signature_profile":{
                "format":"jcs+ed25519",
                "canonicalization":"RFC8785"
              },
              "issued_at":"2026-04-07T12:00:00Z"
            }"#,
        );

        assert_eq!(result, Err(TrustGrantError::DuplicateKeyId));
    }

    #[test]
    fn discovery_document_rejects_too_many_keys() {
        let keys = (0..=MAX_DISCOVERY_KEYS)
            .map(|index| {
                format!(
                    r#"{{
                      "key_id":"root-key-{index}",
                      "algorithm":"ed25519",
                      "public_key":"base64-public-key-{index}",
                      "not_before":"2026-04-07T12:00:00Z",
                      "not_after":"2026-04-08T12:00:00Z"
                    }}"#
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(
            r#"{{
              "authority_id":"https://issuer.example.com",
              "keys":[{keys}],
              "signature_profile":{{
                "format":"jcs+ed25519",
                "canonicalization":"RFC8785"
              }},
              "issued_at":"2026-04-07T12:00:00Z"
            }}"#
        );

        let result = parse_authority_discovery_document(&json);

        assert_eq!(
            result,
            Err(TrustGrantError::CollectionTooLarge {
                field: "discovery.keys",
                max_items: MAX_DISCOVERY_KEYS,
            })
        );
    }

    #[test]
    fn discovery_document_rejects_unknown_fields() {
        let result = parse_authority_discovery_document(
            r#"{
              "authority_id":"https://issuer.example.com",
              "keys":[
                {
                  "key_id":"root-key-1",
                  "algorithm":"ed25519",
                  "public_key":"base64-public-key",
                  "not_before":"2026-04-07T12:00:00Z",
                  "not_after":"2026-04-08T12:00:00Z"
                }
              ],
              "signature_profile":{"format":"jcs+ed25519","canonicalization":"RFC8785"},
              "revocation_policy":null,
              "revocation_endpoints":[],
              "issued_at":"2026-04-07T12:00:00Z",
              "delegation":null,
              "unexpected":"value"
            }"#,
        );

        assert_eq!(result, Err(TrustGrantError::InvalidDiscoveryDocument));
    }

    #[test]
    fn revocation_policy_constructs_with_valid_data_and_accessors_return_expected_values() {
        let endpoint: url::Url = "https://issuer.example.com/trustgrant/revoke"
            .parse()
            .unwrap_or_else(|e| panic!("valid URL: {e}"));
        let policy = DiscoveryRevocationPolicy::new(endpoint.clone(), 120, 900)
            .unwrap_or_else(|e| panic!("valid policy: {e}"));

        assert_eq!(policy.status_endpoint(), &endpoint);
        assert_eq!(policy.non_revoked_ttl_seconds(), 120);
        assert_eq!(policy.max_stale_seconds(), 900);
    }

    #[test]
    fn revocation_policy_rejects_zero_non_revoked_ttl() {
        let endpoint: url::Url = "https://issuer.example.com/trustgrant/revoke"
            .parse()
            .unwrap_or_else(|e| panic!("valid URL: {e}"));
        let result = DiscoveryRevocationPolicy::new(endpoint, 0, 900);

        assert_eq!(result, Err(TrustGrantError::InvalidRevocationPolicy));
    }

    #[test]
    fn revocation_policy_rejects_zero_max_stale() {
        let endpoint: url::Url = "https://issuer.example.com/trustgrant/revoke"
            .parse()
            .unwrap_or_else(|e| panic!("valid URL: {e}"));
        let result = DiscoveryRevocationPolicy::new(endpoint, 120, 0);

        assert_eq!(result, Err(TrustGrantError::InvalidRevocationPolicy));
    }

    #[test]
    fn delegation_constructs_with_valid_data_and_accessor_returns_expected_value() {
        let endpoint: url::Url = "https://issuer.example.com/trustgrant/delegated-principals"
            .parse()
            .unwrap_or_else(|e| panic!("valid URL: {e}"));
        let delegation = DiscoveryDelegation::new(endpoint.clone());

        assert_eq!(delegation.principal_key_endpoint(), &endpoint);
    }

    #[test]
    fn delegated_principal_document_rejects_revoked_keys() {
        // When all keys in a delegated principal document have revoked=true,
        // the keys are filtered out during construction. Resolution of any key
        // must therefore fail with MissingSigningKey.
        let document = match parse_delegated_principal_key_document(
            r#"{
              "authority_id":"https://issuer.example.com",
              "principal":{"kind":"project","id":"alpha"},
              "keys":[
                {
                  "key_id":"revoked-key-1",
                  "algorithm":"ed25519",
                  "public_key":"base64-public-key",
                  "not_before":"2026-04-07T12:00:00Z",
                  "not_after":"2026-04-08T12:00:00Z",
                  "revoked":true
                }
              ]
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("delegated principal document should parse: {error}"),
        };

        // The revoked key should have been filtered out, leaving zero keys.
        assert!(
            document.keys().is_empty(),
            "revoked key should be filtered out",
        );

        // Resolution must fail because no keys are available.
        let result = document.resolve_signer_binding(
            &authority("https://issuer.example.com"),
            &validated_principal("project", "alpha"),
            &key_id("revoked-key-1"),
            &signature_profile(),
        );

        assert_eq!(result, Err(TrustGrantError::MissingSigningKey));
    }

    #[test]
    fn discovery_document_rejects_authority_mismatch() {
        let document = match parse_authority_discovery_document(
            r#"{
              "authority_id":"https://issuer.example.com",
              "keys":[
                {
                  "key_id":"root-key-1",
                  "algorithm":"ed25519",
                  "public_key":"base64-public-key",
                  "not_before":"2026-04-07T12:00:00Z",
                  "not_after":"2026-04-08T12:00:00Z"
                }
              ],
              "signature_profile":{"format":"jcs+ed25519","canonicalization":"RFC8785"},
              "issued_at":"2026-04-07T12:00:00Z"
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("discovery document should parse: {error}"),
        };

        let result = document.resolve_root_signer_binding(
            &authority("https://other.example.com"),
            &key_id("root-key-1"),
        );

        assert_eq!(result, Err(TrustGrantError::DiscoveryAuthorityMismatch));
    }

    #[test]
    fn discovery_document_accessors_return_expected_values() {
        let document = match parse_authority_discovery_document(
            r#"{
              "authority_id":"https://issuer.example.com",
              "keys":[
                {
                  "key_id":"root-key-1",
                  "algorithm":"ed25519",
                  "public_key":"base64-public-key",
                  "not_before":"2026-04-07T12:00:00Z",
                  "not_after":"2026-04-08T12:00:00Z"
                }
              ],
              "signature_profile":{"format":"jcs+ed25519","canonicalization":"RFC8785"},
              "revocation_endpoints":["https://issuer.example.com/revoke"],
              "issued_at":"2026-04-07T12:00:00Z"
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("discovery document should parse: {error}"),
        };

        assert_eq!(document.revocation_endpoints().len(), 1);
        assert_eq!(
            document
                .revocation_endpoints()
                .first()
                .map(|e| e.as_str())
                .unwrap_or_else(|| panic!("expected at least one revocation endpoint")),
            "https://issuer.example.com/revoke"
        );
        assert_eq!(
            document.issued_at(),
            Utc.with_ymd_and_hms(2026, 4, 7, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("timestamp should be valid"))
        );
    }

    #[test]
    fn delegated_principal_document_rejects_authority_mismatch() {
        let document = match parse_delegated_principal_key_document(
            r#"{
              "authority_id":"https://issuer.example.com",
              "principal":{"kind":"project","id":"alpha"},
              "keys":[
                {
                  "key_id":"project-key-1",
                  "algorithm":"ed25519",
                  "public_key":"base64-public-key",
                  "not_before":"2026-04-07T12:00:00Z",
                  "not_after":"2026-04-08T12:00:00Z",
                  "revoked":false
                }
              ]
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("delegated principal document should parse: {error}"),
        };

        let result = document.resolve_signer_binding(
            &authority("https://other.example.com"),
            &validated_principal("project", "alpha"),
            &key_id("project-key-1"),
            &signature_profile(),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::DelegatedDiscoveryAuthorityMismatch)
        );
    }

    fn authority(value: &str) -> AuthorityId {
        match AuthorityId::new(value) {
            Ok(value) => value,
            Err(error) => panic!("authority should be valid: {error}"),
        }
    }

    fn key_id(value: &str) -> KeyId {
        match KeyId::new(value) {
            Ok(value) => value,
            Err(error) => panic!("key id should be valid: {error}"),
        }
    }

    fn signature_profile() -> SignatureProfile {
        match SignatureProfile::new("jcs+ed25519", "RFC8785") {
            Ok(value) => value,
            Err(error) => panic!("signature profile should be valid: {error}"),
        }
    }

    fn validated_principal(kind: &str, id: &str) -> ValidatedPrincipal {
        ValidatedPrincipal::try_from(RawPrincipal {
            kind: kind.into(),
            id: id.into(),
        })
        .unwrap_or_else(|error| panic!("validated principal should be valid: {error}"))
    }
}
