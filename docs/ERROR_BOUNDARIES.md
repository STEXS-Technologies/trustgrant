# TrustGrant Error Boundaries

## Overview

TrustGrant errors fall into two categories: **fatal** and **recoverable**.
Fatal errors mean the input is malformed or the protocol is violated —
retrying with the same inputs will always fail. Recoverable errors mean a
transient condition may resolve on retry with fresh data.

## Fatal errors (do not retry)

These errors indicate that the trust grant document itself is invalid, the
signature doesn't match, or the protocol is being used incorrectly. Retrying
with the same inputs will never succeed.

| Error variant | Description | Typical cause |
|---|---|---|
| `EmptyAuthorityId` | The authority ID field is empty. | A document or discovery record was constructed without an `authority_id`. |
| `EmptyStringField` | A required string field is empty. | A field like `key_id`, `operation`, or `scope_id` was set to an empty string. |
| `InvalidStringFieldCharacter` | A field contains an invalid character. | A field value includes a character not permitted by the string validation rules. |
| `InvalidAuthorityIdCharacter` | The authority ID contains an invalid character. | An authority ID includes a space, control character, or other disallowed symbol. |
| `InvalidAuthorityIdMissingScheme` | The authority ID lacks a scheme prefix. | An authority ID is provided as `example:user` instead of `did:example:user`. |
| `InvalidScopeShape` | A scope has an invalid all/allow shape. | A resource scope combines `all` with explicit allow entries in an unsupported way. |
| `InvalidSelectorShape` | A selector has an invalid all/values/expressions shape. | A field selector mixes `all` with explicit values or expressions. |
| `UnsupportedSelectorExpressionPredicate` | A selector expression uses an unsupported predicate. | A selector uses `regex` or another predicate that the implementation does not support. |
| `InvalidSelectorExpressionSyntax` | A selector expression has invalid syntax. | A selector expression string is malformed and cannot be parsed. |
| `DocumentTooLarge` | A document exceeds the maximum allowed size. | The trust grant JSON document is larger than the implementation limit (e.g., 64 KiB). |
| `CollectionTooLarge` | A collection exceeds the maximum allowed number of items. | The `selectors` array contains more entries than the maximum allowed. |
| `StringTooLong` | A string field exceeds the maximum allowed size in bytes. | A `key_id` or `operation` value is longer than the implementation limit (e.g., 256 bytes). |
| `DuplicateSelector` | A duplicate selector is present in the document. | The same field selector appears twice in the `selectors` array. |
| `DuplicateKeyId` | A duplicate key ID is present in the discovery material. | The same `key_id` appears in multiple keys within an authority discovery document. |
| `DuplicateOperationName` | A duplicate operation name is present. | The same custom operation name appears more than once in the document. |
| `ReservedOperationName` | A custom operation name reuses a reserved built-in name. | A custom operation is named `recognize`, `mint`, or `create`, which conflicts with built-in operations. |
| `InvalidJsonDocument` | The trust grant document JSON is invalid. | The document cannot be parsed as valid JSON or is structurally incorrect. |
| `CanonicalizationFailure` | Canonicalization of the document failed. | The document contains constructs that cannot be canonicalized (e.g., unsupported number formats). |
| `InvalidDiscoveryDocument` | The authority discovery document JSON is invalid. | A fetched or provided discovery document fails JSON validation. |
| `InvalidDelegatedPrincipalDocument` | The delegated principal key document JSON is invalid. | A delegated principal document cannot be parsed or validated. |
| `InvalidRevocationProofDocument` | The revocation proof JSON is invalid. | A revocation proof document fails JSON structure validation. |
| `InvalidOwnershipTransitionDocument` | The ownership transition JSON is invalid. | An ownership transition document cannot be parsed or validated. |
| `SignatureVerificationFailed` | The trust grant signature verification failed. | The cryptographic signature on the document does not match the claimed signer key. |
| `OwnershipTransitionPredecessorSignatureFailed` | The predecessor signature verification failed. | The outgoing owner's signature on the ownership transition is invalid. |
| `OwnershipTransitionSuccessorSignatureFailed` | The successor acceptance signature verification failed. | The incoming owner's acceptance signature is invalid. |
| `SignerAuthorityMismatch` | The resolved signer authority does not match the document issuer authority. | The key resolved from discovery belongs to a different authority than the document's `issuer_authority`. |
| `KeyIdMismatch` | The resolved signer key ID does not match the document key ID. | The `key_id` in the document does not match any key in the resolved authority's discovery material. |
| `DiscoveryAuthorityMismatch` | The discovery document authority does not match the expected issuer authority. | The authority in the fetched discovery document differs from the document issuer. |
| `DelegatedDiscoveryAuthorityMismatch` | The delegated principal document authority does not match the expected issuer authority. | The delegated principal document's authority field does not match expectations. |
| `DelegationNotSupported` | The authority does not support delegated principal key lookup. | An authority discovery document indicates no delegated principal endpoint is available. |
| `DelegatedPrincipalMismatch` | The delegated principal does not match the document issuer principal. | The principal in the delegated key document differs from the document's issuer principal. |
| `OwnershipOriginMismatch` | The resolved ownership origin authority does not match the document origin authority. | The ownership origin resolved from the chain differs from `origin_authority` in the document. |
| `ActiveOwningAuthorityMismatch` | The resolved active owning authority does not match the document's active owning authority. | The current owner resolved from the chain differs from `active_owning_authority` in the document. |
| `MissingOwnershipTransitionChain` | The ownership transition chain is missing when required. | The document has different origin and active owning authorities but no chain is provided. |
| `OwnershipTransitionOriginMismatch` | The chain has an incompatible origin authority. | The first entry in the ownership chain does not match the document's origin authority. |
| `OwnershipTransitionActiveOwnerMismatch` | The chain does not resolve to the document's active owning authority. | The last entry in the ownership chain does not resolve to `active_owning_authority`. |
| `InvalidOwnershipTransitionChain` | The ownership transition chain is not valid for the resolved lineage. | The chain entries do not form a valid sequence of ownership transitions. |
| `OwnershipTransitionScopeMismatch` | The transition scope does not cover the document resource scope. | An ownership transition's resource scope is narrower than the document's resource scope. |
| `SignerKeyInactive` | The resolved signer key is not active at verification time. | The key used to sign the document has expired or is not yet valid. |
| `SignatureProfileMismatch` | The signature profile does not match the canonicalization profile. | The algorithm or profile declared in the signature does not match what was used for canonicalization. |
| `IssuerPrincipalMismatch` | The issuer principal binding does not match the signed document. | The principal bound to the signing key differs from the document's issuer principal. |
| `InvalidRevocationFreshnessWindow` | The revocation freshness window has `checked_at` after `fresh_until`. | The revocation proof timestamp window is inverted or malformed. |
| `InvalidRevocationPolicy` | The revocation freshness policy has a non-positive TTL. | The `freshness_ttl_seconds` value is zero or negative. |
| `InsufficientRevocationProofFinality` | The revocation evidence does not meet proof finality requirements. | The revocation proof has fewer confirmations or lower finality than the policy requires. |
| `VerificationPostureRequiresNonLiveRevocation` | The verification posture requires non-live revocation evidence. | The caller requested a posture that demands cached/offline revocation data but live data was provided. |
| `RevocationProofGrantMismatch` | The revocation proof does not match the requested trust grant. | The proof references a different grant ID or authority than the one being verified. |
| `ConflictingProofBundleEntry` | A proof bundle entry conflicts with an existing entry. | A proof bundle contains two entries with the same identifier or overlapping scope. |
| `UnexpectedRevocationProofForNonRevocableGrant` | A non-revocable grant carries revocation proof material. | A grant marked as non-revocable includes a `revocation` section in the proof bundle. |
| `MissingIdSeparator` | A prefixed ID lacks the underscore separator. | A grant ID like `tg123` was provided instead of `tg_123`. |
| `InvalidIdPrefix` | A prefixed ID does not use the expected prefix. | A grant ID uses `tx_` instead of `tg_`. |
| `InvalidIdUuid` | A prefixed ID does not contain a valid UUID. | The portion after the prefix is not a valid UUID string. |
| `InvalidProtocolVersion` | An unsupported protocol version was provided. | The document declares a nonzero `version`, but the implementation supports only v0 wire payloads. |
| `InvalidSupersedesForFirstRevision` | The first revision declares a supersedes field. | Revision 1 of a grant lineage includes a `supersedes` field, which is only allowed for later revisions. |
| `MissingSupersedesForNonFirstOwnershipTransitionRevision` | A non-first ownership transition revision is missing `supersedes_transition_id`. | Revision 2+ of an ownership transition must reference the previous transition ID. |
| `SelfSupersession` | A grant directly supersedes itself. | A document's `supersedes` field equals its own `trustgrant_id`. |
| `InvalidOwnershipTransitionParties` | The from and to authorities in a transition are the same. | An ownership transition lists the same authority as both predecessor and successor. |
| `InvalidOwnershipTransitionScope` | The transition requires an explicit finite resource scope. | An ownership transition uses `all` scope instead of listing specific resources. |
| `InvalidOwnershipTransitionEffectiveAt` | The `effective_at` timestamp falls outside the declared time window. | The transition effective time is before `not_before` or after `not_after`. |
| `InvalidOwnershipTransitionAcceptanceTime` | The acceptance timestamp is in the future. | The successor's acceptance signature timestamp is ahead of the verifier's clock. |
| `UnsupportedV0WireSupersessionPolicy` | The supersession policy cannot be converted to v0 wire format. | A supersession policy construct is incompatible with the version 0 wire format. |
| `InvalidPersistedVerifiedGrantRecord` | A persisted verified-grant record field is invalid. | A record loaded from storage has a corrupted or unexpected field value. |
| `UnsupportedPersistedVerifiedGrantRecordVersion` | An unsupported persisted record version was encountered. | A record stored by a newer version of the library cannot be read by the current version. |
| `InvalidTimeWindow` | The time window has `not_before` after `not_after`. | The grant's time window end precedes its start. |
| `InvalidKeyValidityWindow` | The key validity window has `not_before` after `not_after`. | The key's validity end precedes its start. |
| `ZeroRevision` | The revision number is zero. | A document was created with `revision: 0` but revision must be ≥ 1. |

## Recoverable errors (safe to retry)

These errors indicate that external proof material (revocation status,
discovery documents) was unavailable or stale. Retrying with fresh data may
succeed.

| Error variant | Description | Typical cause |
|---|---|---|
| `StaleRevocationRecord` | Revocation evidence is stale at verification time. | The revocation proof was fetched too long ago and exceeds the freshness TTL. |
| `MissingAuthorityDiscoveryDocument` | The authority discovery document was not provided. | The caller omitted the discovery document from the verification material bundle. |
| `MissingDelegatedPrincipalDocument` | The delegated principal key document was not provided. | A delegation was asserted but the corresponding principal key document was not included. |
| `MissingRevocationProof` | The revocation proof was not provided. | The grant is revocable but no revocation proof entry was included in the verification material. |
| `MissingSigningKey` | The requested signing key is missing from the resolved authority discovery material. | The discovery material is stale or incomplete; refreshing from the authority may include the key. |

## Retry guidance

- **Recoverable errors**: retry with exponential backoff (1s, 2s, 4s, 8s, max 30s).
  After fetching fresh discovery or revocation material, re-run verification.
- **Fatal errors**: surface immediately to the caller. Do not retry with the
  same inputs.
- **When in doubt about an error variant, treat it as fatal**.
