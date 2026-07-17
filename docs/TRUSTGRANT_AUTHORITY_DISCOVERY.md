**Document Version:** 0.3\
**Last Updated:** 2026-04-08\
**Status:** Draft\
**Related Documents:** [TrustGrant Crate Docs](README.md),
[TrustGrant v0 Spec](TRUSTGRANT_V0_SPEC.md),
[TrustGrant Federation Flow](TRUSTGRANT_FEDERATION_FLOW.md)

# TrustGrant Authority Discovery

## 1. Purpose

Each authority participating in TrustGrant federation must make authenticated discovery
material available that binds its `authority_id` to cryptographic public keys and
related verification metadata.

In the default HTTPS-hosted profile, that material is represented by a public discovery
document. Other profiles may resolve equivalent material through a different
authenticated source.

This discovery material is used to:

- verify TrustGrant signatures
- discover active signing keys
- support key rotation
- establish cryptographic identity of an authority

This is analogous to OAuth2 / OpenID well-known discovery and JWKS-style key
distribution.

* * *

## 2. Discovery Location

For an HTTPS-hosted authority with:

```text
authority_id = https://authority.example.com
```

the discovery document must be hosted at:

```text
https://authority.example.com/.well-known/trustgrant.json
```

TLS is required for this HTTPS-hosted profile.

This HTTPS `/.well-known` form is the default web-hosted discovery profile.

For non-HTTP authority schemes, consumers may use a profile-specific resolver that
returns equivalent discovery material.
The protocol requirement is authenticated discovery, not one mandatory transport.

Current v0 core guarantee:
- the crate parses and validates discovery material once it is already obtained
- the crate does not ship built-in DID, chain, or other non-HTTP discovery resolvers
- non-HTTP profiles must provide equivalent authenticated discovery material to the core
  through adapters

* * *

## 3. Canonical Format

```json
{
  "authority_id": "https://authority.example.com",
  "keys": [
    {
      "key_id": "2026-01",
      "algorithm": "ed25519",
      "public_key": "base64-encoded-public-key",
      "not_before": "2026-01-01T00:00:00Z",
      "not_after": "2027-01-01T00:00:00Z"
    }
  ],
  "signature_profile": {
    "format": "jcs+ed25519",
    "canonicalization": "RFC8785"
  },
  "revocation_policy": {
    "status_endpoint": "https://authority.example.com/trustgrant/revoke",
    "non_revoked_ttl_seconds": 120,
    "max_stale_seconds": 900
  },
  "revocation_endpoints": [
    "https://authority.example.com/trustgrant/revoke"
  ],
  "issued_at": "2026-01-01T00:00:00Z"
}
```

* * *

## 4. Semantics

### 4.1 authority_id

- must exactly match the value used in TrustGrant documents
- must be globally unique
- must be controlled by the authority under the active discovery profile

### 4.2 keys

Defines active signing keys for the authority.

Each key entry contains:

- `key_id`
- `algorithm`
- `public_key`
- `not_before`
- `not_after`

Multiple keys may be active simultaneously to support rotation.

The generic protocol must also remain compatible with authorities whose effective signer
proof comes from:
- delegated keys
- threshold or multisig authority models
- contract-managed or blockchain-backed signer ownership

The concrete proof format may vary by consumer profile, but the verifier must always be
able to authenticate the signer authority behind the presented `key_id`.

Current v0 core guarantee:
- discovery documents directly model discrete key records
- delegated-principal signing is modeled explicitly
- richer signer models must be reduced by the surrounding profile into one effective key
  record and signature-verification backend before entering the current TrustGrant core

### 4.3 signature_profile

Declares how TrustGrant payload bytes are canonicalized for signature verification.

- `format` identifies the signing profile
- `canonicalization` identifies the deterministic encoding rule set
- verifiers should enforce the same profile within a trust domain
- unknown profile values should fail closed

### 4.4 revocation_policy

Provides issuer-advertised verifier tuning defaults for API-backed revocation.

- `status_endpoint`: primary revocation status endpoint
- `non_revoked_ttl_seconds`: suggested cache TTL for non-revoked status
- `max_stale_seconds`: upper bound for using stale cached non-revoked status

These values are policy hints; local operators may tighten them.

### 4.5 revocation_endpoints

Optional list of endpoints where TrustGrant revocation status can be queried.

HTTP endpoints are one revocation profile, not the only one.
Other consumer profiles may resolve revocation state from:
- signed snapshots
- proof bundles
- blockchain-backed finalized state

* * *

## 5. Verification Algorithm

When verifying a TrustGrant:

1. read `issuer_authority` from the TrustGrant
2. resolve authenticated authority discovery material for the signer using the active
   authority-resolution profile
3. if HTTPS is used, verify TLS and hostname
4. select a key where:
   - `key_id` matches the TrustGrant header
   - current time is within `[not_before, not_after]`
5. resolve canonicalization and signature profile
6. verify signature using canonical bytes and the selected key
7. cache keys until expiry or resolver-policy invalidation

If any step fails, reject the TrustGrant.

Ownership-authority validation is an additional verifier step and is not replaced by
signer discovery alone.

* * *

## 6. Security Notes

- TLS is mandatory for HTTPS-hosted discovery
- redirects should not be followed
- `authority_id` must be an exact match
- keys should be rotated periodically
- expired keys must not be used
- signature profile mismatches must fail closed
- revocation status checks should be cached with bounded staleness and background
  refresh

* * *

## 7. Delegated Principal Key Discovery

Large authorities may delegate signing authority to internal principals such as tenants,
projects, or services without publishing all delegated keys in the root discovery
document.

To support scalable delegation, the discovery document may include a `delegation`
section:

```json
{
  "authority_id": "https://authority.example.com",
  "keys": [
    {
      "key_id": "root-2026",
      "algorithm": "ed25519",
      "public_key": "base64-encoded-public-key",
      "not_before": "2026-01-01T00:00:00Z",
      "not_after": "2027-01-01T00:00:00Z"
    }
  ],
  "signature_profile": {
    "format": "jcs+ed25519",
    "canonicalization": "RFC8785"
  },
  "revocation_policy": {
    "status_endpoint": "https://authority.example.com/trustgrant/revoke",
    "non_revoked_ttl_seconds": 120,
    "max_stale_seconds": 900
  },
  "delegation": {
    "principals_supported": true,
    "principal_key_endpoint": "https://authority.example.com/.well-known/trustgrant/principals/{kind}/{id}"
  },
  "revocation_endpoints": [
    "https://authority.example.com/trustgrant/revoke"
  ],
  "issued_at": "2026-01-01T00:00:00Z"
}
```

Semantics:

- root `keys` must contain only root authority keys
- delegated principal keys must not be embedded in this document
- if `delegation` is present, verifiers may resolve delegated signing keys via
  `principal_key_endpoint`

The delegated key endpoint returns a document of the form:

```json
{
  "authority_id": "https://authority.example.com",
  "principal": {
    "kind": "<issuer-defined>",
    "id": "<principal-id>"
  },
  "keys": [
    {
      "key_id": "tenant-a-2026",
      "algorithm": "ed25519",
      "public_key": "base64-encoded-public-key",
      "not_before": "2026-01-01T00:00:00Z",
      "not_after": "2027-01-01T00:00:00Z",
      "revoked": false
    }
  ]
}
```

Verification rules when a TrustGrant contains `issuer_principal`:

1. resolve authenticated root discovery material through the active authority-resolution
   profile
2. verify the discovery material matches the asserted `authority_id`
3. if the current profile uses `principal_key_endpoint`, resolve the delegated key
   document from that endpoint; other profiles may use an equivalent delegated-signer
   resolution mechanism
4. verify the delegated key is bound to the asserted principal
5. verify the TrustGrant signature using the delegated key

Delegated keys are cryptographically subordinate to the root authority.

## Review & Maintenance

- **Last Reviewed:** 2026-04-08
- **Next Review:** When authority-resolution or signer-proof modeling changes materially
- **Change Log:**
  - v0.3 (2026-04-08): Clarified that current v0 core parses normalized discovery
    material but does not ship non-HTTP resolvers or native multisig/contract signer
    adapters
  - v0.2 (2026-04-06): Generalized discovery and revocation guidance beyond HTTPS-only
    authorities and simple key-hosting models
