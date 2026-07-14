**Document Version:** 1.3\
**Last Updated:** 2026-07-13\
**Status:** Draft\
**Owner:** CTO (Wladimir Trubizin)\
**Related Documents:** [TrustGrant Crate Docs](README.md),
[TrustGrant Authority Discovery](TRUSTGRANT_AUTHORITY_DISCOVERY.md),
[TrustGrant Federation Flow](TRUSTGRANT_FEDERATION_FLOW.md),
[TrustGrant v0 Schema](TRUSTGRANT_V0_SCHEMA_FINAL_WITH_KEY_ID.json)

# TrustGrant v0 Spec

> Status: Experimental (v0)\
> TrustGrant v0 defines a selector-based, certificate-driven protocol for decentralized
> delegation of authority over resources and operations across independent systems.\
> It is intentionally expressive to explore real-world needs before stabilizing
> TrustGrant v1.

* * *

## 1. Purpose and Scope

TrustGrant is a decentralized delegation protocol for cryptographically representing and
enforcing authority over data and operations across system boundaries.

It externalizes trust relationships from application logic into signed, portable
certificates that can be interpreted by middleware, services, event consumers,
federation gateways, or offline verifiers.

TrustGrant is not an API token, an access key, or a middleware.
It is an authority primitive.

TrustGrant defines how one authority can delegate authority to a set of other
authorities and/or internal principals:

- the right to **recognize** resources minted by the issuer
- the right to **mint** resources on behalf of the issuer
- the right to perform **service-defined operations** on those resources

Additionally, TrustGrant defines where those resources may be valid and used through
**audience scope**, and by whom inside the audience authority through **principal
scope**.

The goals of v0 are:

- enable cross-domain and cross-organization resource portability
- enable delegation between independent authorities and internal principals
- enable cross-backend, cross-authority, and cross-domain interoperability
- support delegation to dynamic sets of authorities and principals, not only single
  targets
- support both unrestricted and constrained delegation of authority over resources and
  operations
- be explicit, auditable, revocable, and fail-closed

For standardization, v0 also carries a v1 hardening direction:
- keep the core trust model
- tighten ambiguous or operationally risky areas
- favor deterministic verifier behavior and outage-resistant revocation checks

Consumer implementations must also enforce explicit finite cost bounds on:
- raw document size
- selector count and selector value count
- selector expression count and length
- proof material cardinality such as ownership-transition chains
- imported persisted verified-state cardinality when rehydrating cached or stored
  normalized records

TrustGrant v0 must fail closed when those bounds are exceeded.
Bounded hostile-input handling is part of the protocol hardening posture, even when the
exact numeric thresholds are profile-specific.

* * *

## 2. Core Concepts

### 2.1 Authority

An Authority is any organization or system that can:

- mint resources
- sign TrustGrants
- verify TrustGrants
- act as a root of trust

Each authority is identified by a globally unique `authority_id`.

The protocol must not assume that every `authority_id` is an HTTPS service URL. Consumer
profiles may support schemes such as:
- HTTPS service authorities
- DID-style authorities
- blockchain-network authorities
- other globally unique authority schemes accepted by local trust policy

Each authority makes authenticated discovery material available through the active
authority-resolution profile described in
[TrustGrant Authority Discovery](TRUSTGRANT_AUTHORITY_DISCOVERY.md).

Current v0 core note:
- the core consumes already-obtained authenticated discovery material
- non-HTTP authority resolution remains outside the current core
- the exact current guarantee is defined in
  [TrustGrant Authority Discovery](TRUSTGRANT_AUTHORITY_DISCOVERY.md) and
  [TrustGrant Interoperability and Proof Models](INTEROPERABILITY_AND_PROOF_MODELS.md)

### 2.2 Resource

A resource is any cross-tenant object, for example:

- item
- currency
- achievement
- entitlement
- license
- badge
- token

Minimal resource identity:

```json
{
  "resource_id": "uuid",
  "resource_type": "item",
  "origin_authority": "authority_id",
  "active_owning_authority": "authority_id",
  "owner_subject": {
    "kind": "user",
    "id": "user_id",
    "authority_id": "authority_id"
  },
  "attributes": {}
}
```

`owner_subject.kind` should be treated as a typed subject category such as:
- `user`
- `wallet`
- `contract`
- `service`
- `organization`
- `group`
- other issuer-defined subject kinds

Resources are globally namespaced by:

```text
(origin_authority, resource_type, resource_id)
```

`origin_authority` is immutable and anchors canonical identity. It is an implicit
constraint on all evaluation: a TrustGrant may never apply to resources whose
`origin_authority` differs from the grant's `origin_authority`.

`active_owning_authority` identifies the authority currently recognized as owning the
lineage for future owner-level delegation and settlement.

Ownership transfer must change `active_owning_authority` without rewriting
`origin_authority`.

The protocol distinguishes between:
- origin identity of the canonical resource lineage
- currently active owning authority for future delegation

Ownership transfer must not silently rewrite historical resource identity.

Deployments may additionally organize resources under namespace-like selector dimensions
such as:
- project
- collection
- namespace
- tag
- item or resource ID

TrustGrant v0 keeps those selector kinds issuer-defined rather than standardizing them
into a closed protocol enum.

The three built-in selector kinds (`authority`, `namespace`, `player_id`) are matched
case-insensitively. Other selector kinds continue to be exact-case tokens. This is a
deliberate design choice to prevent common casing mistakes in the built-in kinds while
keeping the open kind space case-sensitive by default.

### 2.3 TrustGrant

A TrustGrant is a signed delegation certificate.

It defines:

- who signed this exact grant: `issuer_authority`
- which canonical lineage the grant concerns: `origin_authority`
- which authority currently owns that lineage for owner-level rights:
  `active_owning_authority`
- who may act: `target_scope`
- what rights are granted: `capabilities`
- over which resources: `resource_scope`
- where those resources may be used: `audience_scope`
- under which constraints

TrustGrants are explicit, signed, versioned, and revocable.

The term "versioned" covers two different concerns:
- **protocol version** via `version`, which identifies the TrustGrant schema/profile
  version
- **grant lineage versioning** via lineage fields, which identify revisions of the same
  logical delegation over time

For the first v0 implementation, the machine-contract baseline is the JSON schema in
[TrustGrant v0 Schema](TRUSTGRANT_V0_SCHEMA_FINAL_WITH_KEY_ID.json).
Prose and examples should not drift from that field set.

For clarity, the machine-contract `version` field is the integer `0` in v0 payloads.
The human document label "v0" must not be serialized as the wire value of `version`.

### 2.4 TrustGrant Identifier

`trustgrant_id` is the canonical protocol identifier of a TrustGrant document.

Rules:
- it is part of the signed TrustGrant document
- it is generated by issuer-side software tooling before signing
- it must remain stable across transport, registration, and verification
- verifiers must not rewrite or replace it when storing the grant

Canonical v0 format:

```text
trustgrant_id   = tg_<uuid>
grant_series_id = tgs_<uuid>
```

The UUID portion provides global uniqueness.
The prefix provides type clarity across issuers and systems.

A verifier may create additional local identifiers such as a registration handle or
storage key, but those are implementation-local and must not be confused with protocol
`trustgrant_id`.

### 2.5 Grant Lineage and Revisioning

TrustGrant supports versioned grant lineages.

The model is:
- `trustgrant_id`: exact signed document identity for one specific TrustGrant revision
- `grant_series_id`: stable lineage identifier for revisions of the same logical
  delegation
- `revision`: monotonically increasing revision number within one `grant_series_id`
- `supersedes`: optional previous `trustgrant_id` in the same lineage
- `supersession_policy`: issuer-declared update behavior for older revisions

This distinction exists so verifiers can:
- identify the exact signed grant used at runtime
- store multiple revisions of the same logical delegation simultaneously
- distinguish coexistence from automatic supersession
- revoke an older revision later without confusing it with a different revision

Rules:
- `version` is the protocol version and must not be reused as a lineage revision number
- `trustgrant_id` identifies the exact signed document revision and must remain unique
- `grant_series_id` groups revisions that belong to the same logical delegation family
- `revision` must increase monotonically within one `grant_series_id`
- `supersedes`, when present, must point to an older `trustgrant_id` in the same
  `grant_series_id`
- `supersession_policy` controls whether a new revision coexists with older revisions or
  automatically supersedes them

Recommended v0 policies:
- `coexist`: older revisions remain active until separately revoked, expired, or retired
  by local policy
- `supersede_previous`: the new revision supersedes older active revisions in the same
  lineage once accepted by the verifier

Supersession and revocation are different:
- supersession is lifecycle progression inside one grant lineage
- revocation is an explicit invalidation control

Runtime authorization should always evaluate the exact referenced `trustgrant_id` unless
a consumer explicitly opts into lineage-aware "latest revision" behavior.

### 2.6 Grant Cardinality

An authority may issue multiple TrustGrants concurrently.

TrustGrant does not assume "one authority = one grant".
Instead:
- one authority may issue many grants over the same resource namespace
- one grant may target one or many authorities or principals when the delegated policy
  is genuinely the same
- separate grants are preferred when targets, capabilities, resource scopes, lifetimes,
  or revocation risk differ

This keeps delegation auditable, easier to rotate, and narrower in blast radius.

### 2.7 Ownership Authority Transition Profile

Some deployments need a stronger primitive than ordinary delegation: the ability to move
active ownership authority for a canonical resource lineage from one authority to
another.

TrustGrant v0 does not treat that as an ordinary `recognize` or `mint` grant.

Instead, deployments should model ownership transfer through a dedicated
ownership-authority transition profile or adjacent proof model that:
- preserves canonical resource identity
- proves the predecessor was the active owning authority
- proves the successor accepted the transfer
- lets verifiers derive the current owning authority for future grant issuance

See [TrustGrant Ownership Authority Transitions](OWNERSHIP_AUTHORITY_TRANSITIONS.md).

* * *

## 3. Delegation Capabilities

TrustGrant v0 supports two orthogonal capabilities.

### 3.1 Recognize

Allows a target authority to:

- accept resources minted by the issuer as valid
- verify ownership and provenance
- use them in local logic or application workflows

This is read-only trust.

### 3.2 Mint

Allows a target authority to:

- mint resources on behalf of the issuer authority
- produce resources whose `issuer_authority` is the issuer

This is write authority and is security-critical.

* * *

## 4. TrustGrant Document Format

Canonical JSON form:

```json
{
  "trustgrant_id": "tg_550e8400-e29b-41d4-a716-446655440000",
  "version": 0,
  "grant_series_id": "tgs_550e8400-e29b-41d4-a716-446655440100",
  "revision": 3,
  "supersedes": "tg_550e8400-e29b-41d4-a716-446655440099",
  "supersession_policy": "coexist",
  "issuer_authority": "https://issuer.example.com",
  "origin_authority": "https://issuer.example.com",
  "active_owning_authority": "https://issuer.example.com",
  "key_id": "2026-01",
  "target_scope": {
    "all": false,
    "allow": [
      {
        "kind": "authority",
        "all": false,
        "values": ["https://studio-a.example.com"],
        "expressions": null
      }
    ],
    "deny": null
  },
  "capabilities": {
    "recognize": true,
    "mint": false
  },
  "default_audience_scope": [
    {
      "authority_id": "https://consumer-a.example.com",
      "scope": {
        "all": true,
        "allow": null,
        "deny": null
      }
    }
  ],
  "resource_scope": {
    "types": {
      "resource": {
        "all": true,
        "allow": null,
        "deny": [
          {
            "kind": "id",
            "all": false,
            "values": ["banned_sword"],
            "expressions": null
          }
        ],
        "capabilities": {
          "recognize": null,
          "mint": true
        },
        "operations": {
          "all": false,
          "allow": ["create"],
          "deny": null
        },
        "constraints": {
          "minting": {
            "max_total": 100000,
            "max_per_user": 100
          },
          "audience_scope": [
            {
              "authority_id": "https://consumer-b.example.com",
              "scope": {
                "all": false,
                "allow": [
                  {
                    "kind": "tag",
                    "all": false,
                    "values": ["pvp"],
                    "expressions": null
                  }
                ],
                "deny": null
              }
            }
          ]
        }
      }
    }
  },
  "global_constraints": {
    "time": {
      "not_before": "2026-01-01T00:00:00Z",
      "not_after": "2027-01-01T00:00:00Z"
    }
  },
  "revocation": {
    "revocable": true,
    "revocation_endpoint": "https://issuer.example.com/revoke"
  },
  "issued_at": "2026-01-01T00:00:00Z",
  "signature": "base64(signature)"
}
```

* * *

## 5. Target Scope Model

Target scope defines which authorities may use a TrustGrant.

Canonical structure:

```json
"target_scope": {
  "all": true,
  "allow": null,
  "deny": null
}
```

Rules:

- if `all = true`, `allow` must be null
- if `all = false`, `allow` must be non-empty
- `deny` may be null or non-empty
- allow is primary, deny is subtractive
- target must match `target_scope` before any other checks

Target selector kinds may include:

- `authority_id`
- `org_group`
- `org_tag`
- `other`

Issuer-defined selector kinds may also express namespace-like or deployment-local
dimensions as long as verifier policy understands them.

Resolution model:

```text
target_allowed = if all then true else matches_any(target, allow)
if deny not null and matches_any(target, deny):
    target_allowed = false
```

* * *

## 6. Resource Scope Model

Resource scope is defined per resource type.

Canonical structure:

```json
"types": {
  "<resource_type>": {
    "all": true,
    "allow": null,
    "deny": null,
    "capabilities": {},
    "operations": {},
    "constraints": {}
  }
}
```

Rules:

- if `all = true`, `allow` must be null
- if `all = false`, `allow` must be non-empty
- `deny` may be null or non-empty
- deny is always evaluated after allow
- no implicit allow is permitted

All resources are always implicitly constrained to:

```text
resource.origin_authority == trustgrant.origin_authority
```

No TrustGrant may ever apply to resources of another origin authority.

For deployments that support ownership transitions:

```text
owner-level delegation requires trustgrant.active_owning_authority to be the active owner
for the referenced lineage, either directly or through a valid delegated-principal model
```

### 6.1 Operations

`operations` is optional and scoped per resource type.

Operations never replace `capabilities`. Capabilities answer whether an authority
may mint or recognize a resource type on behalf of the issuer. Operations answer
which concrete service-defined actions may be performed on that type. They are
orthogonal gates evaluated independently.

#### Built-in Operations

Two operation names are built-in and correspond directly to capabilities:

- **`recognize`** — the built-in operation name associated with the recognize
  capability. It is not a user-defined custom operation name.
- **`create`** — the built-in operation name associated with the mint capability.
  It is not a user-defined custom operation name.

These names are reserved: they must not be used as custom operation names.

#### Implicit Operations (v0 Compatibility Mode)

When `operations` is null on a resource type:

- if `mint = true`, there is an implicit allow of operation `create`
- the recognize capability implicitly allows operation `recognize`
- custom operations (service-defined names other than `"recognize"` and `"create"`)
  require an explicit `operations` scope

This ensures existing grants with no operations scope still function for their
intended built-in capabilities. Issuers who want fine-grained control over individual
operation names should provide an explicit `operations` scope in the resource type.

#### Explicit Operations Scope

When operations is present:

```json
"operations": {
  "all": false,
  "allow": ["create", "update"],
  "deny": ["cancel"]
}
```

Resolution:

```text
allowed = if scope.all then true else matches_any(requested_operation, scope.allow)
if scope.deny not null and matches_any(requested_operation, scope.deny):
    allowed = false
```

- allow is primary and explicit
- deny is always subtractive
- deny cannot expand privilege
- default is fail-closed

#### Reserved Names

The strings `"recognize"`, `"mint"`, and `"create"` are reserved and must not appear
as custom operation names in a protocol-compliant grant:

- `"recognize"` — reserved: maps to the recognize capability
- `"create"` — reserved: maps to the mint capability
- `"mint"` — reserved: the capability name itself; the corresponding operation
  name is `"create"`

Using a reserved name in the operations scope as an explicit allow/deny entry is
permitted but will never match a protocol-issued request (the reserved names are
routed to their capability-specific paths).

#### Custom Operations

All operation names other than `"recognize"` and `"create"` are custom (service-defined).
Custom operations:

- have no corresponding built-in capability
- are authorized solely by the operations scope (allow/deny lists)
- do not require a built-in capability to be enabled

Examples:

- `update`
- `cancel`
- `fulfill`
- `item.thumbnail.update`
- `order.refund`
- `custom:*`

There is no global registry of custom operation names in v0.

Token note:
- operation names are exact validated tokens in v0
- the core does not apply general case-folding or alias expansion to service-defined
  operations
- deployments that need portable meaning should standardize exact operation strings
  through an interoperability profile

For reliable cross-runtime interoperability, deployments should define named
interoperability profiles that standardize:
- shared operation names
- subject and selector conventions
- capability expectations
- proof and freshness requirements

One concrete starting point is documented in
[TrustGrant Baseline Interoperability Profile](BASELINE_INTEROPERABILITY_PROFILE.md).

#### v1 Hardening Direction (Future)

- `mint = true` should eventually require an explicit `operations` scope
- `operations.allow` should explicitly contain `"create"`
- a grant with `mint = true` and no explicit `"create"` operation should fail closed
- the implicit-operation fallback may be removed in a future protocol version

Current v0 core note:
- operation names, selector kinds, and principal kinds remain validated but otherwise
  open
- interoperability profiles remain deployment/profile responsibility rather than a
  built-in core registry
- the detailed compatibility boundary is defined in
  [TrustGrant Interoperability and Proof Models](INTEROPERABILITY_AND_PROOF_MODELS.md)

* * *

## 7. Selector Model

Each selector defines a filter over a set of entities such as targets, resources, or
audiences.

Canonical form:

```json
{
  "kind": "id",
  "all": false,
  "values": ["v1", "v2"],
  "expressions": null
}
```

Rules:

- if `all = true`, `values` and `expressions` must be null
- if `all = false`, at least one of `values` or `expressions` must be non-empty

Matching semantics:

```text
matches(selector, entity) =
    if selector.all:
        true
    else:
        matches_any_value(entity, selector.values)
        OR matches_any_expression(entity, selector.expressions)
```

* * *

## 8. Expression Semantics

Expressions in v0 are:

- pure
- deterministic
- side-effect free

They are restricted to single-predicate form:

- no `AND` / `OR` / `NOT`
- no nesting
- no cross-attribute references

Examples:

- `equals("gold")`
- `startsWith("vip_")`
- `endsWith("_skin")`
- `contains("event")`

v1 hardening direction:

- support only a tiny built-in predicate set
- forbid custom evaluators or user-defined functions
- fail closed on unsupported expressions
- optionally disable expressions entirely

* * *

## 9. Audience Scope Model

Audience defines where resources may be used and recognized.

Audience is an array of authority-based scopes.
Each audience entry may also include a `principal_scope` that further restricts usage
inside that authority.

Canonical structure:

```json
{
  "authority_id": "https://consumer.example.com",
  "principal_scope": null,
  "scope": {
    "all": true,
    "allow": null,
    "deny": null
  }
}
```

Audience scope is defined at two levels:

1. `default_audience_scope` at the grant level (Section 4), which applies to all
   resource types that do not specify their own audience scope.
2. `audience_scope` per resource type (Section 6, inside `constraints`), which
   **replaces** the default when present.

When a resource type declares a non-empty `audience_scope` in its constraints, the
default audience scope at the grant level is replaced, not merged. If a resource
type's `audience_scope` is empty or null, the grant-level default is used instead.

This allows issuers to narrow the audience for specific resource types without
affecting others.

Semantics:

- `authority_id` must match the current verifying authority
- if `principal_scope` is null, the entry applies to the entire authority
- if `principal_scope` is non-null, the caller principal must match it using the
  standard allow/deny model
- `principal_scope` restricts audience usage, it does not grant capabilities

Additional semantics:

- `principal_scope.allow[].kind` is issuer-defined
- there is no global registry of principal kinds in v0
- verifiers must treat `kind` as an opaque namespace under the signing authority
- the core does not apply general case-folding or alias expansion to principal kinds

v1 hardening direction:

- signing systems should reject duplicate selector entries
- verifiers should fail closed on duplicate selector entries

* * *

## 10. Allow / Deny Resolution

Uniform resolution model:

```text
allowed = if scope.all then true else matches_any(entity, scope.allow)
if scope.deny not null and matches_any(entity, scope.deny):
    allowed = false
```

Properties:

- allow is primary and explicit
- deny is always subtractive
- deny cannot expand privilege
- default is fail-closed

* * *

## 11. Capabilities Inheritance

Global capabilities:

```json
"capabilities": {
  "recognize": true,
  "mint": false
}
```

Per-type capabilities:

```json
"capabilities": {
  "recognize": null,
  "mint": true
}
```

Resolution:

```text
if type.capability != null:
    use type.capability
else:
    use global.capability
```

Capabilities and operations are distinct:

- capabilities answer whether an authority may mint or recognize a resource type on
  behalf of the issuer
- operations answer which concrete service-defined actions may be performed on that type

* * *

## 12. Constraint Semantics

Constraints are evaluated at two levels:

- global constraints
- per-type constraints

In v0, only time validity and revocation policy are global.

All minting and audience limits should be per-type.

#### Per-user mint limit requires audience principal context

When `max_per_user` is set, the evaluation engine requires audience
principal context to be present on the evaluation request (spec §13,
step 9). If no audience principal context is provided, the engine rejects
the request with `MissingAudiencePrincipalContext`. This ensures that
per-user limits are always evaluated against a known principal, preventing
unbounded minting through anonymous requests.

Applications should populate audience principal selectors on the
evaluation request using the same selector kind expected by the grant's
`principal_scope`.

v1 mint hardening direction includes:

- explicit minting class or template constraints
- issuer-controlled ID namespace rules
- issuer-controlled idempotency or nonce requirements
- optional monotonic sequence constraints
- explicit `create` operation requirement for mint

* * *

## 13. Verification Algorithm

Verification is split into two phases: cold-path (cryptographic and structural
verification) and hot-path (authorization evaluation). Both must pass for a grant
to be accepted.

### Phase 1: Cold-Path Verification (performed once per document)

1. **Canonicalize** — produce RFC 8785 canonical bytes of the raw document
2. **Validate** — parse and validate the document structure; reject structurally
   invalid documents
3. **Verify signer binding** — resolve the signer authority and key from discovery
4. **Verify signature** — verify the cryptographic signature against the canonical
   bytes; reject if signature does not match the declared issuer and key
5. **Verify ownership chain** — verify the ownership transition chain (if any)
   for continuity, monotonicity, and scope coverage
6. **Check revocation state** — verify revocation freshness and consistency with
   the document's revocation policy

If any step fails, reject. The cold-path produces a `VerifiedTrustGrant` that
can be evaluated repeatedly.

### Phase 2: Hot-Path Evaluation (performed on each authorization request)

When evaluating a `VerifiedTrustGrant` for a target and a resource:

1. **Check revocation** — if the grant is revoked, reject immediately
2. **Check time window** — if evaluation time is outside `not_before`/`not_after`,
   reject as `NotYetValid` or `Expired`
3. **Check origin authority** — reject if the resource's `origin_authority` does
   not match the grant's `origin_authority`
4. **Check target `target_scope`** — reject if target does not match
5. **Lookup resource type** — lookup the resource type in the grant's
   `resource_scope`; reject as `ResourceTypeNotGranted` if not present
6. **Check capability allows operation** — reject if the requested capability
   is not enabled for the resource type
7. **Check resource matches `resource_scope`** — reject if the resource's
   selectors do not match the per-type allow/deny selectors
8. **Check operation matches `operations`** — if present, reject if not in
   allow or in deny; if absent, apply implicit operation rules per
   Section 6.1
9. **Check audience** — reject if the audience's `authority_id` does not match
   any audience entry, or if the audience deny/allow selectors do not match.
   Check `principal_scope` if present.
10. **Check minting constraints** — if minting is requested, reject if
    `max_total` or `max_per_user` limits are exceeded, or if mint context is
    missing
11. **Allow** — all checks passed

If any step fails, reject with the corresponding deny reason.

* * *

## 14. Revocation Model

- TrustGrants may be revocable or non-revocable
- revocation must be queryable through an authenticated proof source
- verifiers must check revocation status
- revocation must be treated as an operationally hardened control, not a best-effort
  optional call

Proof sources may include:
- online API status endpoints
- signed snapshots
- blockchain-backed finalized state
- proof bundles carried with the verification request

For the current v0 core, one verification run consumes one already-selected proof-source
set.
The core verifier does not merge multiple mirrored sources or arbitrate disagreement
between caches, relays, chain-backed resolvers, or live APIs during one verification
call.

If a deployment uses multiple candidate sources, local verifier-profile policy must
define:
- how those sources are authenticated
- how disagreement is detected
- how one final source set is selected
- when disagreement forces fail-closed rejection

After revocation:

- no new minting is allowed
- no new recognition is allowed
- existing resources may remain valid or be invalidated based on policy

v1 operational direction:

- grants should be short-lived
- revocation should act as a kill switch, not the primary lifecycle mechanism

## Review & Maintenance

- **Last Reviewed:** 2026-04-08
- **Next Review:** When schema or signer-proof modeling changes materially
- **Change Log:**
  - v1.3 (2026-07-13): Added documentation for `MissingAudiencePrincipalContext`
    error when `max_per_user` is set without audience principal context (§12).
  - v1.2 (2026-07-12): Fixed canonical example — target scope selector kind
    `"authority_id"` → `"authority"` to match built-in SelectorKind list (Section 2.2).
  - v1.1 (2026-07-11): Resolved v0/v1 contradiction in operations; defined
    `recognize` as built-in operation name; documented reserved names
    (`recognize`, `mint`, `create`); documented custom operations as capability-
    independent; documented audience scope override semantics; split verification
    algorithm into cold-path and hot-path phases; added origin authority constraint;
    acknowledged built-in SelectorKind case-insensitivity; moved v1 hardening
    topics to a separate subsection
  - v1.0 (2026-04-08): Clarified the current core guarantee for non-HTTP authority
    resolution and interoperability-profile responsibility while keeping the protocol
    itself open to broader profiles
  - v0.8 (2026-04-07): Standardized TrustGrant v0 identifier formats as typed prefixed
    IDs generated by issuer tooling before signing
  - v0.7 (2026-04-07): Clarified schema baseline wording and documented namespace-like
    selector dimensions as issuer-defined v0 behavior
  - v0.6 (2026-04-07): Declared the TrustGrant v0 schema artifact as the
    machine-contract baseline for the first implementation
  - v0.5 (2026-04-06): Reframed canonical resource identity around immutable
    `origin_authority` plus mutable `active_owning_authority`, while keeping
    `issuer_authority` as the signer of the exact grant
  - v0.4 (2026-04-06): Added explicit ownership-authority transition profile guidance
    for deployments that need successor-authority issuance without rewriting canonical
    identity
  - v0.3 (2026-04-06): Added authority-scheme, typed-subject, interoperability-profile,
    and generalized revocation-proof guidance
