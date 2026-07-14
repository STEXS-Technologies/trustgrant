# What TrustGrant Is Not

A collection of things TrustGrant explicitly does **not** do, does **not** own, and is
**not** designed for. These boundaries keep the core protocol focused on authorization
and prevent scope creep into adjacent problem spaces.

## Authorization Only, Not Execution

TrustGrant is an **authorization precondition** — it decides whether an operation
is allowed by the grant, but it does **not** execute the operation itself.

- No inventory ledger, item database, or resource state storage
- No atomic execution of mint, transfer, consume, or burn operations
- No settlement, order books, or royalties
- No production-capable transaction engine (`InMemoryAtomicInventoryExecutor`
  exists only for tests)
- No `authorize-and-execute` transaction boundary (this is the integration
  layer's responsibility to implement per §15)

## Not an Authentication System

TrustGrant does not authenticate users, players, services, or wallets.

- No user/account/wallet login or session management
- No principal identity verification — the protocol assumes the caller has
  already authenticated the principal through some other mechanism
- Principal selectors alone must not become authentication
- No mapping of game-authenticated players to profile subjects

## No Transport or Protocol Assumptions

TrustGrant is transport-agnostic. The core protocol does not require HTTP,
gRPC, or any specific wire protocol.

- No built-in HTTP client, server, or middleware
- No DID, blockchain, or other non-HTTP resolver adapters shipped in the core
- No assumption of always-online connectivity (offline verification is a
  first-class posture)
- No redirect following or multi-hop resolution built in
- No cross-source arbitration — the core does not merge multiple mirrored
  sources, vote between conflicting sources, or reconcile disagreement
  between caches, relays, chain-backed resolvers, or live APIs

## Not a Database or Persistence Layer

TrustGrant produces and consumes data but does not store it.

- No database adapters, cache backends, or persistence implementations
- No storage engine for verified grant records (the `StorageSource` trait
  defines the interface; the adapter provides the implementation)
- No automatic cache invalidation or lifecycle management
- No migration or version migration for stored records

## Not a Profile Registry

TrustGrant defines a core set of selector kinds, principal kinds, and operation
names, but it does not maintain a global registry of deployment-specific values.

- No built-in interoperability-profile registry
- No shared operation registry or operation-name namespace
- No cross-profile subject taxonomy
- No case-folding or alias expansion on service-defined selector kinds,
  principal kinds, operation names, or resource type names
- No silent renaming or normalization of profile-specific tokens

## Not a Networking or Discovery Layer

TrustGrant defines interfaces for discovery and revocation sources but does
not implement the transport that satisfies them.

- No built-in DNS, DID resolution, or chain-index lookup
- No built-in multisig or contract-based signer verification
- No endpoint discovery beyond what an integration provides
- No automatic trust-on-first-use or certificate pinning

## Not a Replacement for Other Protocol Features

- Supersession does not replace revocation — they serve different purposes
  and operate independently
- Ownership authority transitions do not replace grant issuance — they handle
  governance, not individual authorization
- The `origin_authority` check does not replace target-scope or resource-scope
  evaluation — it is one of several independent checks in spec §13

## Out of Scope for v0

These may be addressed in future versions but are deliberately excluded from
the v0 core:

- Cross-source proof merging and arbitration
- Built-in DID, chain, or decentralized identifier resolvers
- Soft-delete, tombstone, or reversible operations
- Built-in multisig or threshold signing verification
- Global selector-kind or operation-name registry
- Automated cache invalidation or push-based revocation
