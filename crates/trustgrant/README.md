# trustgrant

Pure TrustGrant protocol crate for STEXS, with a future extraction path into its own
repository under the STEXS organization.

This crate is intended to own protocol/domain concerns only:
- TrustGrant document types
- validation and normalization
- scope and capability evaluation
- signature and verification interfaces
- discovery and revocation types

It should not own:
- HTTP routing
- database adapters
- streaming adapters
- STEXS runtime wiring

See [docs/README.md](docs/README.md) for the crate-local documentation set, including
the protocol spec, federation flow, discovery rules, and implementation architecture.
