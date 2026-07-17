# TrustGrant Evaluate

Hot-path evaluation engine for [TrustGrant](https://github.com/STEXS-Technologies/trustgrant) grants.

Evaluates a verified grant against an authorization request: checks resource
scope, operation scope, capabilities (recognize/mint), selector matching,
audience scope, principal scope, mint limits, time windows, and revocation
state. Returns an allow/deny decision with a structured reason.

See the [trustgrant] crate for full documentation and integration guide.
