# Product

BadTower.js is an invitation-gated, protocol-neutral **communication
Station**: a permanent mailbox relay that stores opaque packets until the
recipient claims and settles them. It is infrastructure, not an
application, an identity system, or a protocol implementation.

## Who it is for

- An operator who wants to run a small, self-hosted or Cloudflare-hosted
  relay for endpoints that cannot stay online continuously.
- A protocol implementer who needs a store-and-forward carrier without
  making that protocol part of the relay's core.
- A client author who wants one native Reserve → Submit → Claim → Settle
  contract instead of a different mailbox API per protocol.

## Product boundary

1. **Protocol-neutral.** The core accepts fixed opaque fields. It does
   not parse LicoArc, A2A, MCP, agent cards, JSON-RPC, CBOR, identities,
   or application content. Compatibility listeners are separately
   packaged plugins that drive the native contract through the core's
   published API.
2. **Station is untrusted.** A Station signal — a status code, a stored
   acknowledgement, a delivery, a capacity number, a health response —
   is service-local evidence. It never proves endpoint identity,
   authenticity, freshness, receipt, approval, task completion, effect,
   or business acknowledgement. Endpoints and applications establish
   their own trust.
3. **Opaque by construction.** The Station routes 32-byte delivery
   handles by their first 16 bytes. It does not need plaintext,
   identities, sessions, addresses, or protocol metadata, and the
   native contract has no field for them.
4. **Permanent until settled or revoked.** An undelivered packet does
   not expire. A packet leaves storage only when the recipient settles
   it or the operator revokes the mailbox. There is no background
   expiry, polling, alarm, or scavenger in the product.
5. **Bounded and fail-closed.** Admission, storage, connections, queues,
   work, retries, observations and every other resource-bearing unit
   must have a bound. Overload and recovery behavior is stable and fails
   closed; it never silently widens a limit.
6. **Invitation-gated.** A mailbox exists only after a valid `btm1`
   admission credential binds it. Credentials are minted offline by the
   operator; the only operator endpoint is revocation.
7. **Plugin isolation.** Station Core never discovers, loads, executes,
   or supervises plugin code. A deployment supervisor owns separately
   packaged plugin processes. Starting, stopping, exhausting,
   upgrading, rolling back or retiring one plugin must not alter native
   Station behavior or another plugin. In this repository
   `apps/station` is the build-time composition of the core and the
   selected LicoArc listener; it is not a plugin host. A future
   deployment supervisor may run the same plugin as a separate process.

## Non-goals

BadTower.js is not:

- an identity provider, key custodian, trust authority, or approval
  service;
- an endpoint client, a LicoArc implementation, or the owner of any
  protocol's semantics, identifiers, negotiation, wire, lifecycle or
  conformance;
- a content store, search index, address book, contact directory, or
  email service — a mailbox id is not an email address and a handle is
  not an identity;
- a hosted service with an availability target, a support contract, or
  a published compatibility matrix beyond what this repository states;
- a cluster, a plugin host, or a general compute platform. Cluster and
  plugin-host scaffolding are later stages and are not implied by this
  product definition.

## Product surfaces

| Surface | Owner | Purpose |
| --- | --- | --- |
| Native HTTP contract (`/v1/native/…`) | `packages/station-core` | Reserve, Submit, Claim, Settle, capacity and contract version |
| Revocation (`POST /v1/revoke`) | `packages/station-core` + Worker edge | Operator-verified mailbox destruction |
| Compatibility listeners | A plugin package | One exact protocol binding over the native contract |
| Deployable Worker | `apps/station` | The only composition of core and selected plugins |
| Operator CLI | `scripts/station.mjs` | Offline key, invitation, TLS and deploy operations |

## Success criteria

- A native client can complete Reserve → Submit → Claim → Settle with no
  plugin installed.
- A plugin can be added, removed or fail without changing native
  behavior or another plugin's state.
- No response carries plaintext, protocol content, identity, or error
  text.
- Every resource-bearing unit has a documented bound and a fail-closed
  answer at that bound.
- The repository's checks prove the boundary and the native contract
  without requiring a production plugin, external protocol checkout,
  secret, or protected runtime record.

## Maturity

The product is pre-1.0. The native contract, the LicoArc mailbox
listener, the Worker composition, the operator CLI and the test suite
exist. A2A and MCP compatibility plugins, an offline wake hook, an
aggregate operations view, clustering, and a published release are
designs or later stages, not current features. See `STATUS.md` for the
per-dimension state.
