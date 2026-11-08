# BadTower.js architecture

BadTower.js is a TypeScript implementation candidate for Cloudflare Workers
with three horizontally sharded, SQLite-backed Durable Object classes. It has
no shared database, singleton allocator, polling process, or mutable
module-global request state. The repository implements a bounded opaque relay;
it does not own endpoint trust or external protocol semantics.

## Split ingress

Two independently built Worker entrypoints own disjoint request surfaces:

- `src/data-entry.ts` owns fixed public liveness, invitation exchange, relay
  admission, carrier validation, and relay dispatch. Its configuration binds
  `AccessGrant`, `AffiliationShard`, and `RelayHandle`.
- `src/operator-entry.ts` owns internal readiness and exact operator routes.
  Its only Durable Object binding is the data Worker's `AccessGrant`; it has no
  affiliation or relay handler.

The corresponding production configuration templates disable `workers.dev`,
preview URLs, invocation logs, and traces. Each declares one non-wildcard
custom-domain placeholder. These files prove local route and binding intent,
not that real DNS, edge policy, certificates, or deployments exist.

The operator entrypoint requires both an application `bto1` bearer token and
Cloudflare's verified mTLS request metadata. It consumes only the certificate
presented, verified, and non-revoked result and does not retain certificate
identity fields. Correct certificate policy and enforcement remain an external
deployment obligation; the repository does not turn them into endpoint trust.

## Data request path

1. `/healthz` returns a fixed liveness response. Readiness exists only on the
   operator entrypoint after both operator gates.
2. Invitation exchange authenticates a canonical `bti2` capability before
   selecting its `AccessGrant`, then binds the grant to a supplied Ed25519
   public key and returns a `bta2` capability.
3. Relay admission authenticates the `bta2` capability, validates the fixed
   carrier and bounded body, and hashes the admitted bytes without selecting a
   business Durable Object.
4. The entrypoint verifies the Ed25519 request proof, applies selector-scoped
   platform shedding, and asks the selected `AccessGrant` to atomically consume
   replay state and resource budgets. For a handle-bound route, it then
   verifies the 32-byte handle before selecting a `RelayHandle`.
5. The request is dispatched to one sharded Durable Object and the application
   response is normalized through the security response constructor.

Malformed or unauthenticated capability selectors do not select business
objects. An authenticated grant is charged before affiliation or relay
dispatch. A forged handle can consume only already-authorized admission work;
it cannot select or initialize a relay object.

## AccessGrant

One object per random invitation selector owns the credential and budget atom.
An invited grant stores the invitation digest, invitation expiry, and bounded
access lifetime. Successful exchange stores the client public key, epoch,
access expiry, fixed 128-counter replay bitmap, fixed token buckets, creation
usage, and bounded concurrency leases. Invitation retry evidence is retained
for at most ten minutes and then removed by the alarm.

`authorizeAndCharge` uses monotonic Durable Object-local time and performs
replay acceptance, request/byte/weight token refill and debit, creation debit, and concurrency-lease allocation in one
Durable Object transaction. There is no per-request nonce collection or global
grant registry. Expiry and revocation delete the grant's stored state.

## AffiliationShard

One object per domain-separated digest of opaque candidate fields owns bounded
operation replay and retry-safe first-contact reservation. The implementation
does not invent missing signature behavior: `AFFILIATE` and asynchronous
`RESERVE` return the closed `unsupportedProfile` failure. These names and
shapes are a locally pinned transport surface, not a claim that BadTower.js
defines the protocol or proves conformance.

## RelayHandle

One object per authenticated delivery handle owns an indexed SQLite BLOB store
for opaque packets, usage counters, control-operation replay, claims,
retrieval, settlement, and bounded expiry cleanup.

- Packet size is at most 512 KiB; a handle holds at most 128 queued items and
  64 MiB.
- A claim holds at most 64 items and 32 MiB. Storage retention is one hour;
  operation replay and claim windows are five minutes.
- Claim selection and ownership update occur synchronously in SQLite before a
  response stream is returned.
- Non-empty CLAIM and RETRIEVE replay records store response metadata, ordered
  item references, and byte lengths rather than a duplicate response body.
  Packets needed by a live replay reference are retained after settlement.
- The stream emits canonical prefixes and at most one packet BLOB at a time in
  chunks no larger than 64 KiB. Cancellation stops output but does not undo the
  committed claim. Replaying the same operation id and request digest rebuilds
  the same response bytes.
- Small control responses remain bounded and may be persisted in chunks for
  idempotent replay. Indexed cleanup changes at most 64 logical rows per turn.

## Response and observability boundaries

All application-created responses force `no-store`, `no-referrer`, and
`nosniff`, and remove wildcard CORS. Entrypoint exceptions become closed
response classes; exception text is not returned. Structured application events are built from a closed categorical
allowlist and exclude stable identifiers, packet data, request metadata,
individual sizes, and exception objects. Stream failures after response
construction and provider telemetry remain outside this response-body boundary.
