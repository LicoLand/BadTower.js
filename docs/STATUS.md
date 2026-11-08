# BadTower.js status

This document is the lifecycle authority. English is normative.

## Lifecycle dimensions

- **Intent:** open-source, invitation-gated, bounded storage and forwarding of
  opaque protected packets on Cloudflare Workers.
- **Implementation:** the source candidate contains split data/operator
  entrypoints, authenticated v2 invitation and access capabilities, Ed25519
  per-request proof, atomic grant budgets, authenticated relay handles,
  manifest-backed response streaming, explicit secret tools, and closed
  response/log boundaries.
- **Verification:** local TypeScript, Workers-runtime, Node, configuration,
  script, dry-run build, and repository checks are present. Their scope is
  summarized below.
- **Release:** no stable release or support horizon is asserted here.
- **Operation:** no public deployment, hostname, account configuration,
  production health, traffic, or operator activity is asserted here.

BadTower.js is not the Go BadTower implementation and makes no compatibility,
stable LicoArc conformance, publication, endpoint-evidence, endpoint-trust,
anonymity, delivery, approval, or application-effect claim.

## Implemented security boundary

- The data Worker owns fixed liveness, invitation exchange, proof-bound relay
  admission, and the three Durable Object classes. The operator Worker owns
  readiness and exact invitation/grant administration and binds only
  `AccessGrant`.
- Both production configuration templates disable `workers.dev`, preview URLs,
  invocation logs, and traces and contain one non-wildcard placeholder route.
- `bti2` and `bta2` capabilities are canonical, HMAC-authenticated, bounded,
  and rejected before `AccessGrant` selection when invalid. Each `bta2` binds
  an Ed25519 public key, epoch, and expiry.
- Relay requests require a signature over all security-relevant canonical
  request fields. `AccessGrant` atomically consumes one fixed-window counter
  and per-grant request, byte, weight, creation, and concurrency budgets before
  relay or affiliation dispatch. Claim/retrieve leases remain held until the
  response stream closes, fails, is cancelled, or reaches its bounded safety
  deadline.
- Relay handles are fixed 32-byte, versioned, slot-bound, authenticated values
  checked before `RelayHandle` selection.
- CLAIM and RETRIEVE commit compact manifests and stream packet references in
  chunks no larger than 64 KiB. Replays reconstruct the same bytes without a
  persisted full response copy; cancellation does not release committed claim
  ownership.
- Bootstrap and rotation require explicit confirmation and owner-only files.
  Ordinary deployment only validates existing material before invoking
  Wrangler and does not generate or rotate secrets.
- Application responses force `no-store`, `no-referrer`, and `nosniff` and
  remove wildcard CORS. Application logs use a closed categorical schema that
  excludes stable identifiers, request metadata, packet data, sizes, and
  exception text.

`AFFILIATE` and asynchronous `RESERVE` remain closed with
`unsupportedProfile` because required signature material is absent. The relay
does not invent that behavior or redefine external protocol semantics.

## Verified evidence scope

Focused tests cover split ingress and the mTLS application gate; canonical v2
capabilities and Ed25519 transcript binding; monotonic Durable Object-local
charging, replay, exact budgets, and selector-scoped shedding; authenticated
handles; maximum-queue streaming, allocation high-water, stream-lease
completion and cancellation, concurrent ownership, byte-identical restart,
and alarm resumption; invariant responses; disjoint, consistent owner-only
secret material and deployment preflight; and closed observability categories.

Other Workers-runtime suites cover the bounded carrier, opaque relay queue,
claim, retrieval, settlement, expiry, cleanup, and fail-closed unsupported
operations. Wrangler checks generated binding types and can produce local
dry-run bundles without network mutation.

These tests use synthetic inputs and platform metadata. They do not prove real
edge framing, certificates, mTLS integration, DNS, WAF, account policy,
deployment, production capacity, backup/restore, or operation.

## Residual risks

- Cloudflare account, DNS, certificate, route, mTLS, WAF, secret, and
  deployment control remain external trust and availability boundaries.
- Simultaneous theft of an access capability and its bound client private key
  permits use until expiry or revocation. Per-grant budgets bound but do not
  eliminate that impact.
- The platform can observe traffic and storage-access metadata; no anonymity
  or global traffic-analysis resistance is provided.
- Streaming avoids claim-sized response duplication, but one packet BLOB is
  still materialized at a time and extreme concurrency remains subject to the
  Worker's shared resource limits.
- The two Worker deployments are separate operations and are not an atomic
  release or rollback mechanism.
- Provider-generated errors and telemetry are outside the application's
  response and log constructors.

## Publication boundary

Public source may include code, tests, documentation, container and Wrangler
configuration. Credentials, private material directories, local variable
files, Durable Object state, protected packets, logs, usage records, and
deployment-account metadata are private operational material and must never
enter a source release.
