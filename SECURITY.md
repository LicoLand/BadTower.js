# Security policy

## Supported source surface

Security maintenance covers the current source candidate and artifacts built
from it without source changes. This repository does not establish that any
particular instance has been deployed, is correctly configured, or is being
operated. Report vulnerabilities through the repository's private
vulnerability-reporting form under its Security tab. Reports must not include
real credentials, protected packets, plaintext, Durable Object rows, service
logs, account data, or user-identifying information.

## Credentials and request proof

The implemented credential boundary has three classes:

- `bto1` is the operator bearer token. The operator Worker receives its
  SHA-256 digest, not the token, through `BADTOWER_OPERATOR_TOKEN_DIGEST`.
- `bti2` is a fixed-format invitation capability authenticated with
  HMAC-SHA-256. It contains a version, capability-key identifier, random
  selector, absolute expiry, and authentication tag.
- `bta2` is a fixed-format access capability authenticated with
  HMAC-SHA-256. It additionally binds one Ed25519 public key and grant epoch.

An access capability is not sufficient to authorize a relay request. Each
request carries an Ed25519 proof over a length-prefixed transcript containing
the access-capability digest, method, canonical path, media type, canonical
content length, 16-byte operation id, SHA-256 body digest, issuance time, and
unsigned 64-bit counter. Proof timestamps have a fixed five-minute skew
window. The bound private key remains client-owned and is never sent to or
stored by the service.

The `AccessGrant` Durable Object atomically checks expiry, epoch, public-key
binding, the 128-counter replay bitmap, and per-grant resource budgets before
authorizing dispatch. Its fixed-state budgets cover request tokens, request
bytes, weighted operations, a 32-creation ceiling, and at most eight live
claim/retrieve response-stream leases. Platform rate-limit bindings use an
authenticated selector and fixed operation class as an outer shedding
layer and are not the authorization or accounting authority.

Invitation and access capabilities are authenticated before selecting an
`AccessGrant`. Relay handles are 32-byte authenticated values containing a
version, key slot, 16 random bytes, and a truncated HMAC tag. A handle's tag
and slot lifetime are checked before selecting a `RelayHandle`. These checks
reduce forged-selector and forged-handle object creation; they do not make a
service handle an endpoint identity or trust assertion.

## Secret lifecycle

- Production configuration names the required Worker secrets but contains no
  secret values. Private local material belongs only in ignored, owner-only
  locations.
- `npm run secrets:bootstrap -- --target-dir <private-dir> --confirm bootstrap`
  is the explicit, exclusive initialization action.
- `npm run secrets:rotate -- --target-dir <private-dir> --confirm rotate`
  explicitly advances capability and handle key slots in existing validated
  material. It does not rotate the operator token.
- `npm run cloudflare:deploy -- <private-dir>` validates existing material and
  configuration, then invokes Wrangler. It never creates or rotates secrets.
- Lifecycle scripts reject missing confirmation, symbolic links, broad file
  permissions, incomplete material, and non-canonical schemas. Their normal
  output reports only the action result, not values, digests, or paths.

The capability keyring is bounded to four keys. Retained capability keys keep
capabilities issued under those keys verifiable; handle slots have explicit
deadlines. Key retirement, grant revocation, external secret injection, and
coordination across the two Workers remain operator actions and must be
planned before rotation.

## Request, response, and data boundaries

- Public-service calls require HTTPS. Plain HTTP is admitted only in explicit
  local mode for loopback hostnames.
- Request paths, visible headers, bodies, packets, queues, claims, replay
  records, settlements, retention, and cleanup batches have fixed bounds.
- Protected packets remain opaque BLOBs and are not exposed by operator APIs.
- CLAIM and RETRIEVE persist compact operation manifests and packet references,
  then emit `ReadableStream` responses in chunks no larger than 64 KiB. They do
  not persist a second full response body. Claim ownership commits before
  streaming, so cancellation does not release or duplicate a claim; a valid
  operation replay reconstructs the same bytes from retained packet references.
- Application-created responses pass through one constructor that forces
  `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, and
  `X-Content-Type-Options: nosniff`, while removing wildcard CORS.
- Exceptions caught by either entrypoint are mapped
  to closed failure classes without returning exception text or stack traces.

## Observability

Application logs are constructed from a closed schema containing only schema
version, event class, operation, outcome, failure class, and an optional
bounded coarse count. They exclude credentials, selectors, client-derived
digests, handles, item and claim identifiers, protected packets, individual
sizes, headers, URLs, addresses, error text, and stack traces. Both production
configurations disable invocation logs and traces. Provider-side telemetry,
network metadata and failures after a response stream begins remain outside
this application-level response guarantee.

## Explicit limitations and residual risks

- The implementation does not provide anonymity or resistance to global
  traffic analysis. The infrastructure can observe connection, timing, size,
  route, and Durable Object access metadata.
- Acceptance, health, readiness, claim, retrieval, or settlement is only
  service-local state. It is not proof of endpoint identity, authenticity,
  freshness, delivery, approval, or application effect.
- A stolen access capability cannot be used without its bound private key, but
  simultaneous compromise of both permits use until expiry or revocation.
  Atomic budgets limit resource use; they do not recover a compromised client.
- Compromise or misconfiguration of the Cloudflare account, DNS, routes,
  mTLS policy, WAF, deployment credentials, or secret material can
  defeat repository-level controls.
- Streaming removes claim-sized response copies, but each selected packet is
  still read as one bounded BLOB and extreme concurrency still consumes the
  Worker's shared memory and CPU budget.
- The repository verifies split entrypoints and closed configuration
  templates locally. It does not verify a real hostname, certificate, edge
  identity mapping, WAF policy, deployed artifact, or running service.
- This service does not define external protocol meaning, endpoint trust, or
  conformance. Unsupported signature-dependent operations fail closed.
