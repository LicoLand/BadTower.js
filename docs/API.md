# HTTP API

BadTower.js has separate data and operator origins. The checked-in hostnames
are non-routable placeholders; this document does not identify a deployed
service. HTTPS is required except for explicit local mode on a loopback host.
Application-created responses include `Cache-Control: no-store`,
`Referrer-Policy: no-referrer`, and `X-Content-Type-Options: nosniff` and do not
enable wildcard CORS.

## Data origin

### Liveness

`GET /healthz` returns only a fixed liveness result. The data origin has no
readiness or operator handler.

### Invitation exchange

`POST /v1/invitations/exchange` accepts an exact JSON object no larger than
1 KiB:

```json
{
  "invitation": "bti2.<authenticated-capability>",
  "clientPublicKey": "<32-byte Ed25519 public key as unpadded base64url>"
}
```

Success returns:

```json
{
  "accessToken": "bta2.<authenticated-capability>",
  "expiresAt": "<UTC timestamp>"
}
```

The invitation capability is authenticated before its selector is used. The
exchange atomically binds the grant to the supplied public key. A repeat with
the same invitation and public key can reproduce the result during the
ten-minute exchange window; another key is rejected. The default access
lifetime is 24 hours and the accepted range is one hour through seven days.

### Proof-bound relay requests

Relay calls use `Authorization: Bearer bta2.<authenticated-capability>` and
the following required proof headers:

- `badtower-proof-issued-at`: canonical decimal Unix epoch milliseconds,
  within five minutes of service time;
- `badtower-proof-counter`: canonical decimal unsigned 64-bit counter; and
- `badtower-proof-signature`: 64-byte Ed25519 signature as canonical unpadded
  base64url.

The signature transcript binds the capability digest, HTTP method, exact
canonical path, media type, canonical `Content-Length`, 16-byte operation id,
SHA-256 digest of the exact request body, issuance time, and counter. The
request also carries `licoarc-operation-id` as 32 lowercase hexadecimal
characters. Reuse of a counter is rejected by the grant's fixed 128-counter
window.

All relay methods are `POST`:

| Path | Request media type | Request-body bound |
| --- | --- | ---: |
| `/v1/affiliate` | `application/licoarc-transport+cbor` | 16 KiB |
| `/v1/reserve` | `application/licoarc-transport+cbor` | 16 KiB |
| `/v1/handles/<handle>/submit` | `application/licoarc-protected-packet` | 512 KiB |
| `/v1/handles/<handle>/retrieve` | `application/licoarc-transport+cbor` | 16 KiB |
| `/v1/handles/<handle>/claim` | `application/licoarc-transport+cbor` | 16 KiB |
| `/v1/handles/<handle>/settle` | `application/licoarc-transport+cbor` | 16 KiB |

The delivery handle is canonical unpadded base64url for a 32-byte
self-authenticating value. CLAIM and RETRIEVE success bodies are streamed and
their operation replays are rebuilt from compact manifests and retained packet
references. The operation names, CBOR labels, media types, and response headers
project the implementation's pinned candidate transport. They do not make
BadTower.js the authority for external protocol semantics, endpoint behavior,
or conformance.

## Operator origin

Every route below first requires the configured external mTLS gate
and then `Authorization: Bearer bto1.<secret>`. The repository does not supply
or verify a real edge policy.

### Readiness

`GET /readyz` reports only whether required operator and capability material
has a valid application shape. It does not inspect relay state or prove that
DNS, certificates, account policy, dependencies, or a deployed service are
healthy.

### Create invitation

`POST /v1/operator/invitations` accepts an exact JSON object with optional
fields:

```json
{
  "invitationTtlSeconds": 604800,
  "accessTtlSeconds": 86400
}
```

Invitation lifetime is five minutes through 30 days. Access lifetime is one
hour through seven days. Success returns the one-time `bti2` invitation,
opaque invitation id, invitation expiry, and selected access lifetime. No
grant-list endpoint exists.

### Exact-id status and revocation

- `GET /v1/operator/grants/<invitationId>` returns `absent`, `invited`, or
  `active`, plus bounded expiry and epoch facts when present.
- `DELETE /v1/operator/grants/<invitationId>` deletes that grant's invitation,
  access, replay, and budget state and returns `204`.

These are service-local administrative facts. They do not attest to an
endpoint, packet delivery, approval, or application effect.
