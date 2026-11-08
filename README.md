# BadTower.js

BadTower.js is an open-source, invitation-gated opaque relay for small public
previews. It runs at the Cloudflare edge, stores bounded opaque packet bytes in
SQLite-backed Durable Objects, and never needs message plaintext or client
private keys.

This repository is deployable as a public Workers service and as an isolated
local container. It remains an independent JavaScript implementation: it is
not the Go BadTower product and does not claim stable LicoArc conformance.

## Security model

- An operator creates a service-authenticated, one-time `bti2` invitation.
- Exchange binds the resulting short-lived `bta2` capability to an Ed25519
  client public key. Every relay request requires a fresh canonical signature.
- Invitations and capabilities have bounded lifetimes, epochs, fixed replay
  windows, and exact revocation by opaque invitation id.
- Per-grant request, byte, weighted-operation, creation, and concurrency
  budgets are enforced in strongly consistent Durable Object state.
- Relay handles authenticate before object selection. CLAIM and RETRIEVE
  replay from compact manifests through bounded streams rather than cached
  full response bodies.

The source is public by design. Deployment secrets, operator credentials,
runtime state, ciphertext, and logs are not source artifacts.

## Local container

```sh
docker compose build
docker compose run --rm --entrypoint node badtower \
  scripts/bootstrap-secrets.mjs --target-dir data/private --confirm bootstrap
docker compose up -d
curl --fail http://127.0.0.1:8790/healthz
```

The container binds only to loopback, requires explicitly bootstrapped private
material in its named volume, and persists Durable Object state there. Create an
invitation without copying the operator credential onto the host:

```sh
docker compose exec badtower node scripts/operator.mjs invite \
  --operator-origin http://127.0.0.1:8787
```

Stop it with `docker compose down`. Add `--volumes` only when intentionally
destroying all invitations, access grants, and relay state.

The host-side port defaults to `8790` to avoid common development collisions;
set `BADTOWER_PORT` before `docker compose up` to choose another loopback port.

## Deploy to Cloudflare

Prerequisites are Node.js 24+, npm, a Cloudflare account, and an authenticated
Wrangler session.

```sh
npm ci
npm run check
npm run secrets:bootstrap -- --target-dir .local/cloudflare --confirm bootstrap
# Replace both non-routable route placeholders before the preflight below.
npm run cloudflare:deploy -- .local/cloudflare
```

Deployment validates existing owner-only material and fails closed before
Wrangler if it is incomplete or unsafe. The two production templates disable
`workers.dev` and preview URLs and contain explicit non-wildcard placeholder
hosts that an operator must intentionally replace. Keep the operator token
offline and backed up; losing it removes the supported management path.

Create an invitation:

```sh
npm run operator -- invite \
  --operator-origin https://<your-operator-host> \
  --token-file .local/cloudflare/operator-token
```

The response contains the only copy of the invitation plaintext. Send it to
one intended tester over a separate secure channel. See
[`docs/API.md`](docs/API.md) for client exchange and management calls, and
[`docs/OPERATIONS.md`](docs/OPERATIONS.md) for rotation, revocation, capacity,
and incident procedures.

## Verify

```sh
npm ci
npm run verify:focused
npm run dryrun
```

Tests run in the Workers runtime and cover access exchange, retry stability,
revocation, expiry, denial ordering, protocol contract bytes, reservation,
opaque relay lifecycle, capacity, and privacy-minimal observability.

## Repository map

- `src/access/` — credential formats, exchange, authorization, and operator API
- `src/durable/access-grant.ts` — one invitation/access grant per Durable Object
- `src/durable/affiliation-shard.ts` — bounded per-affiliation coordination
- `src/durable/relay-handle.ts` — bounded opaque packet store
- `src/transport/` — pinned candidate transport and strict CBOR codec
- `scripts/` — explicit secret bootstrap/rotation, operator client, container, and deployment
- `docs/STATUS.md` — verified capability and lifecycle authority

BadTower.js is licensed under AGPL-3.0-or-later.
