# Contributing

## Prerequisites

- Node.js 22 or later
- npm
- Docker only for container verification
- A Cloudflare account only for an explicitly authorized deployment

## Development

```sh
npm ci
npm run test
```

`npm run test` runs the vitest suite: the Workers-runtime LicoArc
protocol and composition tests, the core-only native-contract tests
against `test/harness/`, the source-boundary checks, and the Node
ops-script checks. `npm run check` adds strict TypeScript checks,
script lint, generated-binding drift detection and a Wrangler
deployment dry run without publishing anything.

## Layout

- `packages/station-core` — protocol-neutral core: admission
  credentials (`btm1`/`btr1` HMAC), the per-mailbox store, the native
  `/v1/native/…` HTTP binding.
- `packages/plugin-licoarc-mailbox` — the `licoarc.mailbox.v1`
  listener: `/v1/mailbox`, subprotocol check, canonical CBOR frames,
  Ed25519 handshake, close codes.
- `apps/station` — the deployable Worker and the composed `Mailbox`
  Durable Object; the only place core and plugin meet.

## Rules

- Never commit credentials, `.local/`, `.dev.vars*`, `.env*`, Cloudflare state,
  runtime data, logs, ciphertext, or plaintext user content.
- Never write a key, credential or test secret as a literal in the
  tree; mint all credential-shaped values at run time.
- Generate all credentials with the provided cryptographic generator. Do not
  add human-chosen invitation or access-token paths.
- Keep authentication before relay lookup, carrier validation before body
  reading, and all allocations and durable collections explicitly bounded.
- Keep core routing protocol-neutral. Core never imports, loads or
  executes plugin code, never stores protocol descriptors or
  plugin-specific state, and never widens its contract for one
  listener; `test/boundary.test.mts` enforces it. Each plugin owns its
  listener, its exact protocol binding, configuration, state and
  tests, and drives the core store API only.
- `scripts/station.mjs` refuses private outputs inside the repository
  unless they sit under an ignore-covered root (`data/` or `secrets/`).
- Use synthetic opaque bytes in tests. Never convert production traffic or
  logs into fixtures.
- Update canonical documentation in the same change as behavior. Pending plans
  belong only in ignored `docs/plans/`.

## Pull requests

Keep one independently testable behavior per change. Include the focused test
that proves it, describe security-boundary changes, and state whether the
Wrangler dry run and container smoke test were performed. Publishing,
deployment, credential rotation, and runtime-data access are separate operator
decisions and must not occur as a side effect of a source contribution.
