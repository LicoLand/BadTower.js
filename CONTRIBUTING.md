# Contributing

## Prerequisites

- Node.js 24 or later
- npm
- Docker only for container verification
- A Cloudflare account only for an explicitly authorized deployment

## Development

```sh
npm ci
npm run verify:focused
```

`verify:focused` runs strict TypeScript checks, generated-binding drift,
Workers-runtime access, admission, contract, reservation and relay suites, and
repository-fact checks. Run the integrated `npm run check` once after all
changes; it adds a Wrangler deployment dry run without publishing anything.

## Rules

- Never commit credentials, `.local/`, `.dev.vars*`, `.env*`, Cloudflare state,
  runtime data, logs, ciphertext, or plaintext user content.
- Generate all credentials with the provided cryptographic generator. Do not
  add human-chosen invitation or access-token paths.
- Keep authentication before relay lookup, carrier validation before body
  reading, and all allocations and durable collections explicitly bounded.
- Keep core routing protocol-neutral. Candidate transport behavior remains in
  `src/transport/`; access control cannot acquire endpoint identity or trust
  semantics.
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
