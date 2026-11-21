# Status

Last updated: 2026-11-16. Source version: `0.0.0-preview.0`
(`package.json`; see `CHANGELOG.md`). Native contract version: `1.0`
(`GET /v1/native/version`).

This file separates six questions that are often collapsed into one
"done" claim: what the product intends, what is implemented, what was
actually verified, what is released, what is supported, and what is
operated. A later section being weak does not invalidate an earlier one,
and an earlier section being strong does not prove a later one.

## 1. 意图 (Intent)

BadTower.js is a protocol-neutral, invitation-gated communication
Station: one permanent mailbox per mailbox id, opaque packets stored
until the recipient settles them or the operator revokes the mailbox.
The Station is untrusted infrastructure. It is not an identity provider,
a trust authority, a protocol implementation, or a client. Its native
contract is complete without any compatibility plugin, and plugins are
separately packaged listeners that drive the contract through the core's
published API.

The product boundary is stated in `PRODUCT.md`; terminology and
ownership are in `CONTEXT.md`. The intended invariants are protocol
neutrality, opacity, permanent storage, bounded resources, fail-closed
overload, and plugin isolation.

## 2. 实现 (Implementation)

Implemented in this repository:

- `packages/station-core` — admission credentials, per-mailbox SQLite
  store, native HTTP binding, health, capacity, revocation, contract
  version query.
- `packages/plugin-licoarc-mailbox` — the `licoarc.mailbox.v1` WebSocket
  listener: canonical CBOR frames, Ed25519 challenge/hello, SEND/RESULT,
  DELIVER/ACK, DRAINED, close codes, hibernatable sockets.
- `apps/station` — the deployable Worker and the composed `Mailbox`
  Durable Object; the only place core and plugin are wired together.
- `scripts/station.mjs` — offline key/invitation/TLS/deploy CLI.
- `scripts/check-version.mjs` — single version source check.
- `scripts/interop.mjs` — local two-endpoint interop harness.
- Native contract version `1.0`, served at `GET /v1/native/version` and
  documented in `API.md` and `NATIVE-CONTRACT.md`.
- Implementation-neutral native-contract conformance cases
  (`test/conformance/*.json`, format in `test/conformance/README.md`)
  driven against the core harness; the same data files are the
  conformance source for other implementations.
- Plan-aware limits: `BADTOWER_PLAN` selects the explicit Free/Paid
  platform ceilings; mailbox capacity above the plan's per-object
  limit refuses to run.
- Measured capacity accounting: submit judges the post-insert
  `databaseSize` inside a transaction (row overhead and page growth
  counted), and `SQLITE_FULL` maps to the transient `mailbox-full`.
- Aggregate cost meters at `GET /v1/metrics` (station-key or
  metrics-only bearer):
  Worker/DO requests, DO active duration, SQLite rows read/written and
  stored bytes, labelled only by `operation`/`direction`/`plan`.
- Design documents: `PLUGIN-A2A.md`, `PLUGIN-MCP.md`,
  `ABUSE-CAPACITY.md`, `OPERATIONS-VISIBILITY.md`, `COST.md`,
  `OFFLINE-WAKE.md`, `ISSUANCE.md`.

Not implemented (do not infer from a design document):

- A2A compatibility plugin, MCP compatibility plugin, or any listener
  beyond `licoarc.mailbox.v1`.
- Self-serve issuance (`ISSUANCE.md` is the design), offline wake hook,
  per-credential/per-target ingress budgets, global storage budget,
  the wider operations metric catalogue and abandoned-mailbox sweep.
- Cluster, replication, failover, backup/restore, or plugin host.
- Any A2A or MCP conformance claim. Both plugin documents are pins and
  support scopes, not implementations.

## 3. 验证 (Verification)

Verified in this working tree on 2026-11-21:

| Check | Command | Result |
| --- | --- | --- |
| Version source | `npm run check:version` | pass: `0.0.0-preview.0` consistent across root manifest, 3 workspace manifests, lockfile and CHANGELOG |
| TypeScript | `npm run typecheck` | pass (source and test projects) |
| Native contract | `npm run test:core` | pass: native suite plus the 16 data-file conformance cases from `test/conformance/` |
| Full repository check | `npm run check` | pass: version, typecheck, script syntax, generated types, all tests, wrangler dry-run |

Earlier on 2026-11-16:

| Check | Command | Result |
| --- | --- | --- |
| Two-endpoint interop | `node scripts/interop.mjs` with published `licoarc-client 0.2.0` | pass: two enrollments/handshakes, A→B 96-byte offline delivery, B→A 64-byte offline delivery, both byte-equal, redrain returned 0 |

The interop run used the crates.io release `licoarc-client 0.2.0`
(`cargo install licoarc-client --version 0.2.0 --locked`), a locally
generated CA and `wrangler dev --local` over HTTPS. It did not use a
production Station, a production secret, or a repository-external
script. The packets are deterministic (`0xa1` × 96 for A→B, `0xb2` × 64
for B→A), so the passing run's SHA-256 values are reproducible:
`7e8289d9dd1f003c18fbe0a244a2dbf585b38bd341a637975682b9920a8f3180`
(A→B, 96 bytes) and
`330fe7e64d21a084e54c7f62827ab9c978e656a8c507eb0daf91d6a7969e40ca`
(B→A, 64 bytes).

The GitHub Actions workflow now has a `source` job (`npm run check`) and
an `interop` job (installs the published client and runs the same
script). **No GitHub Actions run has been observed in this session.**
The local commands above are the evidence; the workflow is the
automation, not proof that it already ran on GitHub.

Not verified: A2A or MCP conformance, Cloudflare invoice amounts, a
production deployment, free-plan limit behavior under load, wake-hook
privacy properties, or any cluster behavior.

## 4. 发布 (Release)

- The only version source is the root `package.json` version,
  `0.0.0-preview.0`. Workspace manifests and `package-lock.json` must
  match it; `CHANGELOG.md` must contain exactly one matching heading.
  The bump procedure is in `VERSIONING.md`.
- `CHANGELOG.md` now has its first record for `0.0.0-preview.0`.
- There is **no tagged release, no published image, and no hosted
  deployment** claimed by this repository state. The version is a source
  identifier, not a release artifact.
- The native contract version (`1.0`) is independent of the package
  version. Its change rules are in `NATIVE-CONTRACT.md`.
- A2A and MCP plugin versions do not exist yet; their pinned Lines are
  design inputs, not releases.

## 5. 支持 (Support)

- Scope: the native contract, the `licoarc.mailbox.v1` listener, the
  Worker composition, the operator CLI and the documented checks.
- No SLA, no availability target, no compatibility guarantee beyond the
  documented contract and pinned plugin Lines, and no support for a
  production plugin that is not in this repository.
- A2A and MCP are design pins only; there is no support commitment for an
  unimplemented listener, and no conformance claim.
- Security disclosure: see `SECURITY.md`. Do not put secrets, invitation
  tokens, mailbox ids, packet bodies, or private deployment data in an
  issue.
- The maintenance statement remains: BadTower.js is the actively
  maintained BadTower implementation; the Go implementation in the
  `BadTower` repository follows it through periodic updates.

## 6. 运营 (Operations)

- Deployment paths: Cloudflare Worker (`station cloudflare-deploy`),
  self-hosted Docker (`station docker-deploy`), and local TLS
  (`wrangler dev --local` with a private CA). See `OPERATIONS.md`.
- `wrangler.jsonc` still sets `observability.enabled: false` and
  `logs.enabled: false`. There is no per-mailbox inventory and no
  abandoned-mailbox sweep. The cost-dimension meters are exported at
  `GET /v1/metrics` for the holder of the station key or the
  metrics-only key; the rest of the
  catalogue in `OPERATIONS-VISIBILITY.md` is not built.
- Cost: the official inputs and formulas are in `COST.md`, read from
  Cloudflare documentation on 2026-11-16. No invoice, spend forecast, or
  free-tier guarantee is claimed. Plan-aware limits, measured capacity
  accounting and the cost meters are implemented; the global storage
  budget remains a Kanban task.
- Abuse: per-mailbox capacity (now measured post-insert), the 16-packet
  in-flight window, one live socket and admission are implemented.
  Per-credential/per-target budgets and the global storage budget are
  not. See `ABUSE-CAPACITY.md`.
- Offline wake: not configured, not implemented, and absent by default.
  When unconfigured, Station behavior is unchanged by design; see
  `OFFLINE-WAKE.md`.
- A2A/MCP plugins: not deployed, not supported, not running.

## Maintenance note

The repository is pre-1.0. The strongest current evidence is the native
core test suite and the local two-endpoint interop run. The weakest
current areas are release artifacts, aggregate operations visibility,
abuse budgets, and the unimplemented compatibility plugins. Those gaps
are stated rather than papered over.
