# Changelog

All notable changes to BadTower.js are recorded here. The release version
lives in the root `package.json`; `npm run check:version` requires every
workspace manifest, `package-lock.json` and the newest heading below to
agree with it. The version is a source identifier, not a claim that a
tag, image or hosted deployment exists.

## [0.0.0-preview.0] - 2026-11-16

The first recorded preview baseline. It is the state of the repository
before the first tagged release; no tag or published artifact is implied.

### Added

- Protocol-neutral `station-core` with the native Reserve → Submit →
  Claim → Settle HTTP contract, opaque admission credentials, capacity
  reporting, revocation and the fixed-binary native contract version
  query.
- The separately packaged `licoarc.mailbox.v1` WebSocket compatibility
  listener and the deployable Worker that composes it with the core.
- SQLite-backed `Mailbox` Durable Object with permanent undelivered
  storage, at-least-once claim/replay and an in-flight window.
- Offline-minted `btm1` admission credentials and `btr1` revocation,
  plus the `station.mjs` operator CLI.
- Cloudflare, Docker and local-TLS deployment paths.
- Version-source checking and this changelog.
- Product, context, native-contract, cost, abuse/capacity, operations
  visibility and offline-wake design documents.
- Pinned A2A and MCP plugin Lines, bindings, consistency sources and
  support scopes; no plugin implementation or conformance claim.
- Implementation-neutral native-contract conformance cases under
  `test/conformance/`, consumed by the core test suite and sharable
  with other implementations.
- Plan-aware platform limits (`BADTOWER_PLAN`, validated at startup
  against explicit Free/Paid ceilings) and measured capacity
  accounting: submit judges the post-insert `databaseSize` in a
  transaction and maps `SQLITE_FULL` to the transient `mailbox-full`.
- Operator aggregate cost meters at `GET /v1/metrics`: Worker/DO
  requests, DO active duration, SQLite rows and stored bytes with
  bounded `operation`/`direction`/`plan` labels only.
- `docs/ISSUANCE.md` — design for self-serve credential issuance
  alongside offline invitations; no issuance endpoint exists yet.

### Fixed

- Recipient operations are scoped to the binding transport: a mailbox
  bound through a compatibility listener now answers 403 to native
  claim, settle and capacity, so a copied `btm1` admission credential
  can no longer read or delete a device-bound mailbox's packets. The
  first binding records its transport in `meta.via`; mailboxes bound
  before this record exists answer as unknown, never as native.
  Submit stays open cross-transport. No wire field, status
  set or documented outcome changed, so the native contract stays
  `1.0`; the refusal shape is the one unbound and revoked mailboxes
  already answered.
- The verified bind deadline now travels in the WebSocket attachment
  and is enforced again at the durable first bind, so a challenged
  socket can no longer complete a first HELLO after the invitation's
  signed `notAfter`. An already-bound subject keeps facing only its
  subject check.
- Packet sequences are allocated from a durable, non-reusing `alloc`
  row inside the packet transaction instead of the rowid default, so
  a delayed or retried settle can never delete a newer packet under a
  reused sequence and stale in-flight exclusions cannot suppress one.
- `station.mjs` resolves a private output's physical ancestry through
  symlinks (and the repository root itself) before permitting an
  in-tree write, so `--dir`/`--out` can no longer place key material
  in a tracked path or the Docker build context via a symlinked
  ancestor.
- `GET /v1/metrics` accepts a separate metrics-only credential
  (`BADTOWER_METRICS_KEY`) alongside the station key, and
  `station.mjs metrics` reads it from disk inside the process — the
  credential no longer appears in a command line or process listing.
  `init` mints `metrics.key`; `metrics-key` adds it to directories
  initialized earlier.
- The binding transport is enforced on the listener too: a mailbox
  bound natively refuses the listener's READY, recipient operations on
  both surfaces pass through recorded-transport gates, and a listener
  ACK settles only a sequence its own connection was delivered — a
  stale or forged ACK can never delete a packet another session is
  owed.
- A mailbox bound before binding records existed refuses new
  submissions and all recipient operations until a verified re-bind —
  re-reserving the stored subject natively, or re-HELLOing the bound
  device key — records the transport, preserving the queued packets.
- The durable sequence allocator seeds above every sequence a
  pre-allocator mailbox could have issued, so sequences settled before
  the allocator existed can never be reissued to newer packets.
- `station.mjs metrics-key` aligns the credential across `metrics.key`
  and `.dev.vars` instead of minting a divergent one: a valid existing
  `.dev.vars` entry is adopted, a missing or malformed one is repaired
  in place, and the command converges safely on rerun.
- `station.mjs` resolves every component of a private write
  destination through links — including dangling ones — so key
  material cannot be written outside the intended private directory,
  and every file a command writes is validated, not only its parent.
- `cloudflare-deploy --domain` writes its temporary Wrangler config
  beside `apps/station/wrangler.jsonc`, so the config's relative
  `main` still resolves to `src/worker.ts`; deploy-button and
  operations documentation now name both required secrets.
- Mailboxes bound under the original schema (owner in
  `meta.device_key`) upgrade on first read: the column is renamed to
  `subject`, so the verified owner re-binds and recovers queued
  packets instead of hitting a missing-column insert. The binding
  transport now lives in `meta.via`: recording it on re-bind is an
  in-place update that needs no new page, so a mailbox at its storage
  ceiling can still re-bind and drain, and the retired `binding`
  table is folded in and dropped.
- Allocator rows persisted below the sequence floor are raised inside
  the packet transaction, so databases that already carried a low
  counter keep every future sequence above the pre-allocator epoch.
- A HELLO against a natively bound mailbox now closes with the
  documented wrong-transport 1008 before the subject is compared,
  whether or not the presented device key matches.
- `station.mjs metrics-key` resolves `BADTOWER_METRICS_KEY` the way
  Wrangler parses `.dev.vars` — quoted values and last-wins
  duplicates — so it can no longer adopt a shadowed entry and strand
  the CLI on a stale credential. Both output files are now replaced
  atomically, and metrics.key/.dev.vars resolving to the same file is
  refused before either write.
- The private-output containment check matches only an actual `..`
  path component, so in-repository names that merely start with two
  dots are refused on both the lexical and symlink-resolved paths.
- `cloudflare-deploy --domain` writes its temporary Wrangler config
  under a unique per-process name and removes it even when the
  Wrangler child fails, so a rejected deploy no longer strands a
  generated file and concurrent deploys cannot collide.
