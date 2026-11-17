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
