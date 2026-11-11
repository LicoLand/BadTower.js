# Status

BadTower.js is a permanent-mailbox Station in three layers: the
protocol-neutral `station-core` (admission credentials, per-mailbox
store, native HTTP binding), the `licoarc.mailbox.v1` compatibility
listener, and the deployable Worker that composes them — one Worker +
one SQLite DO `Mailbox`, permanent undelivered storage, offline-minted
admission credentials, no operator service.

Current state: pre-1.0 preview. The native contract and the LicoArc wire
grammar are documented in `docs/API.md`; conformance runs through
`npm run check` and the test suite (`test/mailbox.test.ts`,
`test/composition.test.ts`, `test/native.test.ts`,
`test/station.test.mts`, `test/boundary.test.mts`). The core is
verifiable without the plugin through `test/harness/`, a core-only
synthetic station.
