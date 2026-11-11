# Status

BadTower.js is the Station for the `licoarc.mailbox.v1` mailbox
transport: one Worker + one SQLite DO `Mailbox`, permanent undelivered
storage, offline-minted admission credentials, no operator service.

Current state: pre-1.0 preview. The relay implements the wire grammar in
`docs/API.md`; conformance runs through `npm run check` and the test
suite (`test/mailbox.test.ts`, `test/station.test.mts`).
