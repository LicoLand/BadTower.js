# BadTower.js

An invitation-gated opaque mailbox relay on Cloudflare Workers: one
Worker in front of one SQLite-backed Durable Object class (`Mailbox`),
one permanent mailbox per mailbox id. Undelivered packets never expire —
a stored packet leaves only on the recipient's settle or on revocation.

The protocol-neutral core (`packages/station-core`) serves a native
Reserve → Submit → Claim → Settle HTTP contract on its own; the
`licoarc.mailbox.v1` WebSocket listener
(`packages/plugin-licoarc-mailbox`) is a replaceable compatibility
plugin; `apps/station` composes them into the deployable Worker.

## Properties

- **Opaque**: the Worker routes 32-byte delivery handles to mailboxes; it
  never sees plaintext, identities, sessions or sizes beyond packet bytes.
- **Invitation-gated**: a mailbox exists after the first valid `btm1`
  admission credential binds. Credentials are minted offline by
  `scripts/station.mjs`; the only operator endpoint is `POST /v1/revoke`,
  which verifies a fixed-size offline-HMAC body.
- **Idle cost**: hibernatable WebSockets — client pings never wake the
  object, so an idle connection costs zero requests and zero object time.

## Deploy to Cloudflare

```sh
npm ci
npm run station -- init --dir <private-dir>
npm run station -- cloudflare-deploy --dir <private-dir> [--domain <name>]
```

`init` creates the 32-byte station key and `.dev.vars` in your private
directory; `cloudflare-deploy` uploads that key as the
`BADTOWER_STATION_KEY` secret and deploys the Worker in one step.

Or deploy with the button:

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/LicoLand/BadTower.js)

The button flow requires the `BADTOWER_STATION_KEY` secret (a 32-byte
base64url string — generate one with `station init`).

Or run it self-hosted in the container: see `docs/OPERATIONS.md`.

## Wire (summary)

Native: `https://<station>/v1/native/{reserve,submit,claim,settle}` with
`Authorization: Bearer btm1.<…>` and fixed binary bodies. LicoArc:
`wss://<station>/v1/mailbox` with `Sec-WebSocket-Protocol:
licoarc.mailbox.v1`; frames are deterministic-CBOR closed maps:
CHALLENGE/HELLO/READY, SEND/RESULT, DELIVER/ACK, DRAINED. Full contracts
in `docs/API.md`; semantics in `ARCHITECTURE.md`.

## Operations

`npm run station -- <command>`: `init`, `invite`, `revoke`, `tls`,
`cloudflare-deploy`, `docker-deploy`, `health`. Private material stays in
an operator directory you pass with `--dir`; nothing private is tracked.
See `docs/OPERATIONS.md`.

## Development

```sh
npm ci
npm run check   # typecheck + script lint + generated-type check + vitest + wrangler dry-run
```

License: AGPL-3.0-or-later. See `SECURITY.md` for disclosure.
