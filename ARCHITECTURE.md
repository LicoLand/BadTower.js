# Architecture

BadTower.js is a permanent-mailbox relay with three ownership layers:

- `packages/station-core` — the protocol-neutral core: admission
  credential verification, the per-mailbox store, and the native HTTP
  binding. Core never imports, loads or executes plugin code, never
  stores protocol descriptors or plugin-specific state, and never widens
  its contract for one listener.
- `packages/plugin-licoarc-mailbox` — the `licoarc.mailbox.v1`
  compatibility listener: its `/v1/mailbox` route, subprotocol check,
  canonical CBOR frame codec, Ed25519 device-key handshake, and close
  codes. It drives the core store API and reaches nothing beneath it.
- `apps/station` — the deployable Worker (`src/worker.ts`) and the
  composed SQLite Durable Object class `Mailbox` (`src/mailbox.ts`),
  the only place that wires core and plugin together. One Worker and
  one Durable Object class per mailbox stay the whole shape.

## Trust split

- **Worker (edge)**: terminates TLS, refuses non-https requests
  (`BADTOWER_ALLOW_PLAINTEXT` opts in for local development only),
  verifies the `btm1` admission credential (HMAC-SHA256 under
  `BADTOWER_STATION_KEY`, constant-time compare) and forwards verified
  requests. `POST /v1/revoke` verifies a separate `btr1`-domain HMAC
  body and calls `revoke()`.
- **Mailbox DO (per mailbox id)**: the core `MailboxStore` owns the
  SQLite tables `meta` (bound opaque subject identifier, revoked flag)
  and `packet` (sequence, handle, body). The plugin session owns the
  WebSocket attachments; all session state lives there, so the object
  hibernates freely. Core and plugin share no tables.
- **Offline minting**: `scripts/station.mjs` creates credentials —
  `btm1.<base64url>` = mailboxId ‖ notAfter ‖ HMAC(key, "btm1" ‖ …), and
  the revoke body = mailboxId ‖ HMAC(key, "btr1" ‖ mailboxId). `notAfter`
  bounds only the first binding; a bound subject stays admitted until
  revocation.

## Semantics

- A mailbox exists after the first successful binding stores ONE
  fixed-size opaque subject identifier supplied by the caller — the core
  does not know it is an Ed25519 key; a different identifier thereafter
  is refused (the LicoArc listener surfaces this as close code 4003).
- The native contract is Reserve → Submit → Claim → Settle over fixed
  opaque binary fields (`/v1/native/…`, same `btm1` admission), plus
  health, capacity and revocation. It works with no plugin installed.
- Delivery is at-least-once with a 16-packet in-flight window; settle
  deletes the row. Unsettled packets replay in sequence order. When
  nothing is stored and nothing is in flight, the listener signals
  drained.
- Submit targets any mailbox id (the first 16 handle bytes); the store
  rejects unbound/revoked mailboxes and answers transient mailboxFull
  when the object would exceed `BADTOWER_MAILBOX_CAPACITY_BYTES`
  (reads `ctx.storage.sql.databaseSize`).
- The LicoArc listener admits one live connection per mailbox: a new
  READY supersedes older ready sockets (4000). Revocation deletes
  everything and closes sockets (4001).
- Frame errors: text frames, non-canonical CBOR, unknown/duplicate
  labels, out-of-range sizes, trailing bytes → close 1002; state or
  limit violations and bad signatures → 1008.

## Cost shape (Workers Free)

Idle connected devices cost nothing: the object hibernates, WebSocket
Ping/Pong never reaches it, and there are no alarms, no polling, no
leases and no rate-limit buckets to charge.
