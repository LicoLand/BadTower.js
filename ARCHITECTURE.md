# Architecture

BadTower.js is a permanent-mailbox relay: one Worker (`src/worker.ts`) in
front of one SQLite Durable Object class `Mailbox` (`src/mailbox.ts`).

## Trust split

- **Worker (edge)**: terminates TLS, verifies the `btm1` admission
  credential (HMAC-SHA256 under `BADTOWER_STATION_KEY`, constant-time
  compare) and forwards the upgrade to the mailbox object. No request
  reaches an object before verification. `POST /v1/revoke` verifies a
  separate `btr1`-domain HMAC body and calls `revoke()`.
- **Mailbox DO (per mailbox id)**: SQLite tables `meta` (bound device key,
  revoked flag) and `packet` (sequence, handle, body). All session state
  lives in WebSocket attachments, so the object hibernates freely; the
  only cached field is the lazily re-read meta row.
- **Offline minting**: `scripts/station.mjs` creates credentials —
  `btm1.<base64url>` = mailboxId ‖ notAfter ‖ HMAC(key, "btm1" ‖ …), and
  the revoke body = mailboxId ‖ HMAC(key, "btr1" ‖ mailboxId). `notAfter`
  bounds only the first binding; a bound device stays admitted until
  revocation.

## Semantics

- A mailbox exists after the first successful HELLO binds its Ed25519
  device key; a different key thereafter is refused (4003).
- Delivery is at-least-once with a 16-packet in-flight window; ACK
  deletes the row. A reconnect without ACK replays in sequence order.
  When nothing is stored and nothing is in flight, the object sends
  DRAINED.
- SEND targets any mailbox id (the first 16 handle bytes); `store()`
  rejects unknown/revoked mailboxes and answers transient mailboxFull
  when the object would exceed `BADTOWER_MAILBOX_CAPACITY_BYTES` (reads
  `ctx.storage.sql.databaseSize`).
- One live connection per mailbox: a new READY supersedes older ready
  sockets (4000). Revocation deletes everything and closes sockets (4001).
- Frame errors: text frames, non-canonical CBOR, unknown/duplicate
  labels, out-of-range sizes, trailing bytes → close 1002; state or limit
  violations and bad signatures → 1008.

## Cost shape (Workers Free)

Idle connected devices cost nothing: the object hibernates, WebSocket
Ping/Pong never reaches it, and there are no alarms, no polling, no
leases and no rate-limit buckets to charge.
