# Station API

Two surfaces share one mailbox store:

- the **native contract** — the station's own protocol-neutral
  Reserve → Submit → Claim → Settle over fixed opaque binary fields.
  It is complete on its own and needs no compatibility listener.
- the **LicoArc mailbox listener** — the `licoarc.mailbox.v1` WebSocket
  binding owned by `plugin-licoarc-mailbox`. It is exactly one protocol
  line, with no negotiation and no translation.

Every authenticated surface admits the same credential:

`btm1.` + base64url( mailboxId(16) ‖ notAfter(u64 BE, unix seconds) ‖
HMAC-SHA256(stationKey, "btm1" ‖ mailboxId ‖ notAfter) ) — 56 bytes.
`notAfter` bounds only the first binding; a bound subject stays admitted.

## Native contract

Carrier: `https://<station>/v1/native/*`, `Authorization: Bearer btm1.<…>`.
Bodies are `application/octet-stream`; every response body is the same.
No response carries error text.

- `POST /v1/native/reserve` — body: subject(32), one fixed-size opaque
  identifier. First call binds the credential's mailbox; the same
  subject repeats idempotently; a different one is refused. Status:
  200 bound, 400 bad shape, 401 credential, 403 bind window closed or
  revoked, 409 different subject already bound.
- `POST /v1/native/submit` — body: handle(32) ‖ packet(1..524288).
  Routes by the handle's first 16 bytes to the target mailbox.
  200 body: outcome(1) ‖ reason(1): outcome 0 accepted / 1 rejected /
  2 transient; reason 255 none, 0 invalidRequest, 1 targetUnavailable,
  2 packetTooLarge, 3 mailboxFull, 4 internalUnavailable.
- `POST /v1/native/claim` — body: limit(1 ≤16) ‖ count(1) ‖
  sequence(u64 BE)×, the caller's still-in-flight sequences.
  200 body: count(1) ‖ [sequence(u64 BE) ‖ handle(32) ‖
  length(u32 BE) ‖ body]× in replay order. 403 while the mailbox is
  unbound or revoked.
- `POST /v1/native/settle` — body: count(1) ‖ sequence(u64 BE)× —
  deletes those packets. 204 settled, 403 unbound or revoked.
- `GET /v1/native/capacity` — 200 body: capacityBytes(u64 BE) ‖
  databaseBytes(u64 BE). 403 while unbound or revoked.
- `POST /v1/revoke` — body: mailboxId(16) ‖ HMAC(stationKey, "btr1" ‖
  mailboxId). Idempotent 204: the mailbox's packets are gone and the
  mailbox can never bind again.
- `GET /healthz` — unauthenticated liveness.

Claimed-but-unsettled packets replay on the next claim — delivery is
at-least-once. The caller owns its in-flight set and passes it as the
exclude list.

## LicoArc mailbox listener

Carrier: `wss://<station>/v1/mailbox`, TLS 1.3, HTTP/1.1 Upgrade.
Required request headers: `Upgrade: websocket`,
`Sec-WebSocket-Protocol: licoarc.mailbox.v1` (echoed on success),
`Authorization: Bearer <station admission credential>`.

Every WebSocket message is one binary frame: a deterministic-CBOR closed
map whose label 0 is the frame type. Canonical rules: definite shortest
lengths, no tags, no floats or text, no duplicate/unknown/unordered
labels, no trailing bytes. Max frame 524288 + 128 bytes.

### Frames

Client → Station
- `HELLO {0:1, 1: bstr 32 (Ed25519 public key), 2: bstr 64}` — signature
  over `"licoarc-mailbox-hello-v1" ‖ nonce`. First frame after upgrade
  must be HELLO; anything else → close 1008. The verified key becomes
  the mailbox's opaque subject in the core store.
- `SEND {0:2, 1: uint reqid, 2: bstr 32 (delivery handle), 3: bstr 1..524288}`
- `ACK {0:3, 1: uint (delivery sequence)}`

Station → Client
- `CHALLENGE {0:16, 1: bstr 32}` — first frame after upgrade.
- `READY {0:17, 1: bstr 16 (mailbox id)}`.
- `RESULT {0:18, 1: uint reqid, 2: uint ≤2 (0 accepted/1 rejected/2
  transient), ?3: uint failure class, ?4: uint ≤60000 retryAfterMs}`.
- `DELIVER {0:19, 1: uint seq, 2: bstr 32 (handle), 3: bstr 1..524288}`.
- `DRAINED {0:20}` — nothing stored, nothing in flight.

Failure classes: 0 invalidRequest, 1 targetUnavailable, 2 packetTooLarge,
3 mailboxFull (transient), 4 internalUnavailable (transient).

### Semantics

Delivery Handle (32 B) = mailboxId(16) ‖ endpoint tag(16). The Station
routes only by mailboxId; the tag rides opaquely through DELIVER.
At-most-16 un-ACKed DELIVERs and at-most-16 un-RESULTed SENDs per
connection (exceeding closes 1008). One live connection per mailbox; a
new READY supersedes older ones (4000). RESULT accepted means durably
stored; connection loss before RESULT is the sender's ambiguous outcome —
resend on a new connection.

### Revocation

`POST /v1/revoke`, `content-type: application/octet-stream`, body =
mailboxId(16) ‖ HMAC-SHA256(stationKey, "btr1" ‖ mailboxId) — 48 bytes.
Idempotent 204: the mailbox's packets are gone, sockets close 4001, and
the credential can never bind again.

## Errors

No response carries error text. HTTP: 400 bad request shape, 401 failed
credential, 403 plaintext transport, expired bind, revoked or unbound
mailbox, 404 unknown path, 409 subject mismatch (native reserve only).
Close codes: 1002 malformed, 1008 policy, 4000 superseded, 4001 revoked,
4003 device key mismatch.
