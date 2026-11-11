# Wire API — mailbox transport v1

Carrier: `wss://<station>/v1/mailbox`, TLS 1.3, HTTP/1.1 Upgrade.
Required request headers: `Upgrade: websocket`,
`Sec-WebSocket-Protocol: licoarc.mailbox.v1` (echoed on success),
`Authorization: Bearer <station admission credential>`.

Every WebSocket message is one binary frame: a deterministic-CBOR closed
map whose label 0 is the frame type. Canonical rules: definite shortest
lengths, no tags, no floats or text, no duplicate/unknown/unordered
labels, no trailing bytes. Max frame 524288 + 128 bytes.

## Credential

`btm1.` + base64url( mailboxId(16) ‖ notAfter(u64 BE, unix seconds) ‖
HMAC-SHA256(stationKey, "btm1" ‖ mailboxId ‖ notAfter) ) — 56 bytes.
`notAfter` bounds only the first binding; a bound device stays admitted.

## Frames

Client → Station
- `HELLO {0:1, 1: bstr 32 (Ed25519 public key), 2: bstr 64}` — signature
  over `"licoarc-mailbox-hello-v1" ‖ nonce`. First frame after upgrade
  must be HELLO; anything else → close 1008.
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

## Semantics

Delivery Handle (32 B) = mailboxId(16) ‖ endpoint tag(16). The Station
routes only by mailboxId; the tag rides opaquely through DELIVER.
At-most-16 un-ACKed DELIVERs and at-most-16 un-RESULTed SENDs per
connection (exceeding closes 1008). One live connection per mailbox; a
new READY supersedes older ones (4000). RESULT accepted means durably
stored; connection loss before RESULT is the sender's ambiguous outcome —
resend on a new connection.

## Revocation

`POST /v1/revoke`, `content-type: application/octet-stream`, body =
mailboxId(16) ‖ HMAC-SHA256(stationKey, "btr1" ‖ mailboxId) — 48 bytes.
Idempotent 204: the mailbox's packets are gone, sockets close 4001, and
the credential can never bind again.

## Errors

No response carries error text. HTTP: 400 bad request shape, 401 failed
credential, 403 expired bind or revoked mailbox, 404 unknown path.
Close codes: 1002 malformed, 1008 policy, 4000 superseded, 4001 revoked,
4003 device key mismatch.
