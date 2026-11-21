# Native contract conformance cases

Implementation-neutral contract cases for the native mailbox contract
(`docs/API.md`, `docs/NATIVE-CONTRACT.md`). Every case is data — a JSON
document an implementation's own harness drives over HTTP — so the
TypeScript mainline and the Go implementation share one source of truth
for contract behavior. The cases say nothing about how the contract is
implemented; they express requests and expected responses only.

`schema` is `badtower-native-conformance/1`. A runner needs a live
Station deployment (or an in-process equivalent) plus these injected
values it owns locally:

- `stationKey` — the 32-byte HMAC key, used to mint `btm1` credentials
  and `btr1` revocation bodies;
- `mailboxCapacityBytes` — the deployment's configured
  `BADTOWER_MAILBOX_CAPACITY_BYTES`, for `capacity` expectations;
- `plaintextAllowed` — whether the deployment serves plain HTTP; a case
  may declare `assumes.plaintextAllowed` and a runner whose deployment
  differs must skip that case (the suite currently only assumes
  `false`).

## Case document

```jsonc
{
  "schema": "badtower-native-conformance/1",
  "cases": [
    {
      "name": "unique-case-name",
      "mailboxes": { "A": "0011…ff" },   // name → 16-byte mailbox id (hex)
      "assumes": { "plaintextAllowed": false },   // optional
      "steps": [ /* request/expect pairs, executed in order */ ]
    }
  ]
}
```

Mailbox ids are fixed hex so cases are deterministic. Each case should
use mailbox ids no other case uses.

## Step

```jsonc
{
  "request": {
    "method": "POST",
    "path": "/v1/native/submit",
    "mailbox": "A",              // mint a valid btm1 for this mailbox id
    "auth": "valid|none|forged", // default "valid"; "forged" = bad HMAC
    "bindDeadline": "future",    // "past" mints notAfter in the past
    "scheme": "https",           // "http" tests the plaintext refusal
    "contentType": "application/octet-stream", // default when a body is sent
    "body": { /* body macro, below */ },
    "repeat": 18                 // optional: perform the request N times
  },
  "expect": {
    "status": 200,
    "body": { /* expectation, below; omit to ignore the body */ }
  }
}
```

The runner always sets `Content-Type: application/octet-stream` when a
body is present unless `contentType` overrides it. With `auth: "valid"`
(default when `mailbox` is present) the runner mints
`btm1.base64url(mailboxId ‖ notAfter ‖ HMAC(key,"btm1"‖mailboxId‖notAfter))`
with `notAfter` one hour ahead, or one hour behind for
`bindDeadline: "past"`. `auth: "forged"` sends a correctly shaped token
whose HMAC does not verify. `auth: "none"` sends no `Authorization`
header.

## Body macros

- `{ "bytes": "a1b2…" }` — literal hex ("" is an empty body).
- `{ "fill": { "byte": "aa", "length": 31 } }` — `length` copies of the
  given byte; for size-boundary cases that would bloat the file.
- `{ "submit": { "mailbox": "M", "tag": "01…", "packet": "aa55" } }` —
  `mailboxId(16) ‖ tag(16) ‖ packet`; `"packetFill"` may replace
  `"packet"` with the same `{byte,length}` shape as `fill`.
- `{ "claim": { "limit": 16, "exclude": "name" } }` — `limit(1) ‖
  count(1) ‖ sequence(u64 BE)×`; `exclude` names a sequence list saved
  by an earlier `saveAs`, `null`/absent for none.
- `{ "settle": { "sequences": "name" | { "literal": [1, 2] },
  "pick": [0, 2] } }` — `count(1) ‖ sequence(u64 BE)×`; `pick` selects
  indices from a saved list.
- `{ "revoke": { "mailbox": "M", "forged": true } }` — `mailboxId(16) ‖
  HMAC(key,"btr1"‖mailboxId)`; `forged` signs with the wrong key.

## Response expectations

`expect.status` is always required. `expect.body` is one of:

- `{ "bytes": "…" }` — exact binary match.
- `{ "text": "ok\n" }` — exact UTF-8 text.
- `{ "submitResult": { "outcome": "…", "reason": "…" } }` — the 2-byte
  submit answer; outcomes `accepted|rejected|transient` map to 0/1/2,
  reasons `none|invalid-request|target-unavailable|packet-too-large|
  mailbox-full|internal-unavailable` map to 255/0/1/2/3/4.
- `{ "version": { "major": 1, "minor": 0, "revision": 0, "reserved": 0 } }`
  — the 8-byte contract version body.
- `{ "capacity": { "capacityBytes": "configured",
  "databaseBytes": "positive" } }` — `capacityBytes` equals the
  deployment's configured capacity; `databaseBytes` is a measured
  storage figure and is only checked `> 0` because its value is
  implementation- and engine-dependent.
- `{ "claim": { "packets": [ { "handle": "…", "body": "…" } ],
  "saveAs": "name" } }` — the claim body decodes to exactly these
  packets in this order (sequences themselves are implementation-owned;
  `saveAs` records the returned sequences for a later `exclude` or
  `settle`). `"count": N` may replace `packets` when only the count
  matters.
