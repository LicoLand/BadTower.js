# Self-serve admission issuance

**Status: design.** No issuance endpoint, rate limiter, or issued-class
capacity exists in this repository today. This document is the contract
a future implementation must satisfy. Operator-minted offline
invitations (`station.mjs invite`) remain fully supported; this design
adds a second, self-serve path to the same `btm1` credential format.

## Problem

A client that knows a Station's address but holds no invitation cannot
use it. Requiring an account, an email address, or an out-of-band
operator action for every first use would contradict the product goal
of minimal infrastructure that does not know its users. The Station
should be able to hand a first-time client an admission credential —
without learning who the client is — while bounding how much one party,
and all self-serve parties together, can consume.

## Surface

```
POST /v1/issue                → 200 body: credential bytes | 429 | 403
```

- Unauthenticated `application/octet-stream` request; the body is empty
  or carries an optional proof field defined by the deployment (see
  "Source cost" below). No response carries error text, consistent with
  the rest of the wire surface.
- On success the body is the 56-byte credential payload
  `mailboxId(16) ‖ notAfter(u64 BE) ‖ HMAC(stationKey,"btm1"‖…)`, the
  same bytes the `btm1.` token encodes. The client base64url-wraps it
  exactly like an offline invitation.
- `/v1/issue` is an admission surface like `/v1/revoke`, not a mailbox
  route: it is not part of the native contract and does not change the
  contract version.
- `429` is the rate-limited refusal; `403` is the transport/configured-
  off refusal. Both carry no body.

## Credential term

Issued credentials are **short-window** credentials: `notAfter` bounds
only the first binding, exactly as for offline invitations, but the
operator configures a much shorter window for issuance
(`BADTOWER_ISSUE_BIND_WITHIN`, e.g. hours rather than the offline
default of days). The formula for choosing it:

```
bind_within_issue ≈ longest expected first-connect delay
                  ≪ bind window the operator gives offline invitations
```

Once bound, a mailbox behaves identically regardless of how its
credential was minted; the window only limits how long an unbound
issued credential stays usable.

## Issued mailbox capacity class

To bound per-mailbox damage without a second credential format, the
mailbox id's top bit marks the issuance class:

```
mailboxId[0] & 0x80  →  issued class: capacity C_issue
mailboxId[0] & 0x00  →  invited class: capacity C (BADTOWER_MAILBOX_CAPACITY_BYTES)
```

- The Station mints issued ids with the bit set; `station.mjs invite`
  keeps minting with the bit clear. The bit travels inside the
  HMAC-signed id, so it cannot be flipped without a station key.
- `C_issue` is a separate operator configuration
  (`BADTOWER_ISSUE_CAPACITY_BYTES`, default a fraction of `C`), validated
  against the plan's per-object platform limit exactly like `C`
  (docs/COST.md). Smaller `C_issue` directly reduces the permanent
  storage one self-serve party can pin per mailbox.
- The class is read by the mailbox object from its own id at bind time;
  no per-mailbox record is needed.

## Rate limits and their derivation

The rule from `ABUSE-CAPACITY.md` applies: no fixed limit ships without
a measured or formula basis. Issuance is bounded by the resource it
creates — permanent storage — so the primary control is a global
issuance token bucket whose inputs are the operator's storage budget
and the issued capacity:

```
R_issue  ≤  S_issue_budget_bytes / (C_issue × W_horizon_seconds)
B_issue  =  R_issue × T_burst_issue
```

- `S_issue_budget_bytes` is how much of the storage budget the operator
  dedicates to self-serve mailboxes; `W_horizon` is the window over
  which issued mailboxes are expected to be reclaimed or revoked.
  Together they make the worst case arithmetic: full-bucket issuance
  cannot create more than `S_issue_budget` of issued storage inside the
  horizon.
- `T_burst_issue` absorbs legitimate first-use bursts (a release
  announcement, a client update); it is an operator input like
  `T_burst` in `ABUSE-CAPACITY.md`.
- Exceeding the bucket answers `429`, a retryable refusal; it is not a
  mailbox result and does not enter the native outcome grammar.

Secondary controls, each optional and independently configurable:

1. **Per-source bound.** A per-source-IP token bucket implemented by the
   platform's rate-limiting feature (a Cloudflare rate-limiting rule on
   `/v1/issue`), not by Station state — the Station keeps no IP record.
   Its rate is an operator input derived from observed legitimate
   first-use rates per source.
2. **Source cost (proof).** A deployable option where the request body
   carries a solution to a station-published challenge (e.g. a
   hashcash-style proof of work): raises the marginal cost of a
   credential without identity. Difficulty is a config input set from
   the target issuance rate, not a fixed constant.
3. **Global storage budget.** The same budget that bounds all mailboxes
   (`ABUSE-CAPACITY.md` §C) bounds issued ones; when `S_total` is at
   budget, issuance answers `429` before per-source checks matter.

Rate-limit state lives in a small shared Durable Object (a token bucket
is a counter, not a mailbox); it records no credential, mailbox id, or
source identity — only the bucket level and window.

## Coexistence with offline issuance

- One credential format, one verifier. `btm1` verification,
  `/v1/revoke`, and every native/plugin route are unchanged; nothing in
  the admission layer distinguishes how a credential was minted.
- Offline invitations remain the path for mailboxes the operator wants
  at full `C` capacity and longer bind windows.
- An operator that wants no self-serve surface deploys with
  `BADTOWER_ISSUE_ENABLED=false` (default): `/v1/issue` then answers
  `403` and consumes no rate-limit state.
- Both classes share `S_total`; revocation reclaims either.

## Abuse scenarios and responses

| Scenario | Response |
| --- | --- |
| **Credential farming** — one party mints thousands of issued credentials to squat mailbox ids | Global bucket bounds total issuance rate; per-source bound slows one source; each issued mailbox is limited to `C_issue` |
| **Storage denial-of-wallet** — issued mailboxes filled to `C_issue` each | `R_issue × C_issue` is bounded by `S_issue_budget`; the global budget trips issuance to `429` before the platform limit; revocation remains the reclaim path |
| **Bind-window squatting** — farmed credentials left unbound to retry later | Short `BADTOWER_ISSUE_BIND_WITHIN`; an unbound mailbox costs nothing but a credential |
| **Capacity-class spoofing** — a client asking for invited-class treatment | The class bit is inside the HMAC-signed mailbox id and only the Station mints it; `station.mjs invite` never sets it |
| **Issue-endpoint flooding** — requests that never intend to bind | The endpoint is cheap (one HMAC, one counter); `429`/`403` carry no body; per-source and global bounds still apply |
| **Enumeration** — probing which ids exist | Issued ids are 127 bits of entropy minus none; mailbox ids were never enumerable |
| **Replay of a bound issued credential** | Identical to replay of an offline credential — the admission layer does not distinguish them; not a new surface |

## What is explicitly not claimed

- No fixed numeric rate, difficulty, or `C_issue` ships in this
  document; the formulas and named config inputs are the design, the
  numbers are the operator's measured inputs.
- Issuance does not create an identity, reputation, or per-source
  record on the Station. The metrics that exist are the aggregate cost
  meters (`OPERATIONS-VISIBILITY.md`), plus at most an
  `issued`/`refused` counter pair by closed labels.
- `429` is a new HTTP status on one route; it changes neither the
  native contract version nor any mailbox semantic.
