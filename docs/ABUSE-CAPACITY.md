# Abuse and capacity boundaries

**Status: design.** The formulas below describe the boundary the Station
must enforce. Some controls are implemented (per-mailbox capacity,
in-flight windows, one live socket, admission); others are not yet
implemented and are registered as follow-up work rather than implied by
this document.

## The threat in one sentence

Any party holding one valid `btm1` admission credential can submit
packets to **any** bound mailbox whose 16-byte id it knows, so it can fill
that mailbox, and many mailboxes, without ever binding them or knowing
their subject, content, or owner.

That is intentional routing behavior: Submit does not require ownership of
the target mailbox, because a sender must be able to reach a recipient it
does not control. The missing piece is a bound on how much one admitted
party, and the Station as a whole, may consume.

## Assumptions

- Mailbox ids are 16 random bytes minted by the operator. They are not
  enumerable from the Station; an attacker must obtain one out of band or
  guess it. This document does not assume secrecy of a handle once a
  legitimate peer has it.
- A delivery handle is 32 bytes: mailbox id (16) plus a plugin-owned tag
  (16). The Station routes only by the mailbox id.
- Packets are 1 to 524288 bytes. The Station does not inspect content.
- The Station has no per-sender identity. The admission credential proves
  only that the Station key signed a mailbox id and a first-bind deadline;
  it does not prove a person, endpoint, or application.
- Permanent storage means an accepted packet remains until Settle or
  Revocation. There is no expiry, polling, alarm, or background sweep.

## Capacity model

Define:

| Symbol | Meaning |
| --- | --- |
| `C` | configured per-mailbox capacity in bytes (`BADTOWER_MAILBOX_CAPACITY_BYTES`, default `1000000000`) |
| `D0` | empty SQLite database size; Cloudflare documents approximately 12 KB |
| `H` | measured per-row and page overhead for one packet row |
| `P` | packet body size in bytes, `1 ≤ P ≤ 524288` |
| `M` | number of bound mailboxes |
| `S` | actual stored bytes (`ctx.storage.sql.databaseSize`), summed over mailboxes |
| `R` | submit requests available to one credential per unit time |

The current implementation checks `databaseSize + body.length > C`. That
under-counts `H` and SQLite page growth. The design bound is:

```
N(C, P) = floor((C - D0) / (H + P))          packets that fit at size P
F(C)    = ceil((C - D0) / (H + 524288))      submits to fill an empty mailbox at maximum packet size
S_mailbox = D0 + Σ_i (H + P_i)               actual mailbox bytes
S_total   = Σ_mailboxes S_mailbox
```

`H` must be measured on the deployed SQLite backend, not assumed. A
conservative capacity check uses `databaseSize` after the insert, or
reserves `H + P` before the insert, and refuses when the projected size
would exceed `C`. The current check is therefore an implementation gap.

### Derived fill and fan-out

These are consequences of the formulas and the documented platform
limits, not policy constants:

```
mailboxes_filled_per_day ≈ floor(R_day / F(C))
mailboxes_full_on_free   = floor(5 GB / S_mailbox_full)
```

With `C = 1,000,000,000` and `P = 524288`, `F` is approximately 1,908
submits per mailbox before `H` is added. The exact number moves with `H`
and SQLite page growth; the point is that a single admitted party with a
free-plan request budget can fill multiple mailboxes in a day, and each
filled mailbox is permanent until settled or revoked.

The free plan's 5 GB total Durable Object storage is a hard bound: at
`C = 1 GB`, at most a handful of full mailboxes fit before writes fail.
The paid plan's 10 GB per-object bound and unlimited account storage mean
the attack does not hit a hard ceiling; it becomes a recurring bill. See
`COST.md` for the rates.

## Abuse scenarios

### 1. Mailbox stuffing

An admitted sender submits maximum-size packets to a victim's mailbox
until it answers `mailboxFull` (transient). Legitimate senders then also
receive `mailboxFull`, and the victim cannot receive new packets until it
claims and settles. The attacker learns only accepted/rejected/transient
and the failure class; it does not learn content, subject, or owner.

Impact: availability of one mailbox; no confidentiality loss.

### 2. Denial of wallet

The same sender spreads packets across many known mailbox ids, or many
credentials spread them further. Every accepted packet becomes billable
stored data and a row write; every claim/settle adds reads and writes.
Because storage is permanent, the cost persists after the attack stops.
The attacker does not need to bind the target mailboxes.

Impact: recurring Cloudflare bill, possible free-plan storage exhaustion,
and new mailboxes failing closed.

### 3. Capacity-edge failures

If `C` is set at or above the platform's per-object limit (1 GB free,
10 GB paid), the Station's own capacity check can be satisfied while the
SQLite database hits `SQLITE_FULL`. Reads and deletes still work, but
writes fail. The Station must keep `C` below the platform limit with room
for `D0`, `H`, and page growth, and must map a storage-full condition to a
stable fail-closed answer rather than an unhandled exception.

### 4. Connection and request amplification

One live connection per mailbox and a 16-packet in-flight window bound a
single socket. An admitted party can still open many connections to its
own mailboxes, or send many small submits, consuming requests, rows and
duration. This is a request-budget problem, not a content problem.

### 5. What is not a threat here

- The Station cannot read plaintext, so packet content is not an abuse
  surface for the core.
- Mailbox ids are random; there is no directory to enumerate.
- Revocation is operator-only and HMAC-verified; an admitted sender
  cannot revoke another mailbox.
- A Station signal is not evidence; an attacker cannot turn `accepted`
  into a claim that a person received or approved anything.

## Controls and their derivation

The rule for this design is: **no fixed limit ships without a measured
basis.** Each control is a formula with named inputs; the operator chooses
the inputs from observed traffic and a stated risk tolerance.

### A. Per-credential ingress budget

```
r_c = max(observed_p99_submit_rate_per_credential × safety_factor,
          minimum_useful_rate)
B_c = r_c × T_burst
```

`r_c` is refill per second, `B_c` is burst capacity, `T_burst` is the
longest legitimate burst the operator wants to absorb. `observed_p99` and
`T_burst` come from the operator's own measurements; `safety_factor` and
`minimum_useful_rate` are explicit policy inputs, not hidden constants.
Exceeding the budget fails closed with a transient answer. A future
native-contract minor may add a distinct `rateLimited` reason; until then
the contract's existing transient class is used so old clients keep
working.

### B. Per-target ingress budget

```
Q_target = C / T_fill_min
q_sender_target = Q_target / expected_legitimate_senders
```

`T_fill_min` is the shortest time the operator is willing to let one
mailbox be filled; `expected_legitimate_senders` is measured per mailbox
cohort, not guessed. A sender's share is capped so one credential cannot
consume the whole target budget. The sum of shares must not exceed
`Q_target`. If the legitimate fan-in is unknown, the safe default is to
enforce the target budget first and add per-sender shares only after
measurement.

### C. Global storage budget

```
S_budget_bytes = min(
  platform_storage_limit_bytes,
  (operator_cost_budget_usd_per_month / storage_rate_usd_per_gb_month) × 1_000_000_000
)
admit_new_bind only while S_total + C_reserve ≤ S_budget_bytes
reject_nonurgent_submit while S_total ≥ S_budget_bytes
keep claim, settle and revoke available
```

`C_reserve` is the headroom needed for one mailbox's metadata and page
growth. On the free plan the platform limit is 5 GB total; on the paid
plan the operator's cost tolerance sets `S_budget_bytes`, because account
storage is not capped. The Station must not let a global budget failure
break the paths that reduce storage (settle, revoke) or the paths that
let a recipient drain its mailbox (claim).

### D. Fair-share admission

Per-mailbox capacity `C` is the first isolation boundary. A global budget
alone is not enough: an attacker who fills it first can block new
mailboxes. The operator needs one of:

- a reservation for new binds, funded by a revocation/expiry policy the
  operator controls; or
- an admission queue that prioritizes never-bound mailboxes and existing
  bound mailboxes over new bulk binds; or
- a paid-plan budget large enough that the global bound is a cost alarm,
  not an availability bound.

The choice is an operational policy. This document does not invent a
ratio or a fixed number of reserved mailboxes.

### E. Backpressure and observability

- Answer overload with the contract's transient class; never silently
  drop an accepted packet.
- Count accepted, rejected and transient submits by reason, bytes stored,
  rows written/read, and active duration. These are aggregates; see
  `OPERATIONS-VISIBILITY.md`.
- Alert on `S_total / S_budget`, per-mailbox `databaseSize / C`, and
  submit rate per credential. Alert thresholds are operator inputs.
- Revocation is the only way to reclaim a hostile mailbox permanently;
  the operator must be able to find it without a per-person record.

## Cloudflare billing impact

Every accepted packet has four billable effects:

1. **Worker request** — the inbound `/v1/native/submit` or WebSocket
   message that carries it.
2. **Durable Object request** — the RPC session into the target mailbox
   (`submit`) or the WebSocket message that drives it.
3. **Row write** — the `INSERT` into `packet`.
4. **Stored data** — the packet row and SQLite overhead, billed monthly
   until Settle or Revocation.

Claim adds Worker and DO requests plus row reads; Settle adds Worker and
DO requests plus row writes (deletes count as rows written). A filled
mailbox therefore costs storage every month even when nobody connects.
The exact rates and included allowances are in `COST.md`; they are not
duplicated here so there is one source of truth.

The important asymmetry: **an attacker pays request cost once, while the
operator pays storage cost every month until revocation.** A per-request
limit alone does not fix denial of wallet; a storage budget and a
revocation path do.

## Implementation gaps to close

These are tracked as Kanban tasks, not claimed as done:

- capacity accounting must include `H`, SQLite page growth and the
  platform per-object limit, and must map `SQLITE_FULL` to a stable
  fail-closed answer;
- per-credential and per-target ingress budgets with measured inputs;
- a global storage budget that keeps claim, settle and revoke available;
- aggregate cost and abuse metrics without per-person records.

## Non-goals

- No content inspection, no sender identity, no reputation score, no
  address book.
- No fixed rate limit or mailbox quota in this document. A number is
  legitimate only with the measurement and formula that produced it.
- No automatic expiry of undelivered packets. Reclaiming storage is an
  explicit Settle or Revocation, or an operator policy that is documented
  and bounded.
