# Cloudflare cost reconciliation

**Status: reconciliation against the official Cloudflare documentation
read on 2026-11-16.** Prices and allowances change; this document records
the inputs it used so a later change is visible rather than silent. It
does not claim an invoice, a spend forecast, or a free-tier guarantee.

## Official inputs

| Input | Workers Free | Workers Paid | Source |
| --- | --- | --- | --- |
| Worker requests | 100,000/day | 10,000,000/month included, then $0.30/million | [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/) |
| Worker CPU | 10 ms/invocation | 30,000,000 CPU-ms/month included, then $0.02/million; default 30 s/invocation | [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/) |
| Durable Object requests | 100,000/day | 1,000,000/month included, then $0.15/million | [Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/) |
| Durable Object duration | 13,000 GB-s/day | 400,000 GB-s/month included, then $12.50/million GB-s | [Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/) |
| SQLite rows read | 5,000,000/day | first 25,000,000,000/month included, then $0.001/million | [Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/) |
| SQLite rows written | 100,000/day | first 50,000,000/month included, then $1.00/million | [Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/) |
| SQLite stored data | 5 GB total | 5 GB-month included, then $0.20/GB-month | [Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/) |
| Paid plan minimum | — | $5/month per account | [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/) |
| Storage per Durable Object | 1 GB | 10 GB | [Durable Objects limits](https://developers.cloudflare.com/durable-objects/platform/limits/) |
| Storage per account | 5 GB | Unlimited | [Durable Objects limits](https://developers.cloudflare.com/durable-objects/platform/limits/) |
| WebSocket connection | One request to create | One request to create | [Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/) footnote 2 |
| Incoming WebSocket messages | Billed at 20:1 for compute requests | Billed at 20:1 for compute requests | [Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/) footnote 2 |
| Outgoing WebSocket messages | No charge | No charge | [Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/) footnote 2 |
| WebSocket protocol pings | No charge | No charge | [Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/) footnote 2 |

Additional official statements used below:

- SQLite storage billing was enabled in January 2026 with a target date of
  January 7, 2026; Workers Free plan users are not charged for SQLite
  storage. See [Billing for SQLite Storage](https://developers.cloudflare.com/changelog/post/2025-12-12-durable-objects-sqlite-storage-billing/).
- An empty SQLite database consumes approximately 12 KB; empty tables and
  Durable Object metadata count toward billable storage. See the
  [pricing FAQ](https://developers.cloudflare.com/durable-objects/platform/pricing/#frequently-asked-questions).
- A Durable Object is billed for wall-clock duration while it is actively
  running, or idle but unable to hibernate. An idle object eligible for
  hibernation is not billed for duration. See the
  [pricing FAQ](https://developers.cloudflare.com/durable-objects/platform/pricing/#frequently-asked-questions).
- Calling `accept()` on a WebSocket without the Hibernation API incurs
  duration for the entire time the socket is connected. The Hibernation
  API is recommended to avoid that. See the
  [pricing footnotes](https://developers.cloudflare.com/durable-objects/platform/pricing/).
- Pending I/O keeps an object in memory for up to 15 minutes; that time is
  billed. See the [pricing examples](https://developers.cloudflare.com/durable-objects/platform/pricing/#compute-billing-examples).
- Billable usage is rounded up to the next billable unit before the rate
  is applied. See the
  [pricing overview](https://developers.cloudflare.com/durable-objects/platform/pricing/).

The Station's default `BADTOWER_MAILBOX_CAPACITY_BYTES` is `1000000000`
(1 GB) and `MAX_PACKET_BYTES` is `524288` (512 KiB). Those are
implementation inputs, not Cloudflare prices.

## Notation

| Symbol | Meaning |
| --- | --- |
| `M` | bound mailboxes |
| `S` | stored bytes, the sum of `ctx.storage.sql.databaseSize` |
| `D0` | empty SQLite database, approximately 12 KB |
| `H` | measured per-packet row/page overhead |
| `P_i` | packet body bytes |
| `R_w` | Worker requests |
| `R_do` | Durable Object requests |
| `T_active` | wall-clock seconds the object is active and not hibernating |
| `Rows_r`, `Rows_w` | SQLite rows read / written |
| `Ws_in`, `Ws_out` | WebSocket messages received / sent |
| `Conn` | WebSocket connection establishments |

All byte-to-GB conversions below use `1 GB = 1,000,000,000 bytes` to match
Cloudflare's published `128 MB / 1 GB = 0.128` duration example. Verify
against the invoice if Cloudflare changes the unit convention.

## Storage: permanent mailboxes

```
S(t) = Σ_mailboxes (D0 + Σ_packets (H + P_i)) at time t
GB_month = (average S over the billing month) / 1_000_000_000
storage_cost_paid = max(0, GB_month - 5) × $0.20
storage_cost_free = $0.00, but S must stay under the 5 GB account limit
```

Use the month-average stored bytes for cost; the peak is a capacity
bound, not the billed quantity. The Station can only observe its own
`databaseSize` samples, so the operator should reconcile the average
against Cloudflare's usage record.

An unbound mailbox writes no schema, so it contributes nothing. A bound
but empty mailbox contributes at least `D0` (about 12 KB) plus metadata.
An accepted packet contributes its body plus row/page overhead and stays
until Settle or Revocation. There is no expiry.

**Permanent-storage consequence:** a filled mailbox is a monthly charge
even with no connections and no requests. An attacker pays the one-time
request cost; the operator pays the storage every month until revocation.

## Requests: Worker and Durable Object are separate meters

```
R_w  = inbound HTTP requests + WebSocket upgrade connections
R_do = DO RPC sessions + WebSocket upgrade connections
       + ceil(Ws_in / 20)          # billing-only ratio for incoming messages
```

Outgoing WebSocket messages and WebSocket protocol pings add no request
charge. Worker WebSocket messages routed through the Worker do not count
as Worker requests; the connection itself does. Each `stub.reserve(...)`,
`stub.submit(...)`, `stub.claim(...)`, `stub.settle(...)`,
`stub.capacityInfo()` and `stub.revoke()` is an RPC session and therefore
a DO request — this includes the `licoarc.mailbox.v1` listener's SEND,
which calls `submit` on the target mailbox's stub. The listener's own
`claim`, `settle`, `reserve` and `hasPending` run as local `MailboxStore`
calls inside the object's message handler; they are not RPC sessions and
cost SQLite rows and active duration instead (see Rows below).

```
worker_cost  = max(0, R_w  - included_w)  × rate_w
do_cost      = max(0, R_do - included_do) × rate_do
```

`included` and `rate` are plan-dependent and come from the table above.
Billable units are rounded up before the rate is applied.

## CPU (secondary meter)

Worker CPU time is active processing time, not wall-clock duration and
not time spent waiting on storage or network I/O.

```
CPU_ms = Σ active CPU milliseconds across invocations
cpu_cost_paid = max(0, CPU_ms - 30_000_000) × $0.02 / 1_000_000
```

The Station's handlers are small and I/O-bound, so CPU is normally far
below the included allowance. It is recorded here so the request and
duration meters are not mistaken for the whole bill.

## Duration: active time, not connection time

```
GB_s = T_active × 128 MB / 1 GB = T_active × 0.128
duration_cost_paid = max(0, GB_s - 400_000) × $12.50 / 1_000_000
```

- **Hibernatable WebSocket:** after the event handler finishes, the object
  can hibernate; an idle connection then costs zero duration. The
  connection still costs one request to establish.
- **Non-hibernatable `accept()`:** the object is billed for the entire
  connected lifetime, not just handler time. The Station uses the
  Hibernation API (`ctx.acceptWebSocket`) precisely to avoid this.
- **Pending I/O:** keeps the object active for up to 15 minutes per
  operation; include that time in `T_active`.
- **No alarms/polling:** the Station has no alarms and no periodic work,
  so a backlog does not create duration by itself.

## Rows: SQLite reads and writes

```
Rows_r = rows examined by meta/reserve/claim/capacity/hasPending queries
Rows_w = rows inserted/updated/deleted by reserve/submit/settle/revoke
```

Cloudflare counts deletes as rows written. A submit is one insert; a
settle of `k` sequences is `k` deletes; a claim examines up to the
requested limit; a reserve examines the `meta` row. `deleteAll()` on
revocation is a write operation and its rows are counted according to the
platform's row accounting.

The native `version` route answers a fixed constant at the Worker and
never opens a mailbox: it contributes zero rows and zero `R_do`, only one
`R_w`. On the `licoarc.mailbox.v1` socket path the claim, settle,
hasPending and initial meta calls are local to the connection's own
object, so they count here rather than under `R_do`.

```
rows_read_cost    = max(0, Rows_r - included_r) × rate_r
rows_written_cost = max(0, Rows_w - included_w) × rate_w
```

## The three shapes

### 1. Idle

Assumptions: no live sockets, or sockets hibernated; no requests except
operator health checks; no packets.

```
T_active ≈ 0
R_w      ≈ health checks only
R_do     = 0 for health checks that stop at the Worker
S        ≈ M_bound × D0
```

A health check hits the Worker but not a mailbox DO, so it does not add
DO duration. A bound but empty mailbox still costs about 12 KB of
storage; 10,000 such mailboxes are about 0.12 GB-month, inside the 5
GB-month included allowance. The exact figure depends on metadata and
SQLite page size; measure it rather than trusting the approximation.

### 2. Active

Assumptions: `M_active` hibernatable sockets; each device sends `Ws_in`
messages and receives `Ws_out`; each SEND submits one packet through the
target mailbox's `submit` RPC; each delivery is ACKed, and claim/settle
run locally on the socket's own `MailboxStore`.

```
Conn   = M_active
R_w    = M_active + other inbound requests
R_do   = M_active + N_send                  # one cross-object submit RPC per SEND
         + ceil(Ws_in / 20)                 # every incoming frame, HELLO/ACK included
Rows_r += local claim/hasPending reads per fill
Rows_w += local settle deletes per ACK
T_active = Σ handler durations + pending I/O time
S        = unchanged until settle
```

The dominant cost is usually duration if the object cannot hibernate, and
DO requests if it can. The Station's hibernatable sockets keep an idle
connected device at zero duration; a busy device pays only for the
handlers and pending I/O it causes.

### 3. Backlog

Assumptions: packets accumulate faster than they are claimed/settled; no
background process runs.

```
T_active ≈ claim/settle/submit handler time only
S        = D0 + Σ (H + P_i)
GB_month = S / 1_000_000_000
```

The backlog itself costs no duration and no requests. It costs storage
every month, plus the requests and rows needed to drain it. This is the
shape where permanent storage dominates: a 1 GB mailbox is 1 GB-month,
or $0.20/month after the 5 GB-month included allowance, regardless of
whether anyone connects. The number of submits needed to create that
backlog is `ceil((C - D0) / (H + 524288))`; it is not a fixed number
because `H` and SQLite page growth must be measured.

At the platform's per-object limit, writes fail with `SQLITE_FULL`:
1 GB on the free plan, 10 GB on the paid plan. The Station must keep `C`
below that limit and map the condition to a stable fail-closed answer.
See `ABUSE-CAPACITY.md`.

## Worked arithmetic (inputs, not a forecast)

A single 1 GB mailbox filled with maximum-size packets:

```
F ≈ ceil((1,000,000,000 - 12,000) / (H + 524,288)) ≈ 1,908 submits before H
Rows_w ≈ F inserts + F deletes after settle
R_w ≈ F submits + ceil(F/16) claims + ceil(F/16) settles   (native route)
R_do ≈ F submit RPCs + ceil(F/16) claim RPCs + ceil(F/16) settle RPCs
       # claim/settle are RPCs here because the native route drives stub calls;
       # on the WebSocket listener path they would be local store calls in Rows_*
S ≈ 1 GB
GB_month ≈ 1
storage_cost_paid ≈ max(0, 1 - 5) × $0.20 = $0.00 while total storage ≤ 5 GB-month
```

Once the account is past 5 GB-month, each additional full 1 GB mailbox is
about $0.20/month. The request and row counts above are far below the
paid included allowances, so storage is the first meter to matter for a
backlog attack. On the free plan the 5 GB account limit and the 1 GB
per-object limit bind before price does.

These arithmetic results move with `H`, page growth, packet size, and
plan; they are examples of applying the formulas, not limits.

## What the implementation must change

Status after the 2026-11-21 batch — items 1, 2 and 4 are implemented;
the global storage budget remains registered work:

1. **Capacity accounting:** done. Submit inserts inside a transaction
   and judges the measured post-insert `databaseSize` (row overhead and
   page growth are real bytes); `SQLITE_FULL` maps to the transient
   `mailbox-full`.
2. **Cost meters:** done for the cost dimensions. `GET /v1/metrics`
   exports `badtower_worker_requests_total` (R_w),
   `badtower_do_requests_total` (R_do), `badtower_do_active_ms_total`
   (T_active), `badtower_ws_messages_total{direction="in"}` (Ws_in),
   `badtower_rows_read_total`/`badtower_rows_written_total` (Rows_r,
   Rows_w) and `badtower_sqlite_bytes` (S), labelled only by `operation`,
   `direction` and `plan` — each formula above is recomputable from the
   exported aggregates, modulo the per-isolate caveat noted at the
   route.
3. **Global storage budget:** enforce a configured budget that keeps
   claim, settle and revoke available under pressure.
4. **Plan-aware limits:** done. `BADTOWER_PLAN` selects the explicit
   Free/Paid ceilings in `PLANS` (the constants mirror this document's
   inputs table); a mailbox capacity above the plan's per-object limit
   refuses to run.

## Non-goals

- This document does not promise a monthly bill, a free-tier outcome, or
  an invoice match. It records the official inputs and the formulas.
- It does not add a fixed rate limit or quota; those need the measured
  basis in `ABUSE-CAPACITY.md`.
- It does not treat a Station signal as cost evidence. Cloudflare's own
  usage and billing records are authoritative for spend.
