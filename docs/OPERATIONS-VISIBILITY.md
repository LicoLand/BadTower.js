# Operations visibility

**Status: design.** The deployed Worker currently sets
`observability.enabled: false` and `logs.enabled: false`. There is no
server-side mailbox inventory and no per-mailbox history. This document
defines the aggregate view an operator may add without turning the
Station into an identity, content, or address record.

## Principles

1. **Aggregate only.** Every exported metric is a count, sum, gauge or
   histogram over a bounded label set. No metric label is a mailbox id,
   delivery handle, subject, credential, IP address, user agent, packet
   body, content hash, or free-form path.
2. **No request logs.** Request-level logs are not part of this design.
   A log line with a path, a handle, or a timestamp is a per-mailbox
   record even when it looks innocuous.
3. **No long-term per-mailbox activity history.** A single mutable,
   coarse activity bucket may exist for reclamation; it is overwritten in
   place and never exported as a mailbox-level series.
4. **Retention follows a stated purpose.** Raw aggregates are kept for
   operational comparison; monthly rollups are kept for cost
   reconciliation. Nothing is kept "just in case".
5. **The Station remains untrusted.** A metric is service-local
   evidence. It does not prove delivery, identity, approval, or effect.

## Metric catalogue

`retention` means the longest the exported series is kept. The Station
itself may hold a mutable counter only as described in the next section.
Thirteen months is twelve completed monthly billing cycles plus the
current one; thirty days is the operational comparison window. Neither
is a per-mailbox record.

| Metric | Type | Purpose | Labels | Linkability | Retention |
| --- | --- | --- | --- | --- | --- |
| `badtower_station_up` | gauge 0/1 | Availability and alerting | `station`, `region` (operator-defined, not a person) | None | 30 days raw, 13 months rollup |
| `badtower_bound_total` | counter | Mailbox creation rate and capacity planning | none | None | 30 days raw, 13 months rollup |
| `badtower_revoked_total` | counter | Reclamation and abuse response | `reason` (`operator`, `abuse`, `retired`) | None | 30 days raw, 13 months rollup |
| `badtower_submit_total` | counter | Load, rejection mix, abuse detection | `outcome` (`accepted`, `rejected`, `transient`), `reason` (contract reason name) | None | 30 days raw, 13 months rollup |
| `badtower_packet_bytes_total` | counter | Ingress volume and cost model | `outcome` | None | 30 days raw, 13 months rollup |
| `badtower_packet_size_bytes` | histogram | Capacity and cost model; bucket counts only | none | None (aggregate distribution, never per mailbox) | 30 days |
| `badtower_mailbox_capacity_ratio` | histogram | How close mailboxes run to `C`; bucket counts only | `bucket` (fixed ratio buckets) | None (no mailbox id) | 30 days |
| `badtower_claim_total` | counter | Receive-path load | `outcome` | None | 30 days raw, 13 months rollup |
| `badtower_claimed_packets_total` | counter | Receive volume and in-flight behavior | none | None | 30 days raw, 13 months rollup |
| `badtower_settled_packets_total` | counter | Reclamation and at-least-once behavior | none | None | 30 days raw, 13 months rollup |
| `badtower_ws_connections_open` | gauge | Live-connection load and hibernation behavior | `state` (`challenged`, `ready`) | None | 30 days |
| `badtower_ws_closed_total` | counter | Failure classes and supersession | `code` (close code) | None | 30 days raw, 13 months rollup |
| `badtower_ws_message_total` | counter | WebSocket request billing and load | `direction` (`in`, `out`), `kind` (frame kind) | None | 30 days raw, 13 months rollup |
| `badtower_duration_ms` | histogram | Durable Object active duration and cost | none | None (aggregate only) | 30 days |
| `badtower_sqlite_bytes` | gauge | Stored-data cost and capacity | `plan` (`free`, `paid`) | None | 30 days raw, 13 months rollup |
| `badtower_rows_read_total` | counter | SQLite read cost | `operation` (`reserve`, `submit`, `claim`, `settle`, `capacity`, `version`) | None | 30 days raw, 13 months rollup |
| `badtower_rows_written_total` | counter | SQLite write cost | `operation` | None | 30 days raw, 13 months rollup |
| `badtower_wake_total` | counter | Offline-wake delivery health, if configured | `result` (`sent`, `failed`, `skipped`) | None | 30 days raw, 13 months rollup |
| `badtower_abandoned_candidates` | gauge | Reclamation planning | `age_bucket` (whole months, coarse) | None (count only, never ids) | 13 months rollup |
| `badtower_cost_estimate_usd` | gauge | Monthly cost reconciliation | `plan`, `dimension` (`requests`, `duration`, `storage`, `rows`) | None | 13 months rollup |

### Why these labels are safe

- `outcome`, `reason`, `code`, `state`, `direction`, `kind`, `operation`,
  `plan`, `region` and fixed histogram buckets are closed enumerations.
  Their cardinality is bounded and none of them can name a mailbox.
- `station` is an operator-chosen deployment label, not a hostname that
  contains a person's name.
- There is deliberately no `mailbox_id`, `handle`, `subject`, `token`,
  `path`, `client_ip`, `user_agent`, `packet_hash`, or `content_type`
  label. Adding one is a privacy change, not a dashboard tweak.

### Resolution

- Availability and request metrics: five-minute buckets.
- Storage, rows and cost metrics: hourly buckets.
- Monthly rollups: one value per calendar month.

Finer resolution makes traffic analysis easier without improving
operation. If an incident needs finer data, use a bounded, time-boxed
debug session that is deleted afterwards; do not make it a standing
series.

## Abandoned-mailbox identification without a person-linked record

An "abandoned" mailbox is a policy judgement, not a Station fact. A
usable definition is: bound, with no successful Claim, Settle, or ready
WebSocket handshake in the last `N` whole months, where `N` is an
operator policy input. Inbound Submit is deliberately excluded: a
stranger can submit to a mailbox and must not make it look alive. The
design does not ship a default `N`.

### What the Station may store

One mutable row per mailbox, in the existing `meta` table, with one
coarse field:

```
activity_bucket  TEXT  -- 'YYYY-MM' or NULL, overwritten in place
```

Rules:

- `activity_bucket` is set on Reserve and updated on a successful Claim,
  Settle, and a ready WebSocket handshake. It is **recipient activity**,
  not inbound traffic: a Submit from a stranger must not make an
  abandoned mailbox look active. It is a **current bucket**, not an event
  log; it is overwritten, never appended.
- The field contains no subject, handle, packet, address, IP, user
  agent, content, or a per-event timestamp. It is not a bind timestamp.
- `deleteAll()` on revocation removes the field with the mailbox.
- The Station never exports the field as a per-mailbox series.

### What the operator may export

Only aggregate counts:

```
badtower_abandoned_candidates{age_bucket="3"}  = 12
badtower_abandoned_candidates{age_bucket="6"}  = 4
badtower_abandoned_candidates{age_bucket="12"} = 1
```

The operator decides reclamation from the count and its own invitation
inventory (which is offline and outside the Station). If a targeted list
is ever needed, it is a one-off, time-boxed operator action with a
documented purpose; it is not a standing table, dashboard, or export.

### Why this does not create a person-linked record

- A mailbox id is pseudonymous, but the Station does not link it to a
  person, an address, a subject, or content.
- The bucket field is mutable state, not history. There is no record of
  when a mailbox was last active beyond the current month.
- Exports contain counts by age bucket, not mailbox ids. The Station
  cannot produce a list of "people who stopped using the service".
- The operator's invitation inventory is the only place a mailbox id can
  be tied to a recipient, and it is already an operator secret with its
  own retention policy, outside the Station.

## What is not built

- `wrangler.jsonc` still disables observability and logs. The
  cost-dimension meters (`badtower_worker_requests_total`,
  `badtower_do_requests_total`, `badtower_do_active_ms_total`,
  `badtower_ws_messages_total`, `badtower_rows_read_total`,
  `badtower_rows_written_total`, `badtower_sqlite_bytes`) are exported
  at `GET /v1/metrics` to the station key's holder as per-isolate
  aggregates; the rest of this catalogue, a metrics sink and the
  retention job are not built.
- The `activity_bucket` field is not in the schema.
- There is no dashboard, alert rule, or retention job.
- There is no per-mailbox inventory endpoint, and this design does not
  add one.

## Implementation tasks

The schema fields, aggregate exporter, retention job, and dashboards are
registered as follow-up Kanban tasks. They are not claimed as delivered
by this document.
