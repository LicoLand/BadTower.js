# Context and terminology

This document fixes the words used by BadTower.js and the ownership
boundary between the Station, its plugins, protocol implementations, and
endpoint applications. When a term is ambiguous, this document wins for
BadTower repository work; protocol semantics still belong to the protocol
that defines them.

## Ownership

| Owner | Owns | Does not own |
| --- | --- | --- |
| **LicoArc** | Protocol semantics, identifiers, negotiation, wire, lifecycle, conformance | BadTower adapters, fixtures, packages, tests, releases, support, operation |
| **LicoUp** | Endpoint keys, Provider selection, decryption, plaintext, trust, approval, local effects, final effect evidence, client experience | Station storage, routing, admission, revocation |
| **BadTower.js** | One protocol-neutral Station: native contract, mailbox store, health, capacity, graceful shutdown, bounded state, recovery, privacy-minimal operation evidence | Protocol semantics, endpoint trust, application identity, client behavior |
| **Compatibility plugin** | Its listener, exact protocol binding, configuration, bounded state and resources, evidence, artifact, tests, release, support, retirement | Core tables, another plugin's state, protocol translation |
| **Deployment supervisor** | Starting, stopping, upgrading, rolling back and isolating separately packaged plugin processes | Native contract semantics, mailbox state ownership |
| **Operator** | Station key custody, invitation minting, revocation, TLS, deployment, cost and incident response | Endpoint plaintext, endpoint identity, protocol conformance |

## Station terms

**Station** — one deployment of the protocol-neutral relay. A Station
terminates TLS, verifies admission, routes handles and stores packets. It
is not a trust authority.

**Station Instance** — a single Worker (or self-hosted workerd process)
plus its Durable Object namespace. One instance may serve many mailboxes.

**Mailbox** — the unit of storage and admission. It is addressed by a
16-byte mailbox id. A mailbox exists only after a successful first bind.
A mailbox id is an opaque routing label, not an email address, account,
person, or endpoint identity.

**Mailbox id** — 16 opaque bytes. The first 16 bytes of every delivery
handle are the target mailbox id. The Station does not derive it from an
identity and does not publish a directory of them.

**Subject** — one fixed-size opaque identifier supplied by the caller at
Reserve. The core does not know it is an Ed25519 key or anything else; it
only refuses a different subject later. The LicoArc listener supplies the
verified device key as the subject.

**Admission credential** — `btm1.<base64url>`: mailbox id, a `notAfter`
deadline for the first bind, and an HMAC-SHA256 under the Station key.
`notAfter` bounds only the first binding; a bound subject stays admitted
until revocation.

**Invitation** — an operator-minted admission credential plus a fresh
mailbox id. An invitation is delivered out of band; it is not a Station
record and is not stored by the Station.

**Handle** — 32 opaque bytes: mailbox id (16) followed by a plugin-owned
endpoint tag (16). The Station routes only by the mailbox id; the tag
rides through delivery untouched.

**Packet** — 1 to 524288 opaque bytes submitted to a mailbox. The Station
does not inspect, parse, index, or transform it.

**Reserve** — bind the credential's mailbox to one opaque subject. The
first call wins; the same subject repeats idempotently; a different
subject is refused.

**Submit** — store one packet in the mailbox named by the handle's first
16 bytes. The sender may be any admitted party; it does not need to own
the target mailbox.

**Claim** — return stored packets in replay order, excluding the caller's
still-in-flight sequences. Claimed-but-unsettled packets replay, so
delivery is at-least-once.

**Settle** — delete the named packet rows. Settle is the only normal way
a stored packet leaves the Station.

**Capacity** — the configured byte bound for one mailbox database,
reported with current database size. Reaching it answers a transient
`mailboxFull`; the Station does not silently drop packets.

**Revocation** — operator-verified, idempotent destruction of a mailbox.
Stored packets are gone, sockets close, and the mailbox can never bind
again.

**Native contract** — the Station's own Reserve → Submit → Claim →
Settle HTTP surface, fixed binary bodies, `btm1` admission, plus health,
capacity, contract version and revocation. It is complete without a
plugin. Its compatibility identifier is `major.minor`; see
`NATIVE-CONTRACT.md`.

**Native client** — any client that speaks the native contract directly.
It needs no protocol checkout and no compatibility plugin.

## Plugin terms

**Compatibility plugin** — a separately packaged module or process that
owns one exact protocol binding and drives the core store/native contract
through the published core API. It may translate between its protocol and
opaque packets; Station Core must not. It owns its listener,
configuration, bounded state, evidence, tests, release and retirement. In
this repository the LicoArc listener is composed into the Worker by
`apps/station`; a future deployment supervisor may run the same plugin as
a separate process.

**Protocol Line** — one explicitly selected, immutable version and
profile of a protocol, including its binding. A plugin implements one
Line; it does not negotiate across Lines or translate between protocols.
The LicoArc plugin's Line is `licoarc.mailbox.v1`.

**Protocol-neutral core** — `packages/station-core`. It never imports,
loads or executes plugin code, never stores protocol descriptors or
plugin-specific state, and never widens its contract for one listener.

**Extension firewall** — the rule that Station Core does not discover,
fetch, link, load, execute or supervise plugin code; scan plugin sources
or registries; store protocol descriptors or plugin-specific state;
expose raw internals; or widen its contract for one plugin.

**Deployment supervisor** — the process or platform that owns plugin
process lifecycle. BadTower.js does not ship one in this repository;
`apps/station` is a build-time composition, not a supervisor.

## Protocol and application terms

**LicoArc** — the protocol whose `licoarc.mailbox.v1` listener is the one
compatibility plugin currently implemented. LicoArc owns its semantics;
BadTower owns only the mailbox carriage.

**A2A** — Agent2Agent, a protocol for communication between opaque agentic
applications. An A2A compatibility plugin is a design in this repository,
not an implementation. See `PLUGIN-A2A.md`.

**MCP** — Model Context Protocol, a JSON-RPC protocol between hosts,
clients and servers. An MCP compatibility plugin is a design in this
repository, not an implementation. See `PLUGIN-MCP.md`.

**Endpoint** — the client-side party that holds keys, decrypts, decides
trust and performs effects. The Station never becomes an endpoint.

**Station signal** — any value the Station returns or emits. Signals are
service-local and untrusted: they never prove identity, authenticity,
freshness, receipt, approval, task completion, effect, or business
acknowledgement.

**Plaintext** — application content before endpoint encryption or after
endpoint decryption. The Station must never require it.

## What this repository deliberately does not define

- An email address, contact, account, or user model.
- A protocol version negotiation algorithm beyond a plugin's pinned Line.
- A trust, approval, or key-recovery model for endpoints.
- A cluster consistency, fencing, failover, RPO or RTO model. Clustering
  is a later stage with its own gate.
- A hosted-service SLA, support contract, or compatibility guarantee
  beyond the documented checks and the pinned plugin Lines.
