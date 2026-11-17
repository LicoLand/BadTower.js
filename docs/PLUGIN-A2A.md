# A2A compatibility plugin: pinned Line and support scope

**Status: design pin only.** This repository does not yet contain an A2A
listener, package, test, release, or deployment. This document fixes what
a future plugin may claim so that an implementation cannot drift onto a
floating specification or an undocumented subset.

## Pinned protocol Line

| Item | Value |
| --- | --- |
| Protocol | Agent2Agent (A2A) |
| Specification tag | `v1.0.1` |
| Immutable commit | `3303592588e388e62e0f69f701af531d2f4e3991` |
| Release date | 2026-05-28 |
| Wire protocol version | `1.0` (`Major.Minor`; patch is not a compatibility input) |
| Binding | JSON-RPC 2.0 over HTTPS |
| Agent Card URI | `https://<plugin-host>/.well-known/agent-card.json` |
| Interface URL | one HTTPS URL owned by the plugin, declared in the Agent Card |
| Agent Card `protocolBinding` | `JSONRPC` |
| Agent Card `protocolVersion` | `1.0` |

The tag and commit are the pin. A branch name, a moving `main`, a
pre-release, a generated SDK version, or a website "latest" label is not a
pin. The plugin must not fetch, vendor, or load an A2A checkout at
runtime; generated types or fixtures, if any, are committed artifacts
derived from the pinned commit and carry that commit in their header.

### Normative sources at the pin

- `specification/a2a.proto` — the single authoritative definition of A2A
  data objects and request/response messages.
- `docs/specification.md` — normative protocol requirements, including
  versioning, JSON-RPC binding, error mapping and Agent Card rules.
- `docs/whats-new-v1.md` and `CHANGELOG.md` — change context, not a
  substitute for the two sources above.

### Consistency source

The future implementation's conformance target is the A2A Technology
Compatibility Kit at tag `1.0.0.alpha3`
(commit `5daf0144b4a4adbdefb62180739b13c5bd7d8196`), restricted to the
`jsonrpc` transport and the supported capability set below. The TCK has
not been run; **no A2A conformance claim is made today**. A release may
claim only the TCK level it actually ran, with the report attached to the
release record.

## Binding rules

- Transport is HTTPS with `Content-Type: application/json` and
  `Accept: application/json`. The plugin does not accept gRPC, HTTP+JSON/
  REST, SSE, or a custom binding.
- Every request carries `A2A-Version: 1.0`. A different `Major.Minor` is
  answered with `VersionNotSupportedError` (`-32009`), not silently
  downgraded. An empty header is interpreted as 0.3 exactly as the
  specification requires, then refused with the same error because this
  Line is 1.0 only.
- The plugin publishes exactly one JSON-RPC interface in
  `supportedInterfaces`; it does not advertise a second transport.
- JSON field names are camelCase, enums use ProtoJSON string names, and
  timestamps are ISO 8601 UTC with `Z`. Unknown fields are ignored.
- The Agent Card declares `capabilities.streaming: false`,
  `capabilities.pushNotifications: false` and
  `capabilities.extendedAgentCard: false`.
- Authentication is an HTTP bearer security scheme carrying the Station
  admission credential (`btm1.<…>`). The credential is an opaque
  authorization subject; it is not an A2A identity and the Station is
  not a trust authority.

## Supported capabilities

| Capability | Scope |
| --- | --- |
| Agent Card discovery | `/.well-known/agent-card.json`, one `JSONRPC` interface, protocol version `1.0` |
| `SendMessage` | Blocking and `returnImmediately` forms; returns a `Task` or a `Message` as the specification permits |
| `GetTask` | Returns the plugin-owned task state visible to the admitted subject |
| `ListTasks` | Cursor pagination, sorted by last update time descending, scoped to the admitted subject |
| `CancelTask` | Cancels a non-terminal task; `TaskNotCancelableError` otherwise |
| Task states and artifacts | The A2A 1.0 state machine and artifact model, with bounded plugin-owned task state |
| Multi-turn messages | A new message may target a non-terminal task, as the specification allows |
| Error mapping | The JSON-RPC codes in the pinned specification, including `TaskNotFoundError`, `TaskNotCancelableError`, `UnsupportedOperationError`, `VersionNotSupportedError` |
| Idempotent reads | `GetTask`, `ListTasks` and Agent Card reads are safe to repeat |
| Opaque mailbox carriage | A2A payloads cross the Station as opaque packets; Station Core never parses them |

The plugin owns its A2A task store, authentication decision, bounded task
state, and evidence. It drives the Station native contract as a scoped
client. It does not store A2A state in core tables and does not widen the
native contract for A2A.

## Unsupported capabilities

| Capability | Answer |
| --- | --- |
| `SendStreamingMessage` | `UnsupportedOperationError` (`-32004`); `capabilities.streaming` is false |
| `SubscribeToTask` | `UnsupportedOperationError` (`-32004`); no streaming connection |
| Push notification config create/get/list/delete | `PushNotificationNotSupportedError` (`-32003`); `capabilities.pushNotifications` is false |
| `GetExtendedAgentCard` | `UnsupportedOperationError` (`-32004`); `capabilities.extendedAgentCard` is false |
| gRPC binding | Not advertised, not accepted |
| HTTP+JSON/REST binding | Not advertised, not accepted |
| Custom bindings | Not advertised, not accepted |
| A2A extensions | None declared; a required extension is refused with `ExtensionSupportRequiredError` (`-32008`) |
| A2A 0.3 compatibility | Not served; an empty `A2A-Version` is interpreted as 0.3 and refused with `VersionNotSupportedError` |
| Multi-tenant `tenant` routing | Single-tenant interface; no `tenant` value is accepted |
| Signed Agent Cards | Not implemented in the first Line |
| Agent Card registries | The plugin publishes a well-known card; it does not crawl or trust registries |

## Change rules

- A new A2A specification `Major.Minor` is a new **Protocol Line** and a
  new plugin package major. The plugin does not negotiate between Lines
  and does not translate A2A to another protocol.
- A patch-level specification release may be adopted only after a
  diff review confirms it changes no wire field, status, error code,
  timing rule, or bound. The pinned tag and commit in this document must
  be updated in the same change.
- Adding or removing a supported capability is a plugin contract change:
  update this document, the Agent Card, the conformance run, the
  `CHANGELOG.md`, and the package version together.
- The Station native contract version is independent. This plugin must
  work against native contract `1.0` or declare the new minimum; it must
  not require a protocol-specific field in the core.
