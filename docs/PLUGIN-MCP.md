# MCP compatibility plugin: pinned Line and support scope

**Status: design pin only.** This repository does not yet contain an MCP
listener, package, test, release, or deployment. This document fixes what
a future plugin may claim so that an implementation cannot drift onto a
floating specification or an undocumented subset.

## Pinned protocol Line

| Item | Value |
| --- | --- |
| Protocol | Model Context Protocol (MCP) |
| Specification tag | `2026-07-28` |
| Immutable commit | `5f5440bb26a62e2cf3440b92da5a667efa03b267` |
| Release date | 2026-07-28 |
| Protocol version string | `2026-07-28` |
| Binding | Streamable HTTP |
| Endpoint | one HTTPS path owned by the plugin (for example `/mcp`) |
| Transport | JSON-RPC 2.0 over HTTP POST |
| Version header | `MCP-Protocol-Version: 2026-07-28` on every POST |
| Per-request metadata | `_meta["io.modelcontextprotocol/protocolVersion"] = "2026-07-28"` |
| Server capability | `tools` only |

The tag and commit are the pin. A branch name, a moving `main`, a draft
schema, a client SDK version, or a website "latest" label is not a pin.
The plugin must not fetch or load an MCP checkout at runtime; generated
types or fixtures, if any, are committed artifacts derived from the pinned
commit and carry that commit in their header.

### Normative sources at the pin

- `schema/2026-07-28/schema.ts` — the authoritative protocol schema for
  this revision.
- `schema/2026-07-28/schema.json` — the generated JSON Schema form of the
  same schema.
- `docs/specification/2026-07-28/` — normative requirements, including
  `basic/versioning.mdx`, `basic/transports/streamable-http.mdx`,
  `server/discover.mdx`, `server/tools.mdx`, and `server/index.mdx`.
- `docs/specification/2026-07-28/changelog.mdx` — change context, not a
  substitute for the sources above.

### Consistency source

The future implementation's conformance target is the MCP conformance
suite at tag `v0.1.16` (commit
`21a9a2febd7100d7c17ac1021ee7f2ed9f66a1e0`), restricted to the
Streamable HTTP transport and the supported capability set below. The
suite has not been run; **no MCP conformance claim is made today**. A
release may claim only the checks it actually ran, with the report
attached to the release record.

## Binding rules

- One HTTPS endpoint accepts `POST` with a single JSON-RPC request or
  notification. The plugin does not expose stdio, the legacy 2025-11-25
  HTTP+SSE transport, a `GET` stream endpoint, or a second endpoint.
- The request body is one JSON-RPC object. `MCP-Protocol-Version` and the
  per-request `_meta` version must both be `2026-07-28`; a different
  version is answered with `UnsupportedProtocolVersionError` (`-32022`)
  listing `2026-07-28`, not silently downgraded.
- There is no protocol-level session and no `initialize` handshake. Every
  request is self-contained, as required by this revision.
- The plugin validates the `Origin` header and refuses an invalid origin
  with `403`.
- The first Line answers with a single `application/json` JSON-RPC
  response. It does not return a request-scoped `text/event-stream`;
  therefore `Last-Event-ID`, SSE resumption and stream cancellation are
  not implemented.
- Authentication is an HTTP bearer security scheme carrying the Station
  admission credential (`btm1.<…>`). The credential is an opaque
  authorization subject; it is not an identity and the Station is not a
  trust authority. OAuth 2.1 authorization, dynamic client registration,
  and resource indicators are not part of the first Line.

## Supported capabilities

| Capability | Scope |
| --- | --- |
| `server/discover` | Required by the pinned revision; returns supported version `2026-07-28`, `tools` capability, server info and instructions |
| `tools/list` | Returns the static tool set below; no pagination cursor |
| `tools/call` | Invokes one tool and returns a `CallToolResult`; tool errors use `isError: true` |
| `tools` capability | The only advertised server capability |
| JSON-RPC 2.0 | Requests, responses, notifications, standard error objects and `-32022` |
| `Mcp-Method` / `Mcp-Name` headers | Echoed/validated as the revision requires for the supported methods |
| Opaque Station carriage | Tool arguments and results are carried as opaque bytes over the native contract; Station Core never parses MCP |

### Tool set

The plugin is a thin MCP server over the Station native contract. It does
not interpret packet content, identity, or protocol metadata.

| Tool | Arguments | Result |
| --- | --- | --- |
| `badtower_contract_version` | none | `major`, `minor`, `revision` |
| `badtower_reserve` | `subject` (base64url, 32 bytes) | `bound` or a mapped refusal |
| `badtower_submit` | `handle` (base64url, 32 bytes), `packet` (base64url, 1..524288 bytes) | `outcome`, `reason` |
| `badtower_claim` | `limit` (1..16), `exclude` (sequence integers) | packets with sequence, handle and body |
| `badtower_settle` | `sequences` (sequence integers) | `settled` |
| `badtower_capacity` | none | `capacityBytes`, `databaseBytes` |

Revocation is not exposed as a tool. It is an operator action with a
separate `btr1` HMAC body and must not be callable by an MCP client.
The tool set is deliberately small and closed; adding a tool is a plugin
contract change.

## Unsupported capabilities

| Capability | Answer |
| --- | --- |
| stdio transport | Not offered; the plugin is a remote HTTPS server |
| Legacy `2025-11-25` and earlier sessions | Not offered; no `initialize`, no `Mcp-Session-Id` |
| `GET` SSE stream | Not offered; `405` for `GET` on the endpoint |
| Request-scoped SSE responses | Not offered in the first Line; JSON response only |
| `subscriptions/listen` | Not offered; no subscriptions capability |
| `resources/list`, `resources/read`, `resources/templates/list` | Not offered; no resources capability |
| `prompts/list`, `prompts/get` | Not offered; no prompts capability |
| `logging/setLevel` and log notifications | Not offered; no logging capability |
| `completion/complete` | Not offered; no completions capability |
| Sampling and elicitation | Not offered; the server never requests client input |
| Pagination | Not offered for the static tool list |
| Caching (`ttlMs`, `cacheScope`) | Not offered; discovery is answered uncached |
| OAuth 2.1 authorization | Not offered in the first Line; Station admission only |
| MCP extensions | None declared; an unknown capability is not advertised |

## Change rules

- A new MCP specification revision is a new **Protocol Line** and a new
  plugin package major. The plugin does not negotiate between revisions
  and does not translate MCP to another protocol.
- A patch-level schema release may be adopted only after a diff review
  confirms it changes no wire field, error code, header rule, or bound.
  The pinned tag and commit in this document must be updated in the same
  change.
- Adding or removing a tool or capability is a plugin contract change:
  update this document, `server/discover`, the conformance run, the
  `CHANGELOG.md`, and the package version together.
- The Station native contract version is independent. This plugin must
  work against native contract `1.0` or declare the new minimum; it must
  not require a protocol-specific field in the core.
