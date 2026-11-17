# Native contract versioning

The native contract is the Station's own protocol-neutral HTTP surface:
Reserve, Submit, Claim, Settle, capacity, contract version, health and
revocation. This document pins its compatibility identifier and the rule
for changing it. The wire shapes are in `API.md`; the implementation is
`packages/station-core/src/native.ts`.

## Identifier

**Contract version: `1.0`.**

The identifier is `major.minor`. Patch-level documentation corrections do
not change compatibility and are carried in the revision field.

| Field | Size | Meaning |
| --- | --- | --- |
| `major` | `u16` big-endian | Incompatible contract generation |
| `minor` | `u16` big-endian | Backward-compatible addition |
| `revision` | `u16` big-endian | Editorial or non-wire correction |
| `reserved` | `u16` big-endian | Must be zero in `1.0` |

The source constant is `NATIVE_CONTRACT_VERSION` in
`packages/station-core/src/native.ts`; the human-readable form is
`NATIVE_CONTRACT_VERSION_TEXT`.

## Queryable location

`GET /v1/native/version` with the same `Authorization: Bearer btm1.<…>`
admission as every other native route. It does not require the mailbox to
be bound and it does not touch mailbox storage.

```
200, application/octet-stream, 8 bytes:
  major(u16 BE) ‖ minor(u16 BE) ‖ revision(u16 BE) ‖ reserved(u16 BE)
```

For `1.0` the body is `00 01 00 00 00 00 00 00`. An unauthenticated
request answers `401`; the route is not a public version banner.

## Change rules

A change is classified before it is implemented. When in doubt, treat it
as the higher class.

### Major (incompatible) — always a new major

- Changing the size, order, encoding, or meaning of any request or
  response field, including the handle, packet, sequence, count, limit,
  outcome, reason, capacity or version fields.
- Removing or renaming a route, or changing a route's method.
- Changing an existing status code's meaning, or making a previously
  optional request field required.
- Changing admission, revocation, replay, settle, capacity, or
  fail-closed behavior in a way an existing native client can observe.
- Changing the meaning of an existing outcome or reason value.

### Minor (backward-compatible) — new minor

- Adding a new route that an existing client can ignore.
- Adding a new optional request field only if the old body remains a
  complete valid request.
- Adding a new outcome or reason value only if clients are already
  required to treat unknown values as transient/rejected and the
  contract says so before the addition.
- Adding a new response field only if the old response length and prefix
  remain valid and the field is append-only.

### Revision (no wire change)

- Documentation corrections, test-only changes, comments, or internal
  refactors that do not change any observable field, status, timing
  guarantee, or bound.

### Never silent

A version change and its implementation land in the same commit:

1. update `NATIVE_CONTRACT_VERSION`;
2. update `API.md` and this document;
3. update the native contract version test;
4. add a `CHANGELOG.md` entry;
5. state the old and new compatibility class in the change description.

The package release version (`package.json`) and the native contract
version are independent. A package release may ship the same contract
version; a contract change must not hide behind an unchanged package
version.

## Compatibility promise

Within one major version, a client that implements the documented fields
and treats unknown outcome/reason values as the contract requires can
keep using the Station. The Station does not negotiate a contract
version per request in `1.0`; a client that needs a different major uses
a different endpoint or a future negotiated surface. The LicoArc listener
and every future plugin pin their own protocol Line separately; they do
not make the native contract protocol-specific.

## Current surface

| Route | Method | Contract |
| --- | --- | --- |
| `/v1/native/reserve` | `POST` | subject(32) |
| `/v1/native/submit` | `POST` | handle(32) ‖ packet(1..524288) |
| `/v1/native/claim` | `POST` | limit(1..16) ‖ count(1) ‖ sequence(u64 BE)× |
| `/v1/native/settle` | `POST` | count(1) ‖ sequence(u64 BE)× |
| `/v1/native/capacity` | `GET` | capacityBytes(u64 BE) ‖ databaseBytes(u64 BE) |
| `/v1/native/version` | `GET` | major(u16) ‖ minor(u16) ‖ revision(u16) ‖ reserved(u16) |
| `/v1/revoke` | `POST` | mailboxId(16) ‖ HMAC(stationKey, "btr1" ‖ mailboxId) |
| `/healthz` | `GET` | `ok\n`, unauthenticated liveness |
