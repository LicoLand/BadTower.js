/**
 * AC-003 Reservation and sharding: deterministic per-affiliation naming,
 * retry-safe first-contact reservation, exact handle initialization, one
 * usable handle per replay, changed-replay conflicts, no global allocator,
 * and fail-closed AFFILIATE plus async RESERVE without signatures.
 */

import { env, exports } from "cloudflare:workers";
import { listDurableObjectIds, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  CONTROL_MEDIA_TYPE,
  FAILURE_CLASS_HEADER,
  HandleClass,
  CLEANUP_BATCH_ROWS,
  MAX_OPERATION_RECORDS_PER_AFFILIATION,
  OPERATION_ID_HEADER,
  OUTCOME_HEADER,
  PROTECTED_PACKET_MEDIA_TYPE,
} from "../src/transport/candidate";
import { affiliationObjectName } from "../src/durable/affiliation-shard";
import type { RelayHandle } from "../src/durable/relay-handle";
import {
  byteLengthOf,
  encodeAffiliateRequest,
  encodeReserveRequest,
  generateAccessGrant,
  opRequest,
  randomOpId,
  readMap,
  toBase64Url,
  uintValue,
  bytesValue,
  VALID_CF,
} from "./helpers";

const handler = exports.default as { fetch(request: Request, env: Env): Promise<Response> };

interface Reserved {
  token: string;
  handle: Uint8Array;
  handleName: string;
  responseBody: Uint8Array;
}

async function reserveFirstContact(): Promise<Reserved> {
  const invite = await generateAccessGrant();
  const descriptor = crypto.getRandomValues(new Uint8Array(32));
  const commitment = crypto.getRandomValues(new Uint8Array(32));
  const profile = crypto.getRandomValues(new Uint8Array(32));
  const opId = randomOpId();
  const response = await handler.fetch(
    opRequest("/v1/reserve", {
      token: invite.token,
      headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: opId },
      body: encodeReserveRequest(descriptor, commitment, profile, HandleClass.FirstContact),
      cf: VALID_CF,
    }),
    env as Env,
  );
  expect(response.status).toBe(201);
  const body = new Uint8Array(await response.arrayBuffer());
  const entries = readMap(body);
  const handleEntry = entries.find((entry) => entry.key === 1);
  expect(handleEntry).toBeDefined();
  const handle = bytesValue(handleEntry!);
  expect(handle.byteLength).toBe(32);
  return {
    token: invite.token,
    handle,
    handleName: toBase64Url(handle),
    responseBody: body,
  };
}

function submitRequest(token: string, handleName: string, opId: string, packet: Uint8Array): Request {
  return opRequest(`/v1/handles/${handleName}/submit`, {
    token,
    headers: {
      "content-type": PROTECTED_PACKET_MEDIA_TYPE,
      [OPERATION_ID_HEADER]: opId,
    },
    body: packet,
    cf: VALID_CF,
  });
}

describe("affiliation sharding", () => {
  it("derives deterministic distinct names per affiliation and identical names for identical inputs", async () => {
    const a = crypto.getRandomValues(new Uint8Array(32));
    const b = crypto.getRandomValues(new Uint8Array(32));
    const a2 = crypto.getRandomValues(new Uint8Array(32));
    const name1 = await affiliationObjectName(a, b);
    const name1Again = await affiliationObjectName(a, b);
    const name2 = await affiliationObjectName(a, a2);
    const name3 = await affiliationObjectName(a2, b);
    expect(name1).toBe(name1Again);
    expect(name1).not.toBe(name2);
    expect(name2).not.toBe(name3);
    expect(name1).toMatch(/^[0-9a-f]{64}$/);
  });

  it("selects only the deterministic affiliation and 43-char handle objects, never a global allocator", async () => {
    const invite = await generateAccessGrant();
    const descriptor = crypto.getRandomValues(new Uint8Array(32));
    const commitment = crypto.getRandomValues(new Uint8Array(32));
    const name = await affiliationObjectName(descriptor, commitment);
    const opId = randomOpId();
    const response = await handler.fetch(
      opRequest("/v1/reserve", {
        token: invite.token,
        headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: opId },
        body: encodeReserveRequest(
          descriptor,
          commitment,
          crypto.getRandomValues(new Uint8Array(32)),
          HandleClass.FirstContact,
        ),
        cf: VALID_CF,
      }),
      env as Env,
    );
    expect(response.status).toBe(201);
    const entries = readMap(new Uint8Array(await response.arrayBuffer()));
    const handleName = toBase64Url(bytesValue(entries.find((entry) => entry.key === 1)!));

    const shardIds = await listDurableObjectIds(env.AFFILIATION_SHARDS);
    expect(shardIds).toHaveLength(1);
    // The pool exposes ids without a .name; identity is proven by the id
    // string of the deterministic getByName target.
    expect(shardIds[0]!.toString()).toBe(env.AFFILIATION_SHARDS.getByName(name).id.toString());
    expect(shardIds[0]!.toString()).not.toBe(env.AFFILIATION_SHARDS.getByName("global").id.toString());

    expect(handleName).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const relayIds = await listDurableObjectIds(env.RELAY_HANDLES);
    expect(relayIds).toHaveLength(1);
    expect(relayIds[0]!.toString()).toBe(env.RELAY_HANDLES.getByName(handleName).id.toString());
    expect(relayIds[0]!.toString()).not.toBe(env.RELAY_HANDLES.getByName("global").id.toString());
  });
});

describe("retry-safe first-contact reservation", () => {
  it("atomically caps concurrent distinct reservations at the affiliation ceiling", async () => {
    const shard = env.AFFILIATION_SHARDS.getByName(crypto.randomUUID());
    await runInDurableObject(shard, (_instance, state) => {
      const now = Date.now();
      for (let index = 0; index < MAX_OPERATION_RECORDS_PER_AFFILIATION - 1; index += 1) {
        const operationId = new Uint8Array(16);
        new DataView(operationId.buffer).setUint32(12, index);
        const digest = new Uint8Array(32);
        new DataView(digest.buffer).setUint32(28, index);
        state.storage.sql.exec(
          `INSERT INTO operations
             (op_id, request_digest, phase, status, headers, body, created_at, expires_at,
              pending_handle, pending_handle_class)
           VALUES (?, ?, 0, 406, '{}', x'', ?, ?, NULL, NULL)`,
          operationId.buffer,
          digest.buffer,
          now,
          now + 300_000,
        );
      }
      state.storage.sql.exec(
        "UPDATE usage SET operation_count = ? WHERE id = 1",
        MAX_OPERATION_RECORDS_PER_AFFILIATION - 1,
      );
    });

    const results = await Promise.all(Array.from({ length: 8 }, (_, index) => {
      const operationId = new Uint8Array(16);
      new DataView(operationId.buffer).setUint32(12, 10_000 + index);
      const digest = crypto.getRandomValues(new Uint8Array(32));
      return shard.reserve(operationId, digest, { handleClass: HandleClass.FirstContact });
    }));
    expect(results.filter((result) => result.status === 201)).toHaveLength(1);
    expect(results.filter((result) => result.status === 429)).toHaveLength(7);
    const counts = await runInDurableObject(shard, (_instance, state) => ({
      rows: Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM operations").one().n),
      usage: Number(state.storage.sql.exec("SELECT operation_count AS n FROM usage WHERE id = 1").one().n),
    }));
    expect(counts).toEqual({
      rows: MAX_OPERATION_RECORDS_PER_AFFILIATION,
      usage: MAX_OPERATION_RECORDS_PER_AFFILIATION,
    });
  });

  it("returns one byte-identical handle for concurrent and repeated identical reserves", async () => {
    const invite = await generateAccessGrant();
    const descriptor = crypto.getRandomValues(new Uint8Array(32));
    const commitment = crypto.getRandomValues(new Uint8Array(32));
    const opId = randomOpId();
    const body = encodeReserveRequest(
        descriptor,
        commitment,
        crypto.getRandomValues(new Uint8Array(32)),
        HandleClass.FirstContact,
      );
    const request = () => opRequest("/v1/reserve", {
      token: invite.token,
      headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: opId },
      body,
      cf: VALID_CF,
    });

    const responses = await Promise.all(
      Array.from({ length: 6 }, () => handler.fetch(request(), env as Env)),
    );
    const bodies: Uint8Array[] = [];
    const handles: string[] = [];
    for (const response of responses) {
      expect(response.status).toBe(201);
      const body = new Uint8Array(await response.arrayBuffer());
      bodies.push(body);
      const entries = readMap(body);
      handles.push(toBase64Url(bytesValue(entries.find((entry) => entry.key === 1)!)));
    }
    for (const body of bodies.slice(1)) {
      expect(body).toEqual(bodies[0]);
    }
    expect(new Set(handles).size).toBe(1);

    // A later sequential retry replays the same final record.
    const replay = await handler.fetch(request(), env as Env);
    expect(replay.status).toBe(201);
    expect(new Uint8Array(await replay.arrayBuffer())).toEqual(bodies[0]);
  });

  it("initializes the handle exactly once and it accepts exactly one submission", async () => {
    const reserved = await reserveFirstContact();

    const relayStub = env.RELAY_HANDLES.getByName(reserved.handleName);
    const metadata = await runInDurableObject(relayStub, (_instance, state) => {
      const rows = state.storage.sql
        .exec("SELECT handle_class, first_contact_remaining, created_at, expires_at FROM metadata")
        .toArray();
      return {
        handleClass: Number(rows[0]!.handle_class),
        firstContactRemaining: Number(rows[0]!.first_contact_remaining),
        createdAt: Number(rows[0]!.created_at),
        expiresAt: Number(rows[0]!.expires_at),
      };
    });
    expect(metadata.handleClass).toBe(HandleClass.FirstContact);
    expect(metadata.firstContactRemaining).toBe(1);
    expect(metadata.expiresAt).toBeGreaterThan(metadata.createdAt);

    // RPC initialize replay is idempotent for the same arguments.
    const sameArgs = await relayStub.initialize(reserved.handle, { handleClass: HandleClass.FirstContact });
    expect(sameArgs).toEqual({ ok: true });
    const differentHandle = reserved.handle.slice();
    differentHandle[0] = differentHandle[0]! ^ 0xff;
    const mismatchedHandle = await relayStub.initialize(differentHandle, {
      handleClass: HandleClass.FirstContact,
    });
    expect(mismatchedHandle).toEqual({ ok: false, reason: "conflict" });
    // Mismatched arguments conflict without changing the initialized handle.
    const mismatched = await relayStub.initialize(reserved.handle, { handleClass: HandleClass.Async });
    expect(mismatched).toEqual({ ok: false, reason: "conflict" });
    const alarm = await runInDurableObject(relayStub, (_instance, state) =>
      state.storage.getAlarm(),
    );
    expect(alarm).not.toBeNull();

    const packet = crypto.getRandomValues(new Uint8Array(64));
    const submit = await handler.fetch(
      submitRequest(reserved.token, reserved.handleName, randomOpId(), packet),
      env as Env,
    );
    expect(submit.status).toBe(202);
    expect(submit.headers.get(OUTCOME_HEADER)).toBe("accepted");
    expect(new Uint8Array(await submit.arrayBuffer())).toEqual(Uint8Array.from([0xa1, 0x00, 0x00]));

    const after = await runInDurableObject(relayStub, (_instance, state) => {
      const rows = state.storage.sql
        .exec("SELECT first_contact_remaining FROM metadata")
        .toArray();
      return Number(rows[0]!.first_contact_remaining);
    });
    expect(after).toBe(0);

    const second = await handler.fetch(
      submitRequest(reserved.token, reserved.handleName, randomOpId(), packet),
      env as Env,
    );
    expect(second.status).toBe(429);
    expect(second.headers.get(FAILURE_CLASS_HEADER)).toBe("capacityUnavailable");
  });

  it("schedules and drains affiliation replay expiry in bounded alarm batches", async () => {
    const invite = await generateAccessGrant();
    const descriptor = crypto.getRandomValues(new Uint8Array(32));
    const commitment = crypto.getRandomValues(new Uint8Array(32));
    const shardName = await affiliationObjectName(descriptor, commitment);
    const response = await handler.fetch(
      opRequest("/v1/reserve", {
        token: invite.token,
        headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: randomOpId() },
        body: encodeReserveRequest(
          descriptor,
          commitment,
          crypto.getRandomValues(new Uint8Array(32)),
          HandleClass.Async,
        ),
        cf: VALID_CF,
      }),
      env as Env,
    );
    expect(response.status).toBe(406);

    const shard = env.AFFILIATION_SHARDS.getByName(shardName);
    await runInDurableObject(shard, async (_instance, state) => {
      const sql = state.storage.sql;
      const now = Date.now();
      sql.exec("UPDATE operations SET expires_at = ?", now - 1);
      for (let i = 0; i < CLEANUP_BATCH_ROWS; i += 1) {
        const operationId = new Uint8Array(16);
        new DataView(operationId.buffer).setUint32(0, i + 1);
        const digest = new Uint8Array(32);
        new DataView(digest.buffer).setUint32(0, i + 1);
        sql.exec(
          `INSERT INTO operations
             (op_id, request_digest, phase, status, headers, body, created_at, expires_at,
              pending_handle, pending_handle_class)
           VALUES (?, ?, 0, 406, '{}', x'', ?, ?, NULL, NULL)`,
          operationId.buffer,
          digest.buffer,
          now - 1000,
          now - 1,
        );
      }
      sql.exec("UPDATE usage SET operation_count = ? WHERE id = 1", CLEANUP_BATCH_ROWS + 1);
      await state.storage.setAlarm(now + 60_000);
    });

    expect(await runDurableObjectAlarm(shard)).toBe(true);
    const afterFirst = await runInDurableObject(shard, (_instance, state) =>
      Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM operations").one().n),
    );
    expect(afterFirst).toBe(1);
    await runInDurableObject(shard, (_instance, state) =>
      state.storage.setAlarm(Date.now() + 60_000),
    );
    expect(await runDurableObjectAlarm(shard)).toBe(true);
    const afterSecond = await runInDurableObject(shard, (_instance, state) =>
      Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM operations").one().n),
    );
    expect(afterSecond).toBe(0);
  });

  it("conflicts when the same operation id replays a changed request meaning", async () => {
    const invite = await generateAccessGrant();
    const descriptor = crypto.getRandomValues(new Uint8Array(32));
    const commitment = crypto.getRandomValues(new Uint8Array(32));
    const profile = crypto.getRandomValues(new Uint8Array(32));
    const opId = randomOpId();

    const first = opRequest("/v1/reserve", {
      token: invite.token,
      headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: opId },
      body: encodeReserveRequest(descriptor, commitment, profile, HandleClass.FirstContact),
      cf: VALID_CF,
    });
    const firstResponse = await handler.fetch(first, env as Env);
    expect(firstResponse.status).toBe(201);

    const changed = opRequest("/v1/reserve", {
      token: invite.token,
      headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: opId },
      body: encodeReserveRequest(
        descriptor,
        commitment,
        crypto.getRandomValues(new Uint8Array(32)),
        HandleClass.FirstContact,
      ),
      cf: VALID_CF,
    });
    const changedResponse = await handler.fetch(changed, env as Env);
    expect(changedResponse.status).toBe(409);
    expect(changedResponse.headers.get(FAILURE_CLASS_HEADER)).toBe("conflict");
    expect(changedResponse.headers.get(OUTCOME_HEADER)).toBe("rejected");
  });
});

describe("fail-closed signed semantics", () => {
  it("AFFILIATE fails unsupportedProfile with no signature labels", async () => {
    const invite = await generateAccessGrant();
    const response = await handler.fetch(
      opRequest("/v1/affiliate", {
        token: invite.token,
        headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: randomOpId() },
        body: encodeAffiliateRequest(
          crypto.getRandomValues(new Uint8Array(32)),
          crypto.getRandomValues(new Uint8Array(32)),
        ),
        cf: VALID_CF,
      }),
      env as Env,
    );
    expect(response.status).toBe(406);
    expect(response.headers.get(OUTCOME_HEADER)).toBe("rejected");
    expect(response.headers.get(FAILURE_CLASS_HEADER)).toBe("unsupportedProfile");
    const entries = readMap(new Uint8Array(await response.arrayBuffer()));
    const keys = entries.map((entry) => entry.key).sort((a, b) => a - b);
    expect(keys).toEqual([0, 3]);
    expect(uintValue(entries.find((entry) => entry.key === 0)!)).toBe(1); // rejected
    expect(uintValue(entries.find((entry) => entry.key === 3)!)).toBe(1); // unsupportedProfile
  });

  it("async RESERVE fails unsupportedProfile with no handle or signature labels", async () => {
    const invite = await generateAccessGrant();
    const response = await handler.fetch(
      opRequest("/v1/reserve", {
        token: invite.token,
        headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: randomOpId() },
        body: encodeReserveRequest(
          crypto.getRandomValues(new Uint8Array(32)),
          crypto.getRandomValues(new Uint8Array(32)),
          crypto.getRandomValues(new Uint8Array(32)),
          HandleClass.Async,
        ),
        cf: VALID_CF,
      }),
      env as Env,
    );
    expect(response.status).toBe(406);
    expect(response.headers.get(OUTCOME_HEADER)).toBe("rejected");
    expect(response.headers.get(FAILURE_CLASS_HEADER)).toBe("unsupportedProfile");
    const entries = readMap(new Uint8Array(await response.arrayBuffer()));
    const keys = entries.map((entry) => entry.key).sort((a, b) => a - b);
    expect(keys).toEqual([0, 5]);
    expect(uintValue(entries.find((entry) => entry.key === 0)!)).toBe(1);
    expect(uintValue(entries.find((entry) => entry.key === 5)!)).toBe(1);
  });
});

void byteLengthOf;
