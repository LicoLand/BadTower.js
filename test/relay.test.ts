/**
 * AC-004 Bounded opaque relay lifecycle: byte-exact raw BLOB round-trips,
 * exclusive and bounded claims, live-tuple retrieve, atomic complete and
 * release settlement, first-contact single use, replay windows that never
 * extend, exact queue and claim capacity edges, and bounded indexed alarm
 * cleanup. All durable facts are asserted black-box through the Worker plus
 * in-object SQLite reads; packets are synthetic opaque bytes and are never
 * logged.
 */

import { env, exports } from "cloudflare:workers";
import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { CborReader } from "../src/transport/cbor";
import {
  CLAIM_EPOCH_HEADER,
  CLAIM_ID_HEADER,
  CLEANUP_BATCH_ROWS,
  CONTROL_MEDIA_TYPE,
  FAILURE_CLASS_HEADER,
  HandleClass,
  MAX_CLAIM_BYTES,
  MAX_CLAIM_ITEMS,
  MAX_CLAIM_RESPONSE_BYTES,
  MAX_OPERATION_RECORDS_PER_HANDLE,
  MAX_PACKET_BYTES,
  MAX_QUEUE_BYTES_PER_HANDLE,
  MAX_QUEUE_ITEMS_PER_HANDLE,
  MAX_SETTLEMENT_ATTEMPTS,
  OPERATION_ID_HEADER,
  OUTCOME_HEADER,
  PROTECTED_PACKET_MEDIA_TYPE,
  RETRY_AFTER_MS_HEADER,
  SettleAction,
} from "../src/transport/candidate";
import {
  bytesValue,
  encodeAffiliateRequest,
  encodeClaimRequest,
  encodeReserveRequest,
  encodeRetrieveRequest,
  encodeSettleRequest,
  generateAccessGrant,
  opRequest,
  patternBytes,
  randomOpId,
  readMap,
  toBase64Url,
  uintValue,
  VALID_CF,
} from "./helpers";

const handler = exports.default as { fetch(request: Request, env: Env): Promise<Response> };

interface HandleContext {
  token: string;
  handle: Uint8Array;
  handleName: string;
}

async function reserveHandle(): Promise<HandleContext> {
  const invite = await generateAccessGrant();
  const response = await handler.fetch(
    opRequest("/v1/reserve", {
      token: invite.token,
      headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: randomOpId() },
      body: encodeReserveRequest(
        crypto.getRandomValues(new Uint8Array(32)),
        crypto.getRandomValues(new Uint8Array(32)),
        crypto.getRandomValues(new Uint8Array(32)),
        HandleClass.FirstContact,
      ),
      cf: VALID_CF,
    }),
    env as Env,
  );
  expect(response.status).toBe(201);
  const handle = bytesValue(readMap(new Uint8Array(await response.arrayBuffer())).find((e) => e.key === 1)!);
  return { token: invite.token, handle, handleName: toBase64Url(handle) };
}

function submitRequest(context: HandleContext, opId: string, packet: Uint8Array): Request {
  return opRequest(`/v1/handles/${context.handleName}/submit`, {
    token: context.token,
    headers: {
      "content-type": PROTECTED_PACKET_MEDIA_TYPE,
      [OPERATION_ID_HEADER]: opId,
    },
    body: packet,
    cf: VALID_CF,
  });
}

function controlRequest(
  context: HandleContext,
  suffix: "claim" | "retrieve" | "settle",
  opId: string,
  body: Uint8Array,
): Request {
  return opRequest(`/v1/handles/${context.handleName}/${suffix}`, {
    token: context.token,
    headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: opId },
    body,
    cf: VALID_CF,
  });
}

interface ClaimedItem {
  itemId: Uint8Array;
  packet: Uint8Array;
}

interface ClaimResponse {
  outcome: number;
  claimId: Uint8Array | null;
  epoch: number | null;
  items: ClaimedItem[];
}

function parseClaimResponse(body: Uint8Array): ClaimResponse {
  const entries = readMap(body);
  const outcome = uintValue(entries.find((e) => e.key === 0)!);
  const claimIdEntry = entries.find((e) => e.key === 1);
  const epochEntry = entries.find((e) => e.key === 2);
  const itemsEntry = entries.find((e) => e.key === 3);
  if (claimIdEntry === undefined || epochEntry === undefined || itemsEntry === undefined) {
    return { outcome, claimId: null, epoch: null, items: [] };
  }
  const reader = new CborReader(itemsEntry.value);
  const count = reader.arrayHeader();
  const items: ClaimedItem[] = [];
  for (let i = 0; i < count; i += 1) {
    const itemEntries = reader.mapEntries();
    const itemId = bytesValue(itemEntries.find((e) => e.key === 0)!);
    const packet = bytesValue(itemEntries.find((e) => e.key === 1)!);
    items.push({ itemId, packet });
  }
  reader.end();
  return {
    outcome,
    claimId: bytesValue(claimIdEntry),
    epoch: uintValue(epochEntry),
    items,
  };
}

interface SettlementResult {
  itemId: Uint8Array;
  settleOutcome: number;
}

function parseSettleResponse(body: Uint8Array): { outcome: number; results: SettlementResult[] } {
  const entries = readMap(body);
  const outcome = uintValue(entries.find((e) => e.key === 0)!);
  const reader = new CborReader(entries.find((e) => e.key === 1)!.value);
  const count = reader.arrayHeader();
  const results: SettlementResult[] = [];
  for (let i = 0; i < count; i += 1) {
    const itemEntries = reader.mapEntries();
    results.push({
      itemId: bytesValue(itemEntries.find((e) => e.key === 0)!),
      settleOutcome: uintValue(itemEntries.find((e) => e.key === 1)!),
    });
  }
  reader.end();
  return { outcome, results };
}

/** Inserts synthetic item rows directly into the handle store. */
function insertItems(
  stub: DurableObjectStub,
  packets: Uint8Array[],
  opts: { expired?: boolean; past?: number } = {},
): Promise<void> {
  const nowMs = Date.now();
  return runInDurableObject(stub, (_instance, state) => {
    const sql = state.storage.sql;
    const timestamp = opts.expired === true ? nowMs - (opts.past ?? 60_000) : nowMs + 3600_000;
    const sequence = sql.exec("SELECT COALESCE(MAX(queue_seq), 0) AS n FROM items").one();
    const firstSequence = Number(sequence.n) + 1;
    packets.forEach((packet, index) => {
      sql.exec(
        `INSERT INTO items
           (item_id, packet, byte_len, accepted_at, expires_at, queue_seq)
         VALUES (?, ?, ?, ?, ?, ?)`,
        (crypto.getRandomValues(new Uint8Array(32)) as Uint8Array).buffer as ArrayBuffer,
        (packet as Uint8Array).slice().buffer as ArrayBuffer,
        packet.length,
        nowMs,
        timestamp,
        firstSequence + index,
      );
    });
    // Seeded rows are accepted-submit state, so the counters must match.
    const totals = sql
      .exec(
        `SELECT COUNT(*) AS n, COALESCE(SUM(byte_len), 0) AS bytes,
                COALESCE(MAX(queue_seq), 0) AS max_seq
           FROM items`,
      )
      .one();
    sql.exec(
      `UPDATE usage
          SET item_count = ?, byte_count = ?, next_queue_seq = ?
        WHERE id = 1`,
      Number(totals.n),
      Number(totals.bytes),
      Number(totals.max_seq),
    );
  });
}

function countItems(stub: DurableObjectStub): Promise<number> {
  return runInDurableObject(stub, (_instance, state) => {
    const row = state.storage.sql.exec("SELECT COUNT(*) AS n FROM items").one();
    return Number(row.n);
  });
}

function usageRow(stub: DurableObjectStub): Promise<{ itemCount: number; byteCount: number; claimEpoch: number }> {
  return runInDurableObject(stub, (_instance, state) => {
    const row = state.storage.sql
      .exec("SELECT item_count, byte_count, claim_epoch FROM usage WHERE id = 1")
      .one();
    return {
      itemCount: Number(row.item_count),
      byteCount: Number(row.byte_count),
      claimEpoch: Number(row.claim_epoch),
    };
  });
}

describe("opaque packet lifecycle", () => {
  it("round-trips byte-exact BLOBs through submit, claim, and retrieve", async () => {
    const context = await reserveHandle();
    const packet = patternBytes(0xab, 257);
    const opId = randomOpId();

    const submit = await handler.fetch(submitRequest(context, opId, packet), env as Env);
    expect(submit.status).toBe(202);
    expect(submit.headers.get(OUTCOME_HEADER)).toBe("accepted");
    expect(new Uint8Array(await submit.arrayBuffer())).toEqual(Uint8Array.from([0xa1, 0x00, 0x00]));

    const relayStub = env.RELAY_HANDLES.getByName(context.handleName);
    const stored = await runInDurableObject(relayStub, (_instance, state) => {
      const row = state.storage.sql
        .exec("SELECT item_id, packet, byte_len, expires_at FROM items")
        .toArray()[0]!;
      return {
        itemId: new Uint8Array(row.item_id as unknown as ArrayBuffer),
        packet: new Uint8Array(row.packet as unknown as ArrayBuffer),
        byteLen: Number(row.byte_len),
        expiresAt: Number(row.expires_at),
      };
    });
    // Raw BLOB storage: byte-exact, never base64-encoded.
    expect(stored.packet).toEqual(packet);
    expect(stored.byteLen).toBe(257);
    expect(toBase64Url(stored.packet)).toBe(toBase64Url(packet));

    const claim = await handler.fetch(
      controlRequest(context, "claim", randomOpId(), encodeClaimRequest(64)),
      env as Env,
    );
    expect(claim.status).toBe(200);
    expect(claim.headers.get(OUTCOME_HEADER)).toBe("accepted");
    const claimIdHeader = claim.headers.get(CLAIM_ID_HEADER);
    const epochHeader = claim.headers.get(CLAIM_EPOCH_HEADER);
    expect(claimIdHeader).not.toBeNull();
    expect(epochHeader).toBe("1");
    const claimed = parseClaimResponse(new Uint8Array(await claim.arrayBuffer()));
    expect(claimed.outcome).toBe(0);
    expect(claimed.items).toHaveLength(1);
    expect(claimed.items[0]!.packet).toEqual(packet);
    expect(claimed.items[0]!.itemId).toEqual(stored.itemId);
    expect(claimed.claimId).toEqual(fromBase64Url(claimIdHeader!));
    expect(claimed.epoch).toBe(1);

    const retrieve = await handler.fetch(
      controlRequest(
        context,
        "retrieve",
        randomOpId(),
        encodeRetrieveRequest(claimed.claimId!, claimed.epoch!, claimed.items[0]!.itemId),
      ),
      env as Env,
    );
    expect(retrieve.status).toBe(200);
    expect(retrieve.headers.get("content-type")).toBe(PROTECTED_PACKET_MEDIA_TYPE);
    expect(new Uint8Array(await retrieve.arrayBuffer())).toEqual(packet);
  });

  it("rejects empty and oversized submits with 413 before mutation", async () => {
    const context = await reserveHandle();

    const empty = await handler.fetch(submitRequest(context, randomOpId(), new Uint8Array(0)), env as Env);
    expect(empty.status).toBe(413);
    expect(empty.headers.get(FAILURE_CLASS_HEADER)).toBe("packetTooLarge");

    const oversized = await handler.fetch(
      submitRequest(context, randomOpId(), new Uint8Array(MAX_PACKET_BYTES + 1)),
      env as Env,
    );
    expect(oversized.status).toBe(413);
    expect(oversized.headers.get(FAILURE_CLASS_HEADER)).toBe("packetTooLarge");

    const relayStub = env.RELAY_HANDLES.getByName(context.handleName);
    expect(await countItems(relayStub)).toBe(0);
    expect((await usageRow(relayStub)).itemCount).toBe(0);
  });
});

describe("exclusive claims and retrieval", () => {
  it("second claim is an empty accepted response without claim headers", async () => {
    const context = await reserveHandle();
    const packet = patternBytes(0x11, 64);
    const submit = await handler.fetch(submitRequest(context, randomOpId(), packet), env as Env);
    expect(submit.status).toBe(202);

    const first = await handler.fetch(
      controlRequest(context, "claim", randomOpId(), encodeClaimRequest(1)),
      env as Env,
    );
    expect(first.status).toBe(200);
    expect(first.headers.get(CLAIM_ID_HEADER)).not.toBeNull();

    const second = await handler.fetch(
      controlRequest(context, "claim", randomOpId(), encodeClaimRequest(1)),
      env as Env,
    );
    expect(second.status).toBe(200);
    expect(second.headers.get(OUTCOME_HEADER)).toBe("accepted");
    expect(second.headers.get(CLAIM_ID_HEADER)).toBeNull();
    expect(second.headers.get(CLAIM_EPOCH_HEADER)).toBeNull();
    expect(new Uint8Array(await second.arrayBuffer())).toEqual(Uint8Array.from([0xa1, 0x00, 0x00]));
  });

  it("retrieve requires the live claim tuple", async () => {
    const context = await reserveHandle();
    const packet = patternBytes(0x22, 32);
    const submit = await handler.fetch(submitRequest(context, randomOpId(), packet), env as Env);
    expect(submit.status).toBe(202);

    const claim = await handler.fetch(
      controlRequest(context, "claim", randomOpId(), encodeClaimRequest(64)),
      env as Env,
    );
    const claimed = parseClaimResponse(new Uint8Array(await claim.arrayBuffer()));
    const { claimId, epoch, items } = claimed;
    const itemId = items[0]!.itemId;

    const wrongEpoch = await handler.fetch(
      controlRequest(
        context,
        "retrieve",
        randomOpId(),
        encodeRetrieveRequest(claimId!, epoch! + 1, itemId),
      ),
      env as Env,
    );
    expect(wrongEpoch.status).toBe(404);
    expect(wrongEpoch.headers.get(FAILURE_CLASS_HEADER)).toBe("targetUnavailable");

    const wrongClaimId = await handler.fetch(
      controlRequest(
        context,
        "retrieve",
        randomOpId(),
        encodeRetrieveRequest(crypto.getRandomValues(new Uint8Array(32)), epoch!, itemId),
      ),
      env as Env,
    );
    expect(wrongClaimId.status).toBe(404);
    expect(wrongClaimId.headers.get(FAILURE_CLASS_HEADER)).toBe("targetUnavailable");

    const unclaimedItem = await handler.fetch(
      controlRequest(
        context,
        "retrieve",
        randomOpId(),
        encodeRetrieveRequest(claimId!, epoch!, crypto.getRandomValues(new Uint8Array(32))),
      ),
      env as Env,
    );
    expect(unclaimedItem.status).toBe(404);
  });

  it("treats an expired item as stale even while its claim tuple has time left", async () => {
    const context = await reserveHandle();
    await handler.fetch(
      submitRequest(context, randomOpId(), patternBytes(0x23, 32)),
      env as Env,
    );
    const claim = await handler.fetch(
      controlRequest(context, "claim", randomOpId(), encodeClaimRequest(1)),
      env as Env,
    );
    const claimed = parseClaimResponse(new Uint8Array(await claim.arrayBuffer()));
    const item = claimed.items[0]!;
    const relayStub = env.RELAY_HANDLES.getByName(context.handleName);
    await runInDurableObject(relayStub, (_instance, state) => {
      state.storage.sql.exec(
        "UPDATE items SET expires_at = ? WHERE item_id = ?",
        Date.now() - 1,
        item.itemId.slice().buffer,
      );
    });

    const retrieve = await handler.fetch(
      controlRequest(
        context,
        "retrieve",
        randomOpId(),
        encodeRetrieveRequest(claimed.claimId!, claimed.epoch!, item.itemId),
      ),
      env as Env,
    );
    expect(retrieve.status).toBe(404);

    const settle = await handler.fetch(
      controlRequest(
        context,
        "settle",
        randomOpId(),
        encodeSettleRequest(claimed.claimId!, claimed.epoch!, [
          { itemId: item.itemId, action: SettleAction.Complete },
        ]),
      ),
      env as Env,
    );
    expect(parseSettleResponse(new Uint8Array(await settle.arrayBuffer())).results).toEqual([
      { itemId: item.itemId, settleOutcome: 2 },
    ]);
  });

  it("rejects out-of-range claim maxItems with invalidRequest", async () => {
    const context = await reserveHandle();
    for (const maxItems of [0, MAX_CLAIM_ITEMS + 1]) {
      const response = await handler.fetch(
        controlRequest(context, "claim", randomOpId(), encodeClaimRequest(maxItems)),
        env as Env,
      );
      expect(response.status).toBe(400);
      expect(response.headers.get(FAILURE_CLASS_HEADER)).toBe("invalidRequest");
    }
  });
});

describe("settlement", () => {
  it("complete deletes claimed items atomically and replays byte-identically", async () => {
    const context = await reserveHandle();
    const packetA = patternBytes(0x33, 16);
    const packetB = patternBytes(0x44, 16);
    // First contact accepts exactly one HTTP submit; seed the second item.
    const submitA = await handler.fetch(submitRequest(context, randomOpId(), packetA), env as Env);
    expect(submitA.status).toBe(202);
    await insertItems(env.RELAY_HANDLES.getByName(context.handleName), [packetB]);

    const claim = await handler.fetch(
      controlRequest(context, "claim", randomOpId(), encodeClaimRequest(64)),
      env as Env,
    );
    const claimed = parseClaimResponse(new Uint8Array(await claim.arrayBuffer()));
    expect(claimed.items).toHaveLength(2);
    const opId = randomOpId();
    const settleBody = encodeSettleRequest(
      claimed.claimId!,
      claimed.epoch!,
      claimed.items.map((item) => ({ itemId: item.itemId, action: 0 })),
    );
    const settle = await handler.fetch(controlRequest(context, "settle", opId, settleBody), env as Env);
    expect(settle.status).toBe(200);
    expect(settle.headers.get(OUTCOME_HEADER)).toBe("accepted");
    const settleBytes = new Uint8Array(await settle.arrayBuffer());
    const settled = parseSettleResponse(settleBytes);
    expect(settled.outcome).toBe(0);
    expect(settled.results.map((r) => r.settleOutcome)).toEqual([0, 0]);

    const relayStub = env.RELAY_HANDLES.getByName(context.handleName);
    expect(await countItems(relayStub)).toBe(0);
    expect((await usageRow(relayStub)).itemCount).toBe(0);
    expect((await usageRow(relayStub)).byteCount).toBe(0);

    const replay = await handler.fetch(controlRequest(context, "settle", opId, settleBody), env as Env);
    expect(replay.status).toBe(200);
    expect(new Uint8Array(await replay.arrayBuffer())).toEqual(settleBytes);

    const changed = await handler.fetch(
      controlRequest(
        context,
        "settle",
        opId,
        encodeSettleRequest(
          claimed.claimId!,
          claimed.epoch!,
          [{ itemId: crypto.getRandomValues(new Uint8Array(32)), action: 0 }],
        ),
      ),
      env as Env,
    );
    expect(changed.status).toBe(409);
    expect(changed.headers.get(FAILURE_CLASS_HEADER)).toBe("conflict");
  });

  it("release returns items to the queue and stale claims report staleClaim", async () => {
    const context = await reserveHandle();
    const packet = patternBytes(0x55, 24);
    const submit = await handler.fetch(submitRequest(context, randomOpId(), packet), env as Env);
    expect(submit.status).toBe(202);

    const claim = await handler.fetch(
      controlRequest(context, "claim", randomOpId(), encodeClaimRequest(64)),
      env as Env,
    );
    const claimed = parseClaimResponse(new Uint8Array(await claim.arrayBuffer()));
    const item = claimed.items[0]!;

    const release = await handler.fetch(
      controlRequest(
        context,
        "settle",
        randomOpId(),
        encodeSettleRequest(claimed.claimId!, claimed.epoch!, [{ itemId: item.itemId, action: 1 }]),
      ),
      env as Env,
    );
    expect(release.status).toBe(200);
    expect(parseSettleResponse(new Uint8Array(await release.arrayBuffer())).results.map((r) => r.settleOutcome)).toEqual([1]);

    // The item is queued again and claimable with a fresh claim.
    const secondClaim = await handler.fetch(
      controlRequest(context, "claim", randomOpId(), encodeClaimRequest(64)),
      env as Env,
    );
    expect(secondClaim.status).toBe(200);
    expect(secondClaim.headers.get(CLAIM_ID_HEADER)).not.toBeNull();
    expect(parseClaimResponse(new Uint8Array(await secondClaim.arrayBuffer())).items).toHaveLength(1);

    // Settling with a wrong (stale) tuple reports staleClaim without mutation.
    const stale = await handler.fetch(
      controlRequest(
        context,
        "settle",
        randomOpId(),
        encodeSettleRequest(crypto.getRandomValues(new Uint8Array(32)), 999, [{ itemId: item.itemId, action: 0 }]),
      ),
      env as Env,
    );
    expect(stale.status).toBe(200);
    expect(parseSettleResponse(new Uint8Array(await stale.arrayBuffer())).results.map((r) => r.settleOutcome)).toEqual([2]);
  });

  it("reports attemptLimit after the settlement attempt bound", async () => {
    const context = await reserveHandle();
    const packet = patternBytes(0x66, 8);
    const submit = await handler.fetch(submitRequest(context, randomOpId(), packet), env as Env);
    expect(submit.status).toBe(202);

    const claim = await handler.fetch(
      controlRequest(context, "claim", randomOpId(), encodeClaimRequest(64)),
      env as Env,
    );
    const claimed = parseClaimResponse(new Uint8Array(await claim.arrayBuffer()));
    const item = claimed.items[0]!;
    const relayStub = env.RELAY_HANDLES.getByName(context.handleName);
    await runInDurableObject(relayStub, (_instance, state) => {
      state.storage.sql.exec(
        "UPDATE items SET settle_attempts = ? WHERE item_id = ?",
        MAX_SETTLEMENT_ATTEMPTS,
        (item.itemId as Uint8Array).slice().buffer as ArrayBuffer,
      );
    });
    const attempt = await handler.fetch(
      controlRequest(
        context,
        "settle",
        randomOpId(),
        encodeSettleRequest(claimed.claimId!, claimed.epoch!, [{ itemId: item.itemId, action: 1 }]),
      ),
      env as Env,
    );
    expect(attempt.status).toBe(200);
    const results = parseSettleResponse(new Uint8Array(await attempt.arrayBuffer())).results;
    expect(results.map((r) => r.settleOutcome)).toEqual([3]);
    // The item is still claimed and present.
    expect(await countItems(relayStub)).toBe(1);
  });

  it("does not settle any item when the replay cache is at capacity", async () => {
    const context = await reserveHandle();
    await handler.fetch(
      submitRequest(context, randomOpId(), patternBytes(0x67, 16)),
      env as Env,
    );
    const claim = await handler.fetch(
      controlRequest(context, "claim", randomOpId(), encodeClaimRequest(1)),
      env as Env,
    );
    const claimed = parseClaimResponse(new Uint8Array(await claim.arrayBuffer()));
    const item = claimed.items[0]!;
    const relayStub = env.RELAY_HANDLES.getByName(context.handleName);

    await runInDurableObject(relayStub, (_instance, state) => {
      const sql = state.storage.sql;
      const current = Number(sql.exec("SELECT COUNT(*) AS n FROM operations").one().n);
      for (let i = current; i < MAX_OPERATION_RECORDS_PER_HANDLE; i += 1) {
        const operationId = new Uint8Array(16);
        operationId[0] = 0xee;
        new DataView(operationId.buffer).setUint32(4, i + 1);
        sql.exec(
          `INSERT INTO operations
             (op_id, request_digest, status, headers, body_length, created_at, expires_at)
           VALUES (?, zeroblob(32), 200, '{}', 3, ?, ?)`,
          operationId.buffer,
          Date.now(),
          Date.now() + 300_000,
        );
        sql.exec(
          "INSERT INTO operation_chunks (op_id, chunk_index, body) VALUES (?, 0, x'a10000')",
          operationId.buffer,
        );
      }
      const totals = sql
        .exec("SELECT COUNT(*) AS n, COALESCE(SUM(body_length), 0) AS bytes FROM operations")
        .one();
      sql.exec(
        `UPDATE usage
            SET operation_count = ?, cached_response_bytes = ?
          WHERE id = 1`,
        Number(totals.n),
        Number(totals.bytes),
      );
    });

    const response = await handler.fetch(
      controlRequest(
        context,
        "settle",
        randomOpId(),
        encodeSettleRequest(claimed.claimId!, claimed.epoch!, [
          { itemId: item.itemId, action: SettleAction.Complete },
        ]),
      ),
      env as Env,
    );
    expect(response.status).toBe(429);
    expect(response.headers.get(FAILURE_CLASS_HEADER)).toBe("capacityUnavailable");
    const state = await runInDurableObject(relayStub, (_instance, durableState) => {
      const row = durableState.storage.sql
        .exec("SELECT claim_id FROM items WHERE item_id = ?", item.itemId.slice().buffer)
        .toArray();
      return { itemCount: row.length, claimed: row[0]?.claim_id !== null };
    });
    expect(state).toEqual({ itemCount: 1, claimed: true });
  });
});

describe("replay windows", () => {
  it("replays never extend operation, storage, or claim windows", async () => {
    const context = await reserveHandle();
    const packet = patternBytes(0x77, 48);
    const submitOpId = randomOpId();
    const submit = await handler.fetch(submitRequest(context, submitOpId, packet), env as Env);
    expect(submit.status).toBe(202);

    const relayStub = env.RELAY_HANDLES.getByName(context.handleName);
    const before = await runInDurableObject(relayStub, (_instance, state) => {
      const op = state.storage.sql
        .exec("SELECT expires_at FROM operations WHERE op_id = ?", fromHexBytes(submitOpId))
        .one();
      const item = state.storage.sql.exec("SELECT expires_at FROM items").one();
      return { opExpires: Number(op.expires_at), itemExpires: Number(item.expires_at) };
    });

    const replay = await handler.fetch(submitRequest(context, submitOpId, packet), env as Env);
    expect(replay.status).toBe(202);
    expect(new Uint8Array(await replay.arrayBuffer())).toEqual(Uint8Array.from([0xa1, 0x00, 0x00]));

    const after = await runInDurableObject(relayStub, (_instance, state) => {
      const op = state.storage.sql
        .exec("SELECT expires_at FROM operations WHERE op_id = ?", fromHexBytes(submitOpId))
        .one();
      const item = state.storage.sql.exec("SELECT expires_at FROM items").one();
      return { opExpires: Number(op.expires_at), itemExpires: Number(item.expires_at) };
    });
    expect(after.opExpires).toBe(before.opExpires);
    expect(after.itemExpires).toBe(before.itemExpires);

    const claimOpId = randomOpId();
    const claim = await handler.fetch(
      controlRequest(context, "claim", claimOpId, encodeClaimRequest(64)),
      env as Env,
    );
    expect(claim.status).toBe(200);
    const claimBefore = await runInDurableObject(relayStub, (_instance, state) => {
      const row = state.storage.sql
        .exec("SELECT claim_expires_at FROM items WHERE claim_id IS NOT NULL")
        .one();
      return Number(row.claim_expires_at);
    });
    const claimReplay = await handler.fetch(
      controlRequest(context, "claim", claimOpId, encodeClaimRequest(64)),
      env as Env,
    );
    expect(claimReplay.status).toBe(200);
    expect(new Uint8Array(await claimReplay.arrayBuffer())).toEqual(new Uint8Array(await claim.arrayBuffer()));
    const claimAfter = await runInDurableObject(relayStub, (_instance, state) => {
      const row = state.storage.sql
        .exec("SELECT claim_expires_at FROM items WHERE claim_id IS NOT NULL")
        .one();
      return Number(row.claim_expires_at);
    });
    expect(claimAfter).toBe(claimBefore);
  });
});

describe("capacity edges", () => {
  it("queue counters never exceed 128 items and 64 MiB", async () => {
    const context = await reserveHandle();
    const relayStub = env.RELAY_HANDLES.getByName(context.handleName);
    // 128 x 512 KiB fills both the item and byte quota exactly.
    const packets = Array.from({ length: MAX_QUEUE_ITEMS_PER_HANDLE }, () => patternBytes(0x88, MAX_PACKET_BYTES));
    await insertItems(relayStub, packets);
    const usage = await usageRow(relayStub);
    expect(usage.itemCount).toBe(MAX_QUEUE_ITEMS_PER_HANDLE);
    expect(usage.byteCount).toBe(MAX_QUEUE_BYTES_PER_HANDLE);

    const denied = await handler.fetch(submitRequest(context, randomOpId(), new Uint8Array([1])), env as Env);
    expect(denied.status).toBe(429);
    expect(denied.headers.get(OUTCOME_HEADER)).toBe("transient");
    expect(denied.headers.get(FAILURE_CLASS_HEADER)).toBe("capacityUnavailable");
    expect(denied.headers.get(RETRY_AFTER_MS_HEADER)).toBe("1000");
    const body = readMap(new Uint8Array(await denied.arrayBuffer()));
    expect(body.map((e) => e.key)).toEqual([0, 1, 2]);
    expect(uintValue(body.find((e) => e.key === 0)!)).toBe(2); // transient
    expect(uintValue(body.find((e) => e.key === 1)!)).toBe(4); // capacityUnavailable
    expect(uintValue(body.find((e) => e.key === 2)!)).toBe(1000);

    expect(await countItems(relayStub)).toBe(MAX_QUEUE_ITEMS_PER_HANDLE);
  });

  it("claims respect the 64-item, 32 MiB, and 32 MiB-response bounds", async () => {
    const context = await reserveHandle();
    const relayStub = env.RELAY_HANDLES.getByName(context.handleName);
    // 64 x 512 KiB: 64 items fit the claim byte bound (exactly 32 MiB) but
    // the encoded response bound cuts the last item, so exactly 63 are claimed.
    const packets = Array.from({ length: 64 }, () => patternBytes(0x99, MAX_PACKET_BYTES));
    await insertItems(relayStub, packets);
    expect((await usageRow(relayStub)).itemCount).toBe(64);

    const claim = await handler.fetch(
      controlRequest(context, "claim", randomOpId(), encodeClaimRequest(MAX_CLAIM_ITEMS)),
      env as Env,
    );
    expect(claim.status).toBe(200);
    expect(claim.headers.get(CLAIM_ID_HEADER)).not.toBeNull();
    const claimed = parseClaimResponse(new Uint8Array(await claim.arrayBuffer()));
    expect(claimed.items).toHaveLength(63);
    expect(claimed.epoch).toBe(1);
    let packetBytes = 0;
    for (const item of claimed.items) packetBytes += item.packet.length;
    expect(packetBytes).toBeLessThanOrEqual(MAX_CLAIM_BYTES);
    expect(packetBytes).toBeLessThanOrEqual(MAX_CLAIM_RESPONSE_BYTES);

    const claimedCount = await runInDurableObject(relayStub, (_instance, state) => {
      const row = state.storage.sql
        .exec("SELECT COUNT(*) AS n FROM items WHERE claim_id IS NOT NULL")
        .one();
      return Number(row.n);
    });
    expect(claimedCount).toBe(63);
    expect(await countItems(relayStub)).toBe(64);
  });

  it("replays a multi-chunk claim response byte-identically", async () => {
    const context = await reserveHandle();
    const relayStub = env.RELAY_HANDLES.getByName(context.handleName);
    await insertItems(
      relayStub,
      Array.from({ length: 5 }, () => patternBytes(0x9a, MAX_PACKET_BYTES)),
    );
    const operationId = randomOpId();
    const request = controlRequest(
      context,
      "claim",
      operationId,
      encodeClaimRequest(MAX_CLAIM_ITEMS),
    );
    const first = await handler.fetch(request, env as Env);
    const firstBody = new Uint8Array(await first.arrayBuffer());
    expect(firstBody.length).toBeGreaterThan(2_190_000);

    const replay = await handler.fetch(
      controlRequest(context, "claim", operationId, encodeClaimRequest(MAX_CLAIM_ITEMS)),
      env as Env,
    );
    expect(replay.status).toBe(first.status);
    expect(new Uint8Array(await replay.arrayBuffer())).toEqual(firstBody);
    const replayState = await runInDurableObject(relayStub, (_instance, state) => {
      const chunks = state.storage.sql
        .exec(
          `SELECT COUNT(*) AS n
             FROM operation_chunks
            WHERE op_id = ?`,
          fromHexBytes(operationId).buffer,
        )
        .one();
      const manifests = state.storage.sql
        .exec(
          "SELECT COUNT(*) AS n FROM operation_manifests WHERE op_id = ?",
          fromHexBytes(operationId).buffer,
        )
        .one();
      const refs = state.storage.sql
        .exec(
          "SELECT COUNT(*) AS n FROM operation_item_refs WHERE op_id = ?",
          fromHexBytes(operationId).buffer,
        )
        .one();
      return {
        chunks: Number(chunks.n),
        manifests: Number(manifests.n),
        refs: Number(refs.n),
      };
    });
    expect(replayState).toEqual({ chunks: 0, manifests: 1, refs: 5 });
  }, 15_000);
});

describe("expiry cleanup", () => {
  it("alarm releases expired claims and deletes expired items in bounded batches", async () => {
    const context = await reserveHandle();
    const relayStub = env.RELAY_HANDLES.getByName(context.handleName);
    const submit = await handler.fetch(submitRequest(context, randomOpId(), patternBytes(0xaa, 8)), env as Env);
    expect(submit.status).toBe(202);

    // 127 more items (future expiry so the claim below keeps them queued):
    // 128 due rows after forcing, above the 64-row batch.
    await insertItems(
      relayStub,
      Array.from({ length: 127 }, () => patternBytes(0xbb, 4)),
    );
    // Claim one item so an expired claim release is also due.
    const claim = await handler.fetch(
      controlRequest(context, "claim", randomOpId(), encodeClaimRequest(1)),
      env as Env,
    );
    expect(claim.status).toBe(200);
    const claimed = parseClaimResponse(new Uint8Array(await claim.arrayBuffer()));
    expect(claimed.items).toHaveLength(1);
    await runInDurableObject(relayStub, (_instance, state) => {
      state.storage.sql.exec("UPDATE items SET claim_expires_at = ?", Date.now() - 1000);
      state.storage.sql.exec("UPDATE items SET expires_at = ?", Date.now() - 1000);
    });

    const firstRun = await runDurableObjectAlarm(relayStub);
    expect(firstRun).toBe(true);
    expect(await countItems(relayStub)).toBe(128 - CLEANUP_BATCH_ROWS);

    const secondRun = await runDurableObjectAlarm(relayStub);
    expect(secondRun).toBe(true);
    expect(await countItems(relayStub)).toBe(0);
    const usage = await usageRow(relayStub);
    expect(usage.itemCount).toBe(0);
    expect(usage.byteCount).toBe(0);
  });

  it("alarm wipes a fully expired handle", async () => {
    const context = await reserveHandle();
    const relayStub = env.RELAY_HANDLES.getByName(context.handleName);
    const submit = await handler.fetch(submitRequest(context, randomOpId(), patternBytes(0xcc, 8)), env as Env);
    expect(submit.status).toBe(202);
    await runInDurableObject(relayStub, (_instance, state) => {
      state.storage.sql.exec("UPDATE metadata SET expires_at = ?", Date.now() - 1000);
    });
    expect(await runDurableObjectAlarm(relayStub)).toBe(true);
    const afterDataBatch = await runInDurableObject(relayStub, (_instance, state) => {
      const sql = state.storage.sql;
      const items = sql.exec("SELECT COUNT(*) AS n FROM items").one();
      const operations = sql.exec("SELECT COUNT(*) AS n FROM operations").one();
      const usage = sql.exec("SELECT COUNT(*) AS n FROM usage").one();
      const metadata = sql.exec("SELECT COUNT(*) AS n FROM metadata").one();
      return {
        items: Number(items.n),
        operations: Number(operations.n),
        usage: Number(usage.n),
        metadata: Number(metadata.n),
      };
    });
    expect(afterDataBatch).toEqual({ items: 0, operations: 0, usage: 1, metadata: 1 });
    await runInDurableObject(relayStub, (_instance, state) =>
      state.storage.setAlarm(Date.now() + 60_000),
    );
    expect(await runDurableObjectAlarm(relayStub)).toBe(true);
    const leftover = await runInDurableObject(relayStub, (_instance, state) => ({
      usage: Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM usage").one().n),
      metadata: Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM metadata").one().n),
    }));
    expect(leftover).toEqual({ usage: 0, metadata: 0 });
  });
});

function fromHexBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function fromBase64Url(encoded: string): Uint8Array {
  // Base64url decoder without padding for 32-byte values.
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const lookup = new Map<string, number>();
  for (let i = 0; i < alphabet.length; i += 1) lookup.set(alphabet[i]!, i);
  const bytes: number[] = [];
  for (let i = 0; i < encoded.length; i += 4) {
    const c0 = lookup.get(encoded[i]!);
    const c1 = lookup.get(encoded[i + 1]!);
    if (c0 === undefined || c1 === undefined) throw new Error("bad base64url");
    bytes.push((c0 << 2) | (c1 >> 4));
    const c2 = encoded[i + 2];
    if (c2 !== undefined) {
      const v2 = lookup.get(c2);
      if (v2 === undefined) throw new Error("bad base64url");
      bytes.push(((c1 & 15) << 4) | (v2 >> 2));
      const c3 = encoded[i + 3];
      if (c3 !== undefined) {
        const v3 = lookup.get(c3);
        if (v3 === undefined) throw new Error("bad base64url");
        bytes.push(((v2 & 3) << 6) | v3);
      }
    }
  }
  return Uint8Array.from(bytes);
}

void encodeAffiliateRequest;
