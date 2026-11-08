import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import dataHandler from "../src/data-entry";
import { CONTROL_MEDIA_TYPE, HandleClass, MAX_CLAIM_ITEMS, MAX_PACKET_BYTES, OPERATION_ID_HEADER, PROTECTED_PACKET_MEDIA_TYPE } from "../src/transport/candidate";
import { STREAM_ALLOCATION_LIMIT_BYTES } from "../src/durable/relay-handle";
import type { RpcResponse } from "../src/durable/rpc";
import { bytesValue, encodeClaimRequest, encodeReserveRequest, generateAccessGrant, opRequest, randomOpId, readMap, toBase64Url, VALID_CF } from "./helpers";

interface RelayStub extends DurableObjectStub {
  initialize(handle: Uint8Array, args: { handleClass: HandleClass }): Promise<{ ok: boolean }>;
  claim(opId: Uint8Array, digest: Uint8Array, maxItems: number): Promise<RpcResponse>;
}

async function seededRelay(packetCount: number): Promise<RelayStub> {
  const handle = crypto.getRandomValues(new Uint8Array(32));
  const stub = env.RELAY_HANDLES.getByName(crypto.randomUUID()) as unknown as RelayStub;
  expect(await stub.initialize(handle, { handleClass: HandleClass.FirstContact })).toEqual({ ok: true });
  await runInDurableObject(stub, (_instance, state) => {
    const now = Date.now();
    for (let index = 0; index < packetCount; index += 1) {
      const packet = new Uint8Array(MAX_PACKET_BYTES);
      packet.fill(index + 1);
      state.storage.sql.exec(
        `INSERT INTO items
           (item_id, packet, byte_len, accepted_at, expires_at, queue_seq)
         VALUES (?, ?, ?, ?, ?, ?)`,
        crypto.getRandomValues(new Uint8Array(32)).buffer,
        packet.buffer,
        packet.length,
        now,
        now + 3_600_000,
        index + 1,
      );
    }
    state.storage.sql.exec(
      "UPDATE usage SET item_count = ?, byte_count = ?, next_queue_seq = ? WHERE id = 1",
      packetCount,
      packetCount * MAX_PACKET_BYTES,
      packetCount,
    );
  });
  return stub;
}

async function readChunks(body: ReadableStream<Uint8Array>): Promise<Uint8Array[]> {
  const chunks: Uint8Array[] = [];
  const reader = body.getReader();
  for (;;) {
    const next = await reader.read();
    if (next.done) return chunks;
    chunks.push(next.value);
  }
}

describe("manifest-backed relay streaming", () => {
  it("streams a maximum queue incrementally within the structural allocation watermark", async () => {
    const stub = await seededRelay(MAX_CLAIM_ITEMS);
    const result = await stub.claim(
      crypto.getRandomValues(new Uint8Array(16)),
      crypto.getRandomValues(new Uint8Array(32)),
      MAX_CLAIM_ITEMS,
    );
    const reader = (result.body as ReadableStream<Uint8Array>).getReader();
    const first = await reader.read();
    expect(first.done).toBe(false);
    expect(first.value!.length).toBeLessThan(256);
    let total = first.value!.length;
    let largest = first.value!.length;
    for (;;) {
      await Promise.resolve();
      const next = await reader.read();
      if (next.done) break;
      total += next.value.length;
      largest = Math.max(largest, next.value.length);
    }
    expect(total).toBeGreaterThan(31 * 1024 * 1024);
    expect(largest).toBeLessThanOrEqual(64 * 1024);
    const highWater = await runInDurableObject(stub, (instance) =>
      (instance as unknown as { streamAllocationHighWaterBytes: number }).streamAllocationHighWaterBytes,
    );
    expect(highWater).toBeGreaterThan(MAX_PACKET_BYTES);
    expect(highWater).toBeLessThanOrEqual(STREAM_ALLOCATION_LIMIT_BYTES);
  }, 15_000);

  it("emits an encoder prefix first and never emits a chunk above 64 KiB", async () => {
    const stub = await seededRelay(2);
    const opId = crypto.getRandomValues(new Uint8Array(16));
    const digest = crypto.getRandomValues(new Uint8Array(32));
    const result = await stub.claim(opId, digest, 2);
    expect(result.body).toBeInstanceOf(ReadableStream);
    const chunks = await readChunks(result.body as ReadableStream<Uint8Array>);
    expect(chunks.length).toBeGreaterThan(2);
    expect(chunks[0]!.length).toBeLessThan(256);
    expect(Math.max(...chunks.map((chunk) => chunk.length))).toBeLessThanOrEqual(64 * 1024);

    const persisted = await runInDurableObject(stub, (_instance, state) => ({
      chunks: Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM operation_chunks").one().n),
      manifests: Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM operation_manifests").one().n),
      refs: Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM operation_item_refs").one().n),
    }));
    expect(persisted).toEqual({ chunks: 0, manifests: 1, refs: 2 });
  });

  it("reconstructs an identical byte stream from packet references", async () => {
    const stub = await seededRelay(2);
    const opId = crypto.getRandomValues(new Uint8Array(16));
    const digest = crypto.getRandomValues(new Uint8Array(32));
    const first = await stub.claim(opId, digest, 2);
    const replay = await stub.claim(opId, digest, 2);
    const firstChunks = await readChunks(first.body as ReadableStream<Uint8Array>);
    const replayChunks = await readChunks(replay.body as ReadableStream<Uint8Array>);
    expect(replayChunks).toEqual(firstChunks);
  });

  it("holds per-grant concurrency leases until entrypoint streams end", async () => {
    const access = await generateAccessGrant();
    const handles: string[] = [];
    for (let index = 0; index < 9; index += 1) {
      const reserved = await dataHandler.fetch(
        opRequest("/v1/reserve", {
          token: access.token,
          headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: randomOpId() },
          body: encodeReserveRequest(
            crypto.getRandomValues(new Uint8Array(32)),
            crypto.getRandomValues(new Uint8Array(32)),
            crypto.getRandomValues(new Uint8Array(32)),
            HandleClass.FirstContact,
          ),
          cf: VALID_CF,
        }),
        env,
      );
      expect(reserved.status).toBe(201);
      const reserveMap = readMap(new Uint8Array(await reserved.arrayBuffer()));
      const handle = toBase64Url(bytesValue(reserveMap.find((entry) => entry.key === 1)!));
      handles.push(handle);
      const submitted = await dataHandler.fetch(
        opRequest(`/v1/handles/${handle}/submit`, {
          token: access.token,
          headers: { "content-type": PROTECTED_PACKET_MEDIA_TYPE, [OPERATION_ID_HEADER]: randomOpId() },
          body: Uint8Array.of(index + 1),
          cf: VALID_CF,
        }),
        env,
      );
      expect(submitted.status).toBe(202);
    }

    const held: Response[] = [];
    try {
      for (const handle of handles.slice(0, 8)) {
        const response = await dataHandler.fetch(
          opRequest(`/v1/handles/${handle}/claim`, {
            token: access.token,
            headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: randomOpId() },
            body: encodeClaimRequest(1),
            cf: VALID_CF,
          }),
          env,
        );
        expect(response.status).toBe(200);
        held.push(response);
      }
      const denied = await dataHandler.fetch(
        opRequest(`/v1/handles/${handles[8]}/claim`, {
          token: access.token,
          headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: randomOpId() },
          body: encodeClaimRequest(1),
          cf: VALID_CF,
        }),
        env,
      );
      expect(denied.status).toBe(401);

      await held[0]!.body!.cancel();
      held.shift();
      const admitted = await dataHandler.fetch(
        opRequest(`/v1/handles/${handles[8]}/claim`, {
          token: access.token,
          headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: randomOpId() },
          body: encodeClaimRequest(1),
          cf: VALID_CF,
        }),
        env,
      );
      expect(admitted.status).toBe(200);
      expect((await admitted.arrayBuffer()).byteLength).toBeGreaterThan(0);
    } finally {
      await Promise.all(held.map((response) => response.body?.cancel().catch(() => undefined)));
    }
    const leaseCount = await runInDurableObject(
      env.ACCESS_GRANTS.getByName(access.selector),
      async (_instance, state) => {
        const grant = await state.storage.get<{ leases: unknown[] }>("grant");
        return grant?.leases.length ?? 0;
      },
    );
    expect(leaseCount).toBe(0);
  });
});
