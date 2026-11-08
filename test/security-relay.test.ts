import { env } from "cloudflare:workers";
import { abortAllDurableObjects, evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { decodeBase64Url } from "../src/encoding";
import { CLEANUP_BATCH_ROWS, HandleClass, SettleAction } from "../src/transport/candidate";
import type { RpcResponse } from "../src/durable/rpc";
import type { Settlement } from "../src/transport/codec";

interface RelayStub extends DurableObjectStub {
  initialize(handle: Uint8Array, args: { handleClass: HandleClass }): Promise<{ ok: boolean }>;
  claim(opId: Uint8Array, digest: Uint8Array, maxItems: number): Promise<RpcResponse>;
  settle(
    opId: Uint8Array,
    digest: Uint8Array,
    claimId: Uint8Array,
    claimEpoch: number,
    settlements: Settlement[],
  ): Promise<RpcResponse>;
}

describe("relay stream cancellation", () => {
  it("serializes same-operation replay and distinct concurrent claims", async () => {
    const stub = env.RELAY_HANDLES.getByName(crypto.randomUUID()) as unknown as RelayStub;
    expect(await stub.initialize(crypto.getRandomValues(new Uint8Array(32)), {
      handleClass: HandleClass.FirstContact,
    })).toEqual({ ok: true });
    await runInDurableObject(stub, (_instance, state) => {
      const now = Date.now();
      for (let index = 0; index < 3; index += 1) {
        const itemId = new Uint8Array(32);
        new DataView(itemId.buffer).setUint32(28, index);
        state.storage.sql.exec(
          `INSERT INTO items
             (item_id, packet, byte_len, accepted_at, expires_at, queue_seq)
           VALUES (?, ?, 1, ?, ?, ?)`,
          itemId.buffer,
          Uint8Array.of(index + 1).buffer,
          now,
          now + 3_600_000,
          index + 1,
        );
      }
      state.storage.sql.exec(
        "UPDATE usage SET item_count = 3, byte_count = 3, next_queue_seq = 3 WHERE id = 1",
      );
    });
    const sameOpId = crypto.getRandomValues(new Uint8Array(16));
    const sameDigest = crypto.getRandomValues(new Uint8Array(32));
    const [sameA, sameB] = await Promise.all([
      stub.claim(sameOpId, sameDigest, 1),
      stub.claim(sameOpId, sameDigest, 1),
    ]);
    const [sameABytes, sameBBytes] = await Promise.all([
      new Response(sameA.body).arrayBuffer(),
      new Response(sameB.body).arrayBuffer(),
    ]);
    expect(new Uint8Array(sameBBytes)).toEqual(new Uint8Array(sameABytes));

    const distinct = await stub.claim(
      crypto.getRandomValues(new Uint8Array(16)),
      crypto.getRandomValues(new Uint8Array(32)),
      1,
    );
    await new Response(distinct.body).arrayBuffer();
    const ownership = await runInDurableObject(stub, (_instance, state) => ({
      claimedItems: Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM items WHERE claim_id IS NOT NULL").one().n),
      owners: Number(state.storage.sql.exec("SELECT COUNT(DISTINCT hex(claim_id)) AS n FROM items WHERE claim_id IS NOT NULL").one().n),
      manifests: Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM operation_manifests").one().n),
      refs: Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM operation_item_refs").one().n),
    }));
    expect(ownership).toEqual({ claimedItems: 2, owners: 2, manifests: 2, refs: 2 });
  });

  it("reconstructs a committed stream byte-identically after abrupt isolate restart", async () => {
    const name = crypto.randomUUID();
    const stub = env.RELAY_HANDLES.getByName(name) as unknown as RelayStub;
    expect(await stub.initialize(crypto.getRandomValues(new Uint8Array(32)), {
      handleClass: HandleClass.FirstContact,
    })).toEqual({ ok: true });
    await runInDurableObject(stub, (_instance, state) => {
      const now = Date.now();
      const itemId = crypto.getRandomValues(new Uint8Array(32));
      const packet = crypto.getRandomValues(new Uint8Array(128));
      state.storage.sql.exec(
        `INSERT INTO items
           (item_id, packet, byte_len, accepted_at, expires_at, queue_seq)
         VALUES (?, ?, ?, ?, ?, 1)`,
        itemId.buffer,
        packet.buffer,
        packet.length,
        now,
        now + 3_600_000,
      );
      state.storage.sql.exec(
        "UPDATE usage SET item_count = 1, byte_count = ?, next_queue_seq = 1 WHERE id = 1",
        packet.length,
      );
    });
    const opId = crypto.getRandomValues(new Uint8Array(16));
    const digest = crypto.getRandomValues(new Uint8Array(32));
    const interrupted = await stub.claim(opId, digest, 1);
    const interruptedReader = (interrupted.body as ReadableStream<Uint8Array>).getReader();
    const prefix = await interruptedReader.read();
    expect(prefix.done).toBe(false);
    await abortAllDurableObjects();
    await interruptedReader.cancel().catch(() => undefined);

    const replayStub = env.RELAY_HANDLES.getByName(name) as unknown as RelayStub;
    const replay = await replayStub.claim(opId, digest, 1);
    const replayBytes = new Uint8Array(await new Response(replay.body).arrayBuffer());
    expect(replayBytes.slice(0, prefix.value!.length)).toEqual(prefix.value);
    await evictDurableObject(replayStub);
    const restartedStub = env.RELAY_HANDLES.getByName(name) as unknown as RelayStub;
    const restartedReplay = await restartedStub.claim(opId, digest, 1);
    expect(new Uint8Array(await new Response(restartedReplay.body).arrayBuffer())).toEqual(replayBytes);
    const state = await runInDurableObject(restartedStub, (_instance, durableState) => ({
      claimed: Number(durableState.storage.sql.exec("SELECT COUNT(*) AS n FROM items WHERE claim_id IS NOT NULL").one().n),
      manifests: Number(durableState.storage.sql.exec("SELECT COUNT(*) AS n FROM operation_manifests").one().n),
    }));
    expect(state).toEqual({ claimed: 1, manifests: 1 });
  });

  it("continues bounded alarm cleanup exactly after isolate eviction", async () => {
    const name = crypto.randomUUID();
    const stub = env.RELAY_HANDLES.getByName(name) as unknown as RelayStub;
    expect(await stub.initialize(crypto.getRandomValues(new Uint8Array(32)), {
      handleClass: HandleClass.FirstContact,
    })).toEqual({ ok: true });
    await runInDurableObject(stub, async (_instance, state) => {
      const now = Date.now();
      for (let index = 0; index < CLEANUP_BATCH_ROWS + 1; index += 1) {
        const itemId = new Uint8Array(32);
        new DataView(itemId.buffer).setUint32(28, index);
        state.storage.sql.exec(
          `INSERT INTO items
             (item_id, packet, byte_len, accepted_at, expires_at, queue_seq)
           VALUES (?, x'01', 1, ?, ?, ?)`,
          itemId.buffer,
          now - 1_000,
          now - 1,
          index + 1,
        );
      }
      state.storage.sql.exec(
        "UPDATE usage SET item_count = ?, byte_count = ?, next_queue_seq = ? WHERE id = 1",
        CLEANUP_BATCH_ROWS + 1,
        CLEANUP_BATCH_ROWS + 1,
        CLEANUP_BATCH_ROWS + 1,
      );
      await state.storage.setAlarm(now + 60_000);
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    const afterFirst = await runInDurableObject(stub, async (_instance, state) => {
      const items = Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM items").one().n);
      await state.storage.setAlarm(Date.now() + 60_000);
      return items;
    });
    expect(afterFirst).toBe(1);
    await evictDurableObject(stub);
    const restartedStub = env.RELAY_HANDLES.getByName(name) as unknown as RelayStub;
    expect(await runDurableObjectAlarm(restartedStub)).toBe(true);
    const usage = await runInDurableObject(restartedStub, (_instance, state) => ({
      items: Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM items").one().n),
      itemCount: Number(state.storage.sql.exec("SELECT item_count AS n FROM usage WHERE id = 1").one().n),
      byteCount: Number(state.storage.sql.exec("SELECT byte_count AS n FROM usage WHERE id = 1").one().n),
    }));
    expect(usage).toEqual({ items: 0, itemCount: 0, byteCount: 0 });
  });

  it("keeps committed ownership exclusive after output cancellation", async () => {
    const stub = env.RELAY_HANDLES.getByName(crypto.randomUUID()) as unknown as RelayStub;
    expect(await stub.initialize(crypto.getRandomValues(new Uint8Array(32)), {
      handleClass: HandleClass.FirstContact,
    })).toEqual({ ok: true });
    await runInDurableObject(stub, (_instance, state) => {
      const now = Date.now();
      state.storage.sql.exec(
        `INSERT INTO items
           (item_id, packet, byte_len, accepted_at, expires_at, queue_seq)
         VALUES (?, ?, 3, ?, ?, 1)`,
        crypto.getRandomValues(new Uint8Array(32)).buffer,
        Uint8Array.of(1, 2, 3).buffer,
        now,
        now + 3_600_000,
      );
      state.storage.sql.exec(
        "UPDATE usage SET item_count = 1, byte_count = 3, next_queue_seq = 1 WHERE id = 1",
      );
    });

    const claimOpId = crypto.getRandomValues(new Uint8Array(16));
    const claimDigest = crypto.getRandomValues(new Uint8Array(32));
    const first = await stub.claim(claimOpId, claimDigest, 1);
    const reader = (first.body as ReadableStream<Uint8Array>).getReader();
    expect((await reader.read()).done).toBe(false);
    await reader.cancel();

    const second = await stub.claim(
      crypto.getRandomValues(new Uint8Array(16)),
      crypto.getRandomValues(new Uint8Array(32)),
      1,
    );
    expect(second.body).toBeInstanceOf(Uint8Array);
    expect(Array.from(second.body as Uint8Array)).toEqual([0xa1, 0x00, 0x00]);
    const ownership = await runInDurableObject(stub, (_instance, state) => ({
      claimed: Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM items WHERE claim_id IS NOT NULL").one().n),
      manifests: Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM operation_manifests").one().n),
    }));
    expect(ownership).toEqual({ claimed: 1, manifests: 1 });

    const claimId = decodeBase64Url(first.headers["licoarc-claim-id"]!)!;
    const claimEpoch = Number(first.headers["licoarc-claim-epoch"]);
    const itemId = await runInDurableObject(stub, (_instance, state) =>
      new Uint8Array(state.storage.sql.exec("SELECT item_id FROM items").one().item_id as ArrayBuffer),
    );
    await stub.settle(
      crypto.getRandomValues(new Uint8Array(16)),
      crypto.getRandomValues(new Uint8Array(32)),
      claimId,
      claimEpoch,
      [{ itemId, action: SettleAction.Complete }],
    );
    const retained = await runInDurableObject(stub, (_instance, state) => ({
      active: Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM items").one().n),
      retained: Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM retained_packets").one().n),
    }));
    expect(retained).toEqual({ active: 0, retained: 1 });

    const replay = await stub.claim(claimOpId, claimDigest, 1);
    const replayBytes = new Uint8Array(await new Response(replay.body).arrayBuffer());
    expect(Array.from(replayBytes.slice(-3))).toEqual([1, 2, 3]);
  });
});
