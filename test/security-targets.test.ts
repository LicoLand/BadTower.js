import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import dataHandler from "../src/data-entry";
import { toBase64Url } from "../src/encoding";
import {
  MAX_HANDLE_KEY_SLOTS,
  RELAY_HANDLE_BYTES,
  RELAY_HANDLE_RANDOM_BYTES,
  RELAY_HANDLE_TAG_BYTES,
  RELAY_HANDLE_VERSION,
  createRelayHandle,
  parseHandleKeyRing,
  verifyRelayHandle,
} from "../src/transport/handle";
import { CONTROL_MEDIA_TYPE, OPERATION_ID_HEADER } from "../src/transport/candidate";
import { encodeClaimRequest, generateAccessGrant, opRequest, randomOpId, VALID_CF } from "./helpers";

const NOW = 2_000_000_000_000;
const key = (fill: number): string => toBase64Url(new Uint8Array(32).fill(fill));
const json = (slots: unknown[]): string => JSON.stringify(slots);

describe("authenticated relay handles", () => {
  it("uses the exact version, slot, random and tag layout", async () => {
    const ring = parseHandleKeyRing(
      json([{ id: 7, key: key(0x41), notAfter: null }]),
      "7",
    );
    expect(ring).not.toBeNull();
    const handle = await createRelayHandle(ring!, NOW);
    expect(handle).not.toBeNull();
    expect(handle).toHaveLength(RELAY_HANDLE_BYTES);
    expect(handle![0]).toBe(RELAY_HANDLE_VERSION);
    expect(handle![1]).toBe(7);
    expect(RELAY_HANDLE_RANDOM_BYTES).toBeGreaterThanOrEqual(15);
    expect(2 + RELAY_HANDLE_RANDOM_BYTES + RELAY_HANDLE_TAG_BYTES).toBe(RELAY_HANDLE_BYTES);
    expect(await verifyRelayHandle(handle!, ring!, NOW)).toBe(true);
  });

  it("rejects every single-bit mutation", async () => {
    const ring = parseHandleKeyRing(
      json([{ id: 2, key: key(0x22), notAfter: null }]),
      "2",
    )!;
    const handle = (await createRelayHandle(ring, NOW))!;
    for (let byte = 0; byte < handle.length; byte += 1) {
      for (let bit = 0; bit < 8; bit += 1) {
        const mutated = handle.slice();
        mutated[byte]! ^= 1 << bit;
        expect(await verifyRelayHandle(mutated, ring, NOW)).toBe(false);
      }
    }
  });

  it("accepts a live prior slot and rejects it at its exclusive deadline", async () => {
    const oldRing = parseHandleKeyRing(
      json([{ id: 3, key: key(0x33), notAfter: null }]),
      "3",
    )!;
    const oldHandle = (await createRelayHandle(oldRing, NOW))!;
    const rotated = parseHandleKeyRing(
      json([
        { id: 4, key: key(0x44), notAfter: null },
        { id: 3, key: key(0x33), notAfter: NOW + 1_000 },
      ]),
      "4",
    )!;
    expect(await verifyRelayHandle(oldHandle, rotated, NOW + 999)).toBe(true);
    expect(await verifyRelayHandle(oldHandle, rotated, NOW + 1_000)).toBe(false);
  });

  it("rejects malformed, unknown-slot and wrong-key handles", async () => {
    const issuer = parseHandleKeyRing(
      json([{ id: 8, key: key(0x18), notAfter: null }]),
      "8",
    )!;
    const handle = (await createRelayHandle(issuer, NOW))!;
    const unknown = parseHandleKeyRing(
      json([{ id: 9, key: key(0x18), notAfter: null }]),
      "9",
    )!;
    const wrongKey = parseHandleKeyRing(
      json([{ id: 8, key: key(0x19), notAfter: null }]),
      "8",
    )!;
    expect(await verifyRelayHandle(handle.subarray(1), issuer, NOW)).toBe(false);
    expect(await verifyRelayHandle(handle, unknown, NOW)).toBe(false);
    expect(await verifyRelayHandle(handle, wrongKey, NOW)).toBe(false);
  });

  it("parses only the closed bounded rotation schema", async () => {
    const valid = [{ id: 0, key: key(1), notAfter: null }];
    expect(parseHandleKeyRing(json(valid), "0")).not.toBeNull();
    expect(parseHandleKeyRing(json(valid), "00")).toBeNull();
    expect(parseHandleKeyRing(json(valid), "256")).toBeNull();
    expect(parseHandleKeyRing(json([{ ...valid[0], extra: true }]), "0")).toBeNull();
    const boundedCurrent = parseHandleKeyRing(
      json([{ id: 0, key: key(1), notAfter: NOW }]),
      "0",
    );
    expect(boundedCurrent).not.toBeNull();
    await expect(createRelayHandle(boundedCurrent!, NOW)).resolves.toBeNull();
    expect(
      parseHandleKeyRing(
        json([
          ...valid,
          { id: 1, key: key(2), notAfter: null },
        ]),
        "0",
      ),
    ).toBeNull();
    expect(parseHandleKeyRing(json([{ id: 0, key: `${"A".repeat(42)}=`, notAfter: null }]), "0")).toBeNull();
    expect(parseHandleKeyRing(json([...valid, ...valid]), "0")).toBeNull();
    expect(
      parseHandleKeyRing(
        json(Array.from({ length: MAX_HANDLE_KEY_SLOTS + 1 }, (_, id) => ({ id, key: key(id), notAfter: id === 0 ? null : NOW }))),
        "0",
      ),
    ).toBeNull();
  });

  it("releases an authorized concurrency lease when target authentication fails", async () => {
    const access = await generateAccessGrant();
    const invalidHandle = toBase64Url(new Uint8Array(RELAY_HANDLE_BYTES));
    const edgeKeys: string[] = [];
    const clientKeys: string[] = [];
    const trapped = new Proxy(env, {
      get(target, property, receiver) {
        if (property === "RELAY_HANDLES") throw new Error("relay namespace selected");
        if (property === "EDGE_ADMISSION_RATE_LIMITER") {
          return { limit: async ({ key: rateKey }: { key: string }) => {
            edgeKeys.push(rateKey);
            return { success: true };
          } };
        }
        if (property === "CLIENT_RATE_LIMITER") {
          return { limit: async ({ key: rateKey }: { key: string }) => {
            clientKeys.push(rateKey);
            return { success: true };
          } };
        }
        return Reflect.get(target, property, receiver);
      },
    });
    const response = await dataHandler.fetch(
      opRequest(`/v1/handles/${invalidHandle}/claim`, {
        token: access.token,
        headers: {
          "content-type": CONTROL_MEDIA_TYPE,
          [OPERATION_ID_HEADER]: randomOpId(),
        },
        body: encodeClaimRequest(1),
        cf: VALID_CF,
      }),
      trapped,
    );
    expect(response.status).toBe(404);
    expect(edgeKeys).toEqual([`${access.selector}:CLAIM`]);
    expect(clientKeys).toEqual([`${access.selector}:CLAIM`]);
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
