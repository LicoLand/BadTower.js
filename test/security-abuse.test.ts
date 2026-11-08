import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";
import { randomBytes, sha256 } from "../src/access/token";
import { toBase64Url } from "../src/encoding";
import type { GrantChargeResult } from "../src/durable/access-grant";

async function activeGrant(now: number) {
  const selector = toBase64Url(randomBytes(16));
  const grant = env.ACCESS_GRANTS.getByName(selector);
  const invitationDigest = await sha256(randomBytes(32));
  const publicKey = randomBytes(32);
  expect(await grant.initialize(invitationDigest, now + 3_600_000, 3_600_000)).toBe(true);
  const exchange = await grant.exchange(invitationDigest, publicKey);
  expect(exchange).toMatchObject({ ok: true, epoch: 1 });
  return { grant, publicKey, epoch: exchange.epoch!, now };
}

function charge(fixture: Awaited<ReturnType<typeof activeGrant>>, counter: number, overrides: Record<string, number> = {}): Promise<GrantChargeResult> {
  return fixture.grant.authorizeAndCharge({
    epoch: fixture.epoch,
    publicKey: fixture.publicKey,
    counter: String(counter),
    requestCost: overrides.requestCost ?? 1,
    byteCost: overrides.byteCost ?? 1,
    operationWeight: overrides.operationWeight ?? 1,
    creationCost: overrides.creationCost ?? 0,
    concurrencyCost: (overrides.concurrencyCost ?? 0) as 0 | 1,
    leaseTtlMs: overrides.leaseTtlMs ?? 0,
  });
}

describe("atomic grant replay and budgets", () => {
  it("consumes a concurrent counter once and admits bounded reordering", async () => {
    const fixture = await activeGrant(Date.now());
    const duplicate = await Promise.all(Array.from({ length: 12 }, () => charge(fixture, 40)));
    expect(duplicate.filter((result) => result.ok)).toHaveLength(1);
    expect((await charge(fixture, 42)).ok).toBe(true);
    expect((await charge(fixture, 41)).ok).toBe(true);
    expect((await charge(fixture, 41)).ok).toBe(false);
    expect((await charge(fixture, 200)).ok).toBe(true);
    expect((await charge(fixture, 1)).ok).toBe(false);
  });

  it("never regresses bucket time or authorizes after local expiry", async () => {
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    try {
      const fixture = await activeGrant(now);
      expect((await charge(fixture, 1, { byteCost: 16 * 1024 * 1024 })).ok).toBe(true);
      clock.mockReturnValue(now + 3_000);
      expect((await charge(fixture, 3, { byteCost: 3 * 1024 * 1024 })).ok).toBe(true);
      clock.mockReturnValue(now + 2_000);
      expect((await charge(fixture, 2, { byteCost: 0 })).ok).toBe(true);
      clock.mockReturnValue(now + 3_000);
      expect((await charge(fixture, 4, { byteCost: 1 })).ok).toBe(false);

      const updatedAt = await runInDurableObject(fixture.grant, async (_instance, state) => {
        const stored = await state.storage.get<{ byteBucket: { updatedAt: number } }>("grant");
        return stored?.byteBucket.updatedAt;
      });
      expect(updatedAt).toBe(now + 3_000);

      clock.mockReturnValue(now + 3_600_000);
      expect((await charge(fixture, 5, { byteCost: 0 })).ok).toBe(false);
      expect(await runInDurableObject(fixture.grant, (_instance, state) =>
        state.storage.get("grant"),
      )).toBeUndefined();
    } finally {
      clock.mockRestore();
    }
  });

  it("enforces creation, byte, and concurrency ceilings without cross-grant contention", async () => {
    const now = Date.now();
    const first = await activeGrant(now);
    const second = await activeGrant(now);
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    try {
      expect((await charge(first, 1, { creationCost: 32 })).ok).toBe(true);
      expect((await charge(first, 2, { creationCost: 1 })).ok).toBe(false);
      expect((await charge(second, 1, { creationCost: 1 })).ok).toBe(true);
      expect((await charge(first, 3, { byteCost: 16 * 1024 * 1024 - 1 })).ok).toBe(true);
      expect((await charge(first, 4, { byteCost: 2 })).ok).toBe(false);

      const leases = await Promise.all(Array.from({ length: 9 }, (_, index) => charge(second, index + 2, { concurrencyCost: 1, leaseTtlMs: 60_000 })));
      expect(leases.filter((result) => result.ok)).toHaveLength(8);
      await second.grant.releaseLease(second.epoch, leases.find((result) => result.leaseCounter !== undefined)!.leaseCounter!);
      expect((await charge(second, 20, { concurrencyCost: 1, leaseTtlMs: 60_000 })).ok).toBe(true);
    } finally {
      clock.mockRestore();
    }
  });
});

describe("live-lease renewal", () => {
  it("renewal keeps a live lease counted past its original TTL", async () => {
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    try {
      const fixture = await activeGrant(now);
      for (let index = 0; index < 8; index += 1) {
        expect((await charge(fixture, index + 1, { concurrencyCost: 1, leaseTtlMs: 40_000 })).ok).toBe(true);
      }
      // Renewing before expiry keeps the lease alive past its original TTL.
      clock.mockReturnValue(now + 30_000);
      expect(await fixture.grant.renewLease(fixture.epoch, "1", 40_000)).toBe(true);
      clock.mockReturnValue(now + 50_000);
      // Leases 2-8 lapsed at now+40s; the renewed lease 1 still counts, so
      // only seven further leases fit the ceiling.
      for (let index = 0; index < 7; index += 1) {
        expect((await charge(fixture, 30 + index, { concurrencyCost: 1, leaseTtlMs: 40_000 })).ok).toBe(true);
      }
      expect((await charge(fixture, 50, { concurrencyCost: 1, leaseTtlMs: 40_000 })).ok).toBe(false);
    } finally {
      clock.mockRestore();
    }
  });

  it("never resurrects an expired lease and rejects wrong epoch, counter and ttl", async () => {
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    try {
      const fixture = await activeGrant(now);
      expect((await charge(fixture, 1, { concurrencyCost: 1, leaseTtlMs: 10_000 })).ok).toBe(true);
      expect(await fixture.grant.renewLease(fixture.epoch + 1, "1", 10_000)).toBe(false);
      expect(await fixture.grant.renewLease(fixture.epoch, "999", 10_000)).toBe(false);
      expect(await fixture.grant.renewLease(fixture.epoch, "1", 0)).toBe(false);
      expect(await fixture.grant.renewLease(fixture.epoch, "1", 61_000)).toBe(false);
      expect(await fixture.grant.renewLease(fixture.epoch, "1", 10.5)).toBe(false);
      expect(await fixture.grant.renewLease(fixture.epoch, "1", 10_000)).toBe(true);
      clock.mockReturnValue(now + 20_000);
      expect(await fixture.grant.renewLease(fixture.epoch, "1", 10_000)).toBe(false);
      expect((await charge(fixture, 2, { concurrencyCost: 1, leaseTtlMs: 10_000 })).ok).toBe(true);
    } finally {
      clock.mockRestore();
    }
  });
});
