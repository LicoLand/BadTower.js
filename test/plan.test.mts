/**
 * Plan-aware limit configuration: resolvePlan must expose the Free/Paid
 * platform ceilings as explicit values, default fail-safe to "free",
 * and refuse — loudly, at resolution time — any deployment whose
 * per-mailbox capacity exceeds the plan's per-object storage limit.
 */
import { describe, expect, it } from "vitest";
import { PLANS, resolvePlan } from "@badtower/station-core";

describe("resolvePlan", () => {
  it("defaults to the free plan with the documented default capacity", () => {
    const plan = resolvePlan({});
    expect(plan.name).toBe("free");
    expect(plan.mailboxCapacityBytes).toBe(1_000_000_000);
    expect(plan.limits.objectStorageBytes).toBe(1_000_000_000);
  });

  it("exposes free and paid platform ceilings from the documented inputs", () => {
    expect(PLANS.free.objectStorageBytes).toBe(1_000_000_000);
    expect(PLANS.paid.objectStorageBytes).toBe(10_000_000_000);
    expect(PLANS.free.accountStorageBytes).toBe(5_000_000_000);
    expect(PLANS.paid.accountStorageBytes).toBe(Number.POSITIVE_INFINITY);
    expect(PLANS.free.workerRequests).toEqual({ count: 100_000, periodDays: 1 });
    expect(PLANS.paid.workerRequests).toEqual({ count: 10_000_000, periodDays: 30 });
    expect(PLANS.free.doRequests).toEqual({ count: 100_000, periodDays: 1 });
    expect(PLANS.paid.doRequests).toEqual({ count: 1_000_000, periodDays: 30 });
    expect(PLANS.free.doDurationGbs).toEqual({ count: 13_000, periodDays: 1 });
    expect(PLANS.paid.doDurationGbs).toEqual({ count: 400_000, periodDays: 30 });
    expect(PLANS.free.rowsRead).toEqual({ count: 5_000_000, periodDays: 1 });
    expect(PLANS.paid.rowsRead).toEqual({ count: 25_000_000_000, periodDays: 30 });
    expect(PLANS.free.rowsWritten).toEqual({ count: 100_000, periodDays: 1 });
    expect(PLANS.paid.rowsWritten).toEqual({ count: 50_000_000, periodDays: 30 });
    expect(PLANS.free.storageGbMonth).toBe(0);
    expect(PLANS.paid.storageGbMonth).toBe(5);
  });

  it("refuses a mailbox capacity above the plan's per-object limit", () => {
    expect(() =>
      resolvePlan({ BADTOWER_PLAN: "free", BADTOWER_MAILBOX_CAPACITY_BYTES: "1000000001" }),
    ).toThrow(/per-object limit/);
    expect(() =>
      resolvePlan({ BADTOWER_PLAN: "paid", BADTOWER_MAILBOX_CAPACITY_BYTES: "10000000001" }),
    ).toThrow(/per-object limit/);
    // At the limit is allowed: the store's measured check and the
    // SQLITE_FULL mapping close the remaining gap.
    expect(
      resolvePlan({ BADTOWER_PLAN: "free", BADTOWER_MAILBOX_CAPACITY_BYTES: "1000000000" })
        .mailboxCapacityBytes,
    ).toBe(1_000_000_000);
    expect(
      resolvePlan({ BADTOWER_PLAN: "paid", BADTOWER_MAILBOX_CAPACITY_BYTES: "2000000000" })
        .mailboxCapacityBytes,
    ).toBe(2_000_000_000);
  });

  it("refuses unknown plans and malformed capacities", () => {
    expect(() => resolvePlan({ BADTOWER_PLAN: "enterprise" })).toThrow(/free.*paid/);
    expect(() => resolvePlan({ BADTOWER_MAILBOX_CAPACITY_BYTES: "abc" })).toThrow(/positive integer/);
    expect(() => resolvePlan({ BADTOWER_MAILBOX_CAPACITY_BYTES: "0" })).toThrow(/positive integer/);
    expect(() => resolvePlan({ BADTOWER_MAILBOX_CAPACITY_BYTES: "-5" })).toThrow(/positive integer/);
    expect(() => resolvePlan({ BADTOWER_MAILBOX_CAPACITY_BYTES: "1.5" })).toThrow(/positive integer/);
  });
});
