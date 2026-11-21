/**
 * Plan-aware platform limits. Cloudflare's Free and Paid plan ceilings
 * are explicit configuration, not an implicit platform surprise: the
 * constants below mirror the official inputs table in docs/COST.md
 * (Cloudflare Workers and Durable Objects pricing/limits pages, read
 * 2026-11-16). A deployment picks its plan with `BADTOWER_PLAN`
 * ("free" | "paid", default "free") and is refused at startup when its
 * own limits exceed the platform's.
 */

export type PlanName = "free" | "paid";

/**
 * One billing or capacity ceiling from docs/COST.md's inputs table.
 * `perDay`/`perMonth` mark the allowance period; `storageBytes` is a
 * hard storage ceiling rather than a billed allowance.
 */
export type PlanLimits = {
  /** Hard per-object SQLite ceiling: a Durable Object cannot grow past it. */
  objectStorageBytes: number;
  /** Hard account-wide Durable Object storage ceiling; Infinity when uncapped. */
  accountStorageBytes: number;
  /** Included Worker requests and their period in days. */
  workerRequests: { count: number; periodDays: number };
  /** Included Durable Object requests and their period in days. */
  doRequests: { count: number; periodDays: number };
  /** Included Durable Object active duration in GB-s and its period in days. */
  doDurationGbs: { count: number; periodDays: number };
  /** Included SQLite rows read and their period in days. */
  rowsRead: { count: number; periodDays: number };
  /** Included SQLite rows written and their period in days. */
  rowsWritten: { count: number; periodDays: number };
  /** Included stored data in GB-month; 0 where the plan is not billed. */
  storageGbMonth: number;
};

/** Values from the official inputs table in docs/COST.md. */
export const PLANS: Record<PlanName, PlanLimits> = {
  free: {
    objectStorageBytes: 1_000_000_000,
    accountStorageBytes: 5_000_000_000,
    workerRequests: { count: 100_000, periodDays: 1 },
    doRequests: { count: 100_000, periodDays: 1 },
    doDurationGbs: { count: 13_000, periodDays: 1 },
    rowsRead: { count: 5_000_000, periodDays: 1 },
    rowsWritten: { count: 100_000, periodDays: 1 },
    storageGbMonth: 0,
  },
  paid: {
    objectStorageBytes: 10_000_000_000,
    accountStorageBytes: Number.POSITIVE_INFINITY,
    workerRequests: { count: 10_000_000, periodDays: 30 },
    doRequests: { count: 1_000_000, periodDays: 30 },
    doDurationGbs: { count: 400_000, periodDays: 30 },
    rowsRead: { count: 25_000_000_000, periodDays: 30 },
    rowsWritten: { count: 50_000_000, periodDays: 30 },
    storageGbMonth: 5,
  },
};

export const DEFAULT_MAILBOX_CAPACITY_BYTES = 1_000_000_000;

export type ResolvedPlan = {
  name: PlanName;
  limits: PlanLimits;
  /** Configured per-mailbox capacity, validated against the plan. */
  mailboxCapacityBytes: number;
};

export type PlanEnv = {
  BADTOWER_PLAN?: string | undefined;
  BADTOWER_MAILBOX_CAPACITY_BYTES?: string | undefined;
};

/**
 * Resolve the deployment's plan and per-mailbox capacity. Throws —
 * failing startup rather than running an unsafe configuration — when
 * the plan name is unknown, the capacity is not a positive finite
 * number, or the capacity exceeds the plan's per-object platform
 * limit. The "free" default is the tighter bound.
 */
export function resolvePlan(env: PlanEnv): ResolvedPlan {
  const rawPlan = env.BADTOWER_PLAN ?? "free";
  if (rawPlan !== "free" && rawPlan !== "paid") {
    throw new Error(`BADTOWER_PLAN must be "free" or "paid", got ${JSON.stringify(rawPlan)}`);
  }
  const limits = PLANS[rawPlan];
  const rawCapacity = env.BADTOWER_MAILBOX_CAPACITY_BYTES ?? String(DEFAULT_MAILBOX_CAPACITY_BYTES);
  const capacity = Number(rawCapacity);
  if (!Number.isFinite(capacity) || capacity <= 0 || Math.floor(capacity) !== capacity) {
    throw new Error(
      `BADTOWER_MAILBOX_CAPACITY_BYTES must be a positive integer, got ${JSON.stringify(rawCapacity)}`,
    );
  }
  if (capacity > limits.objectStorageBytes) {
    throw new Error(
      `BADTOWER_MAILBOX_CAPACITY_BYTES (${capacity}) exceeds the ${rawPlan} plan's ` +
        `per-object limit (${limits.objectStorageBytes}); lower the capacity or change the plan`,
    );
  }
  return { name: rawPlan, limits, mailboxCapacityBytes: capacity };
}
