/**
 * Aggregate cost meters, per docs/COST.md and
 * docs/OPERATIONS-VISIBILITY.md. Every series is a counter, sum or
 * gauge over a closed label enumeration — `operation`, `direction` and
 * `plan` are the only labels the typed API can emit, so no call site
 * can add a mailbox id, handle, subject, IP address, path, content or
 * address label.
 *
 * The registry is per isolate: a Worker's counters cover the requests
 * that isolate served, and a Durable Object's counters cover the RPCs
 * and sockets its isolate handled. Exported values are isolate-time
 * aggregates for reconciliation against Cloudflare's own usage record,
 * which remains authoritative for spend.
 */
import type { PlanName } from "./plan";

export const OPERATIONS = [
  "reserve",
  "submit",
  "claim",
  "settle",
  "capacity",
  "version",
  "revoke",
  "healthz",
  "mailbox_ws",
  "metrics",
  "other",
] as const;
export type Operation = (typeof OPERATIONS)[number];

export const STORE_OPERATIONS = [
  "meta",
  "binding",
  "alloc",
  "reserve",
  "submit",
  "claim",
  "settle",
  "revoke",
  "hasPending",
] as const;

export class CostMetrics {
  private readonly counters = new Map<string, number>();
  /**
   * Observed databaseSize per mailbox key — internal only so repeated
   * samples replace rather than accumulate; only the sum is exported.
   */
  private readonly storage = new Map<string, number>();

  private bump(name: string, labels: Record<string, string>, amount: number): void {
    const key =
      name +
      "|" +
      Object.keys(labels)
        .sort()
        .map((k) => `${k}="${labels[k]}"`)
        .join(",");
    this.counters.set(key, (this.counters.get(key) ?? 0) + amount);
  }

  /** R_w — inbound HTTP requests and WebSocket upgrades at the Worker. */
  workerRequest(operation: Operation, plan: PlanName): void {
    this.bump("badtower_worker_requests_total", { operation, plan }, 1);
  }

  /** R_do — one RPC session or WebSocket upgrade into a Durable Object. */
  doRequest(operation: Operation, plan: PlanName): void {
    this.bump("badtower_do_requests_total", { operation, plan }, 1);
  }

  /** T_active — wall-clock milliseconds a Durable Object spent active. */
  doActiveMs(operation: Operation, plan: PlanName, ms: number): void {
    this.bump("badtower_do_active_ms_total", { operation, plan }, ms);
  }

  /** Ws_in — incoming WebSocket messages; billed at 20:1 into R_do. */
  wsMessageIn(plan: PlanName): void {
    this.bump("badtower_ws_messages_total", { direction: "in", plan }, 1);
  }

  /** Rows_r — SQLite rows examined, by store operation. */
  rowsRead(operation: string, count: number, plan: PlanName): void {
    if (count <= 0 || !(STORE_OPERATIONS as readonly string[]).includes(operation)) return;
    this.bump("badtower_rows_read_total", { operation, plan }, count);
  }

  /** Rows_w — SQLite rows inserted, updated or deleted, by store operation. */
  rowsWritten(operation: string, count: number, plan: PlanName): void {
    if (count <= 0 || !(STORE_OPERATIONS as readonly string[]).includes(operation)) return;
    this.bump("badtower_rows_written_total", { operation, plan }, count);
  }

  observeStorage(key: string, bytes: number): void {
    this.storage.set(key, bytes);
  }

  /** S — the sum of observed per-mailbox database sizes in this isolate. */
  private storageBytes(): number {
    let sum = 0;
    for (const bytes of this.storage.values()) sum += bytes;
    return sum;
  }

  /**
   * Prometheus text exposition. Label values come only from the typed
   * methods above; this method cannot emit a label that was never
   * recordable.
   */
  export(plan: PlanName): string {
    const lines: string[] = [];
    const sorted = [...this.counters.entries()].sort(([a], [b]) => a.localeCompare(b));
    for (const [key, value] of sorted) {
      const bar = key.indexOf("|");
      lines.push(`${key.slice(0, bar)}{${key.slice(bar + 1)}} ${value}`);
    }
    lines.push(`badtower_sqlite_bytes{plan="${plan}"} ${this.storageBytes()}`);
    return `${lines.join("\n")}\n`;
  }
}

/** The process-wide registry shared by the Worker and the objects it hosts. */
export const METRICS = new CostMetrics();
