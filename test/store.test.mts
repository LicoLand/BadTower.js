/**
 * MailboxStore capacity accounting against a deterministic storage
 * double. The double models what the old `databaseSize + body.length`
 * check could not see: per-row cell overhead and page-granular growth,
 * plus a platform storage ceiling that answers writes with
 * SQLITE_FULL. Run under the plain node project — no workerd needed.
 */
import { describe, expect, it } from "vitest";
import { MailboxStore, isStorageFull } from "@badtower/station-core";

const D0 = 12_288;
const PAGE = 4_096;
const ROW_OVERHEAD = 64; // cell header + handle index slack, per packet row

class FakeSql {
  tables = new Set<string>();
  meta: { subject: ArrayBuffer | null; revoked: number } | null = null;
  packets = new Map<number, { handle: ArrayBuffer; body: ArrayBuffer }>();
  nextSeq = 1;
  payloadBytes = 0;
  fullAt = Number.POSITIVE_INFINITY;

  reset(): void {
    this.tables.clear();
    this.meta = null;
    this.packets.clear();
    this.nextSeq = 1;
    this.payloadBytes = 0;
  }

  /** transactionSync semantics: run the closure, roll back on throw. */
  run<T>(fn: () => T): T {
    const snapshot = {
      packets: new Map(this.packets),
      payloadBytes: this.payloadBytes,
      nextSeq: this.nextSeq,
    };
    try {
      return fn();
    } catch (error) {
      this.packets = snapshot.packets;
      this.payloadBytes = snapshot.payloadBytes;
      this.nextSeq = snapshot.nextSeq;
      throw error;
    }
  }

  get databaseSize(): number {
    if (this.tables.size === 0) return 0;
    return D0 + Math.ceil(this.payloadBytes / PAGE) * PAGE;
  }

  /** Real SQLite answers queries on a missing table with an error. */
  private require(table: string): void {
    if (!this.tables.has(table)) throw new Error(`no such table: ${table}`);
  }

  exec(query: string, ...params: unknown[]): { toArray(): unknown[] } {
    const sql = query.replace(/\s+/g, " ").trim();
    if (sql.startsWith("CREATE TABLE")) {
      this.tables.add(/meta\(/.test(sql) ? "meta" : "packet");
      return { toArray: () => [] };
    }
    if (sql === "SELECT subject, revoked FROM meta WHERE id = 0") {
      this.require("meta");
      return { toArray: () => (this.meta === null ? [] : [this.meta]) };
    }
    if (sql.startsWith("INSERT INTO meta")) {
      this.require("meta");
      this.meta = params.length === 0
        ? { subject: null, revoked: 1 }
        : { subject: params[0] as ArrayBuffer, revoked: 0 };
      return { toArray: () => [] };
    }
    if (sql.startsWith("INSERT INTO packet")) {
      this.require("packet");
      const handle = params[0] as ArrayBuffer;
      const body = params[1] as ArrayBuffer;
      const projected = D0 + Math.ceil((this.payloadBytes + handle.byteLength + body.byteLength + ROW_OVERHEAD) / PAGE) * PAGE;
      if (projected > this.fullAt) {
        throw new Error("SQLITE_FULL: database or disk is full");
      }
      this.packets.set(this.nextSeq, { handle, body });
      this.nextSeq += 1;
      this.payloadBytes += handle.byteLength + body.byteLength + ROW_OVERHEAD;
      return { toArray: () => [] };
    }
    if (sql.startsWith("SELECT seq, handle, body FROM packet WHERE seq NOT IN")) {
      this.require("packet");
      const limit = params[params.length - 1] as number;
      const excluded = new Set(params.slice(0, -1) as number[]);
      const rows = [...this.packets.entries()]
        .filter(([seq]) => !excluded.has(seq))
        .sort(([a], [b]) => a - b)
        .slice(0, limit)
        .map(([seq, row]) => ({ seq, ...row }));
      return { toArray: () => rows };
    }
    if (sql.startsWith("SELECT seq, handle, body FROM packet ORDER BY seq LIMIT")) {
      this.require("packet");
      const limit = params[0] as number;
      const rows = [...this.packets.entries()]
        .sort(([a], [b]) => a - b)
        .slice(0, limit)
        .map(([seq, row]) => ({ seq, ...row }));
      return { toArray: () => rows };
    }
    if (sql === "SELECT seq FROM packet LIMIT 1") {
      this.require("packet");
      const first = [...this.packets.keys()][0];
      return { toArray: () => (first === undefined ? [] : [{ seq: first }]) };
    }
    if (sql === "SELECT COUNT(*) AS n FROM packet") {
      this.require("packet");
      return { toArray: () => [{ n: this.packets.size }] };
    }
    if (sql.startsWith("DELETE FROM packet WHERE seq")) {
      this.require("packet");
      this.packets.delete(params[0] as number);
      return { toArray: () => [] };
    }
    throw new Error(`fake sql cannot run: ${sql}`);
  }
}

type Calls = Array<[string, ...unknown[]]>;

function fixture(capacity: number, calls?: Calls) {
  const sql = new FakeSql();
  const ctx = {
    storage: {
      sql,
      transactionSync: <T,>(fn: () => T) => sql.run(fn),
      deleteAll: async () => sql.reset(),
    },
  };
  const store = new MailboxStore(ctx as unknown as DurableObjectState, {
    capacityBytes: () => capacity,
    meter: calls === undefined ? undefined : {
      rowsRead: (operation, count) => calls.push(["rowsRead", operation, count]),
      rowsWritten: (operation, count) => calls.push(["rowsWritten", operation, count]),
      observeStorage: (bytes) => calls.push(["observeStorage", bytes]),
    },
  });
  return { sql, store };
}

const subject = () => new Uint8Array(32).fill(7);
const live = () => Math.floor(Date.now() / 1000) + 3600;
const bytes = (n: number) => new Uint8Array(n).fill(1);
const handle = () => new Uint8Array(32).fill(9);

describe("capacity accounting", () => {
  it("counts row overhead and page growth the body-only estimate missed", () => {
    // databaseSize 12288; body 4097 → old check saw 16385 ≤ 17000, but
    // the row's real page cost pushes the file to 20480 > 17000.
    const { store } = fixture(17_000);
    expect(store.reserve(subject(), live())).toBe("bound");
    const over = store.submit(handle(), bytes(4097));
    expect(over).toEqual({ outcome: "transient", reason: "mailbox-full" });
    expect(store.claim([], 16)).toEqual([]);
    const fits = store.submit(handle(), bytes(4000));
    expect(fits).toEqual({ outcome: "accepted" });
    expect(store.claim([], 16)).toHaveLength(1);
  });

  it("maps SQLITE_FULL to the stable transient mailbox-full and keeps stored packets", () => {
    const { sql, store } = fixture(1_000_000_000);
    sql.fullAt = 20_000; // simulated platform object ceiling
    expect(store.reserve(subject(), live())).toBe("bound");
    expect(store.submit(handle(), bytes(4000))).toEqual({ outcome: "accepted" });
    const over = store.submit(handle(), bytes(4097));
    expect(over).toEqual({ outcome: "transient", reason: "mailbox-full" });
    const remaining = store.claim([], 16);
    expect(remaining).toHaveLength(1);
    expect(remaining![0]!.body).toEqual(bytes(4000));
  });

  it("isStorageFull recognizes only the storage-full condition", () => {
    expect(isStorageFull(new Error("SQLITE_FULL: database or disk is full"))).toBe(true);
    expect(isStorageFull(new Error("storage is full"))).toBe(true);
    expect(isStorageFull(new Error("SQLITE_CONSTRAINT"))).toBe(false);
    expect(isStorageFull("SQLITE_FULL")).toBe(false);
  });
});

describe("revocation", () => {
  it("revoke on a never-bound mailbox skips packet counting and persists the tombstone", async () => {
    const calls: Calls = [];
    const { sql, store } = fixture(1_000_000_000, calls);
    await store.revoke();
    expect(sql.meta).toEqual({ subject: null, revoked: 1 });
    expect(store.revoked()).toBe(true);
    expect(store.canBind(live())).toBe("closed");
    expect(store.reserve(subject(), live())).toBe("revoked");
    // No packet table existed, so no revoke read was metered; the
    // tombstone alone counts as the written row.
    expect(calls).not.toContainEqual(["rowsRead", "revoke", 1]);
    expect(calls).toContainEqual(["rowsWritten", "revoke", 1]);
  });
});

describe("store meter", () => {
  it("reports rows and stored bytes per operation without identifiers", () => {
    const calls: Calls = [];
    const { store } = fixture(1_000_000_000, calls);
    expect(store.reserve(subject(), live())).toBe("bound");
    expect(store.submit(handle(), bytes(64))).toEqual({ outcome: "accepted" });
    const claimed = store.claim([], 16)!;
    expect(store.settle(claimed.map((p) => p.sequence))).toBe(true);
    const rowsWritten = calls.filter(([name]) => name === "rowsWritten");
    expect(rowsWritten).toContainEqual(["rowsWritten", "reserve", 1]);
    expect(rowsWritten).toContainEqual(["rowsWritten", "submit", 1]);
    expect(rowsWritten).toContainEqual(["rowsWritten", "settle", 1]);
    const rowsRead = calls.filter(([name]) => name === "rowsRead");
    expect(rowsRead).toContainEqual(["rowsRead", "claim", 1]);
    const storage = calls.filter(([name]) => name === "observeStorage");
    expect(storage.length).toBeGreaterThan(0);
    for (const call of calls) {
      for (const arg of call.slice(1)) {
        expect(String(arg)).not.toMatch(/^[0-9a-f]{32}$/i);
      }
    }
  });
});
