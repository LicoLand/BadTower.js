/**
 * MailboxStore capacity accounting against a deterministic storage
 * double. The double models what the old `databaseSize + body.length`
 * check could not see: per-row cell overhead and page-granular growth,
 * plus a platform storage ceiling that answers writes with
 * SQLITE_FULL. Run under the plain node project — no workerd needed.
 */
import { describe, expect, it } from "vitest";
import { MailboxStore, SEQUENCE_FLOOR, isStorageFull } from "@badtower/station-core";

const D0 = 12_288;
const PAGE = 4_096;
const ROW_OVERHEAD = 64; // cell header + handle index slack, per packet row

class FakeSql {
  tables = new Set<string>();
  meta: { subject: ArrayBuffer | null; revoked: number } | null = null;
  binding: string | null = null;
  allocNext: number | undefined = undefined;
  packets = new Map<number, { handle: ArrayBuffer; body: ArrayBuffer }>();
  payloadBytes = 0;
  fullAt = Number.POSITIVE_INFINITY;

  reset(): void {
    this.tables.clear();
    this.meta = null;
    this.binding = null;
    this.allocNext = undefined;
    this.packets.clear();
    this.payloadBytes = 0;
  }

  /** transactionSync semantics: run the closure, roll back on throw. */
  run<T>(fn: () => T): T {
    const snapshot = {
      meta: this.meta,
      binding: this.binding,
      allocNext: this.allocNext,
      packets: new Map(this.packets),
      payloadBytes: this.payloadBytes,
    };
    try {
      return fn();
    } catch (error) {
      this.meta = snapshot.meta;
      this.binding = snapshot.binding;
      this.allocNext = snapshot.allocNext;
      this.packets = snapshot.packets;
      this.payloadBytes = snapshot.payloadBytes;
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
      this.tables.add(/^CREATE TABLE IF NOT EXISTS (\w+)/.exec(sql)![1]!);
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
    if (sql.startsWith("INSERT INTO binding")) {
      this.require("binding");
      this.binding = params[0] as string;
      return { toArray: () => [] };
    }
    if (sql === "SELECT via FROM binding WHERE id = 0") {
      this.require("binding");
      return { toArray: () => (this.binding === null ? [] : [{ via: this.binding }]) };
    }
    if (sql === "SELECT next FROM alloc WHERE id = 0") {
      this.require("alloc");
      return { toArray: () => (this.allocNext === undefined ? [] : [{ next: this.allocNext }]) };
    }
    if (sql.startsWith("INSERT INTO alloc")) {
      this.require("alloc");
      this.allocNext = params[0] as number;
      return { toArray: () => [] };
    }
    if (sql === "SELECT COALESCE(MAX(seq), 0) + 1 AS next FROM packet") {
      this.require("packet");
      return { toArray: () => [{ next: Math.max(0, ...this.packets.keys()) + 1 }] };
    }
    if (sql.startsWith("UPDATE alloc SET next = ?")) {
      this.require("alloc");
      this.allocNext = params[0] as number;
      return { toArray: () => [] };
    }
    if (sql.startsWith("INSERT INTO packet")) {
      this.require("packet");
      const seq = params[0] as number;
      const handle = params[1] as ArrayBuffer;
      const body = params[2] as ArrayBuffer;
      const projected = D0 + Math.ceil((this.payloadBytes + handle.byteLength + body.byteLength + ROW_OVERHEAD) / PAGE) * PAGE;
      if (projected > this.fullAt) {
        throw new Error("SQLITE_FULL: database or disk is full");
      }
      this.packets.set(seq, { handle, body });
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
    expect(store.reserve(subject(), live(), "native")).toBe("bound");
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
    expect(store.reserve(subject(), live(), "native")).toBe("bound");
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

describe("binding-scoped recipient operations", () => {
  it("refuses native recipient operations on a listener-bound mailbox but keeps listener access", () => {
    const { store } = fixture(1_000_000_000);
    expect(store.reserve(subject(), live(), "listener")).toBe("bound");
    expect(store.boundVia()).toBe("listener");
    expect(store.submit(handle(), bytes(8))).toEqual({ outcome: "accepted" });
    // The admission credential alone is not the bound owner: native
    // claim, settle and capacity answer as for an unbound mailbox.
    expect(store.nativeClaim([], 16)).toBeNull();
    expect(store.nativeSettle([1])).toBe(false);
    expect(store.nativeCapacityInfo().bound).toBe(false);
    // The binding transport's own proven session keeps full access.
    const packets = store.claim([], 16)!;
    expect(packets).toHaveLength(1);
    expect(store.settle([packets[0]!.sequence])).toBe(true);
    expect(store.claim([], 16)).toHaveLength(0);
  });

  it("admits native recipient operations on a natively bound mailbox", () => {
    const { store } = fixture(1_000_000_000);
    expect(store.reserve(subject(), live(), "native")).toBe("bound");
    expect(store.boundVia()).toBe("native");
    store.submit(handle(), bytes(8));
    expect(store.nativeClaim([], 16)).toHaveLength(1);
    expect(store.nativeCapacityInfo().bound).toBe(true);
  });

  it("refuses submissions and recipient operations until a verified re-bind records the transport", () => {
    const { sql, store } = fixture(1_000_000_000);
    // A mailbox bound before binding records existed: meta and packet
    // rows only, no binding record.
    sql.tables.add("meta");
    sql.tables.add("packet");
    sql.meta = { subject: new Uint8Array(32).fill(7).buffer, revoked: 0 };
    sql.packets.set(3, { handle: handle().buffer as ArrayBuffer, body: bytes(4).buffer as ArrayBuffer });
    expect(store.boundVia()).toBeNull();
    // Recipient operations answer as unbound on BOTH surfaces, and new
    // submissions are refused: the mailbox cannot receive.
    expect(store.nativeClaim([], 16)).toBeNull();
    expect(store.nativeSettle([3])).toBe(false);
    expect(store.nativeCapacityInfo().bound).toBe(false);
    expect(store.listenerClaim([], 16)).toBeNull();
    expect(store.listenerSettle([3])).toBe(false);
    expect(store.listenerHasPending()).toBe(false);
    expect(store.submit(handle(), bytes(8)))
      .toEqual({ outcome: "rejected", reason: "target-unavailable" });
    // A wrong-subject reserve cannot transition the mailbox.
    expect(store.reserve(new Uint8Array(32).fill(9), live(), "native"))
      .toBe("subject-mismatch");
    expect(store.boundVia()).toBeNull();
    // The operator-controlled transition: a verified re-bind through
    // the native surface records the transport and preserves the
    // already-queued packet.
    expect(store.reserve(subject(), live(), "native")).toBe("bound");
    expect(store.boundVia()).toBe("native");
    const claimed = store.nativeClaim([], 16)!;
    expect(claimed.map((p) => p.sequence)).toEqual([3]);
    expect(store.nativeSettle([3])).toBe(true);
    expect(store.submit(handle(), bytes(8))).toEqual({ outcome: "accepted" });
  });

  it("records the listener transport when a listener session re-binds an unrecorded mailbox", () => {
    const { sql, store } = fixture(1_000_000_000);
    sql.tables.add("meta");
    sql.meta = { subject: new Uint8Array(32).fill(7).buffer, revoked: 0 };
    expect(store.reserve(subject(), live(), "listener")).toBe("bound");
    expect(store.boundVia()).toBe("listener");
    // The listener surface then owns recipient access; native is closed.
    expect(store.submit(handle(), bytes(8))).toEqual({ outcome: "accepted" });
    expect(store.nativeClaim([], 16)).toBeNull();
    expect(store.listenerClaim([], 16)).toHaveLength(1);
  });

  it("admits listener recipient operations only on a listener-bound mailbox", () => {
    const { store } = fixture(1_000_000_000);
    expect(store.reserve(subject(), live(), "native")).toBe("bound");
    expect(store.submit(handle(), bytes(8))).toEqual({ outcome: "accepted" });
    expect(store.listenerClaim([], 16)).toBeNull();
    expect(store.listenerSettle([1])).toBe(false);
    expect(store.listenerHasPending()).toBe(false);
    expect(store.nativeClaim([], 16)).toHaveLength(1);
  });
});

describe("sequence allocation", () => {
  it("seeds a drained legacy queue above the pre-allocator epoch", () => {
    const { sql, store } = fixture(1_000_000_000);
    // A legacy mailbox that queued and settled packets before the
    // allocator existed: its live maximum is gone with the settled rows,
    // so seeding must come from the epoch floor, not the queue.
    sql.tables.add("meta");
    sql.tables.add("packet");
    sql.meta = { subject: new Uint8Array(32).fill(7).buffer, revoked: 0 };
    expect(store.reserve(subject(), live(), "native")).toBe("bound");
    expect(store.submit(handle(), bytes(8))).toEqual({ outcome: "accepted" });
    const first = store.claim([], 16)!;
    expect(first[0]!.sequence).toBe(SEQUENCE_FLOOR);
  });

  it("never reuses a settled sequence for a newer packet", () => {
    const { store } = fixture(1_000_000_000);
    store.reserve(subject(), live(), "native");
    store.submit(handle(), bytes(8));
    const first = store.claim([], 16)!;
    expect(first).toHaveLength(1);
    const seq = first[0]!.sequence;
    expect(store.settle([seq])).toBe(true);
    store.submit(handle(), bytes(9));
    const second = store.claim([], 16)!;
    expect(second).toHaveLength(1);
    expect(second[0]!.sequence).toBeGreaterThan(seq);
    // A delayed or retried settle of the dead sequence is vacuous: the
    // newer packet stays claimable, and a stale in-flight exclusion of
    // the dead sequence cannot suppress it.
    expect(store.settle([seq])).toBe(true);
    expect(store.claim([seq], 16)).toHaveLength(1);
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
    expect(store.reserve(subject(), live(), "native")).toBe("revoked");
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
    expect(store.reserve(subject(), live(), "native")).toBe("bound");
    expect(store.submit(handle(), bytes(64))).toEqual({ outcome: "accepted" });
    const claimed = store.claim([], 16)!;
    expect(store.settle(claimed.map((p) => p.sequence))).toBe(true);
    const rowsWritten = calls.filter(([name]) => name === "rowsWritten");
    expect(rowsWritten).toContainEqual(["rowsWritten", "reserve", 2]);
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
