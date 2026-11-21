/**
 * The protocol-neutral per-mailbox store: one opaque, permanent mailbox
 * per station mailbox id. A mailbox exists after its first successful
 * `reserve` records one fixed-size opaque subject identifier supplied by
 * the caller; the store does not know what the identifier is and never
 * compares it against a protocol. A different identifier later is
 * refused.
 *
 * Packet rows leave only through `settle` or `revoke`: delivery is
 * at-least-once, `claim` replays in sequence order while the caller's
 * in-flight window stays under IN_FLIGHT_WINDOW, and `revoke` destroys
 * the mailbox and refuses it forever.
 *
 * The store owns only SQLite semantics — connections, listeners and
 * frame grammars belong to whoever composes it.
 */
import { fromSqliteBlob } from "./encoding";

export const SUBJECT_BYTES = 32;
export const IN_FLIGHT_WINDOW = 16;
export const MAX_PACKET_BYTES = 524288;

export type ReserveResult =
  | "bound"
  | "subject-mismatch"
  | "revoked"
  | "bind-window-closed";

export type SubmitResult =
  | { outcome: "accepted" }
  | { outcome: "rejected"; reason: "target-unavailable" }
  | { outcome: "transient"; reason: "mailbox-full" | "internal-unavailable" };

export type Packet = { sequence: number; handle: Uint8Array; body: Uint8Array };

/**
 * Optional aggregate accounting hook for the rows and stored bytes a
 * store operation touches. Counts feed the cost meters in
 * docs/COST.md; they never carry mailbox ids, handles or content.
 */
export type StoreMeter = {
  rowsRead(operation: string, count: number): void;
  rowsWritten(operation: string, count: number): void;
  /** The mailbox's current databaseSize after an operation, for the storage gauge. */
  observeStorage(bytes: number): void;
};

type Meta = { subject: Uint8Array | null; revoked: boolean };

/** A subarray's .buffer is its parent's — storing it would leak the whole message. */
function owned(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

/**
 * Whether a storage error is the platform's storage-full condition.
 * workerd reports it as an Error whose message names SQLITE_FULL; the
 * check is deliberately loose so a wording change still fails closed.
 */
/** Marker for the measured-capacity rollback inside submit's transaction. */
class CapacityExceeded extends Error {}

export function isStorageFull(error: unknown): boolean {
  return (
    error instanceof Error &&
    /SQLITE_FULL|database or disk is full|storage.*(is )?full/i.test(error.message)
  );
}

export class MailboxStore {
  private meta: Meta | null = null;

  constructor(
    private readonly ctx: DurableObjectState,
    private readonly options: { capacityBytes(): number; meter?: StoreMeter | undefined },
  ) {}

  private meter(): StoreMeter | undefined {
    return this.options.meter;
  }

  /** Schema exists only where a mailbox exists: a never-bound object writes nothing. */
  private createSchema(): void {
    this.ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS meta(id INTEGER PRIMARY KEY CHECK(id = 0), subject BLOB, revoked INTEGER NOT NULL DEFAULT 0)",
    );
    this.ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS packet(seq INTEGER PRIMARY KEY, handle BLOB NOT NULL, body BLOB NOT NULL)",
    );
  }

  private loadMeta(): Meta {
    if (this.meta !== null) return this.meta;
    let rows: unknown[] = [];
    try {
      rows = this.ctx.storage.sql
        .exec("SELECT subject, revoked FROM meta WHERE id = 0")
        .toArray();
    } catch {
      // No meta table is an unbound mailbox, not an error.
    }
    this.meter()?.rowsRead("meta", rows.length);
    const row = rows[0] as { subject: unknown; revoked: unknown } | undefined;
    this.meta = row === undefined
      ? { subject: null, revoked: false }
      : {
          subject: row.subject === null ? null : fromSqliteBlob(row.subject),
          revoked: row.revoked === 1,
        };
    return this.meta;
  }

  /** The bound opaque subject identifier, or null while unbound. */
  subject(): Uint8Array | null {
    const subject = this.loadMeta().subject;
    return subject === null ? null : subject.slice();
  }

  bound(): boolean {
    return this.loadMeta().subject !== null;
  }

  revoked(): boolean {
    return this.loadMeta().revoked;
  }

  /**
   * Whether a new subject may still bind at `notAfterSeconds`
   * (unix seconds supplied by the caller's admission layer). A revoked
   * mailbox never reopens; a bound mailbox admits its own subject.
   */
  canBind(notAfterSeconds: number): "open" | "closed" {
    const meta = this.loadMeta();
    if (meta.revoked) return "closed";
    if (meta.subject === null && Math.floor(Date.now() / 1000) >= notAfterSeconds) {
      return "closed";
    }
    return "open";
  }

  /**
   * Reserve the mailbox for `subject`. First successful call stores the
   * identifier; a different identifier thereafter is refused. `notAfter`
   * applies only while the mailbox is unbound.
   */
  reserve(subject: Uint8Array, notAfterSeconds: number): ReserveResult {
    if (subject.length !== SUBJECT_BYTES) throw new Error("invalid subject size");
    const meta = this.loadMeta();
    if (meta.revoked) return "revoked";
    if (meta.subject === null) {
      if (Math.floor(Date.now() / 1000) >= notAfterSeconds) return "bind-window-closed";
      this.createSchema();
      this.ctx.storage.sql.exec(
        "INSERT INTO meta(id, subject, revoked) VALUES(0, ?, 0)",
        owned(subject),
      );
      this.meter()?.rowsWritten("reserve", 1);
      this.meta = { subject: subject.slice(), revoked: false };
      this.meter()?.observeStorage(this.ctx.storage.sql.databaseSize);
      return "bound";
    }
    if (
      meta.subject.length !== subject.length ||
      !crypto.subtle.timingSafeEqual(
        new Uint8Array(meta.subject).buffer as ArrayBuffer,
        new Uint8Array(subject).buffer as ArrayBuffer,
      )
    ) {
      return "subject-mismatch";
    }
    return "bound";
  }

  /**
   * Store one packet in this mailbox. The handle rides opaquely.
   *
   * Capacity is judged on the measured database size after the insert,
   * inside a transaction: the packet row's cell overhead and SQLite
   * page growth are real bytes on disk, and an optimistic
   * `body.length` estimate under-counts both. A projected overflow
   * rolls the insert back and answers transient `mailbox-full`; a
   * platform `SQLITE_FULL` — reached when capacity was configured at
   * or beyond the plan's per-object limit — maps to the same stable
   * transient answer. Already stored packets are never touched by
   * either path.
   */
  submit(handle: Uint8Array, body: Uint8Array): SubmitResult {
    const meta = this.loadMeta();
    if (meta.subject === null || meta.revoked) {
      return { outcome: "rejected", reason: "target-unavailable" };
    }
    const sql = this.ctx.storage.sql;
    try {
      return this.ctx.storage.transactionSync(() => {
        sql.exec("INSERT INTO packet(handle, body) VALUES(?, ?)", owned(handle), owned(body));
        if (sql.databaseSize > this.capacityBytes()) throw new CapacityExceeded();
        this.meter()?.rowsWritten("submit", 1);
        this.meter()?.observeStorage(sql.databaseSize);
        return { outcome: "accepted" };
      });
    } catch (error) {
      if (error instanceof CapacityExceeded || isStorageFull(error)) {
        return { outcome: "transient", reason: "mailbox-full" };
      }
      throw error;
    }
  }

  /**
   * Oldest-first packets not in `excludeSequences`, up to `limit`.
   * Claimed-but-unsettled packets replay on the next claim. Returns null
   * while the mailbox is unbound or revoked.
   */
  claim(excludeSequences: number[], limit: number): Packet[] | null {
    const meta = this.loadMeta();
    if (meta.subject === null || meta.revoked) return null;
    if (limit <= 0) return [];
    const rows = excludeSequences.length === 0
      ? this.ctx.storage.sql
          .exec("SELECT seq, handle, body FROM packet ORDER BY seq LIMIT ?", limit)
          .toArray()
      : this.ctx.storage.sql
          .exec(
            `SELECT seq, handle, body FROM packet WHERE seq NOT IN (${excludeSequences.map(() => "?").join(",")}) ORDER BY seq LIMIT ?`,
            ...excludeSequences,
            limit,
          )
          .toArray();
    this.meter()?.rowsRead("claim", rows.length);
    return (rows as Array<{ seq: number; handle: unknown; body: unknown }>).map((row) => ({
      sequence: row.seq,
      handle: fromSqliteBlob(row.handle),
      body: fromSqliteBlob(row.body),
    }));
  }

  /**
   * Settle stored packets by sequence; unknown sequences settle
   * vacuously. Returns false while the mailbox is unbound or revoked.
   */
  settle(sequences: number[]): boolean {
    const meta = this.loadMeta();
    if (meta.subject === null || meta.revoked) return false;
    for (const sequence of sequences) {
      this.ctx.storage.sql.exec("DELETE FROM packet WHERE seq = ?", sequence);
    }
    this.meter()?.rowsWritten("settle", sequences.length);
    this.meter()?.observeStorage(this.ctx.storage.sql.databaseSize);
    return true;
  }

  hasPending(): boolean {
    const meta = this.loadMeta();
    if (meta.subject === null || meta.revoked) return false;
    const rows = this.ctx.storage.sql.exec("SELECT seq FROM packet LIMIT 1").toArray();
    this.meter()?.rowsRead("hasPending", rows.length);
    return rows.length > 0;
  }

  /** Destroy the mailbox and refuse it forever. */
  async revoke(): Promise<void> {
    // Cloudflare counts deleteAll()'s removed rows as rows written;
    // COUNT(*) first keeps the aggregate honest. The extra read is once
    // per mailbox lifetime and cheaper than guessing — but it can only
    // run where a schema exists: a never-bound mailbox has no packet
    // table, and skipping the count must not skip the tombstone below.
    const meta = this.loadMeta();
    let remaining = 0;
    if (meta.subject !== null || meta.revoked) {
      remaining = Number(
        (this.ctx.storage.sql
          .exec("SELECT COUNT(*) AS n FROM packet")
          .toArray()[0] as { n: unknown } | undefined)?.n ?? 0,
      );
      this.meter()?.rowsRead("revoke", 1);
    }
    this.meter()?.rowsWritten("revoke", remaining + 1);
    await this.ctx.storage.deleteAll();
    // deleteAll drops the tables too; the tombstone needs meta back.
    this.createSchema();
    this.ctx.storage.sql.exec("INSERT INTO meta(id, subject, revoked) VALUES(0, NULL, 1)");
    this.meta = { subject: null, revoked: true };
    this.meter()?.observeStorage(this.ctx.storage.sql.databaseSize);
  }

  capacityBytes(): number {
    const value = this.options.capacityBytes();
    return Number.isFinite(value) && value > 0 ? Math.floor(value) : 1_000_000_000;
  }

  capacityInfo(): { bound: boolean; capacityBytes: number; databaseBytes: number } {
    return {
      bound: this.bound(),
      capacityBytes: this.capacityBytes(),
      databaseBytes: this.databaseBytes(),
    };
  }

  databaseBytes(): number {
    return this.ctx.storage.sql.databaseSize;
  }
}
