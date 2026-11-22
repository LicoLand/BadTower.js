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
 * the mailbox and refuses it forever. Sequences come from a durable,
 * non-reusing allocator bumped inside the same transaction as the
 * packet insert, so a settled sequence can never name a newer packet.
 *
 * The first binding records which transport bound the mailbox
 * (`meta.via`). Recipient operations are admitted only through the
 * recorded transport — a listener-bound mailbox's packets belong to
 * the listener's proven owner, not to whoever happens to hold a copied
 * admission credential, and a natively bound mailbox is equally closed
 * to listener sessions. A mailbox bound before records existed carries
 * no transport: it accepts no submissions and admits no recipient
 * operation until a verified re-bind on either surface records one.
 *
 * The store owns only SQLite semantics — connections, listeners and
 * frame grammars belong to whoever composes it.
 */
import { fromSqliteBlob } from "./encoding";

export const SUBJECT_BYTES = 32;
export const IN_FLIGHT_WINDOW = 16;
export const MAX_PACKET_BYTES = 524288;

/**
 * First sequence the durable allocator may issue. Sequences below this
 * mark are the pre-allocator epoch: every sequence a mailbox bound
 * before the allocator existed could have issued stays under it (2^48
 * packets is beyond any live object's cumulative write history), so a
 * delayed or retried legacy settle can never name a newer packet.
 */
export const SEQUENCE_FLOOR = 281_474_976_710_656;

/**
 * The transport a mailbox was first bound through: the station's own
 * native surface, or a compatibility listener hosted in this object.
 */
export type BindingVia = "native" | "listener";

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

type Meta = { subject: Uint8Array | null; revoked: boolean; via: BindingVia | null };

/** A subarray's .buffer is its parent's — storing it would leak the whole message. */
function owned(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

/**
 * Constant-time equality over equal-length inputs: workerd's
 * `subtle.timingSafeEqual` where the platform offers it, a constant-
 * work byte loop elsewhere (plain Node has no such primitive).
 */
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  const subtle = crypto.subtle as SubtleCrypto & {
    timingSafeEqual?(x: BufferSource, y: BufferSource): boolean;
  };
  if (typeof subtle.timingSafeEqual === "function") {
    return subtle.timingSafeEqual(
      new Uint8Array(a).buffer as ArrayBuffer,
      new Uint8Array(b).buffer as ArrayBuffer,
    );
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i]! ^ b[i]!;
  return diff === 0;
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
  private schemaUpgraded = false;

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
      "CREATE TABLE IF NOT EXISTS meta(id INTEGER PRIMARY KEY CHECK(id = 0), subject BLOB, revoked INTEGER NOT NULL DEFAULT 0, via TEXT)",
    );
    this.ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS alloc(id INTEGER PRIMARY KEY CHECK(id = 0), next INTEGER NOT NULL)",
    );
    this.ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS packet(seq INTEGER PRIMARY KEY, handle BLOB NOT NULL, body BLOB NOT NULL)",
    );
  }

  /**
   * Bring a pre-existing schema forward before meta is read. Each step
   * is idempotent and none allocates a data page — column renames and
   * additions rewrite the schema record in place — so even a mailbox at
   * its storage ceiling still upgrades and can re-bind.
   *
   *   - the original schema kept the bound owner in meta.device_key;
   *     renaming it to subject preserves the owner, the revocation
   *     state and every queued packet;
   *   - the intermediate schema kept the binding transport in its own
   *     binding table; it folds into meta.via and the empty table is
   *     dropped, freeing its page.
   */
  private upgradeSchema(): void {
    if (this.schemaUpgraded) return;
    this.schemaUpgraded = true;
    const sql = this.ctx.storage.sql;
    const hasColumn = (table: string, column: string): boolean => {
      try {
        sql.exec(`SELECT ${column} FROM ${table} LIMIT 0`);
        return true;
      } catch {
        return false;
      }
    };
    // No meta table at all: the mailbox never bound — nothing to do.
    if (!hasColumn("meta", "id")) return;
    if (!hasColumn("meta", "subject") && hasColumn("meta", "device_key")) {
      sql.exec("ALTER TABLE meta RENAME COLUMN device_key TO subject");
    }
    if (!hasColumn("meta", "via")) {
      sql.exec("ALTER TABLE meta ADD COLUMN via TEXT");
    }
    if (hasColumn("binding", "via")) {
      const rows = sql.exec("SELECT via FROM binding WHERE id = 0").toArray();
      this.meter()?.rowsRead("binding", rows.length);
      const via = (rows[0] as { via: unknown } | undefined)?.via;
      sql.exec("DROP TABLE binding");
      if (via === "native" || via === "listener") {
        sql.exec("UPDATE meta SET via = ? WHERE id = 0 AND via IS NULL", via);
      }
    }
  }

  private loadMeta(): Meta {
    if (this.meta !== null) return this.meta;
    this.upgradeSchema();
    let rows: unknown[] = [];
    try {
      rows = this.ctx.storage.sql
        .exec("SELECT subject, revoked, via FROM meta WHERE id = 0")
        .toArray();
    } catch {
      // No meta table is an unbound mailbox, not an error.
    }
    this.meter()?.rowsRead("meta", rows.length);
    const row = rows[0] as
      | { subject: unknown; revoked: unknown; via: unknown }
      | undefined;
    this.meta = row === undefined
      ? { subject: null, revoked: false, via: null }
      : {
          subject: row.subject === null ? null : fromSqliteBlob(row.subject),
          revoked: row.revoked === 1,
          via: row.via === "native" || row.via === "listener" ? row.via : null,
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
   * The transport this mailbox was first bound through, or null while
   * unbound — including a bound mailbox whose binding predates binding
   * records, which must not be treated as native.
   */
  boundVia(): BindingVia | null {
    const meta = this.loadMeta();
    return meta.subject === null ? null : meta.via;
  }

  /**
   * Reserve the mailbox for `subject` through transport `via`. First
   * successful call stores the identifier and the binding transport
   * atomically; a different identifier thereafter is refused.
   * `notAfter` applies only while the mailbox is unbound.
   */
  reserve(
    subject: Uint8Array,
    notAfterSeconds: number,
    via: BindingVia,
  ): ReserveResult {
    if (subject.length !== SUBJECT_BYTES) throw new Error("invalid subject size");
    const meta = this.loadMeta();
    if (meta.revoked) return "revoked";
    if (meta.subject === null) {
      if (Math.floor(Date.now() / 1000) >= notAfterSeconds) return "bind-window-closed";
      this.createSchema();
      this.ctx.storage.sql.exec(
        "INSERT INTO meta(id, subject, revoked, via) VALUES(0, ?, 0, ?)",
        owned(subject),
        via,
      );
      this.meter()?.rowsWritten("reserve", 1);
      this.meta = { subject: subject.slice(), revoked: false, via };
      this.meter()?.observeStorage(this.ctx.storage.sql.databaseSize);
      return "bound";
    }
    if (!equalBytes(meta.subject, subject)) {
      return "subject-mismatch";
    }
    // A mailbox bound before transport records existed has no durable
    // transport yet: the first verified re-bind through either surface
    // records it and keeps the queued packets. The record lives in the
    // meta row itself, so the update writes in place — it needs no new
    // page and still lands on a mailbox at its storage ceiling. A
    // present record is never rewritten, so re-reserving cannot
    // retarget a mailbox.
    if (meta.via === null) {
      this.ctx.storage.sql.exec("UPDATE meta SET via = ? WHERE id = 0", via);
      this.meter()?.rowsWritten("reserve", 1);
      this.meta = { ...meta, via };
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
   *
   * The sequence is allocated inside the same transaction from a
   * durable allocator row. On first use the row is seeded at
   * SEQUENCE_FLOOR, above every sequence a mailbox bound before the
   * allocator existed could have issued, so a delayed or retried
   * legacy settle can never remove a newer packet under a reused
   * sequence. A rolled-back attempt leaves the allocator untouched:
   * the sequence was never assigned.
   */
  submit(handle: Uint8Array, body: Uint8Array): SubmitResult {
    const meta = this.loadMeta();
    if (meta.subject === null || meta.revoked || this.boundVia() === null) {
      // Unrecorded transport cannot receive through either surface;
      // the answer is the same shape as unbound or revoked.
      return { outcome: "rejected", reason: "target-unavailable" };
    }
    const sql = this.ctx.storage.sql;
    try {
      return this.ctx.storage.transactionSync(() => {
        // The allocator is lazily created here rather than at bind so
        // mailboxes bound before it existed get the same non-reusing
        // sequences.
        sql.exec(
          "CREATE TABLE IF NOT EXISTS alloc(id INTEGER PRIMARY KEY CHECK(id = 0), next INTEGER NOT NULL)",
        );
        const row = sql
          .exec("SELECT next FROM alloc WHERE id = 0")
          .toArray()[0] as { next: number } | undefined;
        let seeded = 0;
        let issued: number;
        if (row === undefined) {
          const live = (sql
            .exec("SELECT COALESCE(MAX(seq), 0) + 1 AS next FROM packet")
            .toArray()[0] as { next: number }).next;
          issued = Math.max(live, SEQUENCE_FLOOR);
          sql.exec("INSERT INTO alloc(id, next) VALUES(0, ?)", issued + 1);
          seeded = 1;
        } else {
          // A counter persisted below the floor predates the floor
          // itself: raise it inside this transaction so the issued
          // sequence — and every later one — stays above the
          // pre-allocator epoch.
          issued = Math.max(row.next, SEQUENCE_FLOOR);
          sql.exec("UPDATE alloc SET next = ? WHERE id = 0", issued + 1);
        }
        sql.exec(
          "INSERT INTO packet(seq, handle, body) VALUES(?, ?, ?)",
          issued,
          owned(handle),
          owned(body),
        );
        if (sql.databaseSize > this.capacityBytes()) throw new CapacityExceeded();
        this.meter()?.rowsRead("alloc", 1 + seeded);
        this.meter()?.rowsWritten("alloc", 1);
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
   * Recipient operations through a native surface. A mailbox bound
   * through a compatibility listener admits them only to that
   * listener's proven owner, so the native surface answers exactly as
   * it does for an unbound mailbox; sending stays open to every
   * admitted caller on either transport.
   */
  nativeClaim(excludeSequences: number[], limit: number): Packet[] | null {
    return this.boundVia() === "native" ? this.claim(excludeSequences, limit) : null;
  }

  nativeSettle(sequences: number[]): boolean {
    return this.boundVia() === "native" ? this.settle(sequences) : false;
  }

  nativeCapacityInfo(): {
    bound: boolean;
    capacityBytes: number;
    databaseBytes: number;
  } {
    return this.boundVia() === "native"
      ? this.capacityInfo()
      : { bound: false, capacityBytes: 0, databaseBytes: 0 };
  }

  /**
   * The listener's half of the same scope: recipient operations are
   * admitted only while the recorded binding is a compatibility
   * listener's. A natively bound mailbox is as closed to the listener
   * as a listener-bound one is to native claim — and an unrecorded
   * binding is closed to both.
   */
  listenerClaim(excludeSequences: number[], limit: number): Packet[] | null {
    return this.boundVia() === "listener" ? this.claim(excludeSequences, limit) : null;
  }

  listenerSettle(sequences: number[]): boolean {
    return this.boundVia() === "listener" ? this.settle(sequences) : false;
  }

  listenerHasPending(): boolean {
    return this.boundVia() === "listener" && this.hasPending();
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
    this.meta = { subject: null, revoked: true, via: null };
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
