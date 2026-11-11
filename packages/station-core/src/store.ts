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

type Meta = { subject: Uint8Array | null; revoked: boolean };

/** A subarray's .buffer is its parent's — storing it would leak the whole message. */
function owned(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

export class MailboxStore {
  private meta: Meta | null = null;

  constructor(
    private readonly ctx: DurableObjectState,
    private readonly options: { capacityBytes(): number },
  ) {}

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
      this.meta = { subject: subject.slice(), revoked: false };
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

  /** Store one packet in this mailbox. The handle rides opaquely. */
  submit(handle: Uint8Array, body: Uint8Array): SubmitResult {
    const meta = this.loadMeta();
    if (meta.subject === null || meta.revoked) {
      return { outcome: "rejected", reason: "target-unavailable" };
    }
    if (this.ctx.storage.sql.databaseSize + body.length > this.capacityBytes()) {
      return { outcome: "transient", reason: "mailbox-full" };
    }
    this.ctx.storage.sql.exec(
      "INSERT INTO packet(handle, body) VALUES(?, ?)",
      owned(handle),
      owned(body),
    );
    return { outcome: "accepted" };
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
    return true;
  }

  hasPending(): boolean {
    const meta = this.loadMeta();
    if (meta.subject === null || meta.revoked) return false;
    return (
      this.ctx.storage.sql.exec("SELECT seq FROM packet LIMIT 1").toArray().length > 0
    );
  }

  /** Destroy the mailbox and refuse it forever. */
  async revoke(): Promise<void> {
    await this.ctx.storage.deleteAll();
    // deleteAll drops the tables too; the tombstone needs meta back.
    this.createSchema();
    this.ctx.storage.sql.exec("INSERT INTO meta(id, subject, revoked) VALUES(0, NULL, 1)");
    this.meta = { subject: null, revoked: true };
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
