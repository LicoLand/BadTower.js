/**
 * The Mailbox durable object: one permanent mailbox per station mailbox
 * id. Undelivered packets never expire — a stored row leaves only on the
 * recipient's ACK or on revocation. One live connection per mailbox; a
 * newly READY connection supersedes older ones.
 *
 * All per-socket state lives in the WebSocket attachment so the object
 * stays hibernatable: the only field kept outside attachments is a lazy
 * cache of the device key.
 */
import { CborError } from "./transport/cbor";
import {
  decodeClientFrame,
  encodeStationFrame,
  type ClientFrame,
  type StationFrame,
} from "./frames";
import { DurableObject } from "cloudflare:workers";
import { fromSqliteBlob, hexToBytes, toHex } from "./encoding";
import { emptyNoStore } from "./http";

const PROTOCOL = "licoarc.mailbox.v1";
const HELLO_CONTEXT = "licoarc-mailbox-hello-v1";
const WINDOW = 16;
const MAX_OUTSTANDING_SENDS = 16;
const CLOSE_MALFORMED = 1002;
const CLOSE_POLICY = 1008;
const CLOSE_SUPERSEDED = 4000;
const CLOSE_REVOKED = 4001;
const CLOSE_DEVICE_MISMATCH = 4003;

const OUTCOME_ACCEPTED = 0;
const OUTCOME_REJECTED = 1;
const OUTCOME_TRANSIENT = 2;
const FAIL_TARGET_UNAVAILABLE = 1;
const FAIL_MAILBOX_FULL = 3;
const FAIL_INTERNAL_UNAVAILABLE = 4;

type Attachment =
  | { state: "challenged"; nonce: Uint8Array }
  | { state: "ready"; inflight: number[] };

type Meta = { deviceKey: Uint8Array | null; revoked: boolean };

/** A subarray's .buffer is its parent's — storing it would leak the whole message. */
function owned(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

export class Mailbox extends DurableObject<Env> {
  private meta: Meta | null = null;

  /** Schema exists only where a mailbox exists: a never-bound object writes nothing. */
  private createSchema(): void {
    this.ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS meta(id INTEGER PRIMARY KEY CHECK(id = 0), device_key BLOB, revoked INTEGER NOT NULL DEFAULT 0)",
    );
    this.ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS packet(seq INTEGER PRIMARY KEY, handle BLOB NOT NULL, body BLOB NOT NULL)",
    );
  }

  private capacity(): number {
    const value = Number(this.env.BADTOWER_MAILBOX_CAPACITY_BYTES ?? "1000000000");
    return Number.isFinite(value) && value > 0 ? Math.floor(value) : 1_000_000_000;
  }

  private loadMeta(): Meta {
    if (this.meta !== null) return this.meta;
    let rows: unknown[] = [];
    try {
      rows = this.ctx.storage.sql
        .exec("SELECT device_key, revoked FROM meta WHERE id = 0")
        .toArray();
    } catch {
      // No meta table is an unbound mailbox, not an error.
    }
    const row = rows[0] as { device_key: unknown; revoked: unknown } | undefined;
    this.meta = row === undefined
      ? { deviceKey: null, revoked: false }
      : {
          deviceKey: row.device_key === null ? null : fromSqliteBlob(row.device_key),
          revoked: row.revoked === 1,
        };
    return this.meta;
  }

  private mailboxId(): Uint8Array {
    const id = hexToBytes(this.ctx.id.name ?? "");
    if (id === null || id.length !== 16) throw new Error("mailbox id mismatch");
    return id;
  }

  private attachment(ws: WebSocket): Attachment {
    return ws.deserializeAttachment() as Attachment;
  }

  private send(ws: WebSocket, frame: StationFrame): void {
    try {
      ws.send(encodeStationFrame(frame));
    } catch {
      // A stale socket in getWebSockets() must not abort the caller (e.g.
      // store() reporting a transient result after a durable insert); the
      // undelivered packet stays stored for the next live connection.
      this.close(ws, 1011);
    }
  }

  private close(ws: WebSocket, code: number): void {
    try {
      ws.close(code, "");
    } catch {
      // Already closed.
    }
  }

  override async fetch(request: Request): Promise<Response> {
    const meta = this.loadMeta();
    const raw = Number(request.headers.get("x-badtower-bind-not-after") ?? "0");
    // A malformed bind deadline fails safe: an unbound mailbox refuses;
    // a bound device still only faces its device-key check.
    const notAfter = Number.isFinite(raw) ? raw : 0;
    const bound = meta.deviceKey !== null;
    if (meta.revoked || (!bound && Math.floor(Date.now() / 1000) >= notAfter)) {
      return emptyNoStore(403);
    }
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.ctx.acceptWebSocket(server, [PROTOCOL]);
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    server.serializeAttachment({ state: "challenged", nonce } satisfies Attachment);
    this.send(server, { kind: "challenge", nonce });
    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: { "Sec-WebSocket-Protocol": PROTOCOL },
    });
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message === "string") {
      this.close(ws, CLOSE_MALFORMED);
      return;
    }
    let frame: ClientFrame;
    try {
      frame = decodeClientFrame(new Uint8Array(message));
    } catch (error) {
      this.close(ws, error instanceof CborError ? CLOSE_MALFORMED : CLOSE_POLICY);
      return;
    }
    const attachment = this.attachment(ws);
    try {
      if (attachment.state === "challenged") {
        await this.onChallenged(ws, attachment, frame);
      } else {
        await this.onReady(ws, attachment, frame);
      }
    } catch {
      this.close(ws, CLOSE_POLICY);
    }
  }

  private async onChallenged(ws: WebSocket, attachment: Attachment & { state: "challenged" }, frame: ClientFrame): Promise<void> {
    if (frame.kind !== "hello") {
      this.close(ws, CLOSE_POLICY);
      return;
    }
    const payload = new Uint8Array(HELLO_CONTEXT.length + attachment.nonce.length);
    payload.set(new TextEncoder().encode(HELLO_CONTEXT), 0);
    payload.set(attachment.nonce, HELLO_CONTEXT.length);
    const key = await crypto.subtle.importKey("raw", frame.deviceKey as BufferSource, "Ed25519", false, ["verify"]);
    const valid = await crypto.subtle.verify("Ed25519", key, frame.signature as BufferSource, payload);
    if (!valid) {
      this.close(ws, CLOSE_POLICY);
      return;
    }
    const meta = this.loadMeta();
    if (meta.deviceKey === null) {
      this.createSchema();
      this.ctx.storage.sql.exec(
        "INSERT INTO meta(id, device_key, revoked) VALUES(0, ?, 0)",
        owned(frame.deviceKey),
      );
      this.meta = { deviceKey: frame.deviceKey.slice(), revoked: false };
    } else if (
      meta.deviceKey.length !== frame.deviceKey.length ||
      !crypto.subtle.timingSafeEqual(
        new Uint8Array(meta.deviceKey).buffer as ArrayBuffer,
        new Uint8Array(frame.deviceKey).buffer as ArrayBuffer,
      )
    ) {
      this.close(ws, CLOSE_DEVICE_MISMATCH);
      return;
    }
    ws.serializeAttachment({ state: "ready", inflight: [] } satisfies Attachment);
    for (const other of this.ctx.getWebSockets()) {
      if (other !== ws && this.attachment(other).state === "ready") {
        this.close(other, CLOSE_SUPERSEDED);
      }
    }
    this.send(ws, { kind: "ready", mailboxId: this.mailboxId() });
    this.fill(ws, { state: "ready", inflight: [] });
  }

  private async onReady(ws: WebSocket, attachment: Attachment & { state: "ready" }, frame: ClientFrame): Promise<void> {
    switch (frame.kind) {
      case "send": {
        // The object stays active while awaiting the store RPC, so an
        // in-memory counter bounds outstanding SENDs exactly.
        const pending = this.pendingSends++;
        if (pending >= MAX_OUTSTANDING_SENDS) {
          this.pendingSends -= 1;
          this.close(ws, CLOSE_POLICY);
          return;
        }
        try {
          const target = this.env.MAILBOX.getByName(toHex(frame.handle.slice(0, 16)));
          const result = await target.store(frame.handle, frame.packet);
          const reply: StationFrame = {
            kind: "result",
            requestId: frame.requestId,
            outcome: result.outcome,
          };
          if (result.failureClass !== undefined) reply.failureClass = result.failureClass;
          this.send(ws, reply);
        } catch {
          this.send(ws, {
            kind: "result",
            requestId: frame.requestId,
            outcome: OUTCOME_TRANSIENT,
            failureClass: FAIL_INTERNAL_UNAVAILABLE,
          });
        } finally {
          this.pendingSends -= 1;
        }
        return;
      }
      case "ack": {
        this.ctx.storage.sql.exec("DELETE FROM packet WHERE seq = ?", frame.sequence);
        attachment.inflight = attachment.inflight.filter((seq) => seq !== frame.sequence);
        ws.serializeAttachment(attachment);
        this.fill(ws, attachment);
        return;
      }
      default:
        this.close(ws, CLOSE_POLICY);
    }
  }

  private pendingSends = 0;

  private fill(ws: WebSocket, attachment: Attachment & { state: "ready" }): void {
    const room = WINDOW - attachment.inflight.length;
    if (room > 0) {
      const rows = attachment.inflight.length === 0
        ? this.ctx.storage.sql
            .exec("SELECT seq, handle, body FROM packet ORDER BY seq LIMIT ?", room)
            .toArray()
        : this.ctx.storage.sql
            .exec(
              `SELECT seq, handle, body FROM packet WHERE seq NOT IN (${attachment.inflight.map(() => "?").join(",")}) ORDER BY seq LIMIT ?`,
              ...attachment.inflight,
              room,
            )
            .toArray();
      for (const row of rows as Array<{ seq: number; handle: unknown; body: unknown }>) {
        this.send(ws, {
          kind: "deliver",
          sequence: row.seq,
          handle: fromSqliteBlob(row.handle),
          packet: fromSqliteBlob(row.body),
        });
        attachment.inflight.push(row.seq);
      }
      if (attachment.inflight.length > 0) ws.serializeAttachment(attachment);
    }
    if (attachment.inflight.length === 0) {
      const remaining = this.ctx.storage.sql
        .exec("SELECT seq FROM packet LIMIT 1")
        .toArray();
      if (remaining.length === 0) this.send(ws, { kind: "drained" });
    }
  }

  /** Station→station RPC: store one packet in this mailbox. */
  async store(handle: Uint8Array, body: Uint8Array): Promise<StoreResult> {
    const meta = this.loadMeta();
    if (meta.deviceKey === null || meta.revoked) {
      return { outcome: OUTCOME_REJECTED, failureClass: FAIL_TARGET_UNAVAILABLE };
    }
    if (this.ctx.storage.sql.databaseSize + body.length > this.capacity()) {
      return { outcome: OUTCOME_TRANSIENT, failureClass: FAIL_MAILBOX_FULL };
    }
    this.ctx.storage.sql.exec(
      "INSERT INTO packet(handle, body) VALUES(?, ?)",
      owned(handle),
      owned(body),
    );
    for (const ws of this.ctx.getWebSockets()) {
      const attachment = this.attachment(ws);
      if (attachment.state === "ready") this.fill(ws, attachment);
    }
    return { outcome: OUTCOME_ACCEPTED };
  }

  /** Ops RPC: destroy the mailbox and refuse it forever. */
  async revoke(): Promise<void> {
    await this.ctx.storage.deleteAll();
    // deleteAll drops the tables too; the tombstone needs meta back.
    this.createSchema();
    this.ctx.storage.sql.exec("INSERT INTO meta(id, device_key, revoked) VALUES(0, NULL, 1)");
    this.meta = { deviceKey: null, revoked: true };
    for (const ws of this.ctx.getWebSockets()) {
      this.close(ws, CLOSE_REVOKED);
    }
  }
}

export type StoreResult = { outcome: number; failureClass?: number };
