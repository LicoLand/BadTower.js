/**
 * AffiliationShard: one deterministic SQLite coordination atom per
 * affiliation (SHA-256 over the Station descriptor digest and affiliation
 * commitment). It owns bounded operation replay state and retry-safe
 * first-contact reservation; it never stores packet bytes.
 */

import { DurableObject } from "cloudflare:workers";
import { fromSqliteBlob, requireSqliteBlob, toBase64Url } from "../encoding";
import {
  CLEANUP_BATCH_ROWS,
  FailureClass,
  HandleClass,
  IDEMPOTENCY_WINDOW_SECONDS,
  MAX_OPERATION_ID_BYTES,
  MAX_OPERATION_RECORDS_PER_AFFILIATION,
  Operation,
  Outcome,
  RETRY_AFTER_MS_HEADER_VALUE,
} from "../transport/candidate";
import {
  encodeAffiliateFailureBody,
  encodeFirstContactReserveAcceptedBody,
  encodeReserveFailureBody,
  toHex,
} from "../transport/codec";
import { createRelayHandle, parseHandleKeyRing } from "../transport/handle";
import { acceptedResult, ambiguousResult, rejectedResult, transientResult } from "./rpc";
import type { RpcResult } from "./rpc";

const AFFILIATION_DOMAIN = "badtower.js-preview-affiliation-v1";
export interface ReserveInitArgs {
  handleClass: number;
}

export interface InitializeResult {
  ok: boolean;
  reason?: "conflict";
}

/** Deterministic per-affiliation object name (domain-separated SHA-256). */
export async function affiliationObjectName(
  descriptorDigest: Uint8Array,
  commitment: Uint8Array,
): Promise<string> {
  const enc = new TextEncoder();
  const domain = enc.encode(AFFILIATION_DOMAIN);
  const input = new Uint8Array(domain.length + 64);
  input.set(domain, 0);
  input.set(descriptorDigest, domain.length);
  input.set(commitment, domain.length + 32);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
  return toHex(digest);
}

/** Exact-size ArrayBuffer copy for SQLite BLOB bindings. */
export function toBlob(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.length);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

interface OperationRow {
  requestDigest: Uint8Array;
  phase: number;
  status: number;
  headers: string;
  body: Uint8Array;
  createdAt: number;
  expiresAt: number;
  pendingHandle: Uint8Array | null;
  pendingHandleClass: number | null;
}

export class AffiliationShard extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec(`
          CREATE TABLE IF NOT EXISTS operations (
            op_id BLOB PRIMARY KEY,
            request_digest BLOB NOT NULL,
            phase INTEGER NOT NULL,
            status INTEGER NOT NULL,
            headers TEXT NOT NULL,
            body BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            pending_handle BLOB,
            pending_handle_class INTEGER
          )
        `);
        this.ctx.storage.sql.exec(
          "CREATE INDEX IF NOT EXISTS operations_expiry ON operations(expires_at)",
        );
        this.ctx.storage.sql.exec(`
          CREATE TABLE IF NOT EXISTS usage (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            operation_count INTEGER NOT NULL
          )
        `);
        this.ctx.storage.sql.exec(
          "INSERT OR IGNORE INTO usage (id, operation_count) VALUES (1, 0)",
        );
      });
    });
  }

  private readOperation(opId: Uint8Array): OperationRow | null {
    const rows = this.ctx.storage.sql
      .exec(
        `SELECT request_digest, phase, status, headers, body, created_at,
                expires_at, pending_handle, pending_handle_class
           FROM operations WHERE op_id = ?`,
        toBlob(opId),
      )
      .toArray();
    if (rows.length === 0) return null;
    const row = rows[0]!;
    return {
      requestDigest: fromSqliteBlob(row.request_digest),
      phase: Number(row.phase),
      status: Number(row.status),
      headers: String(row.headers),
      body: fromSqliteBlob(row.body),
      createdAt: Number(row.created_at),
      expiresAt: Number(row.expires_at),
      pendingHandle:
        row.pending_handle === null
          ? null
          : fromSqliteBlob(row.pending_handle),
      pendingHandleClass:
        row.pending_handle_class === null ? null : Number(row.pending_handle_class),
    };
  }

  /** Targeted expiry plus one bounded indexed cleanup batch. */
  private prepareOperation(opId: Uint8Array, nowMs: number): OperationRow | null {
    return this.ctx.storage.transactionSync(() => {
      let remaining = CLEANUP_BATCH_ROWS;
      const current = this.readOperation(opId);
      if (current !== null && current.expiresAt <= nowMs) {
        this.ctx.storage.sql.exec("DELETE FROM operations WHERE op_id = ?", toBlob(opId));
        this.ctx.storage.sql.exec(
          "UPDATE usage SET operation_count = MAX(operation_count - 1, 0) WHERE id = 1",
        );
        remaining -= 1;
      }
      if (remaining > 0) {
        const due = this.ctx.storage.sql
          .exec(
            "SELECT op_id FROM operations WHERE expires_at <= ? ORDER BY expires_at LIMIT ?",
            nowMs,
            remaining,
          )
          .toArray();
        for (const row of due) {
          this.ctx.storage.sql.exec(
            "DELETE FROM operations WHERE op_id = ?",
            requireSqliteBlob(row.op_id),
          );
        }
        if (due.length > 0) {
          this.ctx.storage.sql.exec(
            "UPDATE usage SET operation_count = MAX(operation_count - ?, 0) WHERE id = 1",
            due.length,
          );
        }
      }
      return this.readOperation(opId);
    });
  }

  private operationCount(): number {
    const row = this.ctx.storage.sql
      .exec("SELECT operation_count FROM usage WHERE id = 1")
      .one();
    return Number(row.operation_count);
  }

  private recordPending(
    opId: Uint8Array,
    requestDigest: Uint8Array,
    nowMs: number,
    handle: Uint8Array,
    args: ReserveInitArgs,
  ): "recorded" | "exists" | "capacity" {
    return this.ctx.storage.transactionSync(() => {
      if (this.readOperation(opId) !== null) return "exists";
      if (this.operationCount() >= MAX_OPERATION_RECORDS_PER_AFFILIATION) return "capacity";
      this.ctx.storage.sql.exec(
        `INSERT INTO operations
           (op_id, request_digest, phase, status, headers, body, created_at, expires_at,
            pending_handle, pending_handle_class)
         VALUES (?, ?, 1, 0, '{}', x'', ?, ?, ?, ?)`,
        toBlob(opId),
        toBlob(requestDigest),
        nowMs,
        nowMs + IDEMPOTENCY_WINDOW_SECONDS * 1000,
        toBlob(handle),
        args.handleClass,
      );
      this.ctx.storage.sql.exec(
        "UPDATE usage SET operation_count = operation_count + 1 WHERE id = 1",
      );
      return "recorded";
    });
  }

  private recordNewFinal(
    opId: Uint8Array,
    requestDigest: Uint8Array,
    nowMs: number,
    result: RpcResult,
  ): void {
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(
        `INSERT INTO operations
           (op_id, request_digest, phase, status, headers, body, created_at, expires_at,
            pending_handle, pending_handle_class)
         VALUES (?, ?, 0, ?, ?, ?, ?, ?, NULL, NULL)`,
        toBlob(opId),
        toBlob(requestDigest),
        result.status,
        JSON.stringify(result.headers),
        toBlob(result.body),
        nowMs,
        nowMs + IDEMPOTENCY_WINDOW_SECONDS * 1000,
      );
      this.ctx.storage.sql.exec(
        "UPDATE usage SET operation_count = operation_count + 1 WHERE id = 1",
      );
    });
  }

  private finalizePending(opId: Uint8Array, result: RpcResult): OperationRow | null {
    return this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(
        `UPDATE operations
            SET phase = 0, status = ?, headers = ?, body = ?,
                pending_handle = NULL, pending_handle_class = NULL
          WHERE op_id = ? AND phase = 1`,
        result.status,
        JSON.stringify(result.headers),
        toBlob(result.body),
        toBlob(opId),
      );
      return this.readOperation(opId);
    });
  }

  private replay(row: OperationRow): RpcResult {
    return {
      status: row.status,
      headers: JSON.parse(row.headers) as Record<string, string>,
      body: row.body,
    };
  }

  private rejected(failure: FailureClass): RpcResult {
    return rejectedResult(
      encodeReserveFailureBody(Outcome.Rejected, { failureClass: failure }),
      failure,
    );
  }

  private affiliateRejected(failure: FailureClass): RpcResult {
    return rejectedResult(
      encodeAffiliateFailureBody(Outcome.Rejected, { failureClass: failure }),
      failure,
    );
  }

  private ambiguous(): RpcResult {
    return ambiguousResult(
      encodeReserveFailureBody(Outcome.Ambiguous, {
        failureClass: FailureClass.InternalUnavailable,
      }),
      FailureClass.InternalUnavailable,
    );
  }

  private capacity(body: Uint8Array): RpcResult {
    return transientResult(body, FailureClass.CapacityUnavailable);
  }

  private affiliateCapacity(): RpcResult {
    return transientResult(
      encodeAffiliateFailureBody(Outcome.Transient, {
        failureClass: FailureClass.CapacityUnavailable,
        retryAfterMs: RETRY_AFTER_MS_HEADER_VALUE,
      }),
      FailureClass.CapacityUnavailable,
    );
  }

  private async scheduleAlarm(): Promise<void> {
    const min = this.ctx.storage.sql
      .exec("SELECT MIN(expires_at) AS m FROM operations")
      .one().m;
    if (min === null) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(Number(min));
  }

  private async initializeHandle(
    handle: Uint8Array,
    args: ReserveInitArgs,
  ): Promise<InitializeResult> {
    try {
      return await this.env.RELAY_HANDLES.getByName(toBase64Url(handle)).initialize(handle, args);
    } catch {
      return { ok: false };
    }
  }

  private acceptedReserve(handle: Uint8Array): RpcResult {
    return acceptedResult(
      Operation.RESERVE,
      201,
      encodeFirstContactReserveAcceptedBody(handle),
    );
  }

  private validOperationInput(opId: Uint8Array, requestDigest: Uint8Array): boolean {
    return opId.length === MAX_OPERATION_ID_BYTES && requestDigest.length === 32;
  }

  /**
   * First-contact RESERVE. Storage-first: one pending handle and immutable
   * initialization arguments are persisted before the cross-object
   * RelayHandle.initialize call, so an interrupted call stays retryable and
   * never mints a second handle.
   */
  async reserve(
    opId: Uint8Array,
    requestDigest: Uint8Array,
    args: ReserveInitArgs,
  ): Promise<RpcResult> {
    if (
      !this.validOperationInput(opId, requestDigest) ||
      (args.handleClass !== HandleClass.Async && args.handleClass !== HandleClass.FirstContact)
    ) {
      return this.rejected(FailureClass.InvalidRequest);
    }

    const nowMs = Date.now();
    const existing = this.prepareOperation(opId, nowMs);
    if (existing !== null) {
      await this.scheduleAlarm();
      if (!bytesEqual(existing.requestDigest, requestDigest)) {
        return this.rejected(FailureClass.Conflict);
      }
      if (existing.phase === 0) return this.replay(existing);
      if (existing.pendingHandle === null || existing.pendingHandleClass === null) {
        return this.ambiguous();
      }
      const pendingArgs = { handleClass: existing.pendingHandleClass };
      const init = await this.initializeHandle(existing.pendingHandle, pendingArgs);
      if (!init.ok) return this.ambiguous();
      const result = this.acceptedReserve(existing.pendingHandle);
      const finalized = this.finalizePending(opId, result);
      await this.scheduleAlarm();
      return finalized !== null && finalized.phase === 0 ? this.replay(finalized) : this.ambiguous();
    }

    if (this.operationCount() >= MAX_OPERATION_RECORDS_PER_AFFILIATION) {
      await this.scheduleAlarm();
      return this.capacity(
        encodeReserveFailureBody(Outcome.Transient, {
          failureClass: FailureClass.CapacityUnavailable,
          retryAfterMs: RETRY_AFTER_MS_HEADER_VALUE,
        }),
      );
    }
    if (args.handleClass !== HandleClass.FirstContact) {
      const unsupported = this.rejected(FailureClass.UnsupportedProfile);
      this.recordNewFinal(opId, requestDigest, nowMs, unsupported);
      await this.scheduleAlarm();
      return unsupported;
    }

    const handleEnv = this.env as Env & {
      BADTOWER_HANDLE_KEYS?: unknown;
      BADTOWER_HANDLE_CURRENT_SLOT?: unknown;
    };
    const keyRing = parseHandleKeyRing(
      handleEnv.BADTOWER_HANDLE_KEYS,
      handleEnv.BADTOWER_HANDLE_CURRENT_SLOT,
    );
    if (keyRing === null) return this.ambiguous();
    const handle = await createRelayHandle(keyRing, nowMs);
    if (handle === null) return this.ambiguous();
    const pending = this.recordPending(opId, requestDigest, nowMs, handle, args);
    if (pending === "exists") return this.reserve(opId, requestDigest, args);
    if (pending === "capacity") {
      await this.scheduleAlarm();
      return this.capacity(
        encodeReserveFailureBody(Outcome.Transient, {
          failureClass: FailureClass.CapacityUnavailable,
          retryAfterMs: RETRY_AFTER_MS_HEADER_VALUE,
        }),
      );
    }
    await this.scheduleAlarm();
    const init = await this.initializeHandle(handle, args);
    if (!init.ok) return this.ambiguous();
    const result = this.acceptedReserve(handle);
    const finalized = this.finalizePending(opId, result);
    await this.scheduleAlarm();
    return finalized !== null && finalized.phase === 0 ? this.replay(finalized) : this.ambiguous();
  }

  /** AFFILIATE is validated by the entrypoint; the preview fails it closed. */
  async affiliate(opId: Uint8Array, requestDigest: Uint8Array): Promise<RpcResult> {
    if (!this.validOperationInput(opId, requestDigest)) {
      return this.affiliateRejected(FailureClass.InvalidRequest);
    }
    const nowMs = Date.now();
    const existing = this.prepareOperation(opId, nowMs);
    if (existing !== null) {
      await this.scheduleAlarm();
      if (!bytesEqual(existing.requestDigest, requestDigest)) {
        return this.affiliateRejected(FailureClass.Conflict);
      }
      if (existing.phase === 0) return this.replay(existing);
      return ambiguousResult(
        encodeAffiliateFailureBody(Outcome.Ambiguous, {
          failureClass: FailureClass.InternalUnavailable,
        }),
        FailureClass.InternalUnavailable,
      );
    }
    if (this.operationCount() >= MAX_OPERATION_RECORDS_PER_AFFILIATION) {
      await this.scheduleAlarm();
      return this.affiliateCapacity();
    }
    const result = this.affiliateRejected(FailureClass.UnsupportedProfile);
    this.recordNewFinal(opId, requestDigest, nowMs, result);
    await this.scheduleAlarm();
    return result;
  }

  override async alarm(): Promise<void> {
    const nowMs = Date.now();
    this.ctx.storage.transactionSync(() => {
      const due = this.ctx.storage.sql
        .exec(
          "SELECT op_id FROM operations WHERE expires_at <= ? ORDER BY expires_at LIMIT ?",
          nowMs,
          CLEANUP_BATCH_ROWS,
        )
        .toArray();
      for (const row of due) {
        this.ctx.storage.sql.exec(
          "DELETE FROM operations WHERE op_id = ?",
          requireSqliteBlob(row.op_id),
        );
      }
      if (due.length > 0) {
        this.ctx.storage.sql.exec(
          "UPDATE usage SET operation_count = MAX(operation_count - ?, 0) WHERE id = 1",
          due.length,
        );
      }
    });
    await this.scheduleAlarm();
  }
}
