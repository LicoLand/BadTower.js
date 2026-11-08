/**
 * RelayHandle: one per-handle SQLite store for the bounded opaque relay
 * lifecycle. Owns raw packet BLOBs, usage counters, operation replay,
 * first-contact single use, claims, retrieval, settlement, and indexed
 * expiry cleanup with at most one alarm per handle.
 */

import { DurableObject } from "cloudflare:workers";
import { fromSqliteBlob, requireSqliteBlob, toBase64Url } from "../encoding";
import { CborWriter, encodeCborHead } from "../transport/cbor";
import {
  CLAIM_WINDOW_SECONDS,
  CLEANUP_BATCH_ROWS,
  FailureClass,
  HandleClass,
  IDEMPOTENCY_WINDOW_SECONDS,
  MAX_CACHED_RESPONSE_BYTES_PER_HANDLE,
  MAX_CLAIM_BYTES,
  MAX_CLAIM_ITEMS,
  MAX_CLAIM_RESPONSE_BYTES,
  MAX_OPERATION_ID_BYTES,
  MAX_OPERATION_RECORDS_PER_HANDLE,
  MAX_PACKET_BYTES,
  MAX_QUEUE_BYTES_PER_HANDLE,
  MAX_QUEUE_ITEMS_PER_HANDLE,
  MAX_SETTLEMENT_ATTEMPTS,
  MAX_SETTLEMENT_ITEMS,
  Operation,
  Outcome,
  RETRY_AFTER_MS_HEADER_VALUE,
  SettleAction,
  SettleOutcome,
  STORAGE_WINDOW_SECONDS,
} from "../transport/candidate";
import {
  encodeClaimAcceptedEmptyBody,
  encodeClaimFailureBody,
  encodeSettleAcceptedBody,
  encodeSettleFailureBody,
  encodeSubmitAcceptedBody,
  encodeSubmitFailureBody,
} from "../transport/codec";
import type { Settlement, SettlementResult } from "../transport/codec";
import { acceptedResult, rejectedResult, transientResult } from "./rpc";
import type { BufferedRpcResult, RpcResponse, RpcResult } from "./rpc";
import { bytesEqual, toBlob } from "./affiliation-shard";
import type { InitializeResult, ReserveInitArgs } from "./affiliation-shard";

/** Small control replays remain below workerd's SQLite value limit. */
const OPERATION_CHUNK_BYTES = 1_048_576;

interface OperationMeta {
  opId: Uint8Array;
  requestDigest: Uint8Array;
  status: number;
  headers: string;
  bodyLength: number;
  createdAt: number;
  expiresAt: number;
}

interface OperationRow extends OperationMeta {
  body: Uint8Array | null;
  manifest: StreamManifest | null;
}

type StreamManifest =
  | { kind: "claim"; claimId: Uint8Array; claimEpoch: number; items: ManifestItem[] }
  | { kind: "retrieve"; items: ManifestItem[] };

interface ManifestItem {
  itemId: Uint8Array;
  byteLen: number;
}

const STREAM_CHUNK_BYTES = 64 * 1024;
const STREAM_FIXED_ALLOWANCE_BYTES = 1024 * 1024;
export const STREAM_ALLOCATION_LIMIT_BYTES = 2 * MAX_PACKET_BYTES + STREAM_FIXED_ALLOWANCE_BYTES;

function concatSmall(parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function thisClaimItemPrefix(item: ManifestItem): Uint8Array {
  return concatSmall([
    encodeCborHead(5, 2),
    encodeCborHead(0, 0),
    encodeCborHead(2, item.itemId.length),
    item.itemId,
    encodeCborHead(0, 1),
    encodeCborHead(2, item.byteLen),
  ]);
}

function claimBodyLength(claimId: Uint8Array, epoch: number, items: ManifestItem[]): number {
  let length =
    CborWriter.uintSize(4) +
    CborWriter.uintSize(0) + CborWriter.uintSize(0) +
    CborWriter.uintSize(1) + CborWriter.bytesSize(claimId) +
    CborWriter.uintSize(2) + CborWriter.uintSize(epoch) +
    CborWriter.uintSize(3) + CborWriter.uintSize(items.length);
  for (const item of items) {
    length +=
      CborWriter.uintSize(2) +
      CborWriter.uintSize(0) + CborWriter.bytesSize(item.itemId) +
      CborWriter.uintSize(1) + CborWriter.uintSize(item.byteLen) + item.byteLen;
  }
  return length;
}

function claimItemLength(itemId: Uint8Array, byteLen: number): number {
  return CborWriter.uintSize(2) +
    CborWriter.uintSize(0) + CborWriter.bytesSize(itemId) +
    CborWriter.uintSize(1) + CborWriter.uintSize(byteLen) + byteLen;
}

interface MetadataRow {
  handle: Uint8Array;
  handleClass: number;
  firstContactRemaining: number;
  expiresAt: number;
}

interface UsageRow {
  itemCount: number;
  byteCount: number;
  claimEpoch: number;
  operationCount: number;
  cachedResponseBytes: number;
  nextQueueSeq: number;
}

interface ItemState {
  itemId: Uint8Array;
  byteLen: number;
  expiresAt: number;
  claimId: Uint8Array | null;
  claimEpoch: number | null;
  claimExpiresAt: number | null;
  settleAttempts: number;
}

export class RelayHandle extends DurableObject<Env> {
  /** Test-visible structural high-water estimate; never persisted or emitted. */
  private streamAllocationHighWaterBytes = 0;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.transactionSync(() => {
        const sql = this.ctx.storage.sql;
        sql.exec(`
          CREATE TABLE IF NOT EXISTS metadata (
            handle BLOB PRIMARY KEY,
            handle_class INTEGER NOT NULL,
            first_contact_remaining INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
          )
        `);
        sql.exec(`
          CREATE TABLE IF NOT EXISTS usage (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            item_count INTEGER NOT NULL,
            byte_count INTEGER NOT NULL,
            claim_epoch INTEGER NOT NULL,
            operation_count INTEGER NOT NULL,
            cached_response_bytes INTEGER NOT NULL,
            next_queue_seq INTEGER NOT NULL
          )
        `);
        sql.exec(`
          CREATE TABLE IF NOT EXISTS items (
            item_id BLOB PRIMARY KEY,
            packet BLOB NOT NULL,
            byte_len INTEGER NOT NULL,
            accepted_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            queue_seq INTEGER NOT NULL,
            claim_id BLOB,
            claim_epoch INTEGER,
            claim_expires_at INTEGER,
            settle_attempts INTEGER NOT NULL DEFAULT 0
          )
        `);
        sql.exec("CREATE INDEX IF NOT EXISTS items_queue ON items(queue_seq) WHERE claim_id IS NULL");
        sql.exec("CREATE INDEX IF NOT EXISTS items_expiry ON items(expires_at)");
        sql.exec("CREATE INDEX IF NOT EXISTS items_claim_expiry ON items(claim_expires_at)");
        sql.exec("CREATE INDEX IF NOT EXISTS items_claim_tuple ON items(claim_id, claim_epoch, item_id)");
        sql.exec(`
          CREATE TABLE IF NOT EXISTS retained_packets (
            item_id BLOB PRIMARY KEY,
            packet BLOB NOT NULL,
            byte_len INTEGER NOT NULL,
            retained_at INTEGER NOT NULL
          )
        `);
        sql.exec(`
          CREATE TABLE IF NOT EXISTS operations (
            op_id BLOB PRIMARY KEY,
            request_digest BLOB NOT NULL,
            status INTEGER NOT NULL,
            headers TEXT NOT NULL,
            body_length INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
          )
        `);
        sql.exec("CREATE INDEX IF NOT EXISTS operations_expiry ON operations(expires_at)");
        sql.exec(`
          CREATE TABLE IF NOT EXISTS operation_chunks (
            op_id BLOB NOT NULL,
            chunk_index INTEGER NOT NULL,
            body BLOB NOT NULL,
            PRIMARY KEY (op_id, chunk_index)
          )
        `);
        sql.exec(`
          CREATE TABLE IF NOT EXISTS operation_manifests (
            op_id BLOB PRIMARY KEY,
            kind INTEGER NOT NULL,
            claim_id BLOB,
            claim_epoch INTEGER
          )
        `);
        sql.exec(`
          CREATE TABLE IF NOT EXISTS operation_item_refs (
            op_id BLOB NOT NULL,
            item_index INTEGER NOT NULL,
            item_id BLOB NOT NULL,
            byte_len INTEGER NOT NULL,
            PRIMARY KEY (op_id, item_index)
          )
        `);
        sql.exec("CREATE INDEX IF NOT EXISTS operation_refs_item ON operation_item_refs(item_id)");
      });
    });
  }

  private sql() {
    return this.ctx.storage.sql;
  }

  private metadataRow(): MetadataRow | null {
    const rows = this.sql()
      .exec(
        "SELECT handle, handle_class, first_contact_remaining, expires_at FROM metadata LIMIT 1",
      )
      .toArray();
    if (rows.length === 0) return null;
    const row = rows[0]!;
    return {
      handle: fromSqliteBlob(row.handle),
      handleClass: Number(row.handle_class),
      firstContactRemaining: Number(row.first_contact_remaining),
      expiresAt: Number(row.expires_at),
    };
  }

  private usageRow(): UsageRow | null {
    const rows = this.sql()
      .exec(
        `SELECT item_count, byte_count, claim_epoch, operation_count,
                cached_response_bytes, next_queue_seq
           FROM usage WHERE id = 1`,
      )
      .toArray();
    if (rows.length === 0) return null;
    const row = rows[0]!;
    return {
      itemCount: Number(row.item_count),
      byteCount: Number(row.byte_count),
      claimEpoch: Number(row.claim_epoch),
      operationCount: Number(row.operation_count),
      cachedResponseBytes: Number(row.cached_response_bytes),
      nextQueueSeq: Number(row.next_queue_seq),
    };
  }

  private readOperationMeta(opId: Uint8Array): OperationMeta | null {
    const rows = this.sql()
      .exec(
        `SELECT op_id, request_digest, status, headers, body_length, created_at, expires_at
           FROM operations WHERE op_id = ?`,
        toBlob(opId),
      )
      .toArray();
    if (rows.length === 0) return null;
    const row = rows[0]!;
    return {
      opId: fromSqliteBlob(row.op_id),
      requestDigest: fromSqliteBlob(row.request_digest),
      status: Number(row.status),
      headers: String(row.headers),
      bodyLength: Number(row.body_length),
      createdAt: Number(row.created_at),
      expiresAt: Number(row.expires_at),
    };
  }

  private hydrateOperation(meta: OperationMeta): OperationRow {
    const manifestRows = this.sql()
      .exec(
        "SELECT kind, claim_id, claim_epoch FROM operation_manifests WHERE op_id = ?",
        toBlob(meta.opId),
      )
      .toArray();
    if (manifestRows.length > 0) {
      const header = manifestRows[0]!;
      const items = this.sql()
        .exec(
          `SELECT item_id, byte_len FROM operation_item_refs
            WHERE op_id = ? ORDER BY item_index`,
          toBlob(meta.opId),
        )
        .toArray()
        .map((row) => ({ itemId: fromSqliteBlob(row.item_id), byteLen: Number(row.byte_len) }));
      const manifest: StreamManifest =
        Number(header.kind) === 1
          ? {
              kind: "claim",
              claimId: fromSqliteBlob(header.claim_id),
              claimEpoch: Number(header.claim_epoch),
              items,
            }
          : { kind: "retrieve", items };
      return { ...meta, body: null, manifest };
    }
    const body = new Uint8Array(meta.bodyLength);
    const chunks = this.sql()
      .exec(
        "SELECT body FROM operation_chunks WHERE op_id = ? ORDER BY chunk_index",
        toBlob(meta.opId),
      )
      .toArray();
    let offset = 0;
    for (const row of chunks) {
      const chunk = fromSqliteBlob(row.body);
      if (offset + chunk.length > body.length) throw new Error("invalid operation replay chunks");
      body.set(chunk, offset);
      offset += chunk.length;
    }
    if (offset !== body.length) throw new Error("incomplete operation replay chunks");
    return { ...meta, body, manifest: null };
  }

  private readItemState(itemId: Uint8Array): ItemState | null {
    const rows = this.sql()
      .exec(
        `SELECT item_id, byte_len, expires_at, claim_id, claim_epoch,
                claim_expires_at, settle_attempts
           FROM items WHERE item_id = ?`,
        toBlob(itemId),
      )
      .toArray();
    if (rows.length === 0) return null;
    const row = rows[0]!;
    return this.itemStateFromRow(row);
  }

  private itemStateFromRow(row: Record<string, unknown>): ItemState {
    return {
      itemId: fromSqliteBlob(row.item_id),
      byteLen: Number(row.byte_len),
      expiresAt: Number(row.expires_at),
      claimId: row.claim_id === null ? null : fromSqliteBlob(row.claim_id),
      claimEpoch: row.claim_epoch === null ? null : Number(row.claim_epoch),
      claimExpiresAt:
        row.claim_expires_at === null ? null : Number(row.claim_expires_at),
      settleAttempts: Number(row.settle_attempts),
    };
  }

  private deleteOperationsTx(rows: OperationMeta[]): void {
    if (rows.length === 0) return;
    let bytes = 0;
    for (const row of rows) {
      const isManifest = this.sql()
        .exec("SELECT 1 AS present FROM operation_manifests WHERE op_id = ?", toBlob(row.opId))
        .toArray().length > 0;
      this.sql().exec("DELETE FROM operation_item_refs WHERE op_id = ?", toBlob(row.opId));
      this.sql().exec("DELETE FROM operation_manifests WHERE op_id = ?", toBlob(row.opId));
      this.sql().exec("DELETE FROM operation_chunks WHERE op_id = ?", toBlob(row.opId));
      this.sql().exec("DELETE FROM operations WHERE op_id = ?", toBlob(row.opId));
      if (!isManifest) bytes += row.bodyLength;
    }
    this.sql().exec(
      `UPDATE usage
          SET operation_count = MAX(operation_count - ?, 0),
              cached_response_bytes = MAX(cached_response_bytes - ?, 0)
        WHERE id = 1`,
      rows.length,
      bytes,
    );
  }

  /** At most limit logical item/claim/operation rows are changed. */
  private cleanupDueTx(nowMs: number, limit: number): void {
    const usage = this.usageRow();
    if (usage === null || limit <= 0) return;
    let remaining = limit;

    const expiredItems = this.sql()
      .exec(
        `SELECT item_id, byte_len FROM items
          WHERE expires_at <= ?
          ORDER BY expires_at LIMIT ?`,
        nowMs,
        remaining,
      )
      .toArray();
    let deletedBytes = 0;
    for (const row of expiredItems) {
      this.sql().exec(
        `INSERT INTO retained_packets (item_id, packet, byte_len, retained_at)
         SELECT item_id, packet, byte_len, ? FROM items
          WHERE item_id = ? AND EXISTS (
            SELECT 1 FROM operation_item_refs r WHERE r.item_id = items.item_id
          )`,
        nowMs,
        requireSqliteBlob(row.item_id),
      );
      this.sql().exec("DELETE FROM items WHERE item_id = ?", requireSqliteBlob(row.item_id));
      deletedBytes += Number(row.byte_len);
    }
    if (expiredItems.length > 0) {
      this.sql().exec(
        `UPDATE usage
            SET item_count = MAX(item_count - ?, 0),
                byte_count = MAX(byte_count - ?, 0)
          WHERE id = 1`,
        expiredItems.length,
        deletedBytes,
      );
      remaining -= expiredItems.length;
    }

    if (remaining > 0) {
      const expiredClaims = this.sql()
        .exec(
          `SELECT item_id FROM items
            WHERE expires_at > ? AND claim_expires_at IS NOT NULL AND claim_expires_at <= ?
            ORDER BY claim_expires_at LIMIT ?`,
          nowMs,
          nowMs,
          remaining,
        )
        .toArray();
      for (const row of expiredClaims) {
        this.sql().exec(
          `UPDATE items
              SET claim_id = NULL, claim_epoch = NULL, claim_expires_at = NULL
            WHERE item_id = ?`,
          requireSqliteBlob(row.item_id),
        );
      }
      remaining -= expiredClaims.length;
    }

    if (remaining > 0) {
      const retiredItems = this.sql()
        .exec(
          `SELECT item_id FROM retained_packets
            WHERE 1 = 1
              AND NOT EXISTS (
                SELECT 1 FROM operation_item_refs r
                  WHERE r.item_id = retained_packets.item_id
              )
            ORDER BY retained_at LIMIT ?`,
          remaining,
        )
        .toArray();
      for (const row of retiredItems) {
        this.sql().exec(
          "DELETE FROM retained_packets WHERE item_id = ?",
          requireSqliteBlob(row.item_id),
        );
      }
      remaining -= retiredItems.length;
    }

    if (remaining > 0) {
      const expiredOps = this.sql()
        .exec(
          `SELECT op_id, request_digest, status, headers, body_length, created_at, expires_at
             FROM operations WHERE expires_at <= ? ORDER BY expires_at LIMIT ?`,
          nowMs,
          remaining,
        )
        .toArray()
        .map((row) => this.operationMetaFromRow(row));
      this.deleteOperationsTx(expiredOps);
    }
  }

  private operationMetaFromRow(row: Record<string, unknown>): OperationMeta {
    return {
      opId: fromSqliteBlob(row.op_id),
      requestDigest: fromSqliteBlob(row.request_digest),
      status: Number(row.status),
      headers: String(row.headers),
      bodyLength: Number(row.body_length),
      createdAt: Number(row.created_at),
      expiresAt: Number(row.expires_at),
    };
  }

  /** Targeted idempotency expiry plus one bounded indexed cleanup batch. */
  private prepareOperation(opId: Uint8Array, nowMs: number): OperationRow | null {
    const meta = this.ctx.storage.transactionSync(() => {
      let remaining = CLEANUP_BATCH_ROWS;
      const current = this.readOperationMeta(opId);
      if (current !== null && current.expiresAt <= nowMs) {
        this.deleteOperationsTx([current]);
        remaining -= 1;
      }
      this.cleanupDueTx(nowMs, remaining);
      return this.readOperationMeta(opId);
    });
    return meta === null ? null : this.hydrateOperation(meta);
  }

  private canCacheResponse(usage: UsageRow, bodyLength: number): boolean {
    return (
      usage.operationCount < MAX_OPERATION_RECORDS_PER_HANDLE &&
      usage.cachedResponseBytes + bodyLength <= MAX_CACHED_RESPONSE_BYTES_PER_HANDLE
    );
  }

  private recordOperationTx(
    opId: Uint8Array,
    requestDigest: Uint8Array,
    nowMs: number,
    result: BufferedRpcResult,
  ): void {
    this.sql().exec(
      `INSERT INTO operations
         (op_id, request_digest, status, headers, body_length, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      toBlob(opId),
      toBlob(requestDigest),
      result.status,
      JSON.stringify(result.headers),
      result.body.length,
      nowMs,
      nowMs + IDEMPOTENCY_WINDOW_SECONDS * 1000,
    );
    let chunkIndex = 0;
    for (let offset = 0; offset < result.body.length; offset += OPERATION_CHUNK_BYTES) {
      const end = Math.min(offset + OPERATION_CHUNK_BYTES, result.body.length);
      this.sql().exec(
        "INSERT INTO operation_chunks (op_id, chunk_index, body) VALUES (?, ?, ?)",
        toBlob(opId),
        chunkIndex,
        toBlob(result.body.subarray(offset, end)),
      );
      chunkIndex += 1;
    }
    this.sql().exec(
      `UPDATE usage
          SET operation_count = operation_count + 1,
              cached_response_bytes = cached_response_bytes + ?
        WHERE id = 1`,
      result.body.length,
    );
  }

  private recordManifestOperationTx(
    opId: Uint8Array,
    requestDigest: Uint8Array,
    nowMs: number,
    status: number,
    headers: Record<string, string>,
    bodyLength: number,
    manifest: StreamManifest,
  ): void {
    this.sql().exec(
      `INSERT INTO operations
         (op_id, request_digest, status, headers, body_length, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      toBlob(opId),
      toBlob(requestDigest),
      status,
      JSON.stringify(headers),
      bodyLength,
      nowMs,
      nowMs + IDEMPOTENCY_WINDOW_SECONDS * 1000,
    );
    this.sql().exec(
      `INSERT INTO operation_manifests (op_id, kind, claim_id, claim_epoch)
       VALUES (?, ?, ?, ?)`,
      toBlob(opId),
      manifest.kind === "claim" ? 1 : 2,
      manifest.kind === "claim" ? toBlob(manifest.claimId) : null,
      manifest.kind === "claim" ? manifest.claimEpoch : null,
    );
    for (let index = 0; index < manifest.items.length; index += 1) {
      const item = manifest.items[index]!;
      this.sql().exec(
        `INSERT INTO operation_item_refs (op_id, item_index, item_id, byte_len)
         VALUES (?, ?, ?, ?)`,
        toBlob(opId),
        index,
        toBlob(item.itemId),
        item.byteLen,
      );
    }
    this.sql().exec(
      "UPDATE usage SET operation_count = operation_count + 1 WHERE id = 1",
    );
  }

  private replay(row: OperationRow): RpcResponse {
    if (row.manifest !== null) {
      return {
        status: row.status,
        headers: JSON.parse(row.headers) as Record<string, string>,
        body: this.streamManifest(row.manifest),
      };
    }
    if (row.body === null) throw new Error("operation has no response representation");
    return {
      status: row.status,
      headers: JSON.parse(row.headers) as Record<string, string>,
      body: row.body,
    };
  }

  private streamManifest(manifest: StreamManifest): ReadableStream<Uint8Array> {
    const prefix = manifest.kind === "claim"
      ? this.claimPrefix(manifest.claimId, manifest.claimEpoch, manifest.items.length)
      : new Uint8Array(0);
    let itemIndex = 0;
    let packet: Uint8Array | null = null;
    let packetOffset = 0;
    let itemPrefix: Uint8Array | null = prefix.length > 0 ? prefix : null;
    let cancelled = false;
    const sql = this.sql();
    const manifestBytes = prefix.length + manifest.items.reduce(
      (total, item) => total + item.itemId.length + 8,
      0,
    );
    const observe = (packetBytes: number): void => {
      // Conservatively include the live packet, one equal-sized runtime
      // handoff, a full encoder chunk, and all manifest metadata.
      const liveBytes = manifestBytes + 2 * packetBytes + STREAM_CHUNK_BYTES;
      this.streamAllocationHighWaterBytes = Math.max(
        this.streamAllocationHighWaterBytes,
        liveBytes,
      );
      if (liveBytes > STREAM_ALLOCATION_LIMIT_BYTES) {
        throw new Error("stream allocation watermark exceeded");
      }
    };
    observe(0);

    return new ReadableStream<Uint8Array>({
      pull(controller) {
        if (cancelled) return;
        if (itemPrefix !== null) {
          controller.enqueue(itemPrefix);
          itemPrefix = null;
          return;
        }
        if (packet !== null && packetOffset < packet.length) {
          const end = Math.min(packetOffset + STREAM_CHUNK_BYTES, packet.length);
          controller.enqueue(packet.subarray(packetOffset, end));
          packetOffset = end;
          if (packetOffset === packet.length) {
            packet = null;
            packetOffset = 0;
            itemIndex += 1;
          }
          return;
        }
        const item = manifest.items[itemIndex];
        if (item === undefined) {
          controller.close();
          return;
        }
        const rows = sql
          .exec(
            `SELECT packet FROM items WHERE item_id = ?
             UNION ALL
             SELECT packet FROM retained_packets WHERE item_id = ?
             LIMIT 1`,
            toBlob(item.itemId),
            toBlob(item.itemId),
          )
          .toArray();
        if (rows.length !== 1) {
          controller.error(new Error("referenced packet unavailable"));
          return;
        }
        packet = fromSqliteBlob(rows[0]!.packet);
        if (packet.length !== item.byteLen) {
          controller.error(new Error("referenced packet length mismatch"));
          return;
        }
        observe(packet.length);
        itemPrefix = manifest.kind === "claim" ? thisClaimItemPrefix(item) : null;
        if (itemPrefix !== null) {
          controller.enqueue(itemPrefix);
          itemPrefix = null;
          return;
        }
        const end = Math.min(STREAM_CHUNK_BYTES, packet.length);
        controller.enqueue(packet.subarray(0, end));
        packetOffset = end;
        if (packetOffset === packet.length) {
          packet = null;
          packetOffset = 0;
          itemIndex += 1;
        }
      },
      cancel() {
        cancelled = true;
        packet = null;
      },
    });
  }

  private claimPrefix(claimId: Uint8Array, epoch: number, itemCount: number): Uint8Array {
    return concatSmall([
      encodeCborHead(5, 4), encodeCborHead(0, 0), encodeCborHead(0, 0),
      encodeCborHead(0, 1), encodeCborHead(2, claimId.length), claimId,
      encodeCborHead(0, 2), encodeCborHead(0, epoch), encodeCborHead(0, 3),
      encodeCborHead(4, itemCount),
    ]);
  }

  private rejected(failure: FailureClass, body: Uint8Array): RpcResult {
    return rejectedResult(body, failure);
  }

  private capacity(body: Uint8Array): RpcResult {
    return transientResult(body, FailureClass.CapacityUnavailable);
  }

  private async scheduleAlarm(): Promise<void> {
    const min = this.sql()
      .exec(
        `SELECT MIN(m) AS m FROM (
           SELECT MIN(expires_at) AS m FROM items
           UNION ALL SELECT MIN(claim_expires_at) FROM items WHERE claim_expires_at IS NOT NULL
           UNION ALL SELECT MIN(retained_at) FROM retained_packets
             WHERE NOT EXISTS (
               SELECT 1 FROM operation_item_refs r
                 WHERE r.item_id = retained_packets.item_id
             )
           UNION ALL SELECT MIN(expires_at) FROM operations
           UNION ALL SELECT MIN(expires_at) FROM metadata
         )`,
      )
      .one().m;
    if (min === null) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(Number(min));
  }

  private async finish<T extends RpcResponse>(result: T): Promise<T> {
    await this.scheduleAlarm();
    return result;
  }

  private validOperationInput(opId: Uint8Array, requestDigest: Uint8Array): boolean {
    return opId.length === MAX_OPERATION_ID_BYTES && requestDigest.length === 32;
  }

  /** Exact idempotent insert-or-compare initialization. */
  async initialize(handle: Uint8Array, args: ReserveInitArgs): Promise<InitializeResult> {
    if (handle.length !== 32 || args.handleClass !== HandleClass.FirstContact) {
      return { ok: false, reason: "conflict" };
    }
    const nowMs = Date.now();
    const result = this.ctx.storage.transactionSync<InitializeResult>(() => {
      const existing = this.metadataRow();
      if (existing !== null) {
        const usage = this.usageRow();
        return usage !== null && bytesEqual(existing.handle, handle) && existing.handleClass === args.handleClass
          ? { ok: true }
          : { ok: false, reason: "conflict" };
      }
      this.sql().exec(
        `INSERT INTO metadata (handle, handle_class, first_contact_remaining, created_at, expires_at)
         VALUES (?, ?, 1, ?, ?)`,
        toBlob(handle),
        args.handleClass,
        nowMs,
        nowMs + STORAGE_WINDOW_SECONDS * 1000,
      );
      this.sql().exec(
        `INSERT INTO usage
           (id, item_count, byte_count, claim_epoch, operation_count,
            cached_response_bytes, next_queue_seq)
         VALUES (1, 0, 0, 0, 0, 0, 0)`,
      );
      return { ok: true };
    });
    await this.scheduleAlarm();
    return result;
  }

  async submit(
    opId: Uint8Array,
    requestDigest: Uint8Array,
    packet: Uint8Array,
  ): Promise<RpcResponse> {
    if (!this.validOperationInput(opId, requestDigest)) {
      return this.rejected(
        FailureClass.InvalidRequest,
        encodeSubmitFailureBody(Outcome.Rejected, { failureClass: FailureClass.InvalidRequest }),
      );
    }
    if (packet.length < 1 || packet.length > MAX_PACKET_BYTES) {
      return this.rejected(
        FailureClass.PacketTooLarge,
        encodeSubmitFailureBody(Outcome.Rejected, { failureClass: FailureClass.PacketTooLarge }),
      );
    }

    const nowMs = Date.now();
    const existing = this.prepareOperation(opId, nowMs);
    if (existing !== null) {
      if (!bytesEqual(existing.requestDigest, requestDigest)) {
        return this.finish(
          this.rejected(
            FailureClass.Conflict,
            encodeSubmitFailureBody(Outcome.Rejected, { failureClass: FailureClass.Conflict }),
          ),
        );
      }
      return this.finish(this.replay(existing));
    }

    const result = this.ctx.storage.transactionSync<RpcResponse>(() => {
      const metadata = this.metadataRow();
      const usage = this.usageRow();
      if (metadata === null || usage === null || metadata.expiresAt <= nowMs) {
        return this.rejected(
          FailureClass.TargetUnavailable,
          encodeSubmitFailureBody(Outcome.Rejected, { failureClass: FailureClass.TargetUnavailable }),
        );
      }
      if (metadata.firstContactRemaining === 0) {
        return this.capacity(
          encodeSubmitFailureBody(Outcome.Transient, {
            failureClass: FailureClass.CapacityUnavailable,
            retryAfterMs: RETRY_AFTER_MS_HEADER_VALUE,
          }),
        );
      }
      if (
        usage.itemCount >= MAX_QUEUE_ITEMS_PER_HANDLE ||
        usage.byteCount + packet.length > MAX_QUEUE_BYTES_PER_HANDLE
      ) {
        return this.capacity(
          encodeSubmitFailureBody(Outcome.Transient, {
            failureClass: FailureClass.CapacityUnavailable,
            retryAfterMs: RETRY_AFTER_MS_HEADER_VALUE,
          }),
        );
      }
      const accepted = acceptedResult(Operation.SUBMIT, 202, encodeSubmitAcceptedBody());
      if (!this.canCacheResponse(usage, accepted.body.length)) {
        return this.capacity(
          encodeSubmitFailureBody(Outcome.Transient, {
            failureClass: FailureClass.CapacityUnavailable,
            retryAfterMs: RETRY_AFTER_MS_HEADER_VALUE,
          }),
        );
      }
      const queueSeq = usage.nextQueueSeq + 1;
      if (!Number.isSafeInteger(queueSeq)) {
        return this.capacity(
          encodeSubmitFailureBody(Outcome.Transient, {
            failureClass: FailureClass.CapacityUnavailable,
            retryAfterMs: RETRY_AFTER_MS_HEADER_VALUE,
          }),
        );
      }
      const itemId = crypto.getRandomValues(new Uint8Array(32));
      const itemExpiresAt = nowMs + STORAGE_WINDOW_SECONDS * 1000;
      this.sql().exec(
        `INSERT INTO items
           (item_id, packet, byte_len, accepted_at, expires_at, queue_seq)
         VALUES (?, ?, ?, ?, ?, ?)`,
        toBlob(itemId),
        toBlob(packet),
        packet.length,
        nowMs,
        itemExpiresAt,
        queueSeq,
      );
      this.sql().exec(
        `UPDATE usage
            SET item_count = item_count + 1,
                byte_count = byte_count + ?,
                next_queue_seq = ?
          WHERE id = 1`,
        packet.length,
        queueSeq,
      );
      this.sql().exec(
        `UPDATE metadata
            SET first_contact_remaining = 0,
                expires_at = MAX(expires_at, ?)`,
        itemExpiresAt,
      );
      this.recordOperationTx(opId, requestDigest, nowMs, accepted);
      return accepted;
    });
    return this.finish(result);
  }

  async claim(
    opId: Uint8Array,
    requestDigest: Uint8Array,
    maxItems: number,
  ): Promise<RpcResponse> {
    if (
      !this.validOperationInput(opId, requestDigest) ||
      !Number.isSafeInteger(maxItems) ||
      maxItems < 1 ||
      maxItems > MAX_CLAIM_ITEMS
    ) {
      return this.rejected(
        FailureClass.InvalidRequest,
        encodeClaimFailureBody(Outcome.Rejected, { failureClass: FailureClass.InvalidRequest }),
      );
    }

    const nowMs = Date.now();
    const existing = this.prepareOperation(opId, nowMs);
    if (existing !== null) {
      if (!bytesEqual(existing.requestDigest, requestDigest)) {
        return this.finish(
          this.rejected(
            FailureClass.Conflict,
            encodeClaimFailureBody(Outcome.Rejected, { failureClass: FailureClass.Conflict }),
          ),
        );
      }
      return this.finish(this.replay(existing));
    }

    const result = this.ctx.storage.transactionSync<RpcResponse>(() => {
      const metadata = this.metadataRow();
      const usage = this.usageRow();
      if (metadata === null || usage === null || metadata.expiresAt <= nowMs) {
        return this.rejected(
          FailureClass.TargetUnavailable,
          encodeClaimFailureBody(Outcome.Rejected, { failureClass: FailureClass.TargetUnavailable }),
        );
      }
      const epoch = usage.claimEpoch + 1;
      if (!Number.isSafeInteger(epoch)) {
        return this.capacity(
          encodeClaimFailureBody(Outcome.Transient, {
            failureClass: FailureClass.CapacityUnavailable,
            retryAfterMs: RETRY_AFTER_MS_HEADER_VALUE,
          }),
        );
      }
      const rows = this.sql()
        .exec(
          `SELECT item_id, byte_len FROM items
            WHERE claim_id IS NULL AND expires_at > ?
            ORDER BY queue_seq LIMIT ?`,
          nowMs,
          maxItems,
        )
        .toArray();
      const selected: ManifestItem[] = [];
      let packetBytes = 0;
      const fixedResponseBytes = claimBodyLength(new Uint8Array(32), epoch, []);
      let encodedItemsBytes = 0;
      for (const row of rows) {
        const itemId = fromSqliteBlob(row.item_id);
        const byteLen = Number(row.byte_len);
        const nextPacketBytes = packetBytes + byteLen;
        if (nextPacketBytes > MAX_CLAIM_BYTES) break;
        const nextItemsBytes = encodedItemsBytes + claimItemLength(itemId, byteLen);
        const nextResponseBytes = fixedResponseBytes - CborWriter.uintSize(0) +
          CborWriter.uintSize(selected.length + 1) + nextItemsBytes;
        if (nextResponseBytes > MAX_CLAIM_RESPONSE_BYTES) break;
        selected.push({ itemId, byteLen });
        packetBytes = nextPacketBytes;
        encodedItemsBytes = nextItemsBytes;
      }

      if (selected.length === 0) {
        const accepted = acceptedResult(
          Operation.CLAIM,
          200,
          encodeClaimAcceptedEmptyBody(),
        );
        if (!this.canCacheResponse(usage, accepted.body.length)) {
          return this.capacity(
            encodeClaimFailureBody(Outcome.Transient, {
              failureClass: FailureClass.CapacityUnavailable,
              retryAfterMs: RETRY_AFTER_MS_HEADER_VALUE,
            }),
          );
        }
        this.recordOperationTx(opId, requestDigest, nowMs, accepted);
        return accepted;
      }

      const claimId = crypto.getRandomValues(new Uint8Array(32));
      const headers = acceptedResult(Operation.CLAIM, 200, new Uint8Array(0), {
        "licoarc-claim-id": toBase64Url(claimId),
        "licoarc-claim-epoch": String(epoch),
      }).headers;
      if (usage.operationCount >= MAX_OPERATION_RECORDS_PER_HANDLE) {
        return this.capacity(
          encodeClaimFailureBody(Outcome.Transient, {
            failureClass: FailureClass.CapacityUnavailable,
            retryAfterMs: RETRY_AFTER_MS_HEADER_VALUE,
          }),
        );
      }
      this.sql().exec("UPDATE usage SET claim_epoch = ? WHERE id = 1", epoch);
      for (const item of selected) {
        this.sql().exec(
          `UPDATE items
              SET claim_id = ?, claim_epoch = ?, claim_expires_at = ?
            WHERE item_id = ?`,
          toBlob(claimId),
          epoch,
          nowMs + CLAIM_WINDOW_SECONDS * 1000,
          toBlob(item.itemId),
        );
      }
      const manifest: StreamManifest = { kind: "claim", claimId, claimEpoch: epoch, items: selected };
      const bodyLength = claimBodyLength(claimId, epoch, selected);
      this.recordManifestOperationTx(opId, requestDigest, nowMs, 200, headers, bodyLength, manifest);
      return { status: 200, headers, body: this.streamManifest(manifest) };
    });
    return this.finish(result);
  }

  async retrieve(
    opId: Uint8Array,
    requestDigest: Uint8Array,
    claimId: Uint8Array,
    claimEpoch: number,
    itemId: Uint8Array,
  ): Promise<RpcResponse> {
    if (
      !this.validOperationInput(opId, requestDigest) ||
      claimId.length !== 32 ||
      itemId.length !== 32 ||
      !Number.isSafeInteger(claimEpoch) ||
      claimEpoch < 0
    ) {
      return this.rejected(
        FailureClass.InvalidRequest,
        encodeSubmitFailureBody(Outcome.Rejected, { failureClass: FailureClass.InvalidRequest }),
      );
    }

    const nowMs = Date.now();
    const existing = this.prepareOperation(opId, nowMs);
    if (existing !== null) {
      if (!bytesEqual(existing.requestDigest, requestDigest)) {
        return this.finish(
          this.rejected(
            FailureClass.Conflict,
            encodeSubmitFailureBody(Outcome.Rejected, { failureClass: FailureClass.Conflict }),
          ),
        );
      }
      return this.finish(this.replay(existing));
    }

    const result = this.ctx.storage.transactionSync<RpcResponse>(() => {
      const metadata = this.metadataRow();
      const usage = this.usageRow();
      if (metadata === null || usage === null || metadata.expiresAt <= nowMs) {
        return this.rejected(
          FailureClass.TargetUnavailable,
          encodeSubmitFailureBody(Outcome.Rejected, { failureClass: FailureClass.TargetUnavailable }),
        );
      }
      const item = this.readItemState(itemId);
      const live =
        item !== null &&
        item.expiresAt > nowMs &&
        item.claimId !== null &&
        item.claimEpoch !== null &&
        item.claimExpiresAt !== null &&
        item.claimExpiresAt > nowMs &&
        bytesEqual(item.claimId, claimId) &&
        item.claimEpoch === claimEpoch;
      if (!live) {
        return this.rejected(
          FailureClass.TargetUnavailable,
          encodeSubmitFailureBody(Outcome.Rejected, { failureClass: FailureClass.TargetUnavailable }),
        );
      }
      const headers = acceptedResult(Operation.RETRIEVE, 200, new Uint8Array(0)).headers;
      if (usage.operationCount >= MAX_OPERATION_RECORDS_PER_HANDLE) {
        return this.capacity(
          encodeSubmitFailureBody(Outcome.Transient, {
            failureClass: FailureClass.CapacityUnavailable,
            retryAfterMs: RETRY_AFTER_MS_HEADER_VALUE,
          }),
        );
      }
      const manifest: StreamManifest = {
        kind: "retrieve",
        items: [{ itemId: item.itemId, byteLen: item.byteLen }],
      };
      this.recordManifestOperationTx(
        opId, requestDigest, nowMs, 200, headers, item.byteLen, manifest,
      );
      return { status: 200, headers, body: this.streamManifest(manifest) };
    });
    return this.finish(result);
  }

  async settle(
    opId: Uint8Array,
    requestDigest: Uint8Array,
    claimId: Uint8Array,
    claimEpoch: number,
    settlements: Settlement[],
  ): Promise<RpcResponse> {
    const seen = new Set<string>();
    const validSettlements =
      settlements.length >= 1 &&
      settlements.length <= MAX_SETTLEMENT_ITEMS &&
      settlements.every((settlement) => {
        if (
          settlement.itemId.length !== 32 ||
          (settlement.action !== SettleAction.Complete && settlement.action !== SettleAction.Release)
        ) {
          return false;
        }
        const key = toBase64Url(settlement.itemId);
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    if (
      !this.validOperationInput(opId, requestDigest) ||
      claimId.length !== 32 ||
      !Number.isSafeInteger(claimEpoch) ||
      claimEpoch < 0 ||
      !validSettlements
    ) {
      return this.rejected(
        FailureClass.InvalidRequest,
        encodeSettleFailureBody(Outcome.Rejected, { failureClass: FailureClass.InvalidRequest }),
      );
    }

    const nowMs = Date.now();
    const existing = this.prepareOperation(opId, nowMs);
    if (existing !== null) {
      if (!bytesEqual(existing.requestDigest, requestDigest)) {
        return this.finish(
          this.rejected(
            FailureClass.Conflict,
            encodeSettleFailureBody(Outcome.Rejected, { failureClass: FailureClass.Conflict }),
          ),
        );
      }
      return this.finish(this.replay(existing));
    }

    const result = this.ctx.storage.transactionSync<RpcResponse>(() => {
      const metadata = this.metadataRow();
      const usage = this.usageRow();
      if (metadata === null || usage === null || metadata.expiresAt <= nowMs) {
        return this.rejected(
          FailureClass.TargetUnavailable,
          encodeSettleFailureBody(Outcome.Rejected, { failureClass: FailureClass.TargetUnavailable }),
        );
      }

      const results: SettlementResult[] = [];
      const mutations: Array<{
        action: SettleAction;
        item: ItemState;
      } | null> = [];
      for (const settlement of settlements) {
        const item = this.readItemState(settlement.itemId);
        const live =
          item !== null &&
          item.expiresAt > nowMs &&
          item.claimId !== null &&
          item.claimEpoch !== null &&
          item.claimExpiresAt !== null &&
          item.claimExpiresAt > nowMs &&
          bytesEqual(item.claimId, claimId) &&
          item.claimEpoch === claimEpoch;
        if (!live) {
          results.push({ itemId: settlement.itemId, settleOutcome: SettleOutcome.StaleClaim });
          mutations.push(null);
        } else if (item.settleAttempts >= MAX_SETTLEMENT_ATTEMPTS) {
          results.push({ itemId: settlement.itemId, settleOutcome: SettleOutcome.AttemptLimit });
          mutations.push(null);
        } else if (settlement.action === SettleAction.Complete) {
          results.push({ itemId: settlement.itemId, settleOutcome: SettleOutcome.Completed });
          mutations.push({ action: settlement.action, item });
        } else {
          results.push({ itemId: settlement.itemId, settleOutcome: SettleOutcome.Released });
          mutations.push({ action: settlement.action, item });
        }
      }

      const accepted = acceptedResult(Operation.SETTLE, 200, encodeSettleAcceptedBody(results));
      if (!this.canCacheResponse(usage, accepted.body.length)) {
        return this.capacity(
          encodeSettleFailureBody(Outcome.Transient, {
            failureClass: FailureClass.CapacityUnavailable,
            retryAfterMs: RETRY_AFTER_MS_HEADER_VALUE,
          }),
        );
      }

      let completedCount = 0;
      let completedBytes = 0;
      for (const mutation of mutations) {
        if (mutation === null) continue;
        if (mutation.action === SettleAction.Complete) {
          this.sql().exec(
            `INSERT INTO retained_packets (item_id, packet, byte_len, retained_at)
             SELECT item_id, packet, byte_len, ? FROM items WHERE item_id = ?`,
            nowMs,
            toBlob(mutation.item.itemId),
          );
          this.sql().exec("DELETE FROM items WHERE item_id = ?", toBlob(mutation.item.itemId));
          completedCount += 1;
          completedBytes += mutation.item.byteLen;
        } else {
          this.sql().exec(
            `UPDATE items
                SET claim_id = NULL, claim_epoch = NULL, claim_expires_at = NULL,
                    settle_attempts = settle_attempts + 1
              WHERE item_id = ?`,
            toBlob(mutation.item.itemId),
          );
        }
      }
      if (completedCount > 0) {
        this.sql().exec(
          `UPDATE usage
              SET item_count = MAX(item_count - ?, 0),
                  byte_count = MAX(byte_count - ?, 0)
            WHERE id = 1`,
          completedCount,
          completedBytes,
        );
      }
      this.recordOperationTx(opId, requestDigest, nowMs, accepted);
      return accepted;
    });
    return this.finish(result);
  }

  /** Deletes at most limit logical item/operation rows from an expired handle. */
  private cleanupExpiredHandleTx(limit: number): void {
    const anyItems = this.sql()
      .exec(
        `SELECT 1 AS present FROM items
         UNION ALL SELECT 1 FROM retained_packets LIMIT 1`,
      )
      .toArray().length > 0;
    const anyOps = this.sql().exec("SELECT 1 AS present FROM operations LIMIT 1").toArray().length > 0;
    if (!anyItems && !anyOps) {
      this.sql().exec("DELETE FROM usage");
      this.sql().exec("DELETE FROM metadata");
      return;
    }

    let remaining = limit;
    const operations = this.sql()
      .exec(
        `SELECT op_id, request_digest, status, headers, body_length, created_at, expires_at
           FROM operations ORDER BY expires_at LIMIT ?`,
        remaining,
      )
      .toArray()
      .map((row) => this.operationMetaFromRow(row));
    this.deleteOperationsTx(operations);
    remaining -= operations.length;

    const items = remaining > 0 ? this.sql()
      .exec("SELECT item_id, byte_len FROM items ORDER BY expires_at LIMIT ?", remaining)
      .toArray() : [];
    let deletedBytes = 0;
    for (const row of items) {
      this.sql().exec("DELETE FROM items WHERE item_id = ?", requireSqliteBlob(row.item_id));
      deletedBytes += Number(row.byte_len);
    }
    if (items.length > 0) {
      this.sql().exec(
        `UPDATE usage
            SET item_count = MAX(item_count - ?, 0),
                byte_count = MAX(byte_count - ?, 0)
          WHERE id = 1`,
        items.length,
        deletedBytes,
      );
      remaining -= items.length;
    }
    if (remaining > 0) {
      const retained = this.sql()
        .exec("SELECT item_id FROM retained_packets ORDER BY retained_at LIMIT ?", remaining)
        .toArray();
      for (const row of retained) {
        this.sql().exec(
          "DELETE FROM retained_packets WHERE item_id = ?",
          requireSqliteBlob(row.item_id),
        );
      }
      remaining -= retained.length;
    }
  }

  override async alarm(): Promise<void> {
    const nowMs = Date.now();
    this.ctx.storage.transactionSync(() => {
      const metadata = this.metadataRow();
      if (metadata !== null && metadata.expiresAt <= nowMs) {
        this.cleanupExpiredHandleTx(CLEANUP_BATCH_ROWS);
      } else {
        this.cleanupDueTx(nowMs, CLEANUP_BATCH_ROWS);
      }
    });
    await this.scheduleAlarm();
  }
}
