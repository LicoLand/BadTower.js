/**
 * Typed deterministic-CBOR request decoding and response encoding for the
 * pinned Candidate surface. Request parsing is closed: only the exact label
 * sets below are admitted, all bytes must be consumed, and every
 * operation-specific bound is enforced before any state callback.
 */

import { CborReader, CborWriter, CborError } from "./cbor";
import {
  HandleClass,
  MAX_CLAIM_ITEMS,
  MAX_CLAIM_RESPONSE_BYTES,
  MAX_CONTROL_RESPONSE_BYTES,
  MAX_RETRY_AFTER_MS,
  MAX_SETTLEMENT_ITEMS,
  SettleAction,
} from "./candidate";

export interface AffiliateRequest {
  stationDescriptorDigest: Uint8Array;
  affiliationCommitment: Uint8Array;
}

export interface ReserveRequest {
  stationDescriptorDigest: Uint8Array;
  affiliationCommitment: Uint8Array;
  transportProfileId: Uint8Array;
  handleClass: HandleClass;
}

export interface RetrieveRequest {
  claimId: Uint8Array;
  claimEpoch: number;
  itemId: Uint8Array;
}

export interface ClaimRequest {
  maxItems: number;
}

export interface Settlement {
  itemId: Uint8Array;
  action: SettleAction;
}

export interface SettleRequest {
  claimId: Uint8Array;
  claimEpoch: number;
  settlements: Settlement[];
}

export interface ClaimedItem {
  itemId: Uint8Array;
  protectedPacket: Uint8Array;
}

export interface SettlementResult {
  itemId: Uint8Array;
  settleOutcome: number;
}

function readFixedBytes(reader: CborReader, size: number, what: string): Uint8Array {
  const value = reader.bytes();
  if (value.length !== size) throw new CborError(`${what} must be ${size} bytes`);
  return value;
}

function parseClosedMap(reader: CborReader, labels: readonly number[]): Map<number, Uint8Array> {
  const entries = reader.mapEntries();
  if (entries.length !== labels.length) throw new CborError("wrong label count");
  const values = new Map<number, Uint8Array>();
  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i];
    if (entry === undefined || entry.key !== labels[i]) throw new CborError("unknown or missing label");
    values.set(entry.key, entry.value);
  }
  reader.end();
  return values;
}

function readUintFrom(value: Uint8Array): number {
  const reader = new CborReader(value);
  const n = reader.uint();
  reader.end();
  return n;
}

function readBytesFrom(value: Uint8Array, size: number, what: string): Uint8Array {
  const reader = new CborReader(value);
  const out = readFixedBytes(reader, size, what);
  reader.end();
  return out;
}

export function parseAffiliate(body: Uint8Array): AffiliateRequest {
  const reader = new CborReader(body);
  const values = parseClosedMap(reader, [0, 1]);
  return {
    stationDescriptorDigest: readBytesFrom(values.get(0)!, 32, "stationDescriptorDigest"),
    affiliationCommitment: readBytesFrom(values.get(1)!, 32, "affiliationCommitment"),
  };
}

export function parseReserve(body: Uint8Array): ReserveRequest {
  const reader = new CborReader(body);
  const values = parseClosedMap(reader, [0, 1, 2, 3]);
  const handleClass = readUintFrom(values.get(3)!);
  if (handleClass > HandleClass.FirstContact) throw new CborError("invalid handleClass");
  return {
    stationDescriptorDigest: readBytesFrom(values.get(0)!, 32, "stationDescriptorDigest"),
    affiliationCommitment: readBytesFrom(values.get(1)!, 32, "affiliationCommitment"),
    transportProfileId: readBytesFrom(values.get(2)!, 32, "transportProfileId"),
    handleClass: handleClass as HandleClass,
  };
}

export function parseRetrieve(body: Uint8Array): RetrieveRequest {
  const reader = new CborReader(body);
  const values = parseClosedMap(reader, [0, 1, 2]);
  return {
    claimId: readBytesFrom(values.get(0)!, 32, "claimId"),
    claimEpoch: readUintFrom(values.get(1)!),
    itemId: readBytesFrom(values.get(2)!, 32, "itemId"),
  };
}

export function parseClaim(body: Uint8Array): ClaimRequest {
  const reader = new CborReader(body);
  const values = parseClosedMap(reader, [0]);
  const maxItems = readUintFrom(values.get(0)!);
  if (maxItems < 1 || maxItems > MAX_CLAIM_ITEMS) throw new CborError("maxItems out of bounds");
  return { maxItems };
}

export function parseSettle(body: Uint8Array): SettleRequest {
  const reader = new CborReader(body);
  const values = parseClosedMap(reader, [0, 1, 2]);
  const claimId = readBytesFrom(values.get(0)!, 32, "claimId");
  const claimEpoch = readUintFrom(values.get(1)!);
  const itemsReader = new CborReader(values.get(2)!);
  const count = itemsReader.arrayHeader();
  if (count < 1 || count > MAX_SETTLEMENT_ITEMS) throw new CborError("settlements out of bounds");
  const settlements: Settlement[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < count; i += 1) {
    // The items reader is shared across the array, so the closed-map check
    // must not consume trailing bytes (end()) until the array is complete.
    const itemValues = itemsReader.mapEntries();
    if (itemValues.length !== 2 || itemValues[0]?.key !== 0 || itemValues[1]?.key !== 1) {
      throw new CborError("settlement must have labels 0 and 1");
    }
    const itemId = readBytesFrom(itemValues[0]!.value, 32, "itemId");
    const action = readUintFrom(itemValues[1]!.value);
    if (action > SettleAction.Release) throw new CborError("invalid settleAction");
    const key = toHex(itemId);
    if (seen.has(key)) throw new CborError("duplicate settlement item");
    seen.add(key);
    settlements.push({ itemId, action: action as SettleAction });
  }
  itemsReader.end();
  return { claimId, claimEpoch, settlements };
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

type Value =
  | { kind: "uint"; value: number }
  | { kind: "bytes"; value: Uint8Array }
  | { kind: "items"; values: Value[] }
  | { kind: "map"; entries: Array<{ label: number; value: Value }> };

function uint(value: number): Value {
  return { kind: "uint", value };
}

function bytes(value: Uint8Array): Value {
  return { kind: "bytes", value };
}

function items(values: Value[]): Value {
  return { kind: "items", values };
}

function map(entries: Array<[number, Value]>): Value {
  return { kind: "map", entries: entries.map(([label, value]) => ({ label, value })) };
}

function sizeOf(value: Value): number {
  switch (value.kind) {
    case "uint":
      return CborWriter.uintSize(value.value);
    case "bytes":
      return CborWriter.bytesSize(value.value);
    case "items": {
      let total = CborWriter.uintSize(value.values.length);
      for (const v of value.values) total += sizeOf(v);
      return total;
    }
    case "map": {
      let total = CborWriter.uintSize(value.entries.length);
      for (const entry of value.entries) total += CborWriter.uintSize(entry.label) + sizeOf(entry.value);
      return total;
    }
  }
}

function write(writer: CborWriter, value: Value): void {
  switch (value.kind) {
    case "uint":
      writer.uint(value.value);
      return;
    case "bytes":
      writer.bytes(value.value);
      return;
    case "items":
      writer.arrayHeader(value.values.length);
      for (const v of value.values) write(writer, v);
      return;
    case "map":
      writer.mapHeader(value.entries.length);
      for (const entry of value.entries) {
        writer.uint(entry.label);
        write(writer, entry.value);
      }
      return;
  }
}

function encode(value: Value, maxBytes?: number): Uint8Array {
  const size = sizeOf(value);
  if (maxBytes !== undefined && size > maxBytes) throw new CborError("response exceeds bound");
  const writer = new CborWriter(size);
  write(writer, value);
  return writer.finish();
}

export interface FailureFields {
  failureClass: number;
  retryAfterMs?: number;
}

/** Submit-shaped failure body; also used for RETRIEVE failures. */
export function encodeSubmitFailureBody(outcome: number, fields: FailureFields): Uint8Array {
  const entries: Array<[number, Value]> = [[0, uint(outcome)]];
  if (fields.failureClass !== undefined) entries.push([1, uint(fields.failureClass)]);
  if (fields.retryAfterMs !== undefined) {
    if (fields.retryAfterMs > MAX_RETRY_AFTER_MS) throw new CborError("retryAfterMs out of bounds");
    entries.push([2, uint(fields.retryAfterMs)]);
  }
  return encode(map(entries), MAX_CONTROL_RESPONSE_BYTES);
}

export function encodeAffiliateFailureBody(outcome: number, fields: FailureFields): Uint8Array {
  const entries: Array<[number, Value]> = [[0, uint(outcome)]];
  if (fields.failureClass !== undefined) entries.push([3, uint(fields.failureClass)]);
  if (fields.retryAfterMs !== undefined) {
    if (fields.retryAfterMs > MAX_RETRY_AFTER_MS) throw new CborError("retryAfterMs out of bounds");
    entries.push([4, uint(fields.retryAfterMs)]);
  }
  return encode(map(entries), MAX_CONTROL_RESPONSE_BYTES);
}

export function encodeReserveFailureBody(outcome: number, fields: FailureFields): Uint8Array {
  const entries: Array<[number, Value]> = [[0, uint(outcome)]];
  if (fields.failureClass !== undefined) entries.push([5, uint(fields.failureClass)]);
  if (fields.retryAfterMs !== undefined) {
    if (fields.retryAfterMs > MAX_RETRY_AFTER_MS) throw new CborError("retryAfterMs out of bounds");
    entries.push([6, uint(fields.retryAfterMs)]);
  }
  return encode(map(entries), MAX_CONTROL_RESPONSE_BYTES);
}

export function encodeClaimFailureBody(outcome: number, fields: FailureFields): Uint8Array {
  const entries: Array<[number, Value]> = [[0, uint(outcome)]];
  if (fields.failureClass !== undefined) entries.push([4, uint(fields.failureClass)]);
  if (fields.retryAfterMs !== undefined) {
    if (fields.retryAfterMs > MAX_RETRY_AFTER_MS) throw new CborError("retryAfterMs out of bounds");
    entries.push([5, uint(fields.retryAfterMs)]);
  }
  return encode(map(entries), MAX_CONTROL_RESPONSE_BYTES);
}

export function encodeSettleFailureBody(outcome: number, fields: FailureFields): Uint8Array {
  const entries: Array<[number, Value]> = [[0, uint(outcome)]];
  if (fields.failureClass !== undefined) entries.push([2, uint(fields.failureClass)]);
  if (fields.retryAfterMs !== undefined) {
    if (fields.retryAfterMs > MAX_RETRY_AFTER_MS) throw new CborError("retryAfterMs out of bounds");
    entries.push([3, uint(fields.retryAfterMs)]);
  }
  return encode(map(entries), MAX_CONTROL_RESPONSE_BYTES);
}

/** The only accepted RESERVE form in this preview: unsigned first contact. */
export function encodeFirstContactReserveAcceptedBody(
  deliveryHandle: Uint8Array,
): Uint8Array {
  return encode(
    map([
      [0, uint(0)],
      [1, bytes(deliveryHandle)],
      [2, uint(HandleClass.FirstContact)],
    ]),
    MAX_CONTROL_RESPONSE_BYTES,
  );
}

export function encodeSubmitAcceptedBody(): Uint8Array {
  return encode(map([[0, uint(0)]]), MAX_CONTROL_RESPONSE_BYTES);
}

export function claimedItemSize(itemId: Uint8Array, packet: Uint8Array): number {
  return (
    CborWriter.uintSize(2) +
    CborWriter.uintSize(0) +
    CborWriter.bytesSize(itemId) +
    CborWriter.uintSize(1) +
    CborWriter.bytesSize(packet)
  );
}

export function claimResponseSize(claimId: Uint8Array, epoch: number, items: ClaimedItem[]): number {
  let total =
    CborWriter.uintSize(4) +
    CborWriter.uintSize(0) +
    CborWriter.uintSize(0) +
    CborWriter.uintSize(1) +
    CborWriter.bytesSize(claimId) +
    CborWriter.uintSize(2) +
    CborWriter.uintSize(epoch) +
    CborWriter.uintSize(3);
  const elementSizes: number[] = [];
  for (const item of items) elementSizes.push(claimedItemSize(item.itemId, item.protectedPacket));
  total += CborWriter.arraySize(items.length, elementSizes);
  return total;
}

export function encodeClaimAcceptedEmptyBody(): Uint8Array {
  return encode(map([[0, uint(0)]]), MAX_CONTROL_RESPONSE_BYTES);
}

export function encodeClaimAcceptedBody(
  claimId: Uint8Array,
  epoch: number,
  items: ClaimedItem[],
): Uint8Array {
  const size = claimResponseSize(claimId, epoch, items);
  if (size > MAX_CLAIM_RESPONSE_BYTES) throw new CborError("claim response exceeds bound");
  const writer = new CborWriter(size);
  writer.mapHeader(4);
  writer.uint(0);
  writer.uint(0);
  writer.uint(1);
  writer.bytes(claimId);
  writer.uint(2);
  writer.uint(epoch);
  writer.uint(3);
  writer.arrayHeader(items.length);
  for (const item of items) {
    writer.mapHeader(2);
    writer.uint(0);
    writer.bytes(item.itemId);
    writer.uint(1);
    writer.bytes(item.protectedPacket);
  }
  return writer.finish();
}

export function encodeSettleAcceptedBody(results: SettlementResult[]): Uint8Array {
  const entries: Array<[number, Value]> = [
    [0, uint(0)],
    [
      1,
      items(
        results.map((result) =>
          map([
            [0, bytes(result.itemId)],
            [1, uint(result.settleOutcome)],
          ]),
        ),
      ),
    ],
  ];
  return encode(map(entries), MAX_CONTROL_RESPONSE_BYTES);
}
