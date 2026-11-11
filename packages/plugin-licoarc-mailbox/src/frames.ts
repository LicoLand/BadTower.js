/**
 * Mailbox transport v1 frame codec: eight deterministic-CBOR closed maps
 * over the canonical codec. Label 0 is the frame type; every other label
 * is closed per type — an unknown, duplicate, unordered or wrongly-sized
 * member, or any trailing byte, rejects the whole frame.
 */
import { CborError, CborReader, CborWriter } from "./transport/cbor";

export const MAX_PACKET_BYTES = 524288;
export const MAX_FRAME_BYTES = MAX_PACKET_BYTES + 128;

export type ClientFrame =
  | { kind: "hello"; deviceKey: Uint8Array; signature: Uint8Array }
  | { kind: "send"; requestId: number; handle: Uint8Array; packet: Uint8Array }
  | { kind: "ack"; sequence: number };

export type StationFrame =
  | { kind: "challenge"; nonce: Uint8Array }
  | { kind: "ready"; mailboxId: Uint8Array }
  | {
      kind: "result";
      requestId: number;
      outcome: number;
      failureClass?: number;
      retryAfterMs?: number;
    }
  | { kind: "deliver"; sequence: number; handle: Uint8Array; packet: Uint8Array }
  | { kind: "drained" };

function entries(buf: Uint8Array): Map<number, Uint8Array> {
  if (buf.length > MAX_FRAME_BYTES) throw new CborError("oversized frame");
  const reader = new CborReader(buf);
  const map = new Map<number, Uint8Array>();
  for (const { key, value } of reader.mapEntries()) {
    if (map.has(key)) throw new CborError("duplicate label");
    map.set(key, value);
  }
  reader.end();
  return map;
}

function uint(map: Map<number, Uint8Array>, label: number, max = Number.MAX_SAFE_INTEGER): number {
  const raw = map.get(label);
  if (raw === undefined) throw new CborError("missing label");
  const value = new CborReader(raw).uint();
  if (!Number.isInteger(value) || value < 0 || value > max) throw new CborError("uint out of range");
  return value;
}

function bytes(
  map: Map<number, Uint8Array>,
  label: number,
  size: number | { min: number; max: number },
): Uint8Array {
  const raw = map.get(label);
  if (raw === undefined) throw new CborError("missing label");
  const value = new CborReader(raw).bytes();
  const [min, max] = typeof size === "number" ? [size, size] : [size.min, size.max];
  if (value.length < min || value.length > max) throw new CborError("bstr out of range");
  return value;
}

function requireLabels(map: Map<number, Uint8Array>, allowed: number[]): void {
  for (const key of map.keys()) {
    if (!allowed.includes(key)) throw new CborError("unknown label");
  }
}

export function decodeClientFrame(buf: Uint8Array): ClientFrame {
  const map = entries(buf);
  switch (uint(map, 0)) {
    case 1: {
      requireLabels(map, [0, 1, 2]);
      return { kind: "hello", deviceKey: bytes(map, 1, 32), signature: bytes(map, 2, 64) };
    }
    case 2: {
      requireLabels(map, [0, 1, 2, 3]);
      return {
        kind: "send",
        requestId: uint(map, 1, 4294967295),
        handle: bytes(map, 2, 32),
        packet: bytes(map, 3, { min: 1, max: MAX_PACKET_BYTES }),
      };
    }
    case 3: {
      requireLabels(map, [0, 1]);
      return { kind: "ack", sequence: uint(map, 1) };
    }
    default:
      throw new CborError("unknown client frame type");
  }
}

export function decodeStationFrame(buf: Uint8Array): StationFrame {
  const map = entries(buf);
  switch (uint(map, 0)) {
    case 16:
      requireLabels(map, [0, 1]);
      return { kind: "challenge", nonce: bytes(map, 1, 32) };
    case 17:
      requireLabels(map, [0, 1]);
      return { kind: "ready", mailboxId: bytes(map, 1, 16) };
    case 18: {
      requireLabels(map, [0, 1, 2, 3, 4]);
      const frame: StationFrame = {
        kind: "result",
        requestId: uint(map, 1, 4294967295),
        outcome: uint(map, 2, 2),
      };
      if (map.has(3)) frame.failureClass = uint(map, 3, 4);
      if (map.has(4)) frame.retryAfterMs = uint(map, 4, 60000);
      return frame;
    }
    case 19: {
      requireLabels(map, [0, 1, 2, 3]);
      return {
        kind: "deliver",
        sequence: uint(map, 1),
        handle: bytes(map, 2, 32),
        packet: bytes(map, 3, { min: 1, max: MAX_PACKET_BYTES }),
      };
    }
    case 20:
      requireLabels(map, [0]);
      return { kind: "drained" };
    default:
      throw new CborError("unknown station frame type");
  }
}

export function encodeClientFrame(frame: ClientFrame): Uint8Array {
  const writer = new CborWriter(MAX_FRAME_BYTES);
  switch (frame.kind) {
    case "hello":
      writer.mapHeader(3);
      writer.uint(0); writer.uint(1);
      writer.uint(1); writer.bytes(frame.deviceKey);
      writer.uint(2); writer.bytes(frame.signature);
      break;
    case "send":
      writer.mapHeader(4);
      writer.uint(0); writer.uint(2);
      writer.uint(1); writer.uint(frame.requestId);
      writer.uint(2); writer.bytes(frame.handle);
      writer.uint(3); writer.bytes(frame.packet);
      break;
    case "ack":
      writer.mapHeader(2);
      writer.uint(0); writer.uint(3);
      writer.uint(1); writer.uint(frame.sequence);
      break;
  }
  return writer.finish();
}

export function encodeStationFrame(frame: StationFrame): Uint8Array {
  const writer = new CborWriter(MAX_FRAME_BYTES);
  switch (frame.kind) {
    case "challenge":
      writer.mapHeader(2);
      writer.uint(0); writer.uint(16);
      writer.uint(1); writer.bytes(frame.nonce);
      break;
    case "ready":
      writer.mapHeader(2);
      writer.uint(0); writer.uint(17);
      writer.uint(1); writer.bytes(frame.mailboxId);
      break;
    case "result": {
      const extra = (frame.failureClass === undefined ? 0 : 1) + (frame.retryAfterMs === undefined ? 0 : 1);
      writer.mapHeader(3 + extra);
      writer.uint(0); writer.uint(18);
      writer.uint(1); writer.uint(frame.requestId);
      writer.uint(2); writer.uint(frame.outcome);
      if (frame.failureClass !== undefined) { writer.uint(3); writer.uint(frame.failureClass); }
      if (frame.retryAfterMs !== undefined) { writer.uint(4); writer.uint(frame.retryAfterMs); }
      break;
    }
    case "deliver":
      writer.mapHeader(4);
      writer.uint(0); writer.uint(19);
      writer.uint(1); writer.uint(frame.sequence);
      writer.uint(2); writer.bytes(frame.handle);
      writer.uint(3); writer.bytes(frame.packet);
      break;
    case "drained":
      writer.mapHeader(1);
      writer.uint(0); writer.uint(20);
      break;
  }
  return writer.finish();
}
