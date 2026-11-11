/**
 * The native HTTP binding: the station's own protocol-neutral mailbox
 * contract, usable without any compatibility listener. Every route is
 * admitted by the same `btm1` bearer credential; request and response
 * bodies are fixed opaque binary fields — no text, no negotiation.
 *
 *   POST /v1/native/reserve   body: subject(32)
 *                             → 200 bound | 403 closed | 409 different subject
 *   POST /v1/native/submit    body: handle(32) ‖ packet(1..524288)
 *                             → 200 body: outcome(1) ‖ reason(1)
 *   POST /v1/native/claim     body: limit(1) ‖ count(1) ‖ sequence(u64 BE)×
 *                             → 200 body: count(1) ‖ [sequence(u64 BE) ‖
 *                               handle(32) ‖ length(u32 BE) ‖ body]× | 403
 *   POST /v1/native/settle    body: count(1) ‖ sequence(u64 BE)× → 204 | 403
 *   GET  /v1/native/capacity  → 200 body: capacityBytes(u64 BE) ‖
 *                               databaseBytes(u64 BE) | 403
 *
 * Reserve binds the credential's mailbox to one opaque subject;
 * Submit routes by the handle's first 16 bytes to the target mailbox;
 * Claim and Settle act on the credential's own mailbox and require it to
 * be bound. Revocation stays on `POST /v1/revoke`; health on `/healthz`.
 */
import { emptyNoStore, readBoundedBody, secureResponse } from "./http";
import { IN_FLIGHT_WINDOW, MAX_PACKET_BYTES, SUBJECT_BYTES } from "./store";
import type { Admission } from "./admission";
import type { Packet, ReserveResult, SubmitResult } from "./store";

export const NATIVE_PATHS = {
  reserve: "/v1/native/reserve",
  submit: "/v1/native/submit",
  claim: "/v1/native/claim",
  settle: "/v1/native/settle",
  capacity: "/v1/native/capacity",
} as const;

export const NATIVE_OUTCOME = { accepted: 0, rejected: 1, transient: 2 } as const;
export const NATIVE_REASON = {
  none: 255,
  "invalid-request": 0,
  "target-unavailable": 1,
  "packet-too-large": 2,
  "mailbox-full": 3,
  "internal-unavailable": 4,
} as const;

const SUBMIT_MAX_BYTES = 32 + MAX_PACKET_BYTES;
const CLAIM_MAX_BYTES = 2 + IN_FLIGHT_WINDOW * 8;
const SETTLE_MAX_BYTES = 1 + IN_FLIGHT_WINDOW * 8;

/** The mailbox-actor surface a native route drives; the app supplies DO stubs. */
export type NativeMailbox = {
  reserve(subject: Uint8Array, notAfter: number): Promise<ReserveResult>;
  submit(handle: Uint8Array, body: Uint8Array): Promise<SubmitResult>;
  claim(excludeSequences: number[], limit: number): Promise<Packet[] | null>;
  settle(sequences: number[]): Promise<boolean>;
  capacityInfo(): Promise<{
    bound: boolean;
    capacityBytes: number;
    databaseBytes: number;
  }>;
};

function encodeSubmitResult(result: SubmitResult): Uint8Array {
  const reason = result.outcome === "accepted" ? NATIVE_REASON.none
    : NATIVE_REASON[result.reason];
  return new Uint8Array([NATIVE_OUTCOME[result.outcome], reason]);
}

function encodePackets(packets: Packet[]): Uint8Array {
  const total = packets.reduce((sum, p) => sum + 12 + 32 + p.body.length, 1);
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  out[0] = packets.length;
  let at = 1;
  for (const packet of packets) {
    view.setBigUint64(at, BigInt(packet.sequence), false);
    at += 8;
    out.set(packet.handle, at);
    at += 32;
    view.setUint32(at, packet.body.length, false);
    at += 4;
    out.set(packet.body, at);
    at += packet.body.length;
  }
  return out;
}

function encodeCapacity(capacityBytes: number, databaseBytes: number): Uint8Array {
  const out = new Uint8Array(16);
  const view = new DataView(out.buffer);
  view.setBigUint64(0, BigInt(capacityBytes), false);
  view.setBigUint64(8, BigInt(databaseBytes), false);
  return out;
}

function u64list(bytes: Uint8Array, offset: number, count: number): number[] | null {
  const out: number[] = [];
  for (let i = 0; i < count; i += 1) {
    const value = new DataView(bytes.buffer, bytes.byteOffset + offset + i * 8, 8)
      .getBigUint64(0, false);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) return null;
    out.push(Number(value));
  }
  return out;
}

async function body(request: Request, maxBytes: number): Promise<Uint8Array | null> {
  if (request.headers.get("Content-Type") !== "application/octet-stream") return null;
  const read = await readBoundedBody(request, maxBytes + 1);
  return read.kind === "ok" && read.bytes.length <= maxBytes ? read.bytes : null;
}

/**
 * Dispatch one admitted request to a native route. Returns null when the
 * path is not a native route so the caller can answer 404.
 */
export async function handleNativeRequest(
  request: Request,
  admitted: Admission & { kind: "ok" },
  mailboxFor: (mailboxId: Uint8Array) => NativeMailbox,
): Promise<Response | null> {
  const url = new URL(request.url);
  const own = () => mailboxFor(admitted.mailboxId);

  if (request.method === "POST" && url.pathname === NATIVE_PATHS.reserve) {
    const subject = await body(request, SUBJECT_BYTES);
    if (subject === null || subject.length !== SUBJECT_BYTES) return emptyNoStore(400);
    const result = await own().reserve(subject, admitted.notAfter);
    if (result === "bound") return emptyNoStore(200);
    if (result === "subject-mismatch") return emptyNoStore(409);
    return emptyNoStore(403);
  }

  if (request.method === "POST" && url.pathname === NATIVE_PATHS.submit) {
    const payload = await body(request, SUBMIT_MAX_BYTES);
    if (payload === null || payload.length <= 32) return emptyNoStore(400);
    const handle = payload.slice(0, 32);
    const packet = payload.slice(32);
    try {
      const result = await mailboxFor(handle.slice(0, 16)).submit(handle, packet);
      return secureResponse(encodeSubmitResult(result), {
        headers: { "Content-Type": "application/octet-stream" },
      });
    } catch {
      return secureResponse(
        encodeSubmitResult({ outcome: "transient", reason: "internal-unavailable" }),
        { headers: { "Content-Type": "application/octet-stream" } },
      );
    }
  }

  if (request.method === "POST" && url.pathname === NATIVE_PATHS.claim) {
    const payload = await body(request, CLAIM_MAX_BYTES);
    if (payload === null || payload.length < 2) return emptyNoStore(400);
    const [limit, count] = [payload[0]!, payload[1]!];
    if (limit > IN_FLIGHT_WINDOW || payload.length !== 2 + count * 8) {
      return emptyNoStore(400);
    }
    const exclude = u64list(payload, 2, count);
    if (exclude === null) return emptyNoStore(400);
    const packets = await own().claim(exclude, limit);
    if (packets === null) return emptyNoStore(403);
    return secureResponse(encodePackets(packets), {
      headers: { "Content-Type": "application/octet-stream" },
    });
  }

  if (request.method === "POST" && url.pathname === NATIVE_PATHS.settle) {
    const payload = await body(request, SETTLE_MAX_BYTES);
    if (payload === null || payload.length < 1) return emptyNoStore(400);
    const count = payload[0]!;
    if (payload.length !== 1 + count * 8) return emptyNoStore(400);
    const sequences = u64list(payload, 1, count);
    if (sequences === null) return emptyNoStore(400);
    if (!(await own().settle(sequences))) return emptyNoStore(403);
    return emptyNoStore(204);
  }

  if (request.method === "GET" && url.pathname === NATIVE_PATHS.capacity) {
    const info = await own().capacityInfo();
    if (!info.bound) return emptyNoStore(403);
    return secureResponse(encodeCapacity(info.capacityBytes, info.databaseBytes), {
      headers: { "Content-Type": "application/octet-stream" },
    });
  }

  return null;
}
