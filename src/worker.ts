/**
 * BadTower Station Worker: the mailbox relay's public edge. Three routes
 * and nothing else — every failure answers a bare status with the shared
 * security headers, and no request reaches a Durable Object before its
 * station credential has passed constant-time verification.
 */
import { decodeBase64Url, toHex } from "./encoding";
import { emptyNoStore, readBoundedBody, secureResponse } from "./http";

export { Mailbox } from "./mailbox";

const BIND_NOT_AFTER_HEADER = "x-badtower-bind-not-after";
const CREDENTIAL_PREFIX = "btm1.";
const CREDENTIAL_BYTES = 56; // mailboxId(16) || notAfter(8) || hmac(32)
const REVOKE_BYTES = 48; // mailboxId(16) || hmac(32)

type Admission =
  | { kind: "ok"; mailboxId: Uint8Array; notAfter: number }
  | { kind: "bad" };

let stationKey: Promise<CryptoKey> | null = null;

function key(env: Env): Promise<CryptoKey> {
  stationKey ??= (async () => {
    const raw = decodeBase64Url(env.BADTOWER_STATION_KEY);
    if (raw === null || raw.length !== 32) throw new Error("invalid station key");
    return crypto.subtle.importKey("raw", raw as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  })();
  return stationKey;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  const left = new Uint8Array(a).buffer as ArrayBuffer;
  const right = new Uint8Array(b).buffer as ArrayBuffer;
  return crypto.subtle.timingSafeEqual(left, right);
}

async function hmac(env: Env, parts: Uint8Array[]): Promise<Uint8Array> {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const input = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    input.set(part, at);
    at += part.length;
  }
  return new Uint8Array(await crypto.subtle.sign("HMAC", await key(env), input));
}

/** `btm1.` + base64url(mailboxId ‖ notAfter-BE64 ‖ HMAC(key,"btm1"‖id‖notAfter)). */
async function admission(env: Env, header: string | null): Promise<Admission> {
  const token = header?.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token.startsWith(CREDENTIAL_PREFIX)) return { kind: "bad" };
  const raw = decodeBase64Url(token.slice(CREDENTIAL_PREFIX.length));
  if (raw === null || raw.length !== CREDENTIAL_BYTES) return { kind: "bad" };
  const mailboxId = raw.slice(0, 16);
  const notAfter = new DataView(raw.buffer, raw.byteOffset + 16, 8).getBigUint64(0, false);
  const expected = await hmac(env, [new TextEncoder().encode("btm1"), mailboxId, raw.slice(16, 24)]);
  if (!equalBytes(expected, raw.slice(24))) return { kind: "bad" };
  return { kind: "ok", mailboxId, notAfter: Number(notAfter) };
}

function upgradeRequest(request: Request, mailboxId: Uint8Array, notAfter: number): Request {
  const headers = new Headers(request.headers);
  headers.delete(BIND_NOT_AFTER_HEADER);
  headers.set(BIND_NOT_AFTER_HEADER, String(notAfter));
  return new Request(request.url, { method: request.method, headers });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/healthz") {
      return secureResponse("ok\n", { headers: { "Content-Type": "text/plain" } });
    }
    if (request.method === "GET" && url.pathname === "/v1/mailbox") {
      if (request.headers.get("Upgrade") !== "websocket") return emptyNoStore(400);
      const protocols = request.headers.get("Sec-WebSocket-Protocol") ?? "";
      if (!protocols.split(",").map((p) => p.trim()).includes("licoarc.mailbox.v1")) {
        return emptyNoStore(400);
      }
      const seen = await admission(env, request.headers.get("Authorization"));
      if (seen.kind === "bad") return emptyNoStore(401);
      const stub = env.MAILBOX.getByName(toHex(seen.mailboxId));
      const res = await stub.fetch(upgradeRequest(request, seen.mailboxId, seen.notAfter));
      return res.status === 101 ? res : emptyNoStore(res.status);
    }
    if (request.method === "POST" && url.pathname === "/v1/revoke") {
      if (request.headers.get("Content-Type") !== "application/octet-stream") {
        return emptyNoStore(400);
      }
      const body = await readBoundedBody(request, REVOKE_BYTES);
      if (body.kind !== "ok" || body.bytes.length !== REVOKE_BYTES) return emptyNoStore(401);
      const mailboxId = body.bytes.slice(0, 16);
      const expected = await hmac(env, [new TextEncoder().encode("btr1"), mailboxId]);
      if (!equalBytes(expected, body.bytes.slice(16))) return emptyNoStore(401);
      await env.MAILBOX.getByName(toHex(mailboxId)).revoke();
      return emptyNoStore(204);
    }
    return emptyNoStore(404);
  },
} satisfies ExportedHandler<Env>;
