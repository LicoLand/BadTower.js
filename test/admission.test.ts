/**
 * AC-002 Access-before-relay: one indistinguishable denial for every
 * admission failure, zero namespace lookups and zero body reads before
 * admission, bounded-reader cancellation, visible carrier rejection, and
 * recursive allowlist-only observability.
 */

import { env, exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AUTHORIZATION_HEADER_MAX_BYTES } from "../src/access/token";
import {
  CONTROL_MEDIA_TYPE,
  MAX_CONTROL_BODY_BYTES,
  MAX_HEADER_BYTES,
  OPERATION_ID_HEADER,
  PROTECTED_PACKET_MEDIA_TYPE,
} from "../src/transport/candidate";
import {
  generateAccessGrant,
  opRequest,
  randomOpId,
  toBase64Url,
  VALID_CF,
} from "./helpers";

const handler = exports.default as { fetch(request: Request, env: Env): Promise<Response> };

const ALLOWED_KEYS = new Set(["schemaVersion", "event", "operation", "outcome", "failure"]);

function collectKeys(value: unknown, out: Set<string>): void {
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, out);
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      out.add(key);
      collectKeys(item, out);
    }
  }
}

interface Counters {
  shards: number;
  relays: number;
}

// The pool invokes the entrypoint wrapper with its own env object (the one
// imported from "cloudflare:workers"), so counting proxies must be installed
// onto that shared object. Function members are bound to the original
// namespace so real dispatch still works through the traps.
const REAL_SHARDS = env.AFFILIATION_SHARDS;
const REAL_RELAYS = env.RELAY_HANDLES;

function countingEnv(): { testEnv: Env; counters: Counters } {
  const counters: Counters = { shards: 0, relays: 0 };
  const shards = new Proxy(REAL_SHARDS, {
    get(target, prop, receiver) {
      counters.shards += 1;
      const value = Reflect.get(target, prop, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  const relays = new Proxy(REAL_RELAYS, {
    get(target, prop, receiver) {
      counters.relays += 1;
      const value = Reflect.get(target, prop, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  (env as unknown as Record<string, unknown>).AFFILIATION_SHARDS = shards;
  (env as unknown as Record<string, unknown>).RELAY_HANDLES = relays;
  return { testEnv: env as Env, counters };
}

afterEach(() => {
  (env as unknown as Record<string, unknown>).AFFILIATION_SHARDS = REAL_SHARDS;
  (env as unknown as Record<string, unknown>).RELAY_HANDLES = REAL_RELAYS;
});

async function denialBytes(response: Response): Promise<{ status: number; headers: Record<string, string>; body: Uint8Array }> {
  const body = new Uint8Array(await response.arrayBuffer());
  const headers: Record<string, string> = {};
  for (const [key, value] of response.headers.entries()) headers[key.toLowerCase()] = value;
  return { status: response.status, headers, body };
}

describe("invitation admission denial", () => {
  it("returns one byte-identical no-store denial for every invalid admission variant", async () => {
    const invite = await generateAccessGrant();
    const { testEnv, counters } = countingEnv();
    const base = opRequest("/v1/reserve", {
      token: invite.token,
      headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: randomOpId() },
      body: new Uint8Array([0xa1, 0x00, 0x01]),
      cf: VALID_CF,
    });

    const variants: Array<Request> = [
      new Request("https://station.invalid/v1/reserve", {
        method: "POST",
        headers: { "content-type": CONTROL_MEDIA_TYPE },
        body: new Uint8Array([0xa1, 0x00, 0x01]),
      }),
      opRequest("/v1/reserve", { token: "", headers: {}, body: new Uint8Array(1) }),
      opRequest("/v1/reserve", { token: `${invite.token}x`, headers: {}, body: new Uint8Array(1) }),
      opRequest("/v1/reserve", {
        token: "a".repeat(AUTHORIZATION_HEADER_MAX_BYTES),
        headers: {},
        body: new Uint8Array(1),
      }),
      opRequest("/v1/reserve", {
        token: "a".repeat(AUTHORIZATION_HEADER_MAX_BYTES),
        headers: {},
        body: new Uint8Array(1),
      }),
      opRequest("/v1/reserve", { token: "", headers: { authorization: `Basic ${invite.token}` } }),
      opRequest("/v1/reserve", { token: `${invite.token.slice(0, 16)},${invite.token.slice(16)}` }),
      opRequest("/v1/reserve", { token: `\u00e9\u00e9\u00e9` }),
    ];

    let first: { status: number; headers: Record<string, string>; body: Uint8Array } | null = null;
    for (const request of variants) {
      const response = await handler.fetch(request, testEnv);
      const denial = await denialBytes(response);
      expect(denial.status).toBe(401);
      expect(denial.headers["cache-control"]).toBe("no-store");
      expect(denial.body.byteLength).toBe(0);
      if (first === null) first = denial;
      else {
        expect(denial.status).toBe(first.status);
        expect(denial.body).toEqual(first.body);
        expect(denial.headers).toEqual(first.headers);
      }
    }
    expect(counters.shards).toBe(0);
    expect(counters.relays).toBe(0);
    expect(base).toBeInstanceOf(Request);
  });

  it("rejects before reading the request body", async () => {
    const invite = await generateAccessGrant();
    const { testEnv } = countingEnv();
    // A poisoned body: any read attempt beyond workerd's single construction
    // pull would surface the error as a read failure instead of a denial.
    // The handler must return the identical 401 without pulling the stream.
    const reads = { count: 0 };
    const body = new ReadableStream<Uint8Array>({
      pull() {
        reads.count += 1;
        throw new Error("body must not be read before admission");
      },
    });
    const request = new Request("https://station.invalid/v1/reserve", {
      method: "POST",
      headers: {
        "content-length": "8",
        "content-type": CONTROL_MEDIA_TYPE,
        [OPERATION_ID_HEADER]: randomOpId(),
        authorization: "Bearer wrong-token",
      },
      body,
      cf: VALID_CF as unknown as Record<string, unknown>,
    });
    const response = await handler.fetch(request, testEnv);
    expect(response.status).toBe(401);
    expect(reads.count).toBe(1); // workerd's own construction pull only
  });

  it("denies a revoked access grant", async () => {
    const invite = await generateAccessGrant();
    await env.ACCESS_GRANTS.getByName(invite.selector).revoke();
    const { testEnv } = countingEnv();
    const request = opRequest("/v1/reserve", {
      token: invite.token,
      headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: randomOpId() },
      body: new Uint8Array([0xa1, 0x00, 0x01]),
      cf: VALID_CF,
    });
    const response = await handler.fetch(request, testEnv);
    const denial = await denialBytes(response);
    expect(denial.status).toBe(401);
    expect(denial.headers["cache-control"]).toBe("no-store");
    expect(denial.body.byteLength).toBe(0);
  });
});

describe("carrier validation after admission", () => {
  it("rejects an unauthenticated handle before relay namespace selection", async () => {
    const invite = await generateAccessGrant();
    const { testEnv, counters } = countingEnv();
    const handle = toBase64Url(new Uint8Array(32).fill(7));
    const request = opRequest(`/v1/handles/${handle}/claim`, {
      token: invite.token,
      headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: randomOpId() },
      body: new Uint8Array([0xa1, 0x00, 0x01]),
      cf: VALID_CF,
    });
    const response = await handler.fetch(request, testEnv);
    expect(response.status).toBe(404);
    expect(response.headers.get("licoarc-outcome")).toBe("rejected");
    expect(counters.relays).toBe(0);
    expect(counters.shards).toBe(0);
  });

  it("rejects visible carrier failures without touching namespaces", async () => {
    const invite = await generateAccessGrant();
    const { testEnv, counters } = countingEnv();
    const handle = toBase64Url(new Uint8Array(32).fill(7));
    const opId = randomOpId();
    const claimBody = new Uint8Array([0xa1, 0x00, 0x01]);
    const carriers: Array<{ name: string; request: Request }> = [
      { name: "missing-cf", request: opRequest(`/v1/handles/${handle}/claim`, { token: invite.token, headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: opId }, body: claimBody }) },
      { name: "http-1-1", request: opRequest(`/v1/handles/${handle}/claim`, { token: invite.token, headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: opId }, body: claimBody, cf: { httpProtocol: "HTTP/1.1", tlsVersion: "TLSv1.3", tlsCipher: "TLS_AES_128_GCM_SHA256" } }) },
      { name: "tls-1-2", request: opRequest(`/v1/handles/${handle}/claim`, { token: invite.token, headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: opId }, body: claimBody, cf: { httpProtocol: "HTTP/2", tlsVersion: "TLSv1.2", tlsCipher: "TLS_AES_128_GCM_SHA256" } }) },
      { name: "unknown-cipher", request: opRequest(`/v1/handles/${handle}/claim`, { token: invite.token, headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: opId }, body: claimBody, cf: { httpProtocol: "HTTP/2", tlsVersion: "TLSv1.3", tlsCipher: "TLS_AES_256_CCM" } }) },
      { name: "wrong-method", request: opRequest(`/v1/handles/${handle}/claim`, { token: invite.token, method: "GET", headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: opId }, cf: VALID_CF }) },
      { name: "wrong-media-type", request: opRequest(`/v1/handles/${handle}/claim`, { token: invite.token, headers: { "content-type": "application/json", [OPERATION_ID_HEADER]: opId }, body: claimBody, cf: VALID_CF }) },
      { name: "missing-operation-id", request: opRequest(`/v1/handles/${handle}/claim`, { token: invite.token, headers: { "content-type": CONTROL_MEDIA_TYPE }, body: claimBody, cf: VALID_CF }) },
      { name: "uppercase-operation-id", request: opRequest(`/v1/handles/${handle}/claim`, { token: invite.token, headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: opId.toUpperCase() }, body: claimBody, cf: VALID_CF }) },
      { name: "query-present", request: opRequest(`/v1/handles/${handle}/claim?cursor=1`, { token: invite.token, headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: opId }, body: claimBody, cf: VALID_CF }) },
      { name: "content-encoding", request: opRequest(`/v1/handles/${handle}/claim`, { token: invite.token, headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: opId, "content-encoding": "gzip" }, body: claimBody, cf: VALID_CF }) },
      { name: "plain-http", request: opRequest(`/v1/handles/${handle}/claim`, { token: invite.token, url: `http://station.invalid/v1/handles/${handle}/claim`, headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: opId }, body: claimBody, cf: VALID_CF }) },
      { name: "bad-handle-length", request: opRequest("/v1/handles/short/claim", { token: invite.token, headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: opId }, body: claimBody, cf: VALID_CF }) },
    ];

    for (const carrier of carriers) {
      const response = await handler.fetch(carrier.request, testEnv);
      expect(response.status, carrier.name).toBe(400);
      expect(response.headers.get("licoarc-outcome"), carrier.name).toBe("rejected");
      expect(response.headers.get("licoarc-failure-class"), carrier.name).toBe("invalidRequest");
    }
    expect(counters.shards).toBe(0);
    expect(counters.relays).toBe(0);
  });

  it("rejects transfer-encoding and mismatched content-length", async () => {
    const invite = await generateAccessGrant();
    const { testEnv, counters } = countingEnv();
    const handle = toBase64Url(new Uint8Array(32).fill(7));
    const opId = randomOpId();
    const teRequest = new Request(`https://station.invalid/v1/handles/${handle}/claim`, {
      method: "POST",
      headers: {
        "content-type": CONTROL_MEDIA_TYPE,
        [OPERATION_ID_HEADER]: opId,
        "transfer-encoding": "chunked",
        "content-length": "2",
        authorization: `Bearer ${invite.token}`,
      },
      body: new Uint8Array([0xa1, 0x00, 0x01]),
      cf: VALID_CF as unknown as Record<string, unknown>,
    });
    const teResponse = await handler.fetch(teRequest, testEnv);
    expect(teResponse.status).toBe(400);

    const mismatch = new Request(`https://station.invalid/v1/handles/${handle}/claim`, {
      method: "POST",
      headers: {
        "content-type": CONTROL_MEDIA_TYPE,
        [OPERATION_ID_HEADER]: opId,
        "content-length": "9",
        authorization: `Bearer ${invite.token}`,
      },
      body: new Uint8Array([0xa1, 0x00, 0x01]),
      cf: VALID_CF as unknown as Record<string, unknown>,
    });
    const mismatchResponse = await handler.fetch(mismatch, testEnv);
    expect(mismatchResponse.status).toBe(400);
    expect(counters.shards).toBe(0);
    expect(counters.relays).toBe(0);
  });

  it("rejects over-bound declared lengths and visible headers before reading or routing", async () => {
    const invite = await generateAccessGrant();
    const { testEnv, counters } = countingEnv();
    const pulls = { count: 0 };
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls.count += 1;
        if (pulls.count > 2) throw new Error("over-bound framing must not be read");
        controller.enqueue(new Uint8Array([0xa1]));
      },
    });
    const overLength = new Request("https://station.invalid/v1/reserve", {
      method: "POST",
      headers: {
        authorization: `Bearer ${invite.token}`,
        "content-length": String(MAX_CONTROL_BODY_BYTES + 1),
        "content-type": CONTROL_MEDIA_TYPE,
        [OPERATION_ID_HEADER]: randomOpId(),
      },
      body,
      cf: VALID_CF as unknown as Record<string, unknown>,
    });
    const lengthResponse = await handler.fetch(overLength, testEnv);
    expect(lengthResponse.status).toBe(400);
    // The Workers pool constructs and crosses the request context with two
    // pulls; the handler must reject without a third body-reader pull.
    expect(pulls.count).toBeLessThanOrEqual(2);

    const overHeaders = opRequest("/v1/reserve", {
      token: invite.token,
      headers: {
        "content-type": CONTROL_MEDIA_TYPE,
        [OPERATION_ID_HEADER]: randomOpId(),
        "x-padding": "x".repeat(MAX_HEADER_BYTES),
      },
      body: new Uint8Array([0xa1, 0x00, 0x01]),
      cf: VALID_CF,
    });
    const headerResponse = await handler.fetch(overHeaders, testEnv);
    expect(headerResponse.status).toBe(400);
    expect(counters.shards).toBe(0);
    expect(counters.relays).toBe(0);
  });
});

describe("bounded body reader", () => {
  it("cancels the reader at the submit maximum plus one byte", async () => {
    const invite = await generateAccessGrant();
    const { testEnv, counters } = countingEnv();
    const handle = toBase64Url(new Uint8Array(32).fill(7));
    // The body would poison (throw) on the tenth pull. A reader that stops at
    // MAX_PACKET_BYTES + 1 returns 413 without ever reaching it; an unbounded
    // reader would hit the poison and fail as a read error instead.
    const pulls = { count: 0 };
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls.count += 1;
        if (pulls.count > 9) throw new Error("reader did not stop at the bound");
        controller.enqueue(new Uint8Array(65536));
      },
    });
    const request = new Request(`https://station.invalid/v1/handles/${handle}/submit`, {
      method: "POST",
      headers: {
        "content-type": PROTECTED_PACKET_MEDIA_TYPE,
        [OPERATION_ID_HEADER]: randomOpId(),
        "content-length": "524288",
        authorization: `Bearer ${invite.token}`,
      },
      body,
      cf: VALID_CF as unknown as Record<string, unknown>,
    });
    const response = await handler.fetch(request, testEnv);
    expect(response.status).toBe(413);
    expect(response.headers.get("licoarc-failure-class")).toBe("packetTooLarge");
    expect(pulls.count).toBeLessThanOrEqual(9);
    expect(counters.shards).toBe(0);
    expect(counters.relays).toBe(0);
  });

  it("cancels the reader for control operations above their bound", async () => {
    const invite = await generateAccessGrant();
    const { testEnv, counters } = countingEnv();
    // The body would poison on the sixth pull; the bounded reader must stop
    // at MAX_CONTROL_BODY_BYTES + 1 (five pulls) and cancel before that.
    const pulls = { count: 0 };
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls.count += 1;
        if (pulls.count > 6) throw new Error("reader did not stop at the bound");
        controller.enqueue(new Uint8Array(4096));
      },
    });
    const request = new Request("https://station.invalid/v1/reserve", {
      method: "POST",
      headers: {
        "content-type": CONTROL_MEDIA_TYPE,
        [OPERATION_ID_HEADER]: randomOpId(),
        "content-length": "16384",
        authorization: `Bearer ${invite.token}`,
      },
      body,
      cf: VALID_CF as unknown as Record<string, unknown>,
    });
    const response = await handler.fetch(request, testEnv);
    expect(response.status).toBe(400);
    expect(response.headers.get("licoarc-failure-class")).toBe("invalidRequest");
    expect(pulls.count).toBeLessThanOrEqual(6);
    expect(counters.shards).toBe(0);
    expect(counters.relays).toBe(0);
  });
});

describe("privacy-minimal observability", () => {
  it("emits only allowlisted keys with no request-derived values", async () => {
    const invite = await generateAccessGrant();
    const { testEnv } = countingEnv();
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    let records: Array<unknown> = [];
    try {
      await handler.fetch(
        opRequest("/v1/reserve", {
          token: "wrong",
          headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: randomOpId() },
          body: new Uint8Array([0xa1, 0x00, 0x01]),
          cf: VALID_CF,
        }),
        testEnv,
      );
      const handle = toBase64Url(new Uint8Array(32).fill(7));
      await handler.fetch(
        opRequest(`/v1/handles/${handle}/claim`, {
          token: invite.token,
          headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: randomOpId() },
          body: new Uint8Array([0xa1, 0x00, 0x01]),
          cf: VALID_CF,
        }),
        testEnv,
      );
    } finally {
      // Read the recorded calls before mockRestore(): mockRestore resets the
      // mock history in addition to restoring the original implementation.
      records = logSpy.mock.calls.map((call) => call[0]);
      logSpy.mockRestore();
    }
    expect(records.length).toBeGreaterThanOrEqual(2);
    const keys = new Set<string>();
    for (const record of records) {
      expect(typeof record).toBe("string");
      const parsed = JSON.parse(record as string) as unknown;
      collectKeys(parsed, keys);
      const text = JSON.stringify(parsed);
      expect(text).not.toContain(invite.token);
      expect(text).not.toContain(invite.digestHex);
    }
    for (const key of keys) {
      expect(ALLOWED_KEYS.has(key), `forbidden key ${key}`).toBe(true);
    }
    for (const record of records) {
      const parsed = JSON.parse(record as string) as Record<string, unknown>;
      expect(parsed.schemaVersion).toBe(1);
      expect(["admission", "operation"]).toContain(parsed.event);
    }
  });
});
