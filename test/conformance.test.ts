/**
 * Drives the implementation-neutral native-contract conformance cases in
 * `test/conformance/*.json` against the core-only harness worker. The
 * runner supplies the three injected values any implementation's own
 * harness must own: the station key, the configured mailbox capacity
 * and the plaintext policy. Case format: test/conformance/README.md.
 */
/// <reference types="vite/client" />
import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { createHmac, randomBytes } from "node:crypto";

const files = import.meta.glob("./conformance/*.json", {
  eager: true,
  import: "default",
}) as Record<string, unknown>;

type BodySpec =
  | { bytes: string }
  | { fill: { byte: string; length: number } }
  | { submit: { mailbox: string; tag: string; packet?: string; packetFill?: { byte: string; length: number } } }
  | { claim: { limit: number; exclude?: string | null } }
  | { settle: { sequences: string | { literal: number[] }; pick?: number[] } }
  | { revoke: { mailbox: string; forged?: boolean } };

type RequestSpec = {
  method: string;
  path: string;
  mailbox?: string;
  auth?: "valid" | "none" | "forged";
  bindDeadline?: "future" | "past";
  scheme?: "http" | "https";
  contentType?: string;
  body?: BodySpec;
  repeat?: number;
};

type ExpectSpec = {
  status: number;
  body?:
    | { bytes: string }
    | { text: string }
    | { submitResult: { outcome: string; reason: string } }
    | { version: { major: number; minor: number; revision: number; reserved: number } }
    | { capacity: { capacityBytes: string; databaseBytes: string } }
    | { claim: { packets?: Array<{ handle: string; body: string }>; count?: number; saveAs?: string } };
};

type Case = {
  name: string;
  mailboxes?: Record<string, string>;
  assumes?: { plaintextAllowed?: boolean };
  steps: Array<{ request: RequestSpec; expect: ExpectSpec }>;
};

const stationKey = () => Buffer.from(env.BADTOWER_STATION_KEY, "base64url");

function invite(mailboxId: Buffer, key: Buffer, past: boolean): string {
  const notAfter = Buffer.alloc(8);
  notAfter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000) + (past ? -3600 : 3600)));
  const mac = createHmac("sha256", key)
    .update(Buffer.concat([Buffer.from("btm1"), mailboxId, notAfter]))
    .digest();
  return `btm1.${Buffer.concat([mailboxId, notAfter, mac]).toString("base64url")}`;
}

const OUTCOME: Record<string, number> = { accepted: 0, rejected: 1, transient: 2 };
const REASON: Record<string, number> = {
  none: 255,
  "invalid-request": 0,
  "target-unavailable": 1,
  "packet-too-large": 2,
  "mailbox-full": 3,
  "internal-unavailable": 4,
};

const hex = (text: string): Buffer => Buffer.from(text, "hex");

function bodyBytes(spec: BodySpec, mailboxes: Map<string, Buffer>, saved: Map<string, number[]>): Buffer {
  if ("bytes" in spec) return hex(spec.bytes);
  if ("fill" in spec) return Buffer.alloc(spec.fill.length, hex(spec.fill.byte)[0]);
  if ("submit" in spec) {
    const target = mailboxes.get(spec.submit.mailbox);
    if (target === undefined) throw new Error(`unknown mailbox ${spec.submit.mailbox}`);
    const tag = hex(spec.submit.tag);
    if (tag.length !== 16) throw new Error(`submit tag must be 16 bytes, got ${tag.length}`);
    const packet = spec.submit.packetFill !== undefined
      ? Buffer.alloc(spec.submit.packetFill.length, hex(spec.submit.packetFill.byte)[0])
      : hex(spec.submit.packet ?? "");
    return Buffer.concat([target, tag, packet]);
  }
  if ("claim" in spec) {
    const exclude = spec.claim.exclude !== undefined && spec.claim.exclude !== null
      ? saved.get(spec.claim.exclude)
      : undefined;
    if (spec.claim.exclude !== undefined && spec.claim.exclude !== null && exclude === undefined) {
      throw new Error(`no saved sequences named ${spec.claim.exclude}`);
    }
    const seqs = exclude ?? [];
    const out = Buffer.alloc(2 + seqs.length * 8);
    out[0] = spec.claim.limit;
    out[1] = seqs.length;
    seqs.forEach((seq, index) => out.writeBigUInt64BE(BigInt(seq), 2 + index * 8));
    return out;
  }
  if ("settle" in spec) {
    const source = typeof spec.settle.sequences === "string"
      ? saved.get(spec.settle.sequences)
      : spec.settle.sequences.literal;
    if (source === undefined) {
      throw new Error(`no saved sequences named ${String(spec.settle.sequences)}`);
    }
    const picked = spec.settle.pick === undefined ? source : spec.settle.pick.map((i) => source[i]!);
    const out = Buffer.alloc(1 + picked.length * 8);
    out[0] = picked.length;
    picked.forEach((seq, index) => out.writeBigUInt64BE(BigInt(seq), 1 + index * 8));
    return out;
  }
  const target = mailboxes.get(spec.revoke.mailbox);
  if (target === undefined) throw new Error(`unknown mailbox ${spec.revoke.mailbox}`);
  const key = spec.revoke.forged === true ? randomBytes(32) : stationKey();
  const mac = createHmac("sha256", key).update(Buffer.concat([Buffer.from("btr1"), target])).digest();
  return Buffer.concat([target, mac]);
}

function decodeClaim(body: Uint8Array) {
  const count = body[0]!;
  const view = new DataView(body.buffer, body.byteOffset);
  const packets: Array<{ sequence: number; handle: Uint8Array; body: Uint8Array }> = [];
  let at = 1;
  for (let i = 0; i < count; i += 1) {
    const sequence = Number(view.getBigUint64(at, false));
    at += 8;
    const handle = body.slice(at, at + 32);
    at += 32;
    const length = view.getUint32(at, false);
    at += 4;
    packets.push({ sequence, handle, body: body.slice(at, at + length) });
    at += length;
  }
  return packets;
}

async function runStep(
  step: { request: RequestSpec; expect: ExpectSpec },
  mailboxes: Map<string, Buffer>,
  saved: Map<string, number[]>,
): Promise<void> {
  const req = step.request;
  const repeat = req.repeat ?? 1;
  for (let i = 0; i < repeat; i += 1) {
    const headers: Record<string, string> = {};
    if (req.body !== undefined) {
      headers["Content-Type"] = req.contentType ?? "application/octet-stream";
    } else if (req.contentType !== undefined) {
      headers["Content-Type"] = req.contentType;
    }
    const auth = req.auth ?? (req.mailbox !== undefined ? "valid" : "none");
    if (auth !== "none") {
      const mailboxId = mailboxes.get(req.mailbox ?? "");
      if (mailboxId === undefined) throw new Error(`unknown mailbox ${String(req.mailbox)}`);
      const key = auth === "forged" ? randomBytes(32) : stationKey();
      headers.Authorization = `Bearer ${invite(mailboxId, key, req.bindDeadline === "past")}`;
    }
    const body = req.body === undefined ? undefined : bodyBytes(req.body, mailboxes, saved);
    const res = await SELF.fetch(`${req.scheme ?? "https"}://station.test${req.path}`, {
      method: req.method,
      headers,
      body: body === undefined || body.length === 0 ? undefined : body,
    });
    expect(res.status, `${req.method} ${req.path}`).toBe(step.expect.status);
    const expected = step.expect.body;
    if (expected === undefined) continue;
    const raw = new Uint8Array(await res.arrayBuffer());
    if ("bytes" in expected) {
      expect(Buffer.from(raw).toString("hex")).toBe(expected.bytes);
    } else if ("text" in expected) {
      expect(Buffer.from(raw).toString("utf8")).toBe(expected.text);
    } else if ("submitResult" in expected) {
      expect([...raw]).toEqual([
        OUTCOME[expected.submitResult.outcome],
        REASON[expected.submitResult.reason],
      ]);
    } else if ("version" in expected) {
      expect(raw).toHaveLength(8);
      const view = new DataView(raw.buffer, raw.byteOffset);
      expect([
        view.getUint16(0, false),
        view.getUint16(2, false),
        view.getUint16(4, false),
        view.getUint16(6, false),
      ]).toEqual([
        expected.version.major,
        expected.version.minor,
        expected.version.revision,
        expected.version.reserved,
      ]);
    } else if ("capacity" in expected) {
      expect(raw).toHaveLength(16);
      const view = new DataView(raw.buffer, raw.byteOffset);
      expect(view.getBigUint64(0, false)).toBe(BigInt(env.BADTOWER_MAILBOX_CAPACITY_BYTES));
      if (expected.capacity.databaseBytes === "positive") {
        expect(view.getBigUint64(8, false)).toBeGreaterThan(0n);
      }
    } else {
      const packets = decodeClaim(raw);
      if (expected.claim.saveAs !== undefined) {
        saved.set(expected.claim.saveAs, packets.map((p) => p.sequence));
      }
      if (expected.claim.count !== undefined) {
        expect(packets).toHaveLength(expected.claim.count);
      } else {
        const want = expected.claim.packets ?? [];
        expect(packets.map((p) => Buffer.from(p.handle).toString("hex"))).toEqual(
          want.map((p) => p.handle),
        );
        expect(packets.map((p) => Buffer.from(p.body).toString("hex"))).toEqual(
          want.map((p) => p.body),
        );
      }
    }
  }
}

const suites = Object.entries(files)
  .filter(([, content]) => (content as { schema?: unknown }).schema === "badtower-native-conformance/1")
  .sort(([a], [b]) => a.localeCompare(b));
expect(suites.length).toBeGreaterThan(0);

for (const [file, content] of suites) {
  const suite = content as { cases: Case[] };
  describe(`conformance ${file}`, () => {
    for (const testCase of suite.cases) {
      const plaintext = String(env.BADTOWER_ALLOW_PLAINTEXT) === "true";
      const assumption = testCase.assumes?.plaintextAllowed;
      if (assumption !== undefined && assumption !== plaintext) continue;
      it(testCase.name, async () => {
        const mailboxes = new Map(
          Object.entries(testCase.mailboxes ?? {}).map(([name, id]) => [name, hex(id)]),
        );
        const saved = new Map<string, number[]>();
        for (const step of testCase.steps) {
          await runStep(step, mailboxes, saved);
        }
      });
    }
  });
}
