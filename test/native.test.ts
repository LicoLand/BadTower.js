/**
 * Native-contract suite against the core-only harness worker: no
 * compatibility listener exists in that deployment, so every behavior
 * here — Reserve → Submit → Claim → Settle, capacity, revocation, the
 * opaque-subject refusal — is station-core's own.
 */
import { env, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { createHmac, randomBytes } from "node:crypto";

const stationKey = () => Buffer.from(env.BADTOWER_STATION_KEY, "base64url");

function invite(mailboxId: Buffer, notAfterSec = Math.floor(Date.now() / 1000) + 3600): string {
  const notAfter = Buffer.alloc(8);
  notAfter.writeBigUInt64BE(BigInt(notAfterSec));
  const mac = createHmac("sha256", stationKey())
    .update(Buffer.concat([Buffer.from("btm1"), mailboxId, notAfter]))
    .digest();
  return `btm1.${Buffer.concat([mailboxId, notAfter, mac]).toString("base64url")}`;
}

const OCTETS = { "Content-Type": "application/octet-stream" };
const auth = (mailboxId: Buffer, notAfterSec?: number) => ({
  Authorization: `Bearer ${invite(mailboxId, notAfterSec)}`,
});

const post = (pathname: string, mailboxId: Buffer, payload: Uint8Array | Buffer, notAfterSec?: number) =>
  SELF.fetch(`https://station.test${pathname}`, {
    method: "POST",
    headers: { ...OCTETS, ...auth(mailboxId, notAfterSec) },
    body: payload,
  });

const handleFor = (mailboxId: Buffer) => Buffer.concat([mailboxId, randomBytes(16)]);

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

const claimBody = (limit: number, exclude: number[] = []) => {
  const out = new Uint8Array(2 + exclude.length * 8);
  const view = new DataView(out.buffer);
  out[0] = limit;
  out[1] = exclude.length;
  exclude.forEach((seq, index) => view.setBigUint64(2 + index * 8, BigInt(seq), false));
  return out;
};

const settleBody = (sequences: number[]) => {
  const out = new Uint8Array(1 + sequences.length * 8);
  const view = new DataView(out.buffer);
  out[0] = sequences.length;
  sequences.forEach((seq, index) => view.setBigUint64(1 + index * 8, BigInt(seq), false));
  return out;
};

const claim = async (mailboxId: Buffer, limit = 16, exclude: number[] = []) => {
  const res = await post("/v1/native/claim", mailboxId, claimBody(limit, exclude));
  return { status: res.status, packets: res.status === 200 ? decodeClaim(new Uint8Array(await res.arrayBuffer())) : null };
};

const submit = (handle: Buffer, packet: Uint8Array | Buffer) =>
  post("/v1/native/submit", randomBytes(16), Buffer.concat([handle, Buffer.from(packet)]));

const subject = () => randomBytes(32);

describe("native binding admission", () => {
  it("serves healthz, refuses plaintext and unknown paths", async () => {
    expect((await SELF.fetch("https://station.test/healthz")).status).toBe(200);
    expect((await SELF.fetch("http://station.test/healthz")).status).toBe(403);
    expect((await SELF.fetch("https://station.test/v1/mailbox")).status).toBe(404);
    for (const path of ["/", "/v1/native"]) {
      expect((await SELF.fetch(`https://station.test${path}`)).status, path).toBe(404);
    }
    const res = await SELF.fetch("https://station.test/v1/native/nope", {
      method: "POST",
      headers: { ...OCTETS, ...auth(randomBytes(16)) },
      body: new Uint8Array(0),
    });
    expect(res.status).toBe(404);
  });

  it("publishes the native contract version as fixed binary fields", async () => {
    const unauthenticated = await SELF.fetch("https://station.test/v1/native/version");
    expect(unauthenticated.status).toBe(401);
    const res = await SELF.fetch("https://station.test/v1/native/version", {
      headers: auth(randomBytes(16)),
    });
    expect(res.status).toBe(200);
    const body = new Uint8Array(await res.arrayBuffer());
    expect(body).toHaveLength(8);
    const view = new DataView(body.buffer, body.byteOffset);
    expect([view.getUint16(0, false), view.getUint16(2, false), view.getUint16(4, false)]).toEqual([
      1, 0, 0,
    ]);
    expect(view.getUint16(6, false)).toBe(0);
  });

  it("refuses forged or missing credentials on native routes", async () => {
    const bad = `btm1.${Buffer.from(randomBytes(56)).toString("base64url")}`;
    for (const header of [undefined, `Bearer ${bad}`, "Bearer x"]) {
      const res = await SELF.fetch("https://station.test/v1/native/capacity", {
        headers: header === undefined ? {} : { Authorization: header },
      });
      expect(res.status, header).toBe(401);
    }
  });
});

describe("reserve and subject binding", () => {
  it("binds one opaque subject, repeats it idempotently, refuses a different one", async () => {
    const mailboxId = randomBytes(16);
    const first = subject();
    expect((await post("/v1/native/reserve", mailboxId, first)).status).toBe(200);
    expect((await post("/v1/native/reserve", mailboxId, first)).status).toBe(200);
    expect((await post("/v1/native/reserve", mailboxId, subject())).status).toBe(409);
    expect((await post("/v1/native/reserve", mailboxId, first)).status).toBe(200);
  });

  it("refuses an expired first bind and malformed subjects", async () => {
    const mailboxId = randomBytes(16);
    const expired = Math.floor(Date.now() / 1000) - 60;
    expect((await post("/v1/native/reserve", mailboxId, subject(), expired)).status).toBe(403);
    expect((await post("/v1/native/reserve", mailboxId, randomBytes(31))).status).toBe(400);
    expect((await post("/v1/native/reserve", mailboxId, subject())).status).toBe(200);
  });
});

describe("submit → claim → settle", () => {
  it("rejects submits to unbound mailboxes and delivers bound packets in order", async () => {
    const mailboxId = randomBytes(16);
    const ghost = await submit(handleFor(mailboxId), randomBytes(8));
    expect(new Uint8Array(await ghost.arrayBuffer())).toEqual(new Uint8Array([1, 1]));

    expect((await post("/v1/native/reserve", mailboxId, subject())).status).toBe(200);
    const bodies = [randomBytes(8), randomBytes(9), randomBytes(10)];
    for (const body of bodies) {
      const res = await submit(handleFor(mailboxId), body);
      expect(new Uint8Array(await res.arrayBuffer())).toEqual(new Uint8Array([0, 255]));
    }
    const first = await claim(mailboxId);
    expect(first.packets).toHaveLength(3);
    expect(first.packets!.map((p) => Number(p.sequence))).toEqual(
      [...first.packets!.map((p) => Number(p.sequence))].sort((a, b) => a - b),
    );
    expect(first.packets!.map((p) => Buffer.from(p.body).length)).toEqual([8, 9, 10]);
  });

  it("replays unsettled packets and honors the exclude list", async () => {
    const mailboxId = randomBytes(16);
    await post("/v1/native/reserve", mailboxId, subject());
    await submit(handleFor(mailboxId), randomBytes(4));
    await submit(handleFor(mailboxId), randomBytes(5));
    const first = await claim(mailboxId);
    expect(first.packets).toHaveLength(2);
    const second = await claim(mailboxId); // unsettled: at-least-once replay
    expect(second.packets!.map((p) => p.sequence)).toEqual(first.packets!.map((p) => p.sequence));
    const excluding = await claim(mailboxId, 16, [first.packets![0]!.sequence]);
    expect(excluding.packets).toHaveLength(1);
    expect(excluding.packets![0]!.sequence).toBe(first.packets![1]!.sequence);
  });

  it("settles only the given sequences and claims the rest", async () => {
    const mailboxId = randomBytes(16);
    expect((await claim(mailboxId)).status).toBe(403); // unbound refuses
    await post("/v1/native/reserve", mailboxId, subject());
    for (let i = 0; i < 3; i += 1) await submit(handleFor(mailboxId), randomBytes(4));
    const { packets } = await claim(mailboxId);
    const settle = await post("/v1/native/settle", mailboxId, settleBody([packets![0]!.sequence, packets![2]!.sequence]));
    expect(settle.status).toBe(204);
    const remaining = await claim(mailboxId);
    expect(remaining.packets!.map((p) => p.sequence)).toEqual([packets![1]!.sequence]);
    const settleAll = await post("/v1/native/settle", mailboxId, settleBody([packets![1]!.sequence]));
    expect(settleAll.status).toBe(204);
    expect((await claim(mailboxId)).packets).toHaveLength(0);
  });

  it("caps claims at the in-flight window and refuses malformed bodies", async () => {
    const mailboxId = randomBytes(16);
    await post("/v1/native/reserve", mailboxId, subject());
    for (let i = 0; i < 18; i += 1) await submit(handleFor(mailboxId), randomBytes(4));
    expect((await claim(mailboxId, 16)).packets).toHaveLength(16);
    expect((await post("/v1/native/claim", mailboxId, claimBody(17))).status).toBe(400);
    expect((await post("/v1/native/claim", mailboxId, new Uint8Array([16]))).status).toBe(400);
    const wrongType = await SELF.fetch("https://station.test/v1/native/claim", {
      method: "POST",
      headers: { "Content-Type": "text/plain", ...auth(mailboxId) },
      body: "x",
    });
    expect(wrongType.status).toBe(400);
  });
});

describe("unrecorded binding transition", () => {
  it("restores recipient access only through a verified re-bind and preserves queued packets", async () => {
    const mailboxId = randomBytes(16);
    const stub = env.MAILBOX.getByName(Buffer.from(mailboxId).toString("hex"));
    const bound = subject();
    // A mailbox bound before binding records existed: meta and packet
    // rows only, so no durable transport is recorded.
    await runInDurableObject(stub, async (_instance, state) => {
      state.storage.sql.exec(
        "CREATE TABLE IF NOT EXISTS meta(id INTEGER PRIMARY KEY CHECK(id = 0), subject BLOB, revoked INTEGER NOT NULL DEFAULT 0)",
      );
      state.storage.sql.exec(
        "CREATE TABLE IF NOT EXISTS packet(seq INTEGER PRIMARY KEY, handle BLOB NOT NULL, body BLOB NOT NULL)",
      );
      state.storage.sql.exec(
        "INSERT INTO meta(id, subject, revoked) VALUES(0, ?, 0)",
        new Uint8Array(bound).buffer,
      );
      state.storage.sql.exec(
        "INSERT INTO packet(seq, handle, body) VALUES(?, ?, ?)",
        7,
        new Uint8Array(handleFor(mailboxId)).buffer,
        new Uint8Array(randomBytes(6)).buffer,
      );
    });
    // Submissions and recipient operations refuse while no transport is
    // recorded — the mailbox cannot receive through either surface.
    const refused = await submit(handleFor(mailboxId), randomBytes(8));
    expect(new Uint8Array(await refused.arrayBuffer())).toEqual(new Uint8Array([1, 1]));
    expect((await claim(mailboxId)).status).toBe(403);
    // A different subject cannot take the mailbox over; the stored
    // subject's re-reserve records the native binding.
    expect((await post("/v1/native/reserve", mailboxId, subject())).status).toBe(409);
    expect((await post("/v1/native/reserve", mailboxId, bound)).status).toBe(200);
    const { packets } = await claim(mailboxId);
    expect(packets!.map((p) => p.sequence)).toEqual([7]);
    const res = await submit(handleFor(mailboxId), randomBytes(8));
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(new Uint8Array([0, 255]));
  });

  it("restores an original-schema mailbox whose owner lives in meta.device_key", async () => {
    const mailboxId = randomBytes(16);
    const stub = env.MAILBOX.getByName(Buffer.from(mailboxId).toString("hex"));
    const bound = subject();
    // The original mailbox schema kept the bound owner in
    // meta.device_key — no subject column, no transport record.
    await runInDurableObject(stub, async (_instance, state) => {
      state.storage.sql.exec(
        "CREATE TABLE IF NOT EXISTS meta(id INTEGER PRIMARY KEY CHECK(id = 0), device_key BLOB, revoked INTEGER NOT NULL DEFAULT 0)",
      );
      state.storage.sql.exec(
        "CREATE TABLE IF NOT EXISTS packet(seq INTEGER PRIMARY KEY, handle BLOB NOT NULL, body BLOB NOT NULL)",
      );
      state.storage.sql.exec(
        "INSERT INTO meta(id, device_key, revoked) VALUES(0, ?, 0)",
        new Uint8Array(bound).buffer,
      );
      state.storage.sql.exec(
        "INSERT INTO packet(seq, handle, body) VALUES(?, ?, ?)",
        7,
        new Uint8Array(handleFor(mailboxId)).buffer,
        new Uint8Array(randomBytes(6)).buffer,
      );
    });
    // A different subject is still refused; the stored owner's reserve
    // upgrades the schema, records the transport and keeps the queue.
    expect((await post("/v1/native/reserve", mailboxId, subject())).status).toBe(409);
    expect((await post("/v1/native/reserve", mailboxId, bound)).status).toBe(200);
    const { packets } = await claim(mailboxId);
    expect(packets!.map((p) => p.sequence)).toEqual([7]);
  });
});

describe("capacity and revocation", () => {
  it("reports capacity only for bound mailboxes", async () => {
    const mailboxId = randomBytes(16);
    const unbound = await SELF.fetch("https://station.test/v1/native/capacity", {
      headers: auth(mailboxId),
    });
    expect(unbound.status).toBe(403);
    await post("/v1/native/reserve", mailboxId, subject());
    const res = await SELF.fetch("https://station.test/v1/native/capacity", {
      headers: auth(mailboxId),
    });
    expect(res.status).toBe(200);
    const body = new Uint8Array(await res.arrayBuffer());
    const view = new DataView(body.buffer);
    expect(view.getBigUint64(0, false)).toBe(BigInt(1000000000));
    expect(view.getBigUint64(8, false)).toBeGreaterThan(0n);
  });

  it("answers mailbox-full transiently when the object would exceed capacity", async () => {
    const previous = env.BADTOWER_MAILBOX_CAPACITY_BYTES;
    const mailboxId = randomBytes(16);
    await post("/v1/native/reserve", mailboxId, subject());
    await submit(handleFor(mailboxId), randomBytes(16));
    try {
      // Overriding the binding shrinks the store's capacity check for
      // the next submit only; no schema or packet is harmed.
      (env as { BADTOWER_MAILBOX_CAPACITY_BYTES: string }).BADTOWER_MAILBOX_CAPACITY_BYTES = "1";
      const res = await submit(handleFor(mailboxId), randomBytes(64));
      expect(new Uint8Array(await res.arrayBuffer())).toEqual(new Uint8Array([2, 3]));
    } finally {
      (env as { BADTOWER_MAILBOX_CAPACITY_BYTES: string }).BADTOWER_MAILBOX_CAPACITY_BYTES = previous;
    }
    const { packets } = await claim(mailboxId);
    expect(packets).toHaveLength(1);
  });

  it("revokes: stored packets gone, reserve/claim refuse, submit rejected", async () => {
    const mailboxId = randomBytes(16);
    await post("/v1/native/reserve", mailboxId, subject());
    await submit(handleFor(mailboxId), randomBytes(8));
    const mac = createHmac("sha256", stationKey()).update(Buffer.concat([Buffer.from("btr1"), mailboxId])).digest();
    const revoke = await SELF.fetch("https://station.test/v1/revoke", {
      method: "POST",
      headers: OCTETS,
      body: Buffer.concat([mailboxId, mac]),
    });
    expect(revoke.status).toBe(204);
    expect((await post("/v1/native/reserve", mailboxId, subject())).status).toBe(403);
    expect((await claim(mailboxId)).status).toBe(403);
    const res = await submit(handleFor(mailboxId), randomBytes(8));
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(new Uint8Array([1, 1]));
  });

  it("revokes a never-bound mailbox: tombstone persists, reserve refuses", async () => {
    const mailboxId = randomBytes(16);
    const mac = createHmac("sha256", stationKey()).update(Buffer.concat([Buffer.from("btr1"), mailboxId])).digest();
    const revoke = await SELF.fetch("https://station.test/v1/revoke", {
      method: "POST",
      headers: OCTETS,
      body: Buffer.concat([mailboxId, mac]),
    });
    expect(revoke.status).toBe(204);
    expect((await post("/v1/native/reserve", mailboxId, subject())).status).toBe(403);
  });

  it("writes no schema for a mailbox that never binds", async () => {
    const mailboxId = randomBytes(16);
    const res = await post("/v1/native/reserve", mailboxId, subject(), Math.floor(Date.now() / 1000) - 60);
    expect(res.status).toBe(403);
    const stub = env.MAILBOX.getByName(Buffer.from(mailboxId).toString("hex"));
    await runInDurableObject(stub, async (_instance, state) => {
      const tables = state.storage.sql
        .exec("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'")
        .toArray();
      expect(tables).toEqual([]);
    });
  });
});
