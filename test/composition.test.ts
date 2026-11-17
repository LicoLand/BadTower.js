/**
 * Composition proof: the deployable Worker wires station-core and the
 * licoarc.mailbox.v1 listener into one mailbox. A native client can
 * submit a packet that a LicoArc socket then receives, and a LicoArc
 * client can submit one that a native client claims and settles — one
 * store, two surfaces.
 */
import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { createHmac, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import {
  decodeStationFrame,
  encodeClientFrame,
  type StationFrame,
} from "@badtower/plugin-licoarc-mailbox";

const stationKey = () => Buffer.from(env.BADTOWER_STATION_KEY, "base64url");
const HELLO_CONTEXT = Buffer.from("licoarc-mailbox-hello-v1");

function invite(mailboxId: Buffer): string {
  const notAfter = Buffer.alloc(8);
  notAfter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000) + 3600));
  const mac = createHmac("sha256", stationKey())
    .update(Buffer.concat([Buffer.from("btm1"), mailboxId, notAfter]))
    .digest();
  return `btm1.${Buffer.concat([mailboxId, notAfter, mac]).toString("base64url")}`;
}

const bearer = (mailboxId: Buffer) => ({
  Authorization: `Bearer ${invite(mailboxId)}`,
});

function device() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const hello = (nonce: Uint8Array) =>
    sign(null, Buffer.concat([HELLO_CONTEXT, Buffer.from(nonce)]), privateKey);
  return { pub: new Uint8Array(pub), hello };
}

const handleFor = (mailboxId: Uint8Array) => {
  const handle = new Uint8Array(32);
  handle.set(mailboxId, 0);
  handle.set(randomBytes(16), 16);
  return handle;
};

async function takeFrame(events: Array<StationFrame | { closed: number }>, kind: string, tries = 12): Promise<StationFrame> {
  for (let i = 0; i < tries; i += 1) {
    if (events.length > 0) {
      const frame = events.shift()!;
      if ("kind" in frame && frame.kind === kind) return frame;
      if ("closed" in frame) throw new Error(`socket closed ${frame.closed}`);
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`no ${kind} frame`);
}

async function wsReady(mailboxId: Buffer) {
  const response = await SELF.fetch("https://station.test/v1/mailbox", {
    headers: {
      Upgrade: "websocket",
      "Sec-WebSocket-Protocol": "licoarc.mailbox.v1",
      ...bearer(mailboxId),
    },
  });
  expect(response.status).toBe(101);
  const ws = response.webSocket!;
  const events: Array<StationFrame | { closed: number }> = [];
  ws.addEventListener("message", (event) => {
    void (async () => {
      const buffer = event.data instanceof Blob
        ? await event.data.arrayBuffer()
        : (event.data as ArrayBuffer);
      events.push(decodeStationFrame(new Uint8Array(buffer)));
    })();
  });
  ws.addEventListener("close", (e) => events.push({ closed: e.code }));
  ws.accept();
  const challenge = await takeFrame(events, "challenge");
  const dev = device();
  ws.send(encodeClientFrame({
    kind: "hello",
    deviceKey: dev.pub,
    signature: new Uint8Array(dev.hello((challenge as { nonce: Uint8Array }).nonce)),
  }));
  await takeFrame(events, "ready");
  return { ws, events, dev };
}

function decodeClaim(body: Uint8Array) {
  const count = body[0]!;
  const packets: Array<{ sequence: number; handle: Uint8Array; body: Uint8Array }> = [];
  let at = 1;
  const view = new DataView(body.buffer, body.byteOffset);
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

const seqList = (sequences: number[]) => {
  const out = new Uint8Array(1 + sequences.length * 8);
  const view = new DataView(out.buffer);
  out[0] = sequences.length;
  sequences.forEach((seq, index) => view.setBigUint64(1 + index * 8, BigInt(seq), false));
  return out;
};

const OCTETS = { "Content-Type": "application/octet-stream" };

describe("core + plugin composition", () => {
  it("serves the native contract version through the composed Worker", async () => {
    const res = await SELF.fetch("https://station.test/v1/native/version", {
      headers: bearer(randomBytes(16)),
    });
    expect(res.status).toBe(200);
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(
      new Uint8Array([0, 1, 0, 0, 0, 0, 0, 0]),
    );
  });

  it("delivers a native client's packet to the LicoArc socket and drains after ACK", async () => {
    const mailboxId = randomBytes(16);
    const receiver = await wsReady(mailboxId);
    const packet = randomBytes(48);
    const submit = await SELF.fetch("https://station.test/v1/native/submit", {
      method: "POST",
      headers: { ...OCTETS, ...bearer(randomBytes(16)) },
      body: Buffer.concat([Buffer.from(handleFor(mailboxId)), packet]),
    });
    expect(submit.status).toBe(200);
    expect(new Uint8Array(await submit.arrayBuffer())).toEqual(new Uint8Array([0, 255]));

    const deliver = await takeFrame(receiver.events, "deliver");
    if (deliver.kind !== "deliver") throw new Error("unreachable");
    expect(new Uint8Array(deliver.packet)).toEqual(new Uint8Array(packet));
    receiver.ws.send(encodeClientFrame({ kind: "ack", sequence: deliver.sequence }));
    await takeFrame(receiver.events, "drained");
    receiver.ws.close();
  });

  it("lets a native client claim and settle a packet sent over the LicoArc socket", async () => {
    const mailboxId = randomBytes(16);
    // The mailbox must exist for submit to accept: bind it over the wire.
    const owner = await wsReady(mailboxId);
    const sender = await wsReady(randomBytes(16));
    const packet = randomBytes(24);
    sender.ws.send(encodeClientFrame({
      kind: "send",
      requestId: 3,
      handle: handleFor(mailboxId),
      packet,
    }));
    const result = await takeFrame(sender.events, "result");
    if (result.kind !== "result") throw new Error("unreachable");
    expect(result.outcome).toBe(0);
    sender.ws.close();
    owner.ws.close();

    const claim = await SELF.fetch("https://station.test/v1/native/claim", {
      method: "POST",
      headers: { ...OCTETS, ...bearer(mailboxId) },
      body: new Uint8Array([16, 0]),
    });
    expect(claim.status).toBe(200);
    const packets = decodeClaim(new Uint8Array(await claim.arrayBuffer()));
    expect(packets).toHaveLength(1);
    expect(new Uint8Array(packets[0]!.body)).toEqual(new Uint8Array(packet));

    const settle = await SELF.fetch("https://station.test/v1/native/settle", {
      method: "POST",
      headers: { ...OCTETS, ...bearer(mailboxId) },
      body: seqList([packets[0]!.sequence]),
    });
    expect(settle.status).toBe(204);

    const again = await SELF.fetch("https://station.test/v1/native/claim", {
      method: "POST",
      headers: { ...OCTETS, ...bearer(mailboxId) },
      body: new Uint8Array([16, 0]),
    });
    expect(decodeClaim(new Uint8Array(await again.arrayBuffer()))).toHaveLength(0);
  });
});
