/**
 * The operator metrics surface: aggregate cost dimensions from
 * docs/COST.md exported over GET /v1/metrics behind the station key.
 * The assertions pin two contract properties: every cost dimension is
 * present as an aggregate, and nothing exported can name a mailbox,
 * handle, subject, address, path, IP or content.
 */
import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { createHmac, randomBytes } from "node:crypto";

const stationKey = () => Buffer.from(env.BADTOWER_STATION_KEY, "base64url");
const operatorAuth = () => ({ Authorization: `Bearer ${env.BADTOWER_STATION_KEY}` });
const rb = (n: number) => Buffer.from(randomBytes(n));

function invite(mailboxId: Buffer): string {
  const notAfter = Buffer.alloc(8);
  notAfter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000) + 3600));
  const mac = createHmac("sha256", stationKey())
    .update(Buffer.concat([Buffer.from("btm1"), mailboxId, notAfter]))
    .digest();
  return `btm1.${Buffer.concat([mailboxId, notAfter, mac]).toString("base64url")}`;
}

const OCTETS = { "Content-Type": "application/octet-stream" };

const post = (path: string, mailboxId: Buffer, body: Uint8Array | Buffer) =>
  SELF.fetch(`https://station.test${path}`, {
    method: "POST",
    headers: { ...OCTETS, Authorization: `Bearer ${invite(mailboxId)}` },
    body,
  });

describe("GET /v1/metrics", () => {
  it("refuses anyone without the station key", async () => {
    expect((await SELF.fetch("https://station.test/v1/metrics")).status).toBe(401);
    const wrong = rb(32).toString("base64url");
    const res = await SELF.fetch("https://station.test/v1/metrics", {
      headers: { Authorization: `Bearer ${wrong}` },
    });
    expect(res.status).toBe(401);
  });

  it("exports every cost dimension as bounded-label aggregates", async () => {
    const mailboxId = rb(16);
    await post("/v1/native/reserve", mailboxId, rb(32));
    const handle = Buffer.concat([mailboxId, rb(16)]);
    await post("/v1/native/submit", rb(16), Buffer.concat([handle, rb(8)]));
    const claimBody = new Uint8Array([16, 0]);
    await post("/v1/native/claim", mailboxId, claimBody);
    await SELF.fetch("https://station.test/v1/native/capacity", {
      headers: { Authorization: `Bearer ${invite(mailboxId)}` },
    });

    const res = await SELF.fetch("https://station.test/v1/metrics", {
      headers: operatorAuth(),
    });
    expect(res.status).toBe(200);
    const body = await res.text();

    // Worker requests (R_w) by operation and plan.
    expect(body).toMatch(/badtower_worker_requests_total\{operation="reserve",plan="free"\} [1-9]/);
    expect(body).toMatch(/badtower_worker_requests_total\{operation="submit",plan="free"\} [1-9]/);
    expect(body).toMatch(/badtower_worker_requests_total\{operation="metrics",plan="free"\} [1-9]/);
    // Durable Object requests (R_do) and active duration (T_active).
    expect(body).toMatch(/badtower_do_requests_total\{operation="submit",plan="free"\} [1-9]/);
    expect(body).toMatch(/badtower_do_active_ms_total\{operation="submit",plan="free"\} \d+/);
    // SQLite rows read and written (Rows_r, Rows_w).
    expect(body).toMatch(/badtower_rows_read_total\{operation="claim",plan="free"\} [1-9]/);
    expect(body).toMatch(/badtower_rows_written_total\{operation="submit",plan="free"\} [1-9]/);
    // Stored bytes (S) — positive because a bound mailbox wrote schema.
    expect(body).toMatch(/badtower_sqlite_bytes\{plan="free"\} [1-9]\d*/);
  });

  it("never exports an identifier, address, path or content label", async () => {
    const mailboxId = rb(16);
    await post("/v1/native/reserve", mailboxId, rb(32));
    const handle = Buffer.concat([mailboxId, rb(16)]);
    await post("/v1/native/submit", rb(16), Buffer.concat([handle, rb(8)]));
    const res = await SELF.fetch("https://station.test/v1/metrics", {
      headers: operatorAuth(),
    });
    const body = await res.text();

    expect(body).not.toContain(mailboxId.toString("hex"));
    expect(body).not.toContain(handle.toString("hex"));
    for (const forbidden of [
      "mailbox_id",
      "mailbox=",
      "handle=",
      "subject=",
      "ip=",
      "address=",
      "path=",
      "content=",
      "user_agent=",
      "token=",
      "packet=",
    ]) {
      expect(body, forbidden).not.toContain(forbidden);
    }
  });
});
