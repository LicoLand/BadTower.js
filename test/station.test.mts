import { execFileSync } from "node:child_process";
import { createHmac } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

const STATION = path.resolve("scripts/station.mjs");
const run = (args: string[]) =>
  execFileSync("node", [STATION, ...args], { encoding: "utf8" });

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "badtower-station-test-"));
}

describe("station.mjs init", () => {
  it("creates owner-only key material and refuses to overwrite", () => {
    const dir = path.join(tempDir(), "station");
    run(["init", "--dir", dir]);
    const key = fs.readFileSync(path.join(dir, "station.key"), "utf8").trim();
    expect(Buffer.from(key, "base64url")).toHaveLength(32);
    const vars = fs.readFileSync(path.join(dir, ".dev.vars"), "utf8");
    expect(vars).toContain(`BADTOWER_STATION_KEY=${key}`);
    expect((fs.statSync(path.join(dir, "station.key")).mode & 0o777)).toBe(0o600);
    expect((fs.statSync(path.join(dir, ".dev.vars")).mode & 0o777)).toBe(0o600);
    expect((fs.statSync(dir).mode & 0o777)).toBe(0o700);
    expect(() => run(["init", "--dir", dir])).toThrow();
  });
});

describe("station.mjs invite", () => {
  it("mints a btm1 credential matching the worker verifier's shape", () => {
    const dir = path.join(tempDir(), "station");
    run(["init", "--dir", dir]);
    const out = path.join(dir, "one.invitation");
    const output = run(["invite", "--dir", dir, "--out", out]);
    const token = fs.readFileSync(out, "utf8").trim();
    expect(token.startsWith("btm1.")).toBe(true);
    const raw = Buffer.from(token.slice(5), "base64url");
    expect(raw).toHaveLength(56);
    const mailboxId = raw.subarray(0, 16);
    const notAfter = raw.readBigUInt64BE(16);
    expect(Number(notAfter)).toBeGreaterThan(Math.floor(Date.now() / 1000));
    const key = Buffer.from(fs.readFileSync(path.join(dir, "station.key"), "utf8").trim(), "base64url");
    const expected = createHmac("sha256", key)
      .update(Buffer.concat([Buffer.from("btm1"), mailboxId, raw.subarray(16, 24)]))
      .digest();
    expect(raw.subarray(24)).toEqual(expected);
    expect(output).toContain(mailboxId.toString("hex"));
    expect((fs.statSync(out).mode & 0o777)).toBe(0o600);
  });
});

describe("station.mjs tls", () => {
  it("produces a CA-verifiable server certificate with the requested SAN", () => {
    try {
      execFileSync("openssl", ["version"], { stdio: "ignore" });
    } catch {
      console.warn("openssl missing; skipping tls vector");
      return;
    }
    const dir = path.join(tempDir(), "station");
    run(["init", "--dir", dir]);
    run(["tls", "--dir", dir, "--ip", "127.0.0.1", "--dns", "station.test"]);
    const tlsDir = path.join(dir, "tls");
    const verify = execFileSync(
      "openssl",
      ["verify", "-CAfile", path.join(tlsDir, "ca.crt"), path.join(tlsDir, "server.crt")],
      { encoding: "utf8" },
    );
    expect(verify).toContain("OK");
    const text = execFileSync("openssl", ["x509", "-in", path.join(tlsDir, "server.crt"), "-text", "-noout"], {
      encoding: "utf8",
    });
    expect(text).toContain("IP Address:127.0.0.1");
    expect(text).toContain("DNS:station.test");
    expect((fs.statSync(path.join(tlsDir, "ca.key")).mode & 0o777)).toBe(0o600);
    expect((fs.statSync(path.join(tlsDir, "server.key")).mode & 0o777)).toBe(0o600);
  });
});
