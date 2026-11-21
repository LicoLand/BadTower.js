import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

const STATION = path.resolve("scripts/station.mjs");
// Every test here shells out to node/openssl; on a contended host one
// spawn can cost seconds, so both child and suite bounds exceed the
// 5s default. Each child leads its own process group (detached), so a
// wedged tree — openssl grandchildren of `station tls` included — dies
// at CHILD_TIMEOUT instead of blocking the test thread past it.
const CHILD_TIMEOUT = 30_000;
const TEST_TIMEOUT = 60_000;

interface Spawned {
  status: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

function spawnCmd(file: string, args: string[]): Promise<Spawned> {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { detached: true });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const watchdog = setTimeout(() => {
      timedOut = true;
      try {
        process.kill(-(child.pid as number), "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    }, CHILD_TIMEOUT);
    child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString()));
    child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
    child.on("error", (error) => {
      clearTimeout(watchdog);
      reject(error);
    });
    child.on("close", (status) => {
      clearTimeout(watchdog);
      resolve({ status, stdout, stderr, timedOut });
    });
  });
}

async function run(args: string[]): Promise<string> {
  const r = await spawnCmd("node", [STATION, ...args]);
  if (r.timedOut) throw new Error(`station ${args.join(" ")} timed out after ${CHILD_TIMEOUT}ms`);
  if (r.status !== 0) throw new Error(`station ${args.join(" ")} exited ${r.status}: ${r.stderr.trim()}`);
  return r.stdout;
}

async function openssl(args: string[]): Promise<string> {
  const r = await spawnCmd("openssl", args);
  if (r.timedOut) throw new Error(`openssl ${args.join(" ")} timed out after ${CHILD_TIMEOUT}ms`);
  if (r.status !== 0) throw new Error(`openssl ${args.join(" ")} exited ${r.status}: ${r.stderr.trim()}`);
  return r.stdout;
}

// A refused command must fail the Station way — exit 1 with the
// `station:` diagnostic — so a timeout or stray non-zero exit cannot
// stand in for the refusal under test.
async function expectRefusal(args: string[], diagnostic: RegExp): Promise<void> {
  const r = await spawnCmd("node", [STATION, ...args]);
  expect(r.timedOut).toBe(false);
  expect(r.status).toBe(1);
  expect(r.stderr).toMatch(diagnostic);
}

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "badtower-station-test-"));
}

describe("station.mjs init", () => {
  it("creates owner-only key material and refuses to overwrite", async () => {
    const dir = path.join(tempDir(), "station");
    await run(["init", "--dir", dir]);
    const key = fs.readFileSync(path.join(dir, "station.key"), "utf8").trim();
    expect(Buffer.from(key, "base64url")).toHaveLength(32);
    const vars = fs.readFileSync(path.join(dir, ".dev.vars"), "utf8");
    expect(vars).toContain(`BADTOWER_STATION_KEY=${key}`);
    expect((fs.statSync(path.join(dir, "station.key")).mode & 0o777)).toBe(0o600);
    expect((fs.statSync(path.join(dir, ".dev.vars")).mode & 0o777)).toBe(0o600);
    expect((fs.statSync(dir).mode & 0o777)).toBe(0o700);
    await expectRefusal(["init", "--dir", dir], /station: .*already exists; refusing to overwrite/);
  }, TEST_TIMEOUT);
});

describe("station.mjs invite", () => {
  it("mints a btm1 credential matching the worker verifier's shape", async () => {
    const dir = path.join(tempDir(), "station");
    await run(["init", "--dir", dir]);
    const out = path.join(dir, "one.invitation");
    const output = await run(["invite", "--dir", dir, "--out", out]);
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
  }, TEST_TIMEOUT);
});

describe("station.mjs private output boundary", () => {
  const repo = path.resolve(path.dirname(STATION), "..");

  it("refuses private outputs at arbitrary in-repository paths", async () => {
    const strayDir = path.join(repo, "scratch-station-test");
    await expectRefusal(["init", "--dir", strayDir], /station: .*is inside the repository/);
    expect(fs.existsSync(strayDir)).toBe(false);
    const dir = path.join(tempDir(), "station");
    await run(["init", "--dir", dir]);
    const strayInvite = path.join(repo, "stray.invitation");
    await expectRefusal(
      ["invite", "--dir", dir, "--out", strayInvite],
      /station: .*is inside the repository/,
    );
    expect(fs.existsSync(strayInvite)).toBe(false);
  }, TEST_TIMEOUT);

  it("accepts private outputs under the ignored data/ root", async () => {
    const dir = path.join(repo, "data", `station-test-${process.pid}`);
    try {
      await run(["init", "--dir", dir]);
      expect(fs.existsSync(path.join(dir, "station.key"))).toBe(true);
      const out = path.join(repo, "data", `invite-test-${process.pid}.invitation`);
      await run(["invite", "--dir", dir, "--out", out]);
      expect(fs.readFileSync(out, "utf8").trim().startsWith("btm1.")).toBe(true);
      fs.rmSync(out, { force: true });
    } finally {
      fs.rmSync(dir, { force: true, recursive: true });
    }
  }, TEST_TIMEOUT);
});

describe("station.mjs tls", () => {
  it("produces a CA-verifiable server certificate with the requested SAN", async () => {
    try {
      await openssl(["version"]);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        console.warn("openssl missing; skipping tls vector");
        return;
      }
      throw error; // a timed-out probe fails the test, it does not skip it
    }
    const dir = path.join(tempDir(), "station");
    await run(["init", "--dir", dir]);
    await run(["tls", "--dir", dir, "--ip", "127.0.0.1", "--dns", "station.test"]);
    const tlsDir = path.join(dir, "tls");
    const verify = await openssl([
      "verify",
      "-CAfile",
      path.join(tlsDir, "ca.crt"),
      path.join(tlsDir, "server.crt"),
    ]);
    expect(verify).toContain("OK");
    const text = await openssl(["x509", "-in", path.join(tlsDir, "server.crt"), "-text", "-noout"]);
    expect(text).toContain("IP Address:127.0.0.1");
    expect(text).toContain("DNS:station.test");
    expect((fs.statSync(path.join(tlsDir, "ca.key")).mode & 0o777)).toBe(0o600);
    expect((fs.statSync(path.join(tlsDir, "server.key")).mode & 0o777)).toBe(0o600);
  }, TEST_TIMEOUT);
});
