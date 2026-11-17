#!/usr/bin/env node
/**
 * Two-endpoint interoperability run against a local Station.
 *
 * This is the CI proof that the published `licoarc-client` can use the
 * Station end to end: it mints two invitations, enrolls two independent
 * endpoints (registration + CHALLENGE/HELLO handshake), sends while the
 * peer is offline, then drains the peer's mailbox and compares the
 * received bytes. Nothing here uses a repository-external script, a
 * production secret, or a live Station.
 *
 * Requirements:
 *   - node >= 22
 *   - openssl on PATH (station.mjs tls)
 *   - the published licoarc-client binary on PATH, or LICOARC_CLIENT
 *
 * Usage:
 *   node scripts/interop.mjs
 *   KEEP_INTEROP=1 node scripts/interop.mjs   # keep the temp dir/logs
 */
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const STATION = path.join(ROOT, "scripts", "station.mjs");
const CLIENT = process.env.LICOARC_CLIENT ?? "licoarc-client";
const KEEP = process.env.KEEP_INTEROP === "1";
const NPX = process.platform === "win32" ? "npx.cmd" : "npx";

const work = fs.mkdtempSync(path.join(os.tmpdir(), "badtower-interop-"));
const logFile = path.join(work, "wrangler.log");
fs.writeFileSync(logFile, "");
let stationProcess = null;
let stationLog = "";

function fail(message) {
  throw new Error(message);
}

function run(file, args, options = {}) {
  return execFileSync(file, args, {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });
}

function runStation(args) {
  return run(process.execPath, [STATION, ...args]);
}

function runClient(args) {
  return run(CLIENT, args, { timeout: 90_000 });
}

function jsonLine(text) {
  const line = text.trim().split("\n").filter(Boolean).at(-1);
  if (line === undefined) fail(`expected a JSON line, got ${JSON.stringify(text)}`);
  try {
    return JSON.parse(line);
  } catch {
    fail(`expected JSON, got ${JSON.stringify(line)}`);
  }
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => {
        if (address === null || typeof address === "string") reject(new Error("no port"));
        else resolve(address.port);
      });
    });
  });
}

function health(port, caFile) {
  const ca = fs.readFileSync(caFile);
  return new Promise((resolve) => {
    const request = https.get(
      {
        host: "127.0.0.1",
        port,
        path: "/healthz",
        ca,
        rejectUnauthorized: true,
        timeout: 1_000,
      },
      (response) => {
        response.resume();
        resolve(response.statusCode === 200);
      },
    );
    request.on("timeout", () => {
      request.destroy();
      resolve(false);
    });
    request.on("error", () => resolve(false));
  });
}

async function waitForHealth(port, ca) {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if (stationProcess?.exitCode !== null) {
      fail(`wrangler exited before the Station was healthy:\n${stationLog.slice(-4_000)}`);
    }
    if (await health(port, ca)) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  fail(`Station did not become healthy:\n${stationLog.slice(-4_000)}`);
}

function packetFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir, { recursive: true })
    .filter((entry) => String(entry).endsWith(".packet"))
    .map((entry) => path.join(dir, String(entry)));
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function main() {
  const stationDir = path.join(work, "station");
  const ca = path.join(stationDir, "tls", "ca.crt");
  const port = await freePort();

  console.log(`interop: station dir ${work}`);
  runStation(["init", "--dir", stationDir]);
  runStation(["tls", "--dir", stationDir, "--ip", "127.0.0.1", "--dns", "localhost"]);
  const aInvite = path.join(work, "a.invitation");
  const bInvite = path.join(work, "b.invitation");
  const aInfo = runStation(["invite", "--dir", stationDir, "--out", aInvite]);
  const bInfo = runStation(["invite", "--dir", stationDir, "--out", bInvite]);
  const mailboxA = /mailbox ([0-9a-f]{32})/.exec(aInfo)?.[1];
  const mailboxB = /mailbox ([0-9a-f]{32})/.exec(bInfo)?.[1];
  if (mailboxA === undefined || mailboxB === undefined) fail("invite did not print mailbox ids");

  const wranglerHome = path.join(work, "wrangler-home");
  const xdgConfig = path.join(work, "xdg");
  fs.mkdirSync(wranglerHome, { recursive: true });
  fs.mkdirSync(xdgConfig, { recursive: true });

  stationProcess = spawn(
    NPX,
    [
      "wrangler", "dev",
      "--local",
      "--ip", "127.0.0.1",
      "--port", String(port),
      "--local-protocol", "https",
      "--https-key-path", path.join(stationDir, "tls", "server.key"),
      "--https-cert-path", path.join(stationDir, "tls", "server.crt"),
      "--persist-to", path.join(work, "state"),
      "--env-file", path.join(stationDir, ".dev.vars"),
      "-c", "apps/station/wrangler.jsonc",
    ],
    {
      cwd: ROOT,
      env: { ...process.env, WRANGLER_HOME: wranglerHome, XDG_CONFIG_HOME: xdgConfig },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const capture = (chunk) => {
    stationLog += chunk.toString();
    try {
      fs.appendFileSync(logFile, chunk);
    } catch {
      // The temp directory may already be gone during shutdown.
    }
  };
  stationProcess.stdout.on("data", capture);
  stationProcess.stderr.on("data", capture);
  stationProcess.on("exit", (code) => {
    if (code !== 0 && code !== null) stationLog += `\nwrangler exited ${code}\n`;
  });

  await waitForHealth(port, ca);
  console.log(`interop: station healthy on https://127.0.0.1:${port}`);

  const station = `https://127.0.0.1:${port}`;
  const aCredentials = path.join(work, "a.credentials");
  const bCredentials = path.join(work, "b.credentials");
  const aEnroll = jsonLine(
    runClient([
      "enroll", "--station", station,
      "--invitation-file", aInvite,
      "--credentials", aCredentials,
      "--ca", ca,
    ]),
  );
  const bEnroll = jsonLine(
    runClient([
      "enroll", "--station", station,
      "--invitation-file", bInvite,
      "--credentials", bCredentials,
      "--ca", ca,
    ]),
  );
  if (typeof aEnroll.handle !== "string" || typeof bEnroll.handle !== "string") {
    fail("enroll did not return handles");
  }
  // A fresh process must read the same learned mailbox from credentials.
  const aHandle = jsonLine(runClient(["handle", "--credentials", aCredentials])).handle;
  const bHandle = jsonLine(runClient(["handle", "--credentials", bCredentials])).handle;
  // A handle's 16-byte tag is minted per call; only the mailbox-id prefix
  // must survive the credentials round trip.
  const handleMailbox = (handle) => Buffer.from(handle, "base64url").subarray(0, 16).toString("hex");
  if (handleMailbox(aHandle) !== mailboxA || handleMailbox(bHandle) !== mailboxB) {
    fail("handle mailbox prefix did not survive the credentials round trip");
  }
  console.log("interop: two endpoints enrolled and handshook");

  // Direction 1: A sends while B is offline, then B drains. The packet
  // bytes are deterministic so a rerun can compare the same hashes.
  const aToB = Buffer.alloc(96, 0xa1);
  const aPacket = path.join(work, "a-to-b.bin");
  fs.writeFileSync(aPacket, aToB);
  const sendAB = jsonLine(
    runClient(["send", "--credentials", aCredentials, "--handle", bHandle, "--file", aPacket, "--ca", ca]),
  );
  if (sendAB.submitted !== true) fail("A -> B send was not submitted");
  const bSpool = path.join(work, "b-spool");
  const recvB = jsonLine(
    runClient(["receive", "--credentials", bCredentials, "--spool", bSpool, "--ca", ca]),
  );
  if (recvB.delivered !== 1) fail(`B expected 1 delivery, got ${JSON.stringify(recvB)}`);
  const bPackets = packetFiles(bSpool);
  if (bPackets.length !== 1) fail(`B spool expected 1 packet, got ${bPackets.length}`);
  if (!fs.readFileSync(bPackets[0]).equals(aToB)) fail("B received bytes differ from A's packet");

  // Direction 2: B sends while A is offline, then A drains.
  const bToA = Buffer.alloc(64, 0xb2);
  const bPacket = path.join(work, "b-to-a.bin");
  fs.writeFileSync(bPacket, bToA);
  const sendBA = jsonLine(
    runClient(["send", "--credentials", bCredentials, "--handle", aHandle, "--file", bPacket, "--ca", ca]),
  );
  if (sendBA.submitted !== true) fail("B -> A send was not submitted");
  const aSpool = path.join(work, "a-spool");
  const recvA = jsonLine(
    runClient(["receive", "--credentials", aCredentials, "--spool", aSpool, "--ca", ca]),
  );
  if (recvA.delivered !== 1) fail(`A expected 1 delivery, got ${JSON.stringify(recvA)}`);
  const aPackets = packetFiles(aSpool);
  if (aPackets.length !== 1) fail(`A spool expected 1 packet, got ${aPackets.length}`);
  if (!fs.readFileSync(aPackets[0]).equals(bToA)) fail("A received bytes differ from B's packet");

  // A drained mailbox must answer DRAINED with no further deliveries.
  const recvBAgain = jsonLine(
    runClient(["receive", "--credentials", bCredentials, "--spool", path.join(work, "b-spool-2"), "--ca", ca]),
  );
  if (recvBAgain.delivered !== 0) fail(`B expected 0 deliveries after drain, got ${JSON.stringify(recvBAgain)}`);

  console.log(
    JSON.stringify({
      ok: true,
      station,
      client: CLIENT,
      mailboxA,
      mailboxB,
      offlineDeliveries: 2,
      packets: [
        { direction: "A->B", bytes: aToB.length, sha256: sha256(aToB) },
        { direction: "B->A", bytes: bToA.length, sha256: sha256(bToA) },
      ],
      redrained: recvBAgain.delivered,
    }),
  );
}

async function cleanup() {
  if (stationProcess !== null && stationProcess.exitCode === null) {
    stationProcess.kill("SIGTERM");
    await Promise.race([
      new Promise((resolve) => stationProcess.once("exit", resolve)),
      new Promise((resolve) => setTimeout(resolve, 5_000)),
    ]);
  }
  if (!KEEP) fs.rmSync(work, { recursive: true, force: true });
  else console.log(`interop: kept ${work}`);
}

try {
  await main();
} catch (error) {
  console.error(`interop failed: ${error.message}`);
  if (stationLog.length > 0) console.error(`--- wrangler tail ---\n${stationLog.slice(-4_000)}`);
  process.exitCode = 1;
} finally {
  await cleanup();
}
