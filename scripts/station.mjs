#!/usr/bin/env node
/**
 * BadTower Station operations CLI: every privileged input is an argument,
 * never tracked data. Node built-ins only; TLS material comes from the
 * openssl CLI.
 *
 *   init --dir DIR
 *   invite --dir DIR [--bind-within 7d] [--out FILE]
 *   revoke --dir DIR --station URL --mailbox HEX [--ca PEM]
 *   tls --dir DIR --ip ADDR [--dns NAME]
 *   cloudflare-deploy --dir DIR [--domain NAME]
 *   docker-deploy --ssh HOST --dir DIR --listen IP:PORT [--remote-dir PATH]
 *   health --station URL [--ca PEM]
 */
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHmac, randomBytes, webcrypto } from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const B64URL = /^[A-Za-z0-9_-]+$/;
// Flag charsets: nothing a remote shell, scp target or ssh option parser
// could reinterpret (no whitespace, quotes, metacharacters or newlines).
const SAFE_HOST = /^[\w@.-]+$/; // [user@]host
const SAFE_PATH = /^[\w./-]+$/; // remote directory
const SAFE_IP = /^[0-9a-fA-F.:]+$/; // IP literal
const SAFE_DNS = /^[\w.-]+$/; // DNS name
const SAFE_LISTEN = /^[0-9a-fA-F.:[\]]+$/; // IP:PORT

function toBase64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function fromBase64Url(text) {
  if (!B64URL.test(text)) throw new Error("invalid base64url");
  return Buffer.from(text, "base64url");
}

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
// Repository-relative roots that both .gitignore and .dockerignore
// exclude — the only places private material may be written in-tree.
const REPO_PRIVATE_DIRS = ["data", "secrets"];

function fail(message) {
  console.error(`station: ${message}`);
  process.exit(1);
}

/**
 * Private material must never land at an arbitrary repository-relative
 * path: anything inside the repository that is not under an
 * ignore-covered private root is refused outright.
 */
function privateOutput(file) {
  const resolved = path.resolve(file);
  const relative = path.relative(REPO, resolved);
  if (!relative.startsWith("..") && !path.isAbsolute(relative)) {
    const first = relative.split(path.sep)[0];
    if (!REPO_PRIVATE_DIRS.includes(first)) {
      fail(`${file} is inside the repository; private material goes under ${REPO_PRIVATE_DIRS.join("/ or ")}/ or outside the tree`);
    }
  }
  return resolved;
}

function parseArgs(argv) {
  const flags = {};
  const rest = [];
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i].startsWith("--")) {
      const name = argv[i].slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) fail(`--${name} needs a value`);
      flags[name] = next;
      i += 1;
    } else rest.push(argv[i]);
  }
  return { flags, rest };
}

function stationKey(dir) {
  const file = path.join(dir, "station.key");
  const raw = fs.readFileSync(file, "utf8").trim();
  const key = fromBase64Url(raw);
  if (key.length !== 32) fail("station.key is not a 32-byte key");
  return key;
}

function hmac(key, ...parts) {
  return createHmac("sha256", key).update(Buffer.concat(parts)).digest();
}

function writePrivate(file, content, mode = 0o600) {
  fs.writeFileSync(file, content, { mode });
  fs.chmodSync(file, mode); // mode alone only applies to newly created files
}

function run(file, args, options = {}) {
  const result = spawnSync(file, args, { stdio: ["pipe", "pipe", "inherit"], ...options });
  if (result.error) fail(`${file}: ${result.error.message}`);
  if (result.status !== 0) fail(`${file} exited ${result.status}`);
  return result.stdout;
}

/** A flag value must match its full charset before it reaches a child argv. */
function checked(name, value, pattern) {
  if (!pattern.test(value)) fail(`--${name} has unsafe characters`);
  return value;
}

/** `from | to` through real pipes: the payload streams, it never buffers. */
function pipe(from, fromArgs, to, toArgs) {
  return new Promise((resolve, reject) => {
    const src = spawn(from, fromArgs, { stdio: ["ignore", "pipe", "inherit"] });
    const dst = spawn(to, toArgs, { stdio: ["pipe", "inherit", "inherit"] });
    src.stdout.pipe(dst.stdin);
    dst.stdin.on("error", () => {}); // a dead peer reports through dst's own close
    let error = null;
    let open = 2;
    const broke = (cmd) => (e) => {
      error ??= `${cmd}: ${e.message}`;
      src.kill();
      dst.kill();
    };
    src.on("error", broke(from));
    dst.on("error", broke(to));
    src.stdout.on("error", broke(from));
    const closed = (cmd) => (code) => {
      if (code !== 0) error ??= code === null ? `${cmd} killed` : `${cmd} exited ${code}`;
      open -= 1;
      if (open === 0) {
        if (error === null) resolve();
        else reject(new Error(error));
      }
    };
    src.on("close", closed(from));
    dst.on("close", closed(to));
  });
}

function cmdInit({ flags }) {
  const dir = privateOutput(flags.dir ?? fail("--dir required"));
  if (fs.existsSync(dir)) fail(`${dir} already exists; refusing to overwrite`);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const key = toBase64Url(randomBytes(32));
  writePrivate(path.join(dir, "station.key"), `${key}\n`);
  writePrivate(path.join(dir, ".dev.vars"), `BADTOWER_STATION_KEY=${key}\n`);
  console.log(`station initialized at ${dir}`);
}

function cmdInvite({ flags }) {
  const dir = flags.dir ?? fail("--dir required");
  const within = flags["bind-within"] ?? "7d";
  const match = /^(\d+)([smhdw])$/.exec(within);
  if (match === null) fail("--bind-within must look like 300s, 30m, 12h, 7d, 4w");
  const unit = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 }[match[2]];
  const key = stationKey(dir);
  const mailboxId = randomBytes(16);
  const notAfter = Buffer.alloc(8);
  notAfter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000) + Number(match[1]) * unit));
  const mac = hmac(key, Buffer.from("btm1"), mailboxId, notAfter);
  const token = `btm1.${toBase64Url(Buffer.concat([mailboxId, notAfter, mac]))}`;
  const out = privateOutput(flags.out ?? path.join(dir, `invite-${mailboxId.toString("hex")}.invitation`));
  writePrivate(out, `${token}\n`);
  console.log(`mailbox ${mailboxId.toString("hex")}`);
  console.log(`invitation written to ${out}`);
}

// IP-literal station hosts bypass the environment proxy; hostname
// stations keep honouring it. An explicit agent opts out of
// NODE_USE_ENV_PROXY, which is read eagerly at process start, so env
// mutation cannot undo it.
function directAgentIfIp(station) {
  return /^(\d{1,3}\.){3}\d{1,3}$|^\[[0-9a-f:]+\]$/i.test(station.hostname)
    ? new https.Agent()
    : undefined;
}

function post({ flags, pathname, body }) {
  const station = new URL(flags.station ?? fail("--station required"));
  const options = {
    agent: directAgentIfIp(station),
    method: "POST",
    hostname: station.hostname,
    port: station.port || 443,
    path: pathname,
    headers: { "Content-Type": "application/octet-stream", "Content-Length": body.length },
    rejectUnauthorized: true,
  };
  if (flags.ca !== undefined) options.ca = fs.readFileSync(flags.ca);
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    });
    req.on("error", reject);
    req.end(body);
  });
}

async function cmdRevoke({ flags }) {
  const dir = flags.dir ?? fail("--dir required");
  const hex = flags.mailbox ?? fail("--mailbox HEX required");
  if (!/^[0-9a-f]{32}$/.test(hex)) fail("--mailbox must be 32 lowercase hex chars");
  const mailboxId = Buffer.from(hex, "hex");
  const body = Buffer.concat([mailboxId, hmac(stationKey(dir), Buffer.from("btr1"), mailboxId)]);
  const status = await post({ flags, pathname: "/v1/revoke", body });
  if (status !== 204) fail(`revoke failed with status ${status}`);
  console.log(`mailbox ${hex} revoked`);
}

async function cmdHealth({ flags }) {
  const station = new URL(flags.station ?? fail("--station required"));
  const options = {
    agent: directAgentIfIp(station),
    hostname: station.hostname,
    port: station.port || 443,
    path: "/healthz",
    rejectUnauthorized: true,
  };
  if (flags.ca !== undefined) options.ca = fs.readFileSync(flags.ca);
  const status = await new Promise((resolve, reject) => {
    https.get(options, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    }).on("error", reject);
  });
  if (status !== 200) fail(`health check failed with status ${status}`);
  console.log("station healthy");
}

function cmdTls({ flags }) {
  const dir = privateOutput(flags.dir ?? fail("--dir required"));
  const ip = checked("ip", flags.ip ?? fail("--ip required"), SAFE_IP);
  const dns = flags.dns === undefined ? undefined : checked("dns", flags.dns, SAFE_DNS);
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
  } catch {
    fail("openssl is not installed");
  }
  const tlsDir = path.join(dir, "tls");
  fs.mkdirSync(tlsDir, { recursive: true, mode: 0o700 });
  const caKey = path.join(tlsDir, "ca.key");
  const caCrt = path.join(tlsDir, "ca.crt");
  const serverKey = path.join(tlsDir, "server.key");
  const serverCrt = path.join(tlsDir, "server.crt");
  const serverCsr = path.join(tlsDir, "server.csr");
  const extFile = path.join(tlsDir, "server.ext");
  run("openssl", ["ecparam", "-genkey", "-name", "P-256", "-noout", "-out", caKey]);
  run("openssl", ["req", "-x509", "-new", "-key", caKey, "-sha256", "-days", "3650",
    "-subj", "/CN=BadTower Station Private CA", "-out", caCrt]);
  run("openssl", ["ecparam", "-genkey", "-name", "P-256", "-noout", "-out", serverKey]);
  run("openssl", ["req", "-new", "-key", serverKey, "-subj", `/CN=${dns ?? ip}`, "-out", serverCsr]);
  const sans = [`IP:${ip}`];
  if (dns !== undefined) sans.push(`DNS:${dns}`);
  fs.writeFileSync(extFile, `subjectAltName=${sans.join(",")}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n`);
  run("openssl", ["x509", "-req", "-in", serverCsr, "-CA", caCrt, "-CAkey", caKey,
    "-CAcreateserial", "-sha256", "-days", "825", "-extfile", extFile, "-out", serverCrt]);
  fs.rmSync(serverCsr);
  fs.rmSync(extFile);
  fs.rmSync(path.join(tlsDir, "ca.srl"), { force: true });
  fs.chmodSync(caKey, 0o600);
  fs.chmodSync(serverKey, 0o600);
  console.log(`tls material under ${tlsDir} (ca.crt, server.crt, keys 0600)`);
}

function cmdCloudflareDeploy({ flags }) {
  const dir = flags.dir ?? fail("--dir required");
  const varsFile = path.join(dir, ".dev.vars");
  if (!fs.existsSync(varsFile)) fail(`${varsFile} is missing; run station init first`);
  const config = path.join("apps", "station", "wrangler.jsonc");
  if (flags.domain === undefined) {
    run("npx", ["wrangler", "deploy", "-c", config, "--secrets-file", varsFile], { cwd: REPO });
  } else {
    const base = fs.readFileSync(path.join(REPO, config), "utf8");
    const tmp = path.join(REPO, "wrangler.deploy.jsonc");
    fs.writeFileSync(
      tmp,
      base.replace(/"workers_dev": true,/, `"workers_dev": false,`),
    );
    try {
      run("npx", ["wrangler", "deploy", "-c", tmp, "--secrets-file", varsFile, "--domains", flags.domain], { cwd: REPO });
    } finally {
      fs.rmSync(tmp, { force: true });
    }
  }
  console.log("deployed to cloudflare");
}

async function cmdDockerDeploy({ flags }) {
  const host = checked("ssh", flags.ssh ?? fail("--ssh required"), SAFE_HOST);
  const dir = flags.dir ?? fail("--dir required");
  const listen = checked("listen", flags.listen ?? fail("--listen IP:PORT required"), SAFE_LISTEN);
  const remoteDir = checked("remote-dir", flags["remote-dir"] ?? "badtower-station", SAFE_PATH);
  const remoteIsWindows = (spawnSync("ssh", ["-o", "BatchMode=yes", host,
    "powershell", "-NoProfile", "-Command", "echo windows"], { encoding: "utf8" })
    .stdout ?? "").trim() === "windows";
  // Build the image for the remote daemon's architecture.
  const arch = run("ssh", ["-o", "BatchMode=yes", host,
    "docker version --format {{.Server.Arch}}"]).toString().trim();
  if (!/^\w+$/.test(arch)) fail(`remote docker arch unreadable: ${arch}`);
  console.log(`remote docker arch: ${arch}`);
  run("docker", ["build", "--platform", `linux/${arch}`, "-t", "badtower-station:local", "."], { cwd: REPO });
  const envFile = `LISTEN=${listen}\n`;
  const envTmp = path.join(os.tmpdir(), `badtower-env-${process.pid}`);
  fs.writeFileSync(envTmp, envFile, { mode: 0o600 });
  // The image streams to the remote daemon through real pipes — no
  // captured buffer or tar file on either side.
  await pipe("docker", ["save", "badtower-station:local"], "ssh",
    ["-o", "BatchMode=yes", host, "docker", "load"]);
  const copy = (local, remote) => run("scp", [local, `${host}:${remote}`]);
  if (remoteIsWindows) {
    run("ssh", ["-o", "BatchMode=yes", host, "powershell", "-NoProfile", "-Command",
      `\"New-Item -ItemType Directory -Force '${remoteDir}' | Out-Null; New-Item -ItemType Directory -Force '${remoteDir}/secrets' | Out-Null; icacls '${remoteDir}/secrets' /inheritance:r /grant:r ($env:USERNAME + ':(OI)(CI)F') | Out-Null\"`]);
    copy(envTmp, `${remoteDir}/.env`);
    copy(path.join(REPO, "compose.yml"), `${remoteDir}/compose.yml`);
    copy(path.join(dir, ".dev.vars"), `${remoteDir}/secrets/.dev.vars`);
    copy(path.join(dir, "tls/server.key"), `${remoteDir}/secrets/server.key`);
    copy(path.join(dir, "tls/server.crt"), `${remoteDir}/secrets/server.crt`);
    copy(path.join(dir, "tls/ca.crt"), `${remoteDir}/secrets/ca.crt`);
    run("ssh", ["-o", "BatchMode=yes", host, "powershell", "-NoProfile", "-Command",
      `\"Set-Location '${remoteDir}'; docker compose up -d --pull never --no-build\"`]);
  } else {
    run("ssh", ["-o", "BatchMode=yes", host,
      `set -e; mkdir -p '${remoteDir}/secrets' && chmod 700 '${remoteDir}/secrets'`]);
    copy(envTmp, `${remoteDir}/.env`);
    copy(path.join(REPO, "compose.yml"), `${remoteDir}/compose.yml`);
    copy(path.join(dir, ".dev.vars"), `${remoteDir}/secrets/.dev.vars`);
    copy(path.join(dir, "tls/server.key"), `${remoteDir}/secrets/server.key`);
    copy(path.join(dir, "tls/server.crt"), `${remoteDir}/secrets/server.crt`);
    copy(path.join(dir, "tls/ca.crt"), `${remoteDir}/secrets/ca.crt`);
    run("ssh", ["-o", "BatchMode=yes", host,
      `set -e; cd '${remoteDir}'; chmod 600 secrets/.dev.vars secrets/server.key secrets/server.crt; docker compose up -d --pull never --no-build`]);
  }
  fs.rmSync(envTmp, { force: true });
  console.log(`deployed to ${host} on ${listen}`);
}

const commands = {
  init: (a) => cmdInit(a),
  invite: (a) => cmdInvite(a),
  revoke: async (a) => cmdRevoke(a),
  tls: (a) => cmdTls(a),
  "cloudflare-deploy": (a) => cmdCloudflareDeploy(a),
  "docker-deploy": async (a) => cmdDockerDeploy(a),
  health: async (a) => cmdHealth(a),
};

const [command, ...rest] = process.argv.slice(2);
const handler = commands[command];
if (handler === undefined) {
  fail(`unknown command '${command ?? ""}' — expected: ${Object.keys(commands).join(", ")}`);
}
await handler(parseArgs(rest));
