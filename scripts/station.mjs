#!/usr/bin/env node
/**
 * BadTower Station operations CLI: every privileged input is an argument,
 * never tracked data. Node built-ins only; TLS material comes from the
 * openssl CLI.
 *
 *   init --dir DIR
 *   invite --dir DIR [--bind-within 7d] [--out FILE]
 *   metrics-key --dir DIR
 *   revoke --dir DIR --station URL --mailbox HEX [--ca PEM]
 *   tls --dir DIR --ip ADDR [--dns NAME]
 *   cloudflare-deploy --dir DIR [--domain NAME]
 *   docker-deploy --ssh HOST --dir DIR --listen IP:PORT [--remote-dir PATH]
 *   health --station URL [--ca PEM]
 *   metrics --dir DIR --station URL [--ca PEM]
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
const REPO_REAL = fs.realpathSync(REPO);
// Repository-relative roots that both .gitignore and .dockerignore
// exclude — the only places private material may be written in-tree.
const REPO_PRIVATE_DIRS = ["data", "secrets"];

function fail(message) {
  console.error(`station: ${message}`);
  process.exit(1);
}

/**
 * The physical path `target` resolves to: the destination may not
 * exist yet, so the deepest existing ancestor is resolved through
 * symlinks and the remainder re-appended. A symlinked ancestor cannot
 * smuggle private material back into the tracked tree — and a symlink
 * counts as existing even when its target is missing, so a dangling
 * link in the write path is refused rather than silently followed.
 */
function physicalPath(target) {
  let at = target;
  const tail = [];
  for (;;) {
    try {
      fs.lstatSync(at); // a link is a real component even when dangling
      break;
    } catch {
      const parent = path.dirname(at);
      if (parent === at) fail(`cannot resolve ${target}: no existing ancestor`);
      tail.unshift(path.basename(at));
      at = parent;
    }
  }
  try {
    return path.join(fs.realpathSync(at), ...tail);
  } catch (error) {
    fail(`cannot resolve ${target}: ${error.message}`);
  }
}

/**
 * Private material must never land at an arbitrary repository-relative
 * path: anything inside the repository — lexically or through a
 * symlinked ancestor — that is not under an ignore-covered private
 * root is refused outright.
 */
function privateOutput(file) {
  const resolved = path.resolve(file);
  for (const [candidate, root] of [
    [resolved, REPO],
    [physicalPath(resolved), REPO_REAL],
  ]) {
    const relative = path.relative(root, candidate);
    if (!relative.startsWith("..") && !path.isAbsolute(relative)) {
      const first = relative.split(path.sep)[0];
      if (!REPO_PRIVATE_DIRS.includes(first)) {
        fail(`${file} is inside the repository; private material goes under ${REPO_PRIVATE_DIRS.join("/ or ")}/ or outside the tree`);
      }
    }
  }
  return resolved;
}

/**
 * A file about to receive material inside an already-checked private
 * directory: its physical destination must still resolve inside that
 * directory — a dangling link is unresolvable and a link pointing
 * outside escapes, so both are refused.
 */
function privateChild(dir, name) {
  const file = path.join(dir, name);
  const relative = path.relative(physicalPath(dir), physicalPath(file));
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    fail(`${file} escapes its private directory through a link`);
  }
  return file;
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

/** A key file read as text for an in-process Authorization header. */
function readKeyText(file) {
  const raw = fs.readFileSync(file, "utf8").trim();
  const key = fromBase64Url(raw);
  if (key.length !== 32) fail(`${file} is not a 32-byte key`);
  return raw;
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
  const metricsKey = toBase64Url(randomBytes(32));
  writePrivate(path.join(dir, "station.key"), `${key}\n`);
  writePrivate(path.join(dir, "metrics.key"), `${metricsKey}\n`);
  writePrivate(
    path.join(dir, ".dev.vars"),
    `BADTOWER_STATION_KEY=${key}\nBADTOWER_METRICS_KEY=${metricsKey}\n`,
  );
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

/**
 * Align the metrics-only credential between metrics.key (the CLI's
 * in-process read) and .dev.vars (the value deploy uploads). A valid
 * existing .dev.vars entry is adopted — it is what the Worker already
 * expects — then an existing metrics.key, and only then a fresh mint.
 * Both files are always written with the resolved value, so the CLI
 * and the Worker cannot diverge and an interrupted run converges on
 * the next invocation.
 */
function cmdMetricsKey({ flags }) {
  const dir = privateOutput(flags.dir ?? fail("--dir required"));
  const keyFile = privateChild(dir, "metrics.key");
  const varsFile = privateChild(dir, ".dev.vars");
  const validKey = (text) => {
    try {
      return fromBase64Url(text).length === 32;
    } catch {
      return false;
    }
  };
  const vars = fs.existsSync(varsFile) ? fs.readFileSync(varsFile, "utf8") : "";
  // All entries are considered — the first valid one wins — and every
  // entry is rewritten to the resolved line, so duplicates collapse.
  const varsValue = [...vars.matchAll(/^BADTOWER_METRICS_KEY=(.*)$/gm)]
    .map((match) => match[1].trim())
    .find(validKey) ?? "";
  const fileValue = fs.existsSync(keyFile) ? fs.readFileSync(keyFile, "utf8").trim() : "";
  const key = varsValue || (validKey(fileValue) ? fileValue : toBase64Url(randomBytes(32)));
  const line = `BADTOWER_METRICS_KEY=${key}`;
  const rest = vars.replace(/^BADTOWER_METRICS_KEY=.*(\n|$)/gm, "");
  const next = `${rest}${rest === "" || rest.endsWith("\n") ? "" : "\n"}${line}\n`;
  writePrivate(varsFile, next);
  writePrivate(keyFile, `${key}\n`);
  console.log(`metrics credential written to ${keyFile}`);
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

/**
 * Read the aggregate metrics. The credential is read from disk inside
 * this process — metrics.key when present, station.key otherwise — so
 * it never appears in a command line or process listing.
 */
async function cmdMetrics({ flags }) {
  const dir = flags.dir ?? fail("--dir required");
  const scoped = path.join(dir, "metrics.key");
  const bearer = readKeyText(fs.existsSync(scoped) ? scoped : path.join(dir, "station.key"));
  const station = new URL(flags.station ?? fail("--station required"));
  const options = {
    agent: directAgentIfIp(station),
    hostname: station.hostname,
    port: station.port || 443,
    path: "/v1/metrics",
    headers: { Authorization: `Bearer ${bearer}` },
    rejectUnauthorized: true,
  };
  if (flags.ca !== undefined) options.ca = fs.readFileSync(flags.ca);
  const { status, body } = await new Promise((resolve, reject) => {
    let data = "";
    https.get(options, (res) => {
      res.setEncoding("utf8");
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    }).on("error", reject);
  });
  if (status !== 200) fail(`metrics request failed with status ${status}`);
  process.stdout.write(body);
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
  const tlsDir = privateChild(dir, "tls");
  fs.mkdirSync(tlsDir, { recursive: true, mode: 0o700 });
  // openssl follows links on every -out path, so each destination is
  // resolved before it is handed to the child.
  const caKey = privateChild(tlsDir, "ca.key");
  const caCrt = privateChild(tlsDir, "ca.crt");
  const serverKey = privateChild(tlsDir, "server.key");
  const serverCrt = privateChild(tlsDir, "server.crt");
  const serverCsr = privateChild(tlsDir, "server.csr");
  const extFile = privateChild(tlsDir, "server.ext");
  privateChild(tlsDir, "ca.srl");
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
    // Kept beside the original: the config's relative `main` resolves
    // against the file's own directory, so a copy at the repository
    // root would point Wrangler at a missing entrypoint.
    const tmp = path.join("apps", "station", "wrangler.deploy.jsonc");
    fs.writeFileSync(
      path.join(REPO, tmp),
      base.replace(/"workers_dev": true,/, `"workers_dev": false,`),
    );
    try {
      run("npx", ["wrangler", "deploy", "-c", tmp, "--secrets-file", varsFile, "--domains", flags.domain], { cwd: REPO });
    } finally {
      fs.rmSync(path.join(REPO, tmp), { force: true });
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
  "metrics-key": (a) => cmdMetricsKey(a),
  revoke: async (a) => cmdRevoke(a),
  tls: (a) => cmdTls(a),
  "cloudflare-deploy": (a) => cmdCloudflareDeploy(a),
  "docker-deploy": async (a) => cmdDockerDeploy(a),
  health: async (a) => cmdHealth(a),
  metrics: async (a) => cmdMetrics(a),
};

const [command, ...rest] = process.argv.slice(2);
const handler = commands[command];
if (handler === undefined) {
  fail(`unknown command '${command ?? ""}' — expected: ${Object.keys(commands).join(", ")}`);
}
await handler(parseArgs(rest));
