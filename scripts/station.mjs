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
 * Whether a path.relative result means the candidate leaves `root`.
 * Only an actual `..` path component escapes — a name that merely
 * begins with two dots (`..fixture`) is still inside.
 */
function escapes(relative) {
  return (
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  );
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
    if (!escapes(relative)) {
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
  if (escapes(relative)) {
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
  // Temp-then-rename inside the same directory: an interrupted write
  // leaves the old contents or the new ones, never a truncated file —
  // and rename replaces a destination symlink rather than following it.
  const tmp = `${file}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(tmp, content, { mode });
    fs.chmodSync(tmp, mode); // the create mode is still filtered by umask
    fs.renameSync(tmp, file);
  } catch (error) {
    fs.rmSync(tmp, { force: true });
    throw error;
  }
}

function attempt(file, args, options = {}) {
  return spawnSync(file, args, { stdio: ["pipe", "pipe", "inherit"], ...options });
}

function run(file, args, options = {}) {
  const result = attempt(file, args, options);
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
 * The assignment grammar the pinned parser applies to .dev.vars:
 * dotenv 16.3.1's LINE pattern — the exact source the pinned Wrangler
 * 4.122.0 bundles — copied verbatim so the CLI resolves and rewrites
 * the same value deploy would upload. `export` prefixes, `=` or `:`
 * separators, quoted values spanning lines, inline comments after
 * unquoted values, and last-assignment-wins all follow from it; the
 * `d` flag only adds group offsets.
 */
const DEV_VARS_LINE = /(?:^|^)\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?(?:$|$)/mgd;

/**
 * Every assignment the pinned parser sees, in file order: the name,
 * the value exactly as Wrangler would bind it, and the span of the
 * full lines the assignment occupies. A `NAME=` line inside another
 * key's quoted multiline value is part of that value — the pattern
 * above consumes it there — so it never surfaces as an entry, and a
 * comment the match's trailing `\s*(?:#.*)?` pulled in from the NEXT
 * line is likewise excluded from the span below: removal can only
 * ever touch complete assignments.
 */
function devVarsEntries(text) {
  const src = text.replace(/\r\n?/g, "\n");
  const entries = [];
  DEV_VARS_LINE.lastIndex = 0;
  let match;
  while ((match = DEV_VARS_LINE.exec(src)) !== null) {
    const name = match[1];
    let value = (match[2] || "").trim();
    const maybeQuote = value[0];
    value = value.replace(/^(['"`])([\s\S]*)\1$/mg, "$2");
    if (maybeQuote === '"') {
      value = value.replace(/\\n/g, "\n").replace(/\\r/g, "\r");
    }
    // The assignment's first line holds the key (match[0] may start
    // with whitespace from earlier blank lines); its last holds the
    // end of the value token, or of the separator when there is none.
    const keyStart = match.index + /^\s*(?:export\s+)?/.exec(match[0])[0].length;
    const valueEnd =
      match.indices[2]?.[1] ?? match.index + match[0].search(/[=:]/) + 1;
    const lineStart = src.lastIndexOf("\n", keyStart - 1) + 1;
    const newline = src.indexOf("\n", valueEnd);
    entries.push({
      name,
      value,
      start: lineStart,
      end: newline === -1 ? src.length : newline + 1,
    });
  }
  return entries;
}

/**
 * The effective value a .dev.vars file assigns `name` — the LAST
 * complete assignment the pinned parser sees, exactly as deploy would
 * upload it. Anything else — first-match, literal-only or
 * comment-blind parsing — can pick a shadowed stale entry and diverge
 * the CLI credential from the deployed one.
 */
function devVarsValue(text, name) {
  let value;
  for (const entry of devVarsEntries(text)) {
    if (entry.name === name) value = entry.value;
  }
  return value;
}

/**
 * Align the metrics-only credential between metrics.key (the CLI's
 * in-process read) and .dev.vars (the value deploy uploads). A valid
 * effective .dev.vars entry — resolved with Wrangler's own parsing and
 * precedence — is adopted, since it is what the deployed Worker
 * already expects; then an existing metrics.key, and only then a
 * fresh mint. Both files are always written with the resolved value,
 * so the CLI and the Worker cannot diverge and an interrupted run
 * converges on the next invocation.
 */
function cmdMetricsKey({ flags }) {
  const dir = privateOutput(flags.dir ?? fail("--dir required"));
  const keyFile = privateChild(dir, "metrics.key");
  const varsFile = privateChild(dir, ".dev.vars");
  // The two destinations must be distinct files: an alias would let
  // one write erase the other's contents mid-command.
  if (physicalPath(keyFile) === physicalPath(varsFile)) {
    fail("metrics.key and .dev.vars resolve to the same file");
  }
  const validKey = (text) => {
    try {
      return text !== undefined && fromBase64Url(text).length === 32;
    } catch {
      return false;
    }
  };
  const vars = fs.existsSync(varsFile) ? fs.readFileSync(varsFile, "utf8") : "";
  // The value deploy actually uploads is the effective one — every
  // assignment considered under the pinned parser's last-wins
  // precedence, inline comments included.
  const varsValue = devVarsValue(vars, "BADTOWER_METRICS_KEY");
  const fileValue = fs.existsSync(keyFile) ? fs.readFileSync(keyFile, "utf8").trim() : "";
  const key = validKey(varsValue)
    ? varsValue
    : validKey(fileValue)
      ? fileValue
      : toBase64Url(randomBytes(32));
  // Every complete assignment to the key is rewritten as one canonical
  // line, so duplicates, colon forms and quoted forms collapse and a
  // rerun converges. Removing by parsed assignment span — never by
  // line matching — leaves every other setting byte-for-byte intact,
  // including a `NAME=` line nested in an unrelated multiline value.
  const src = vars.replace(/\r\n?/g, "\n");
  let kept = src;
  const spans = devVarsEntries(src)
    .filter((entry) => entry.name === "BADTOWER_METRICS_KEY")
    .map((entry) => [entry.start, entry.end])
    .sort((a, b) => b[0] - a[0]);
  for (const [start, end] of spans) kept = kept.slice(0, start) + kept.slice(end);
  // Only surplus trailing newlines are dropped; other trailing
  // whitespace belongs to the last line. An empty colon-form tail like
  // `OPTIONAL: ` parses as an empty value BECAUSE that space completes
  // its `:` separator — stripping it would leave `OPTIONAL:` whose
  // `:`+newline separator then swallows the appended assignment as
  // OPTIONAL's value, hiding the metrics binding from Wrangler.
  kept = kept.replace(/\n+$/, "");
  const next = `${kept}${kept === "" ? "" : "\n"}BADTOWER_METRICS_KEY=${key}\n`;
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
    // root would point Wrangler at a missing entrypoint. The name is
    // per-process so overlapping deploys cannot clobber each other,
    // and the child result is inspected only after cleanup — exiting
    // on the error first would strand the generated file.
    const tmp = path.join("apps", "station", `wrangler.deploy-${process.pid}.jsonc`);
    let result;
    try {
      fs.writeFileSync(
        path.join(REPO, tmp),
        base.replace(/"workers_dev": true,/, `"workers_dev": false,`),
      );
      result = attempt("npx", ["wrangler", "deploy", "-c", tmp,
        "--secrets-file", varsFile, "--domains", flags.domain], { cwd: REPO });
    } finally {
      fs.rmSync(path.join(REPO, tmp), { force: true });
    }
    if (result.error) fail(`npx: ${result.error.message}`);
    if (result.status !== 0) fail(`npx exited ${result.status}`);
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
