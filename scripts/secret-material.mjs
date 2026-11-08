import { constants } from "node:fs";
import { lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { dirname, join, resolve } from "node:path";

export const DATA_SECRET_FILE = "cloudflare-data-secrets.json";
export const OPERATOR_SECRET_FILE = "cloudflare-operator-secrets.json";
export const TOKEN_FILE = "operator-token";
export const DEV_VARS_FILE = ".dev.vars";

export function parseAction(action) {
  const args = process.argv.slice(2);
  const directoryAt = args.indexOf("--target-dir");
  const confirmAt = args.indexOf("--confirm");
  if (
    args.length !== 4 ||
    directoryAt < 0 ||
    confirmAt < 0 ||
    args[directoryAt + 1] === undefined ||
    args[confirmAt + 1] !== action
  ) {
    throw new Error(`usage: --target-dir <directory> --confirm ${action}`);
  }
  const target = resolve(args[directoryAt + 1]);
  if (target === resolve("/") || target === resolve(".")) {
    throw new Error("target directory must be a dedicated private directory");
  }
  return target;
}

async function rejectLink(path) {
  try {
    const stat = await lstat(path);
    if (stat.isSymbolicLink()) throw new Error("symbolic links are not allowed");
    return stat;
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

export async function prepareDirectory(target) {
  const parent = dirname(target);
  const parentStat = await rejectLink(parent);
  if (parentStat === null || !parentStat.isDirectory()) throw new Error("target parent is unavailable");
  let stat = await rejectLink(target);
  if (stat === null) {
    await mkdir(target, { mode: 0o700 });
    stat = await rejectLink(target);
  }
  if (stat === null || !stat.isDirectory() || (stat.mode & 0o077) !== 0) {
    throw new Error("target directory must be owner-only");
  }
}

export async function writePrivate(path, content, replace) {
  const existing = await rejectLink(path);
  if (existing !== null && (!replace || !existing.isFile() || (existing.mode & 0o077) !== 0)) {
    throw new Error("private material output is unavailable or unsafe");
  }
  if (!replace) {
    const file = await open(
      path,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    try {
      await file.writeFile(content);
      await file.sync();
    } finally {
      await file.close();
    }
    return;
  }
  const temporary = `${path}.tmp-${randomBytes(8).toString("hex")}`;
  const file = await open(
    temporary,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    await file.writeFile(content);
    await file.sync();
  } finally {
    await file.close();
  }
  try {
    await rename(temporary, path);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

function base64url32(value) {
  return typeof value === "string" &&
    /^[A-Za-z0-9_-]{43}$/.test(value) &&
    Buffer.from(value, "base64url").toString("base64url") === value;
}

function exactKeys(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return keys.length === sorted.length && keys.every((key, index) => key === sorted[index]);
}

function validCapabilityKeyring(raw) {
  if (typeof raw !== "string" || raw.length > 1024) return false;
  let capability;
  try { capability = JSON.parse(raw); } catch { return false; }
  if (!exactKeys(capability, ["activeKeyId", "keys"])) return false;
  if (!Number.isInteger(capability.activeKeyId) || capability.activeKeyId < 0 || capability.activeKeyId > 255) return false;
  if (capability.keys === null || typeof capability.keys !== "object" || Array.isArray(capability.keys)) return false;
  const entries = Object.entries(capability.keys);
  if (entries.length < 1 || entries.length > 4) return false;
  for (const [id, key] of entries) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(id) || Number(id) > 255 || !base64url32(key)) return false;
  }
  return base64url32(capability.keys[String(capability.activeKeyId)]);
}

function validHandleKeyring(raw, currentText, now = Date.now()) {
  if (typeof currentText !== "string" || !/^(0|[1-9][0-9]{0,2})$/.test(currentText)) return false;
  const currentHandleSlot = Number(currentText);
  if (currentHandleSlot > 255) return false;
  let handles;
  try { handles = JSON.parse(raw); } catch { return false; }
  if (!Array.isArray(handles) || handles.length < 1 || handles.length > 4) return false;
  const ids = new Set();
  for (const entry of handles) {
    if (
      !exactKeys(entry, ["id", "key", "notAfter"]) ||
      !Number.isInteger(entry.id) || entry.id < 0 || entry.id > 255 || ids.has(entry.id) ||
      !base64url32(entry.key) ||
      (entry.notAfter !== null && (!Number.isSafeInteger(entry.notAfter) || entry.notAfter <= now)) ||
      (entry.id !== currentHandleSlot && entry.notAfter === null)
    ) return false;
    ids.add(entry.id);
  }
  return ids.has(currentHandleSlot);
}

export function validateMaterial(dataSecrets, operatorSecrets, operatorToken) {
  if (!exactKeys(dataSecrets, ["BADTOWER_CAPABILITY_KEYS", "BADTOWER_HANDLE_CURRENT_SLOT", "BADTOWER_HANDLE_KEYS"])) return false;
  if (!exactKeys(operatorSecrets, ["BADTOWER_CAPABILITY_KEYS", "BADTOWER_OPERATOR_TOKEN_DIGEST"])) return false;
  if (dataSecrets.BADTOWER_CAPABILITY_KEYS !== operatorSecrets.BADTOWER_CAPABILITY_KEYS) return false;
  if (!validCapabilityKeyring(dataSecrets.BADTOWER_CAPABILITY_KEYS)) return false;
  if (!validHandleKeyring(dataSecrets.BADTOWER_HANDLE_KEYS, dataSecrets.BADTOWER_HANDLE_CURRENT_SLOT)) return false;
  if (!/^[a-f0-9]{64}$/.test(operatorSecrets.BADTOWER_OPERATOR_TOKEN_DIGEST)) return false;
  if (!/^bto1\.[A-Za-z0-9_-]{43}$/.test(operatorToken)) return false;
  const secret = Buffer.from(operatorToken.slice(5), "base64url");
  if (secret.length !== 32 || secret.toString("base64url") !== operatorToken.slice(5)) return false;
  const actual = createHash("sha256").update(secret).digest();
  const expected = Buffer.from(operatorSecrets.BADTOWER_OPERATOR_TOKEN_DIGEST, "hex");
  return expected.length === actual.length && timingSafeEqual(actual, expected);
}

export async function readValidatedMaterial(target) {
  const directory = await rejectLink(target);
  if (directory === null || !directory.isDirectory() || (directory.mode & 0o077) !== 0) {
    throw new Error("private material directory is unavailable or unsafe");
  }
  const dataSecretPath = join(target, DATA_SECRET_FILE);
  const operatorSecretPath = join(target, OPERATOR_SECRET_FILE);
  const tokenPath = join(target, TOKEN_FILE);
  const devVarsPath = join(target, DEV_VARS_FILE);
  for (const path of [dataSecretPath, operatorSecretPath, tokenPath, devVarsPath]) {
    const stat = await rejectLink(path);
    if (stat === null || !stat.isFile() || (stat.mode & 0o077) !== 0) {
      throw new Error("private material file is unavailable or unsafe");
    }
  }
  const [dataSecretText, operatorSecretText, tokenText, devVarsText] = await Promise.all([
    readFile(dataSecretPath, "utf8"),
    readFile(operatorSecretPath, "utf8"),
    readFile(tokenPath, "utf8"),
    readFile(devVarsPath, "utf8"),
  ]);
  const dataSecrets = JSON.parse(dataSecretText);
  const operatorSecrets = JSON.parse(operatorSecretText);
  const token = tokenText.trim();
  if (!validateMaterial(dataSecrets, operatorSecrets, token)) throw new Error("private material schema is invalid");
  if (devVarsText !== formatDevVars(dataSecrets, operatorSecrets)) throw new Error("local variable material is inconsistent");
  return { dataSecrets, operatorSecrets, token };
}

export function materialPaths(target) {
  return {
    dataSecrets: join(target, DATA_SECRET_FILE),
    operatorSecrets: join(target, OPERATOR_SECRET_FILE),
    token: join(target, TOKEN_FILE),
    devVars: join(target, DEV_VARS_FILE),
  };
}

export function formatDevVars(dataSecrets, operatorSecrets) {
  const combined = { ...dataSecrets, ...operatorSecrets };
  return `${Object.entries(combined).map(([key, value]) => `${key}=${JSON.stringify(value)}`).join("\n")}\n`;
}
