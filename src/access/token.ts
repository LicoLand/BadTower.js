import { decodeBase64Url, hexToBytes, toBase64Url } from "../encoding";

export const AUTHORIZATION_HEADER_MAX_BYTES = 512;
export const TOKEN_SELECTOR_BYTES = 16;
export const TOKEN_SECRET_BYTES = 32;
export const ED25519_PUBLIC_KEY_BYTES = 32;
export const ED25519_SIGNATURE_BYTES = 64;
export const PROOF_MAX_SKEW_MS = 5 * 60 * 1000;

const INVITATION_PREFIX = "bti2";
const ACCESS_PREFIX = "bta2";
const OPERATOR_PREFIX = "bto1";
const CAPABILITY_VERSION = 2;
const MAC_BYTES = 32;
const INVITATION_PAYLOAD_BYTES = 1 + 1 + TOKEN_SELECTOR_BYTES + 8;
const ACCESS_PAYLOAD_BYTES = 1 + 1 + TOKEN_SELECTOR_BYTES + ED25519_PUBLIC_KEY_BYTES + 4 + 8;
const encoder = new TextEncoder();

export interface CapabilityKeyring {
  activeKeyId: number;
  keys: ReadonlyMap<number, Uint8Array>;
}

export interface ParsedInvitationCapability {
  raw: string;
  keyId: number;
  selector: string;
  selectorBytes: Uint8Array;
  expiresAt: number;
  digest: Uint8Array;
}

export interface ParsedAccessCapability extends ParsedInvitationCapability {
  publicKey: Uint8Array;
  epoch: number;
}

export interface RequestProofFields {
  capabilityDigest: Uint8Array;
  method: string;
  path: string;
  mediaType: string;
  contentLength: number;
  operationId: Uint8Array;
  bodyDigest: Uint8Array;
  issuedAt: number;
  counter: bigint;
}

export function randomBytes(size: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(size));
}

export async function sha256(input: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", input));
}

export function digestEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== 32 || right.length !== 32) return false;
  return crypto.subtle.timingSafeEqual(left, right);
}

export function parseDigestSecret(value: unknown): Uint8Array | null {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) return null;
  return hexToBytes(value);
}

export function parseCapabilityKeyring(value: unknown): CapabilityKeyring | null {
  if (typeof value !== "string" || value.length > 1024) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const record = parsed as Record<string, unknown>;
    if (Object.keys(record).sort().join(",") !== "activeKeyId,keys") return null;
    if (!Number.isInteger(record.activeKeyId) || (record.activeKeyId as number) < 0 || (record.activeKeyId as number) > 255) return null;
    if (record.keys === null || typeof record.keys !== "object" || Array.isArray(record.keys)) return null;
    const entries = Object.entries(record.keys as Record<string, unknown>);
    if (entries.length < 1 || entries.length > 4) return null;
    const keys = new Map<number, Uint8Array>();
    for (const [idText, encoded] of entries) {
      if (!/^(0|[1-9][0-9]{0,2})$/.test(idText) || typeof encoded !== "string") return null;
      const id = Number(idText);
      const key = decodeBase64Url(encoded);
      if (id > 255 || key === null || key.length !== TOKEN_SECRET_BYTES || toBase64Url(key) !== encoded) return null;
      keys.set(id, key);
    }
    const activeKeyId = record.activeKeyId as number;
    return keys.has(activeKeyId) ? { activeKeyId, keys } : null;
  } catch {
    return null;
  }
}

function writeU64(target: Uint8Array, offset: number, value: number): void {
  new DataView(target.buffer, target.byteOffset, target.byteLength).setBigUint64(offset, BigInt(value));
}

function readSafeU64(source: Uint8Array, offset: number): number | null {
  const value = new DataView(source.buffer, source.byteOffset, source.byteLength).getBigUint64(offset);
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : null;
}

async function hmac(keyBytes: Uint8Array, payload: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, payload));
}

async function formatCapability(prefix: string, payload: Uint8Array, key: Uint8Array): Promise<string> {
  const bytes = new Uint8Array(payload.length + MAC_BYTES);
  bytes.set(payload);
  bytes.set(await hmac(key, payload), payload.length);
  return `${prefix}.${toBase64Url(bytes)}`;
}

async function authenticateCapability(raw: string, prefix: string, payloadBytes: number, keyring: CapabilityKeyring): Promise<Uint8Array | null> {
  const dot = raw.indexOf(".");
  if (dot !== prefix.length || raw.slice(0, dot) !== prefix || raw.indexOf(".", dot + 1) !== -1) return null;
  const encoded = raw.slice(dot + 1);
  const bytes = decodeBase64Url(encoded);
  if (bytes === null || bytes.length !== payloadBytes + MAC_BYTES || toBase64Url(bytes) !== encoded) return null;
  const payload = bytes.slice(0, payloadBytes);
  if (payload[0] !== CAPABILITY_VERSION) return null;
  const key = keyring.keys.get(payload[1]!);
  if (key === undefined) return null;
  const expected = await hmac(key, payload);
  return crypto.subtle.timingSafeEqual(expected, bytes.slice(payloadBytes)) ? payload : null;
}

export async function formatInvitationToken(selector: Uint8Array, expiresAt: number, keyring: CapabilityKeyring): Promise<string> {
  if (selector.length !== TOKEN_SELECTOR_BYTES || !Number.isSafeInteger(expiresAt) || expiresAt <= 0) throw new TypeError("invalid invitation fields");
  const payload = new Uint8Array(INVITATION_PAYLOAD_BYTES);
  payload[0] = CAPABILITY_VERSION;
  payload[1] = keyring.activeKeyId;
  payload.set(selector, 2);
  writeU64(payload, 18, expiresAt);
  return formatCapability(INVITATION_PREFIX, payload, keyring.keys.get(keyring.activeKeyId)!);
}

export async function parseInvitationToken(raw: string, keyring: CapabilityKeyring, now = Date.now()): Promise<ParsedInvitationCapability | null> {
  const payload = await authenticateCapability(raw, INVITATION_PREFIX, INVITATION_PAYLOAD_BYTES, keyring);
  if (payload === null) return null;
  const expiresAt = readSafeU64(payload, 18);
  if (expiresAt === null || now >= expiresAt) return null;
  const selectorBytes = payload.slice(2, 18);
  return { raw, keyId: payload[1]!, selector: toBase64Url(selectorBytes), selectorBytes, expiresAt, digest: await sha256(encoder.encode(raw)) };
}

export async function formatAccessToken(selector: Uint8Array, publicKey: Uint8Array, epoch: number, expiresAt: number, keyring: CapabilityKeyring): Promise<string> {
  if (selector.length !== TOKEN_SELECTOR_BYTES || publicKey.length !== ED25519_PUBLIC_KEY_BYTES || !Number.isInteger(epoch) || epoch < 1 || epoch > 0xffff_ffff || !Number.isSafeInteger(expiresAt)) throw new TypeError("invalid access fields");
  const payload = new Uint8Array(ACCESS_PAYLOAD_BYTES);
  payload[0] = CAPABILITY_VERSION;
  payload[1] = keyring.activeKeyId;
  payload.set(selector, 2);
  payload.set(publicKey, 18);
  new DataView(payload.buffer).setUint32(50, epoch);
  writeU64(payload, 54, expiresAt);
  return formatCapability(ACCESS_PREFIX, payload, keyring.keys.get(keyring.activeKeyId)!);
}

export async function parseAccessToken(raw: string, keyring: CapabilityKeyring, now = Date.now()): Promise<ParsedAccessCapability | null> {
  const payload = await authenticateCapability(raw, ACCESS_PREFIX, ACCESS_PAYLOAD_BYTES, keyring);
  if (payload === null) return null;
  const expiresAt = readSafeU64(payload, 54);
  const epoch = new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint32(50);
  if (expiresAt === null || now >= expiresAt || epoch === 0) return null;
  const selectorBytes = payload.slice(2, 18);
  return { raw, keyId: payload[1]!, selector: toBase64Url(selectorBytes), selectorBytes, publicKey: payload.slice(18, 50), epoch, expiresAt, digest: await sha256(encoder.encode(raw)) };
}

function lengthPrefix(part: Uint8Array): Uint8Array {
  if (part.length > 0xffff_ffff) throw new TypeError("proof field too long");
  const out = new Uint8Array(4 + part.length);
  new DataView(out.buffer).setUint32(0, part.length);
  out.set(part, 4);
  return out;
}

export function encodeRequestProof(fields: RequestProofFields): Uint8Array {
  if (fields.capabilityDigest.length !== 32 || fields.bodyDigest.length !== 32 || fields.operationId.length !== 16 || !Number.isSafeInteger(fields.contentLength) || fields.contentLength < 0 || !Number.isSafeInteger(fields.issuedAt) || fields.issuedAt < 0 || fields.counter < 0n || fields.counter > 0xffff_ffff_ffff_ffffn) throw new TypeError("invalid proof fields");
  const issuedAt = new Uint8Array(8);
  const counter = new Uint8Array(8);
  const contentLength = new Uint8Array(8);
  writeU64(issuedAt, 0, fields.issuedAt);
  new DataView(counter.buffer).setBigUint64(0, fields.counter);
  writeU64(contentLength, 0, fields.contentLength);
  const parts = [encoder.encode("badtower-request-proof-v2"), fields.capabilityDigest, encoder.encode(fields.method), encoder.encode(fields.path), encoder.encode(fields.mediaType), contentLength, fields.operationId, fields.bodyDigest, issuedAt, counter].map(lengthPrefix);
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

export async function verifyRequestProof(publicKey: Uint8Array, transcript: Uint8Array, signature: Uint8Array): Promise<boolean> {
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES || signature.length !== ED25519_SIGNATURE_BYTES) return false;
  try {
    const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, signature, transcript);
  } catch { return false; }
}

export function formatOperatorToken(secret: Uint8Array): string { return `${OPERATOR_PREFIX}.${toBase64Url(secret)}`; }
export function parseOperatorToken(raw: string): Uint8Array | null {
  const parts = raw.split(".");
  if (parts.length !== 2 || parts[0] !== OPERATOR_PREFIX || parts[1]!.length !== 43) return null;
  const secret = decodeBase64Url(parts[1]!);
  return secret !== null && secret.length === TOKEN_SECRET_BYTES ? secret : null;
}
export function readBearer(request: Request): string | null {
  const raw = request.headers.get("authorization");
  if (raw === null || raw.length === 0 || raw.length > AUTHORIZATION_HEADER_MAX_BYTES || raw.includes(",") || !raw.startsWith("Bearer ")) return null;
  const token = raw.slice(7);
  return token.length === 0 ? null : token;
}
export function parseSelector(value: string): Uint8Array | null {
  if (value.length !== 22) return null;
  const bytes = decodeBase64Url(value);
  return bytes !== null && bytes.length === TOKEN_SELECTOR_BYTES && toBase64Url(bytes) === value ? bytes : null;
}
