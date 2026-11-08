/**
 * Shared synthetic access-grant and request construction helpers. Every test
 * creates an isolated active grant in the Workers runtime. Bearer plaintext
 * is generated in memory and is never committed or logged.
 */

import { env } from "cloudflare:workers";
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import {
  encodeRequestProof,
  formatAccessToken,
  parseCapabilityKeyring,
  randomBytes,
  sha256,
} from "../src/access/token";
import {
  PROOF_COUNTER_HEADER,
  PROOF_ISSUED_AT_HEADER,
  PROOF_SIGNATURE_HEADER,
} from "../src/access/data-service";
import { CborReader, CborWriter } from "../src/transport/cbor";
import { OPERATION_ID_HEADER } from "../src/transport/candidate";

export interface AccessGrantFixture {
  token: string;
  digestHex: string;
  selector: string;
}

interface ProofKey { privateKey: KeyObject; counter: bigint }
const proofKeys = new Map<string, ProofKey>();

export interface ClientProofKey {
  privateKey: KeyObject;
  publicKey: Uint8Array;
}

export function generateClientProofKey(): ClientProofKey {
  const pair = generateKeyPairSync("ed25519");
  const spki = new Uint8Array(pair.publicKey.export({ format: "der", type: "spki" }));
  return { privateKey: pair.privateKey, publicKey: spki.slice(-32) };
}

export function registerProofKey(token: string, privateKey: KeyObject): void {
  proofKeys.set(token, { privateKey, counter: 0n });
}

export async function generateAccessGrant(): Promise<AccessGrantFixture> {
  const selectorBytes = randomBytes(16);
  const invitationDigest = await sha256(randomBytes(32));
  const client = generateClientProofKey();
  const selector = toBase64Url(selectorBytes);
  const now = Date.now();
  const grant = env.ACCESS_GRANTS.getByName(selector);
  const created = await grant.initialize(
    invitationDigest,
    now + 60 * 60 * 1000,
    24 * 60 * 60 * 1000,
  );
  if (!created) throw new Error("synthetic grant collision");
  const exchanged = await grant.exchange(
    invitationDigest,
    client.publicKey,
  );
  const keyring = parseCapabilityKeyring((env as unknown as Record<string, unknown>).BADTOWER_CAPABILITY_KEYS);
  if (!exchanged.ok || exchanged.epoch === undefined || exchanged.credentialExpiresAt === undefined || keyring === null) throw new Error("synthetic grant exchange failed");
  const token = await formatAccessToken(selectorBytes, client.publicKey, exchanged.epoch, exchanged.credentialExpiresAt, keyring);
  registerProofKey(token, client.privateKey);
  return {
    token,
    digestHex: toHex(new Uint8Array(createHash("sha256").update(token).digest())),
    selector,
  };
}

export interface CarrierMetadata {
  httpProtocol: string;
  tlsVersion: string;
  tlsCipher: string;
}

export const VALID_CF: CarrierMetadata = {
  httpProtocol: "HTTP/2",
  tlsVersion: "TLSv1.3",
  tlsCipher: "TLS_AES_128_GCM_SHA256",
};

export interface RequestOptions {
  token?: string;
  method?: string;
  body?: BodyInit | null;
  headers?: Record<string, string>;
  cf?: CarrierMetadata | null;
  url?: string;
}

export function opRequest(path: string, options: RequestOptions = {}): Request {
  const headers = new Headers(options.headers);
  if (options.body !== undefined && options.body !== null) {
    const length = byteLengthOf(options.body);
    if (!headers.has("content-length")) headers.set("content-length", String(length));
  }
  if (options.token !== undefined) headers.set("authorization", `Bearer ${options.token}`);
  const token = options.token;
  const proof = token === undefined ? undefined : proofKeys.get(token);
  if (proof !== undefined && options.body !== undefined && options.body !== null) {
    const contentType = headers.get("content-type");
    const operationId = headers.get(OPERATION_ID_HEADER);
    const contentLength = headers.get("content-length");
    const bodyBytes = bodyBytesOf(options.body);
    if (contentType !== null && operationId !== null && /^[0-9a-f]{32}$/.test(operationId) && contentLength !== null && bodyBytes !== null) {
      proof.counter += 1n;
      const issuedAt = Date.now();
      const transcript = encodeRequestProof({
        capabilityDigest: new Uint8Array(createHash("sha256").update(token!).digest()),
        method: options.method ?? "POST",
        path: new URL(options.url ?? `https://station.invalid${path}`).pathname,
        mediaType: contentType,
        contentLength: Number(contentLength),
        operationId: fromHex(operationId),
        bodyDigest: new Uint8Array(createHash("sha256").update(bodyBytes).digest()),
        issuedAt,
        counter: proof.counter,
      });
      headers.set(PROOF_ISSUED_AT_HEADER, String(issuedAt));
      headers.set(PROOF_COUNTER_HEADER, String(proof.counter));
      headers.set(PROOF_SIGNATURE_HEADER, toBase64Url(new Uint8Array(sign(null, transcript, proof.privateKey))));
    }
  }
  const request = new Request(options.url ?? `https://station.invalid${path}`, {
    method: options.method ?? "POST",
    headers,
    body: options.body ?? null,
    // Real RequestInit cf: the vitest pool crosses Durable Object contexts
    // when it invokes the entrypoint, which reconstructs the request from its
    // standard fields. Platform `cf` (RequestInit.cf) survives that crossing;
    // ad-hoc properties such as defineProperty("cf") do not.
    ...(options.cf !== undefined ? { cf: options.cf as unknown as Record<string, unknown> } : {}),
  });
  return request;
}

function bodyBytesOf(body: BodyInit): Uint8Array | null {
  if (typeof body === "string") return new TextEncoder().encode(body);
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  return null;
}

export function randomOpId(): string {
  return toHex(crypto.getRandomValues(new Uint8Array(16)));
}

export function opId(seed: number): string {
  const out = new Uint8Array(16);
  new DataView(out.buffer).setUint32(0, seed);
  out[8] = seed >> 24;
  out[9] = (seed >> 16) & 0xff;
  out[10] = (seed >> 8) & 0xff;
  out[11] = seed & 0xff;
  return toHex(out);
}

export function controlHeaders(opIdHex: string, mediaType: string): Record<string, string> {
  return {
    "content-type": mediaType,
    [OPERATION_ID_HEADER]: opIdHex,
    "content-encoding": "identity",
  };
}

export function byteLengthOf(body: BodyInit): number {
  if (typeof body === "string") return new TextEncoder().encode(body).length;
  if (body instanceof ArrayBuffer) return body.byteLength;
  if (ArrayBuffer.isView(body)) return body.byteLength;
  return 0;
}

export function toBase64Url(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2]! : 0;
    out += alphabet[b0 >> 2];
    out += alphabet[((b0 & 3) << 4) | (b1 >> 4)];
    if (i + 1 < bytes.length) out += alphabet[((b1 & 15) << 2) | (b2 >> 6)];
    if (i + 2 < bytes.length) out += alphabet[b2 & 63];
  }
  return out;
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function patternBytes(value: number, count: number): Uint8Array {
  const out = new Uint8Array(count);
  for (let i = 0; i < count; i += 1) out[i] = value;
  return out;
}

export interface MapEntry {
  key: number;
  value: Uint8Array;
}

/** Reads a deterministic-CBOR map and returns its raw label/value slices. */
export function readMap(body: Uint8Array): MapEntry[] {
  const reader = new CborReader(body);
  const entries = reader.mapEntries();
  reader.end();
  return entries.map((entry) => ({ key: entry.key, value: entry.value }));
}

export function uintValue(entry: MapEntry): number {
  const reader = new CborReader(entry.value);
  const value = reader.uint();
  reader.end();
  return value;
}

export function bytesValue(entry: MapEntry): Uint8Array {
  const reader = new CborReader(entry.value);
  const value = reader.bytes();
  reader.end();
  return value;
}

/**
 * Test-side deterministic-CBOR request encoders mirroring the pinned request
 * grammars (labels from candidate.ts). They share the CborWriter so bytes are
 * structurally identical to what the entrypoint parsers accept.
 */

function encodeBytesMap(entries: Array<[number, Uint8Array]>): Uint8Array {
  let size = CborWriter.uintSize(entries.length);
  for (const [label, value] of entries) {
    size += CborWriter.uintSize(label) + CborWriter.bytesSize(value);
  }
  const writer = new CborWriter(size);
  writer.mapHeader(entries.length);
  for (const [label, value] of entries) {
    writer.uint(label);
    writer.bytes(value);
  }
  return writer.finish();
}

export function encodeAffiliateRequest(
  stationDescriptorDigest: Uint8Array,
  affiliationCommitment: Uint8Array,
): Uint8Array {
  return encodeBytesMap([
    [0, stationDescriptorDigest],
    [1, affiliationCommitment],
  ]);
}

export function encodeReserveRequest(
  stationDescriptorDigest: Uint8Array,
  affiliationCommitment: Uint8Array,
  transportProfileId: Uint8Array,
  handleClass: number,
): Uint8Array {
  let size =
    CborWriter.uintSize(4) +
    CborWriter.uintSize(0) +
    CborWriter.bytesSize(stationDescriptorDigest) +
    CborWriter.uintSize(1) +
    CborWriter.bytesSize(affiliationCommitment) +
    CborWriter.uintSize(2) +
    CborWriter.bytesSize(transportProfileId) +
    CborWriter.uintSize(3) +
    CborWriter.uintSize(handleClass);
  const writer = new CborWriter(size);
  writer.mapHeader(4);
  writer.uint(0);
  writer.bytes(stationDescriptorDigest);
  writer.uint(1);
  writer.bytes(affiliationCommitment);
  writer.uint(2);
  writer.bytes(transportProfileId);
  writer.uint(3);
  writer.uint(handleClass);
  return writer.finish();
}

export function encodeClaimRequest(maxItems: number): Uint8Array {
  const writer = new CborWriter(CborWriter.uintSize(1) + CborWriter.uintSize(0) + CborWriter.uintSize(maxItems));
  writer.mapHeader(1);
  writer.uint(0);
  writer.uint(maxItems);
  return writer.finish();
}

export function encodeRetrieveRequest(
  claimId: Uint8Array,
  claimEpoch: number,
  itemId: Uint8Array,
): Uint8Array {
  let size =
    CborWriter.uintSize(3) +
    CborWriter.uintSize(0) +
    CborWriter.bytesSize(claimId) +
    CborWriter.uintSize(1) +
    CborWriter.uintSize(claimEpoch) +
    CborWriter.uintSize(2) +
    CborWriter.bytesSize(itemId);
  const writer = new CborWriter(size);
  writer.mapHeader(3);
  writer.uint(0);
  writer.bytes(claimId);
  writer.uint(1);
  writer.uint(claimEpoch);
  writer.uint(2);
  writer.bytes(itemId);
  return writer.finish();
}

export interface TestSettlement {
  itemId: Uint8Array;
  action: number;
}

export function encodeSettleRequest(
  claimId: Uint8Array,
  claimEpoch: number,
  settlements: TestSettlement[],
): Uint8Array {
  const itemSizes: number[] = [];
  for (const settlement of settlements) {
    itemSizes.push(
      CborWriter.uintSize(2) +
        CborWriter.uintSize(0) +
        CborWriter.bytesSize(settlement.itemId) +
        CborWriter.uintSize(1) +
        CborWriter.uintSize(settlement.action),
    );
  }
  let size =
    CborWriter.uintSize(3) +
    CborWriter.uintSize(0) +
    CborWriter.bytesSize(claimId) +
    CborWriter.uintSize(1) +
    CborWriter.uintSize(claimEpoch) +
    CborWriter.uintSize(2);
  size += CborWriter.arraySize(settlements.length, itemSizes);
  const writer = new CborWriter(size);
  writer.mapHeader(3);
  writer.uint(0);
  writer.bytes(claimId);
  writer.uint(1);
  writer.uint(claimEpoch);
  writer.uint(2);
  writer.arrayHeader(settlements.length);
  for (const settlement of settlements) {
    writer.mapHeader(2);
    writer.uint(0);
    writer.bytes(settlement.itemId);
    writer.uint(1);
    writer.uint(settlement.action);
  }
  return writer.finish();
}
