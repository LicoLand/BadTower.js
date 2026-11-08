import { decodeBase64Url, toBase64Url } from "../encoding";
import { emptyNoStore, jsonNoStore, readBoundedBody } from "../http";
import {
  ED25519_PUBLIC_KEY_BYTES,
  PROOF_MAX_SKEW_MS,
  encodeRequestProof,
  formatAccessToken,
  parseAccessToken,
  parseCapabilityKeyring,
  parseInvitationToken,
  readBearer,
  verifyRequestProof,
} from "./token";
import type { ParsedAccessCapability } from "./token";

const JSON_BODY_MAX_BYTES = 1024;
export const PROOF_ISSUED_AT_HEADER = "badtower-proof-issued-at";
export const PROOF_COUNTER_HEADER = "badtower-proof-counter";
export const PROOF_SIGNATURE_HEADER = "badtower-proof-signature";
const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)$/;
function capabilityKeys(env: Env): unknown { return (env as unknown as Record<string, unknown>).BADTOWER_CAPABILITY_KEYS; }

type JsonObject = Record<string, unknown>;
export interface AccessChargeContext {
  method: string;
  path: string;
  mediaType: string;
  contentLength: number;
  operationId: Uint8Array;
  bodyDigest: Uint8Array;
  operationWeight: number;
  creationCost: number;
  concurrencyCost: 0 | 1;
  leaseTtlMs: number;
  rateLimitClass: string;
}
export type AccessAdmission =
  | { kind: "authorized"; selector: string; epoch: number; counter: string; leaseCounter?: string }
  | { kind: "denied" }
  | { kind: "busy" }
  | { kind: "limited" };

export interface CapabilityPreauthentication {
  readonly kind: "capability-preauthentication";
}
export type CapabilityPreauthenticationResult = CapabilityPreauthentication | { kind: "denied" };
const preauthenticatedCapabilities = new WeakMap<CapabilityPreauthentication, ParsedAccessCapability>();

function isObject(value: unknown): value is JsonObject { return value !== null && typeof value === "object" && !Array.isArray(value); }
async function readJsonObject(request: Request): Promise<JsonObject | null> {
  if (request.headers.get("content-type")?.trim().toLowerCase() !== "application/json") return null;
  const declared = request.headers.get("content-length");
  if (declared !== null && (!CANONICAL_DECIMAL.test(declared) || Number(declared) > JSON_BODY_MAX_BYTES)) return null;
  const body = await readBoundedBody(request, JSON_BODY_MAX_BYTES);
  if (body.kind !== "ok" || body.bytes.length === 0) return null;
  try { const parsed: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body.bytes)); return isObject(parsed) ? parsed : null; } catch { return null; }
}
function exactKeys(value: JsonObject, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return keys.length === sorted.length && keys.every((key, index) => key === sorted[index]);
}
function localHostname(hostname: string): boolean { return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]"; }
export function secureServiceRequest(request: Request, env: Env): boolean {
  const url = new URL(request.url);
  return url.protocol === "https:" || (String(env.BADTOWER_RUNTIME_MODE) === "local" && url.protocol === "http:" && localHostname(url.hostname));
}
async function sensitiveAllowed(env: Env, key: string): Promise<boolean> { return (await env.SENSITIVE_RATE_LIMITER.limit({ key })).success; }
function limited(): Response { const response = emptyNoStore(429); response.headers.set("Retry-After", "60"); return response; }

async function exchangeInvitation(request: Request, env: Env): Promise<Response> {
  const input = await readJsonObject(request);
  if (input === null || !exactKeys(input, ["invitation", "clientPublicKey"]) || typeof input.invitation !== "string" || typeof input.clientPublicKey !== "string") return emptyNoStore(401);
  const keyring = parseCapabilityKeyring(capabilityKeys(env));
  if (keyring === null) return emptyNoStore(401);
  const now = Date.now();
  const invitation = await parseInvitationToken(input.invitation, keyring, now);
  const publicKey = decodeBase64Url(input.clientPublicKey);
  if (invitation === null || publicKey === null || publicKey.length !== ED25519_PUBLIC_KEY_BYTES || toBase64Url(publicKey) !== input.clientPublicKey) return emptyNoStore(401);
  if (!(await sensitiveAllowed(env, `exchange:${invitation.selector}`))) return limited();
  const result = await env.ACCESS_GRANTS.getByName(invitation.selector).exchange(invitation.digest, publicKey);
  if (!result.ok || result.credentialExpiresAt === undefined || result.epoch === undefined) return emptyNoStore(401);
  return jsonNoStore({ accessToken: await formatAccessToken(invitation.selectorBytes, publicKey, result.epoch, result.credentialExpiresAt, keyring), expiresAt: new Date(result.credentialExpiresAt).toISOString() });
}

export async function handleDataServiceRequest(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.search !== "" || url.hash !== "") return null;
  if (url.pathname === "/healthz" && request.method === "GET") return jsonNoStore({ status: "ok" });
  if (url.pathname !== "/v1/invitations/exchange") return null;
  if (!secureServiceRequest(request, env)) return emptyNoStore(400);
  return request.method === "POST" ? exchangeInvitation(request, env) : emptyNoStore(405);
}

function canonicalHeader(request: Request, name: string, pattern: RegExp): string | null {
  const value = request.headers.get(name);
  return value !== null && !value.includes(",") && pattern.test(value) ? value : null;
}

export async function preauthenticateCapability(request: Request, env: Env): Promise<CapabilityPreauthenticationResult> {
  const bearer = readBearer(request);
  const keyring = parseCapabilityKeyring(capabilityKeys(env));
  if (bearer === null || keyring === null) return { kind: "denied" };
  const capability = await parseAccessToken(bearer, keyring, Date.now());
  if (capability === null) return { kind: "denied" };
  const result: CapabilityPreauthentication = { kind: "capability-preauthentication" };
  preauthenticatedCapabilities.set(result, capability);
  return result;
}

export async function authenticateAndCharge(preauthentication: CapabilityPreauthentication, request: Request, env: Env, context: AccessChargeContext): Promise<AccessAdmission> {
  const capability = preauthenticatedCapabilities.get(preauthentication);
  if (capability === undefined) return { kind: "denied" };
  const now = Date.now();
  const issuedText = canonicalHeader(request, PROOF_ISSUED_AT_HEADER, CANONICAL_DECIMAL);
  const counterText = canonicalHeader(request, PROOF_COUNTER_HEADER, /^(0|[1-9][0-9]{0,19})$/);
  const signatureText = canonicalHeader(request, PROOF_SIGNATURE_HEADER, /^[A-Za-z0-9_-]{86}$/);
  if (issuedText === null || counterText === null || signatureText === null) return { kind: "denied" };
  const issuedAt = Number(issuedText);
  const counter = BigInt(counterText);
  const signature = decodeBase64Url(signatureText);
  if (!Number.isSafeInteger(issuedAt) || Math.abs(now - issuedAt) > PROOF_MAX_SKEW_MS || counter > 0xffff_ffff_ffff_ffffn || signature === null || signature.length !== 64 || toBase64Url(signature) !== signatureText) return { kind: "denied" };
  let transcript: Uint8Array;
  try {
    transcript = encodeRequestProof({ capabilityDigest: capability.digest, method: context.method, path: context.path, mediaType: context.mediaType, contentLength: context.contentLength, operationId: context.operationId, bodyDigest: context.bodyDigest, issuedAt, counter });
  } catch { return { kind: "denied" }; }
  if (!(await verifyRequestProof(capability.publicKey, transcript, signature))) return { kind: "denied" };
  const routeKey = `${capability.selector}:${context.rateLimitClass}`;
  const edge = await env.EDGE_ADMISSION_RATE_LIMITER.limit({ key: routeKey });
  if (!edge.success) return { kind: "busy" };
  const client = await env.CLIENT_RATE_LIMITER.limit({ key: routeKey });
  if (!client.success) return { kind: "limited" };
  const result = await env.ACCESS_GRANTS.getByName(capability.selector).authorizeAndCharge({
    epoch: capability.epoch, publicKey: capability.publicKey, counter: counterText,
    requestCost: 1, byteCost: context.contentLength, operationWeight: context.operationWeight,
    creationCost: context.creationCost, concurrencyCost: context.concurrencyCost,
    leaseTtlMs: context.leaseTtlMs,
  });
  if (!result.ok) return { kind: "denied" };
  return { kind: "authorized", selector: capability.selector, epoch: capability.epoch, counter: counterText, ...(result.leaseCounter === undefined ? {} : { leaseCounter: result.leaseCounter }) };
}

export async function releaseAccessLease(env: Env, admission: Extract<AccessAdmission, { kind: "authorized" }>): Promise<void> {
  if (admission.leaseCounter !== undefined) await env.ACCESS_GRANTS.getByName(admission.selector).releaseLease(admission.epoch, admission.leaseCounter);
}
