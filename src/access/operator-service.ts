import { toBase64Url } from "../encoding";
import { emptyNoStore, jsonNoStore, readBoundedBody } from "../http";
import { digestEqual, formatInvitationToken, parseCapabilityKeyring, parseDigestSecret, parseOperatorToken, parseSelector, randomBytes, readBearer, sha256, TOKEN_SELECTOR_BYTES } from "./token";

const JSON_BODY_MAX_BYTES = 1024;
const DEFAULT_INVITATION_TTL_SECONDS = 7 * 24 * 60 * 60;
const DEFAULT_ACCESS_TTL_SECONDS = 24 * 60 * 60;
const MIN_INVITATION_TTL_SECONDS = 5 * 60;
const MAX_INVITATION_TTL_SECONDS = 30 * 24 * 60 * 60;
const MIN_ACCESS_TTL_SECONDS = 60 * 60;
const MAX_ACCESS_TTL_SECONDS = 7 * 24 * 60 * 60;
const OPERATOR_GRANT_PATH = /^\/v1\/operator\/grants\/([A-Za-z0-9_-]{22})$/;
type JsonObject = Record<string, unknown>;
function capabilityKeys(env: Env): unknown { return (env as unknown as Record<string, unknown>).BADTOWER_CAPABILITY_KEYS; }
function operatorDigest(env: Env): unknown { return (env as unknown as Record<string, unknown>).BADTOWER_OPERATOR_TOKEN_DIGEST; }
function localHostname(hostname: string): boolean { return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]"; }
function secureServiceRequest(request: Request, env: Env): boolean {
  const url = new URL(request.url);
  return url.protocol === "https:" || (String(env.BADTOWER_RUNTIME_MODE) === "local" && url.protocol === "http:" && localHostname(url.hostname));
}

async function operatorAuthorized(request: Request, env: Env): Promise<boolean> {
  const bearer = readBearer(request);
  const token = bearer === null ? null : parseOperatorToken(bearer);
  const expected = parseDigestSecret(operatorDigest(env));
  return token !== null && expected !== null && digestEqual(await sha256(token), expected);
}
function configured(env: Env): boolean { return parseDigestSecret(operatorDigest(env)) !== null && parseCapabilityKeyring(capabilityKeys(env)) !== null; }
async function sensitiveAllowed(env: Env): Promise<boolean> { return (await env.SENSITIVE_RATE_LIMITER.limit({ key: "operator" })).success; }
function limited(): Response { const response = emptyNoStore(429); response.headers.set("Retry-After", "60"); return response; }
function ttl(value: unknown, fallback: number, min: number, max: number): number | null { return value === undefined ? fallback : Number.isSafeInteger(value) && (value as number) >= min && (value as number) <= max ? value as number : null; }
async function readJsonObject(request: Request): Promise<JsonObject | null> {
  if (request.headers.get("content-type")?.trim().toLowerCase() !== "application/json") return null;
  const body = await readBoundedBody(request, JSON_BODY_MAX_BYTES);
  if (body.kind !== "ok" || body.bytes.length === 0) return null;
  try { const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body.bytes)); return value !== null && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : null; } catch { return null; }
}
async function createInvitation(request: Request, env: Env): Promise<Response> {
  const input = await readJsonObject(request);
  if (input === null || Object.keys(input).some((key) => key !== "invitationTtlSeconds" && key !== "accessTtlSeconds")) return emptyNoStore(400);
  const invitationTtlSeconds = ttl(input.invitationTtlSeconds, DEFAULT_INVITATION_TTL_SECONDS, MIN_INVITATION_TTL_SECONDS, MAX_INVITATION_TTL_SECONDS);
  const accessTtlSeconds = ttl(input.accessTtlSeconds, DEFAULT_ACCESS_TTL_SECONDS, MIN_ACCESS_TTL_SECONDS, MAX_ACCESS_TTL_SECONDS);
  const keyring = parseCapabilityKeyring(capabilityKeys(env));
  if (invitationTtlSeconds === null || accessTtlSeconds === null || keyring === null) return emptyNoStore(400);
  const now = Date.now();
  const invitationExpiresAt = now + invitationTtlSeconds * 1000;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const selectorBytes = randomBytes(TOKEN_SELECTOR_BYTES);
    const selector = toBase64Url(selectorBytes);
    const invitation = await formatInvitationToken(selectorBytes, invitationExpiresAt, keyring);
    if (await env.ACCESS_GRANTS.getByName(selector).initialize(await sha256(new TextEncoder().encode(invitation)), invitationExpiresAt, accessTtlSeconds * 1000)) return jsonNoStore({ invitation, invitationId: selector, invitationExpiresAt: new Date(invitationExpiresAt).toISOString(), accessTtlSeconds }, 201);
  }
  return emptyNoStore(503);
}
async function grantOperation(request: Request, env: Env, selector: string): Promise<Response> {
  if (parseSelector(selector) === null) return emptyNoStore(404);
  const grant = env.ACCESS_GRANTS.getByName(selector);
  if (request.method === "DELETE") { await grant.revoke(); return emptyNoStore(204); }
  if (request.method !== "GET") return emptyNoStore(405);
  const status = await grant.status();
  return jsonNoStore({ state: status.state, ...(status.expiresAt === undefined ? {} : { expiresAt: new Date(status.expiresAt).toISOString() }), ...(status.epoch === undefined ? {} : { epoch: status.epoch }) });
}

export async function handleOperatorServiceRequest(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.search !== "" || url.hash !== "") return null;
  const known = url.pathname === "/readyz" || url.pathname === "/v1/operator/invitations" || OPERATOR_GRANT_PATH.test(url.pathname);
  if (!known) return null;
  if (!secureServiceRequest(request, env)) return emptyNoStore(400);
  if (!(await sensitiveAllowed(env))) return limited();
  if (!(await operatorAuthorized(request, env))) return emptyNoStore(401);
  if (url.pathname === "/readyz") return request.method === "GET" ? (configured(env) ? jsonNoStore({ status: "ready" }) : jsonNoStore({ status: "unavailable" }, 503)) : emptyNoStore(405);
  if (url.pathname === "/v1/operator/invitations") return request.method === "POST" ? createInvitation(request, env) : emptyNoStore(405);
  const match = OPERATOR_GRANT_PATH.exec(url.pathname);
  return match === null ? null : grantOperation(request, env, match[1]!);
}
