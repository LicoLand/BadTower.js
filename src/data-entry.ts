/**
 * Access-first Worker entrypoint: bounded credential admission, strict
 * Workers-visible carrier validation, bounded body reading, exact route
 * dispatch to the sharded SQLite Durable Object classes, typed response
 * construction, and privacy-minimal observability.
 */

import { authenticateAndCharge, handleDataServiceRequest, preauthenticateCapability, releaseAccessLease, renewAccessLease, secureServiceRequest } from "./access/data-service";
import type { AccessAdmission } from "./access/data-service";
import { sha256 } from "./access/token";
import { decodeBase64Url, toBase64Url } from "./encoding";
import { emptyNoStore, readBoundedBody, secureResponse } from "./http";
import { emitEvent } from "./observability";
import type { EventFailure, EventOutcome } from "./observability";
import {
  ADMITTED_CIPHERS,
  FailureClass,
  MAX_HEADER_BYTES,
  MAX_PATH_BYTES,
  OPERATION_ID_HEADER,
  OPERATION_ID_HEX_LENGTH,
  Operation,
  OPERATION_SHAPES,
  Outcome,
} from "./transport/candidate";
import type { OperationShape } from "./transport/candidate";
import {
  parseAffiliate,
  parseClaim,
  parseReserve,
  parseRetrieve,
  parseSettle,
} from "./transport/codec";
import { affiliationObjectName } from "./durable/affiliation-shard";
import { parseHandleKeyRing, verifyRelayHandle } from "./transport/handle";
import type { RpcResponse, RpcResult } from "./durable/rpc";
import { failureResultFor, transientResult } from "./durable/rpc";

interface Route {
  operation: Operation;
  handle: Uint8Array | null;
}

const HANDLES_PREFIX = "/v1/handles/";
const HEX32 = new RegExp(`^[0-9a-f]{${OPERATION_ID_HEX_LENGTH}}$`);
const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)$/;

/** One indistinguishable empty no-store denial for every admission failure. */
function denial(): Response {
  return emptyNoStore(401);
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function parseRoute(path: string): Route | null {
  if (path === "/v1/affiliate") return { operation: Operation.AFFILIATE, handle: null };
  if (path === "/v1/reserve") return { operation: Operation.RESERVE, handle: null };
  if (!path.startsWith(HANDLES_PREFIX)) return null;
  const rest = path.slice(HANDLES_PREFIX.length);
  const slash = rest.lastIndexOf("/");
  if (slash <= 0) return null;
  const handleEncoded = rest.slice(0, slash);
  const suffix = rest.slice(slash + 1);
  let operation: Operation;
  switch (suffix) {
    case "submit":
      operation = Operation.SUBMIT;
      break;
    case "retrieve":
      operation = Operation.RETRIEVE;
      break;
    case "claim":
      operation = Operation.CLAIM;
      break;
    case "settle":
      operation = Operation.SETTLE;
      break;
    default:
      return null;
  }
  if (handleEncoded.length !== 43) return null;
  const handle = decodeBase64Url(handleEncoded);
  if (handle === null || handle.length !== 32) return null;
  return { operation, handle };
}

function canonicalContentLength(request: Request): number | null {
  const value = request.headers.get("content-length");
  if (value === null || !CANONICAL_DECIMAL.test(value)) return null;
  const length = Number(value);
  if (!Number.isSafeInteger(length)) return null;
  return length;
}

function carrierValid(request: Request, env: Env, route: Route): boolean {
  const url = new URL(request.url);
  if (!secureServiceRequest(request, env)) return false;
  if (url.search !== "" || url.hash !== "") return false;
  if (url.pathname.length > MAX_PATH_BYTES) return false;
  if (new TextEncoder().encode(url.pathname).length > MAX_PATH_BYTES) return false;
  if (request.method !== "POST") return false;
  if (!visibleHeadersWithinBound(request.headers)) return false;
  const local = String(env.BADTOWER_RUNTIME_MODE) === "local" && url.protocol === "http:";
  if (!local) {
    const cf = (request as Request & { cf?: Record<string, unknown> }).cf;
    if (cf === undefined || cf === null) return false;
    if (cf.httpProtocol !== "HTTP/2") return false;
    if (cf.tlsVersion !== "TLSv1.3") return false;
    const cipher = cf.tlsCipher;
    if (typeof cipher !== "string" || !ADMITTED_CIPHERS.includes(cipher)) return false;
  }

  const shape = OPERATION_SHAPES[route.operation];
  if (url.pathname !== shape.pathPrefix && !routeTargetMatches(shape, route)) return false;

  const contentType = request.headers.get("content-type");
  if (contentType === null) return false;
  const normalized = contentType.trim().toLowerCase();
  if (normalized !== shape.requestMediaType) return false;

  const operationId = request.headers.get(OPERATION_ID_HEADER);
  if (operationId === null || !HEX32.test(operationId)) return false;

  const contentEncoding = request.headers.get("content-encoding");
  if (contentEncoding !== null && contentEncoding.toLowerCase() !== "identity") return false;
  if (request.headers.get("transfer-encoding") !== null) return false;

  const length = canonicalContentLength(request);
  if (length === null) return false;
  return true;
}

function visibleHeadersWithinBound(headers: Headers): boolean {
  const encoder = new TextEncoder();
  let total = 0;
  for (const [name, value] of headers.entries()) {
    // UTF-8 byte length is never smaller than the JavaScript code-unit count;
    // avoid copying a large value once the fixed bound is already impossible.
    if (name.length + value.length > MAX_HEADER_BYTES - total) return false;
    total += encoder.encode(name).length + encoder.encode(value).length;
    if (total > MAX_HEADER_BYTES) return false;
  }
  return true;
}

function routeTargetMatches(shape: OperationShape, route: Route): boolean {
  if (!shape.handleBound) return false;
  return true; // handle routes were validated during parseRoute
}

async function semanticDigest(
  method: string,
  path: string,
  mediaType: string,
  length: number,
  bodyDigest: Uint8Array,
): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const parts = [
    enc.encode(method),
    enc.encode(path),
    enc.encode(mediaType),
    enc.encode(String(length)),
    bodyDigest,
  ];
  let total = 0;
  for (const part of parts) total += part.length;
  const input = new Uint8Array(total + 4);
  let at = 0;
  for (let i = 0; i < parts.length; i += 1) {
    input.set(parts[i]!, at);
    at += parts[i]!.length;
    if (i + 1 < parts.length) {
      input[at] = 0;
      at += 1;
    }
  }
  return sha256(input);
}

function parseOperationId(request: Request): Uint8Array {
  return hexToBytes(request.headers.get(OPERATION_ID_HEADER)!);
}

function emitOperation(
  operation: Operation | null,
  outcome: EventOutcome,
  failure?: EventFailure,
): void {
  emitEvent({
    event: "operation",
    operation: operation === null ? undefined : operation,
    outcome,
    failure,
  });
}

type AuthorizedAdmission = Extract<AccessAdmission, { kind: "authorized" }>;

async function releaseLeaseSafely(env: Env, admission: AuthorizedAdmission): Promise<void> {
  try {
    await releaseAccessLease(env, admission);
  } catch {
    emitEvent({ event: "admission", outcome: "transient", failure: "internalUnavailable" });
  }
}

function holdLeaseUntilStreamEnds(
  body: ReadableStream<Uint8Array>,
  env: Env,
  admission: AuthorizedAdmission,
): ReadableStream<Uint8Array> {
  const reader = body.getReader();
  let releasePromise: Promise<void> | null = null;
  const releaseOnce = (): Promise<void> => {
    releasePromise ??= releaseLeaseSafely(env, admission);
    return releasePromise;
  };
  // A live stream keeps its lease through renewals; the TTL only covers a
  // dead isolate, where renewals stop and the lease expires on its own.
  let renewing = false;
  let owned = true;
  let interval: ReturnType<typeof setInterval> | null = null;
  const clearRenewal = () => {
    if (interval !== null) {
      clearInterval(interval);
      interval = null;
    }
  };
  const renew = (controller: ReadableStreamDefaultController<Uint8Array>) => {
    interval = setInterval(() => {
      if (renewing || !owned) return;
      renewing = true;
      renewAccessLease(env, admission, STREAM_LEASE_TTL_MS)
        .then((kept) => {
          renewing = false;
          if (kept || !owned) return;
          owned = false;
          clearRenewal();
          reader.cancel().catch(() => undefined);
          controller.error(new Error("stream unavailable"));
          void releaseOnce();
        })
        .catch(() => {
          renewing = false;
          emitEvent({ event: "admission", outcome: "transient", failure: "internalUnavailable" });
        });
    }, STREAM_LEASE_RENEW_MS);
  };
  return new ReadableStream<Uint8Array>({
    start(controller) {
      renew(controller);
    },
    async pull(controller) {
      try {
        const next = await reader.read();
        if (next.done) {
          clearRenewal();
          await releaseOnce();
          controller.close();
        } else {
          controller.enqueue(next.value);
        }
      } catch {
        clearRenewal();
        await releaseOnce();
        controller.error(new Error("stream unavailable"));
      }
    },
    async cancel(reason) {
      clearRenewal();
      try {
        await reader.cancel(reason);
      } catch {
        // The source has already failed; the grant lease must still be released.
      } finally {
        await releaseOnce();
      }
    },
  });
}

function eventOutcome(value: string): EventOutcome {
  switch (value) {
    case "accepted":
      return "completed";
    case "rejected":
      return "rejected";
    default:
      return "transient";
  }
}

function eventFailure(value: string | undefined): EventFailure | undefined {
  switch (value) {
    case "invalidRequest":
    case "unsupportedProfile":
    case "targetUnavailable":
    case "packetTooLarge":
    case "capacityUnavailable":
    case "rateLimited":
    case "conflict":
    case "internalUnavailable":
      return value;
    default:
      return undefined;
  }
}

async function handleRequest(request: Request, env: Env): Promise<Response> {
    const serviceResponse = await handleDataServiceRequest(request, env);
    if (serviceResponse !== null) return serviceResponse;

    const preauthentication = await preauthenticateCapability(request, env);
    if (preauthentication.kind === "denied") {
      emitEvent({ event: "admission", outcome: "rejected", failure: "unauthorized" });
      return denial();
    }

    const url = new URL(request.url);
    const route = parseRoute(url.pathname);
    if (route === null) {
      emitOperation(null, "rejected", "invalidRequest");
      return toResponse(
        failureResultFor(null, Outcome.Rejected, FailureClass.InvalidRequest),
      );
    }
    if (!carrierValid(request, env, route)) {
      emitOperation(route.operation, "rejected", "invalidRequest");
      return toResponse(
        failureResultFor(route.operation, Outcome.Rejected, FailureClass.InvalidRequest),
      );
    }
    const shape = OPERATION_SHAPES[route.operation];
    const declaredLength = canonicalContentLength(request)!;
    if (declaredLength > shape.maxBodyBytes) {
      const failure =
        route.operation === Operation.SUBMIT
          ? FailureClass.PacketTooLarge
          : FailureClass.InvalidRequest;
      emitOperation(route.operation, "rejected", FAILURE_NAME(failure));
      return toResponse(failureResultFor(route.operation, Outcome.Rejected, failure));
    }
    const read = await readBoundedBody(request, declaredLength);
    if (read.kind === "too-large") {
      const failure =
        route.operation === Operation.SUBMIT && declaredLength === shape.maxBodyBytes
          ? FailureClass.PacketTooLarge
          : FailureClass.InvalidRequest;
      emitOperation(route.operation, "rejected", FAILURE_NAME(failure));
      return toResponse(failureResultFor(route.operation, Outcome.Rejected, failure));
    }
    if (read.kind === "read-error") {
      emitOperation(route.operation, "rejected", "invalidRequest");
      return toResponse(
        failureResultFor(route.operation, Outcome.Rejected, FailureClass.InvalidRequest),
      );
    }
    if (read.bytes.length !== declaredLength) {
      emitOperation(route.operation, "rejected", "invalidRequest");
      return toResponse(
        failureResultFor(route.operation, Outcome.Rejected, FailureClass.InvalidRequest),
      );
    }
    if (route.operation === Operation.SUBMIT && read.bytes.length === 0) {
      emitOperation(route.operation, "rejected", "packetTooLarge");
      return toResponse(
        failureResultFor(route.operation, Outcome.Rejected, FailureClass.PacketTooLarge),
      );
    }
    const bodyDigest = await sha256(read.bytes);
    const digest = await semanticDigest(
      "POST",
      url.pathname,
      shape.requestMediaType,
      declaredLength,
      bodyDigest,
    );
    const operationId = parseOperationId(request);
    const charge = chargeFor(route.operation);
    const admission = await authenticateAndCharge(preauthentication, request, env, {
      method: "POST",
      path: url.pathname,
      mediaType: shape.requestMediaType,
      contentLength: declaredLength,
      operationId,
      bodyDigest,
      rateLimitClass: route.operation,
      ...charge,
    });
    if (admission.kind === "denied") {
      emitEvent({ event: "admission", outcome: "rejected", failure: "unauthorized" });
      return denial();
    }
    if (admission.kind === "busy") {
      emitEvent({ event: "admission", outcome: "transient", failure: "capacityUnavailable" });
      return emptyNoStore(503);
    }
    if (admission.kind === "limited") {
      emitOperation(route.operation, "transient", "rateLimited");
      return toResponse(
        transientResult(
          failureResultFor(route.operation, Outcome.Transient, FailureClass.RateLimited).body,
          FailureClass.RateLimited,
        ),
      );
    }
    let streamOwnsLease = false;
    try {
      if (route.handle !== null) {
        const record = env as unknown as Record<string, unknown>;
        const ring = parseHandleKeyRing(
          record.BADTOWER_HANDLE_KEYS,
          record.BADTOWER_HANDLE_CURRENT_SLOT,
        );
        if (ring === null || !(await verifyRelayHandle(route.handle, ring))) {
          emitOperation(route.operation, "rejected", "targetUnavailable");
          return toResponse(
            failureResultFor(route.operation, Outcome.Rejected, FailureClass.TargetUnavailable),
          );
        }
      }
      let result = await dispatch(env, route, operationId, digest, read.bytes);
      const outcome = eventOutcome(result.headers["licoarc-outcome"]!);
      emitOperation(
        route.operation,
        outcome,
        eventFailure(result.headers["licoarc-failure-class"]),
      );
      if (result.body instanceof ReadableStream && admission.leaseCounter !== undefined) {
        result = { ...result, body: holdLeaseUntilStreamEnds(result.body, env, admission) };
        streamOwnsLease = true;
      }
      return toResponse(result);
    } catch {
      const failure = FailureClass.InternalUnavailable;
      emitOperation(route.operation, "transient", "internalUnavailable");
      return toResponse(
        transientResult(
          failureResultFor(route.operation, Outcome.Transient, failure).body,
          failure,
        ),
      );
    } finally {
      if (!streamOwnsLease) await releaseLeaseSafely(env, admission);
    }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handleRequest(request, env);
    } catch {
      emitEvent({ event: "operation", outcome: "transient", failure: "internalUnavailable" });
      return emptyNoStore(503);
    }
  },
};

export const STREAM_LEASE_TTL_MS = 30_000;
// One third of the TTL: two consecutive renewal misses are still tolerated.
export const STREAM_LEASE_RENEW_MS = 10_000;

function chargeFor(operation: Operation): {
  operationWeight: number;
  creationCost: number;
  concurrencyCost: 0 | 1;
  leaseTtlMs: number;
} {
  switch (operation) {
    case Operation.AFFILIATE:
    case Operation.RESERVE:
      return { operationWeight: 4, creationCost: 1, concurrencyCost: 0, leaseTtlMs: 0 };
    case Operation.CLAIM:
      return { operationWeight: 4, creationCost: 0, concurrencyCost: 1, leaseTtlMs: STREAM_LEASE_TTL_MS };
    case Operation.RETRIEVE:
      return { operationWeight: 2, creationCost: 0, concurrencyCost: 1, leaseTtlMs: STREAM_LEASE_TTL_MS };
    case Operation.SUBMIT:
      return { operationWeight: 2, creationCost: 0, concurrencyCost: 0, leaseTtlMs: 0 };
    case Operation.SETTLE:
      return { operationWeight: 1, creationCost: 0, concurrencyCost: 0, leaseTtlMs: 0 };
  }
}

function FAILURE_NAME(failure: FailureClass): EventFailure {
  return (
    [
      "invalidRequest",
      "unsupportedProfile",
      "targetUnavailable",
      "packetTooLarge",
      "capacityUnavailable",
      "rateLimited",
      "conflict",
      "internalUnavailable",
    ] as const
  )[failure]!;
}

type ParseOutcome<T> = { ok: true; value: T } | { ok: false; failure: RpcResult };

/** Candidate control parse failures are invalidRequest rejections, never 503s. */
function parseOrReject<T>(
  operation: Operation,
  parse: (body: Uint8Array) => T,
  body: Uint8Array,
): ParseOutcome<T> {
  try {
    return { ok: true, value: parse(body) };
  } catch {
    return {
      ok: false,
      failure: failureResultFor(operation, Outcome.Rejected, FailureClass.InvalidRequest),
    };
  }
}

async function dispatch(
  env: Env,
  route: Route,
  operationId: Uint8Array,
  digest: Uint8Array,
  body: Uint8Array,
): Promise<RpcResponse> {
  switch (route.operation) {
    case Operation.AFFILIATE: {
      const parsed = parseOrReject(Operation.AFFILIATE, parseAffiliate, body);
      if (!parsed.ok) return parsed.failure;
      const name = await affiliationObjectName(
        parsed.value.stationDescriptorDigest,
        parsed.value.affiliationCommitment,
      );
      return env.AFFILIATION_SHARDS.getByName(name).affiliate(operationId, digest);
    }
    case Operation.RESERVE: {
      const parsed = parseOrReject(Operation.RESERVE, parseReserve, body);
      if (!parsed.ok) return parsed.failure;
      const name = await affiliationObjectName(
        parsed.value.stationDescriptorDigest,
        parsed.value.affiliationCommitment,
      );
      return env.AFFILIATION_SHARDS.getByName(name).reserve(operationId, digest, {
        handleClass: parsed.value.handleClass,
      });
    }
    case Operation.SUBMIT: {
      return env.RELAY_HANDLES.getByName(toBase64Url(route.handle!)).submit(
        operationId,
        digest,
        body,
      );
    }
    case Operation.CLAIM: {
      const parsed = parseOrReject(Operation.CLAIM, parseClaim, body);
      if (!parsed.ok) return parsed.failure;
      return env.RELAY_HANDLES.getByName(toBase64Url(route.handle!)).claim(
        operationId,
        digest,
        parsed.value.maxItems,
      );
    }
    case Operation.RETRIEVE: {
      const parsed = parseOrReject(Operation.RETRIEVE, parseRetrieve, body);
      if (!parsed.ok) return parsed.failure;
      return env.RELAY_HANDLES.getByName(toBase64Url(route.handle!)).retrieve(
        operationId,
        digest,
        parsed.value.claimId,
        parsed.value.claimEpoch,
        parsed.value.itemId,
      );
    }
    case Operation.SETTLE: {
      const parsed = parseOrReject(Operation.SETTLE, parseSettle, body);
      if (!parsed.ok) return parsed.failure;
      return env.RELAY_HANDLES.getByName(toBase64Url(route.handle!)).settle(
        operationId,
        digest,
        parsed.value.claimId,
        parsed.value.claimEpoch,
        parsed.value.settlements,
      );
    }
  }
}

function toResponse(result: RpcResponse): Response {
  return secureResponse(result.body, {
    status: result.status,
    headers: result.headers,
  });
}

export { AffiliationShard } from "./durable/affiliation-shard";
export { AccessGrant } from "./durable/access-grant";
export { RelayHandle } from "./durable/relay-handle";
