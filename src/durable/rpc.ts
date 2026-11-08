/**
 * Typed RPC result shared by the Worker entrypoint and relay Durable Object
 * classes. Every durable response is fully formed here (status, headers,
 * body bytes) so that operation replay can return it byte-for-byte.
 */

import {
  CONTROL_MEDIA_TYPE,
  FAILURE_CLASS_HEADER,
  FAILURE_CLASS_NAMES,
  FailureClass,
  OUTCOME_HEADER,
  OUTCOME_NAMES,
  Outcome,
  PROTECTED_PACKET_MEDIA_TYPE,
  RETRY_AFTER_MS_HEADER,
  RETRY_AFTER_MS_HEADER_VALUE,
} from "../transport/candidate";
import {
  encodeAffiliateFailureBody,
  encodeClaimFailureBody,
  encodeReserveFailureBody,
  encodeSettleFailureBody,
  encodeSubmitFailureBody,
} from "../transport/codec";
import { Operation } from "../transport/candidate";

export interface RpcResult {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

export interface StreamingRpcResult {
  status: number;
  headers: Record<string, string>;
  body: ReadableStream<Uint8Array>;
}

export type RpcResponse = RpcResult | StreamingRpcResult;

/** Explicit alias used where only a persistable control response is valid. */
export type BufferedRpcResult = RpcResult;

export const NO_STORE_DENIAL: BufferedRpcResult = {
  status: 401,
  headers: { "cache-control": "no-store" },
  body: new Uint8Array(0),
};

function outcomeHeader(outcome: Outcome): string {
  return OUTCOME_NAMES[outcome];
}

function failureHeader(failure: FailureClass): string {
  return FAILURE_CLASS_NAMES[failure];
}

export function statusFor(outcome: Outcome, failure?: FailureClass): number {
  switch (outcome) {
    case Outcome.Accepted:
      return 200;
    case Outcome.Rejected:
      switch (failure) {
        case FailureClass.TargetUnavailable:
          return 404;
        case FailureClass.UnsupportedProfile:
          return 406;
        case FailureClass.Conflict:
          return 409;
        case FailureClass.PacketTooLarge:
          return 413;
        default:
          return 400;
      }
    case Outcome.Transient:
      if (failure === FailureClass.RateLimited || failure === FailureClass.CapacityUnavailable) {
        return 429;
      }
      return 503;
    case Outcome.Ambiguous:
      return 504;
  }
}

export function acceptedResult(
  operation: Operation,
  acceptedStatus: number,
  body: Uint8Array,
  extraHeaders?: Record<string, string>,
): BufferedRpcResult {
  const headers: Record<string, string> = {
    [OUTCOME_HEADER]: outcomeHeader(Outcome.Accepted),
    "content-type": operation === "RETRIEVE" ? PROTECTED_PACKET_MEDIA_TYPE : CONTROL_MEDIA_TYPE,
    ...extraHeaders,
  };
  return { status: acceptedStatus, headers, body };
}

export function rejectedResult(
  body: Uint8Array,
  failure: FailureClass,
  extraHeaders?: Record<string, string>,
): BufferedRpcResult {
  const headers: Record<string, string> = {
    [OUTCOME_HEADER]: outcomeHeader(Outcome.Rejected),
    [FAILURE_CLASS_HEADER]: failureHeader(failure),
    "content-type": CONTROL_MEDIA_TYPE,
    ...extraHeaders,
  };
  return { status: statusFor(Outcome.Rejected, failure), headers, body };
}

export function transientResult(body: Uint8Array, failure: FailureClass): BufferedRpcResult {
  const headers: Record<string, string> = {
    [OUTCOME_HEADER]: outcomeHeader(Outcome.Transient),
    [FAILURE_CLASS_HEADER]: failureHeader(failure),
    [RETRY_AFTER_MS_HEADER]: String(RETRY_AFTER_MS_HEADER_VALUE),
    "content-type": CONTROL_MEDIA_TYPE,
  };
  return { status: statusFor(Outcome.Transient, failure), headers, body };
}

export function ambiguousResult(body: Uint8Array, failure: FailureClass): BufferedRpcResult {
  const headers: Record<string, string> = {
    [OUTCOME_HEADER]: outcomeHeader(Outcome.Ambiguous),
    [FAILURE_CLASS_HEADER]: failureHeader(failure),
    "content-type": CONTROL_MEDIA_TYPE,
  };
  return { status: statusFor(Outcome.Ambiguous, failure), headers, body };
}

/**
 * Operation-shaped failure result used by the entrypoint for admission,
 * carrier, and internal failures. The failure-class label is always present
 * and the retry label only for transient outcomes, matching the Candidate
 * response grammar; an unknown route falls back to the submit shape.
 */
export function failureResultFor(
  operation: Operation | null,
  outcome: Outcome,
  failure: FailureClass,
): BufferedRpcResult {
  const retryAfterMs = outcome === Outcome.Transient ? RETRY_AFTER_MS_HEADER_VALUE : undefined;
  const fields = { failureClass: failure, retryAfterMs };
  let body: Uint8Array;
  switch (operation) {
    case Operation.AFFILIATE:
      body = encodeAffiliateFailureBody(outcome, fields);
      break;
    case Operation.RESERVE:
      body = encodeReserveFailureBody(outcome, fields);
      break;
    case Operation.CLAIM:
      body = encodeClaimFailureBody(outcome, fields);
      break;
    case Operation.SETTLE:
      body = encodeSettleFailureBody(outcome, fields);
      break;
    default:
      body = encodeSubmitFailureBody(outcome, fields);
      break;
  }
  switch (outcome) {
    case Outcome.Rejected:
      return rejectedResult(body, failure);
    case Outcome.Transient:
      return transientResult(body, failure);
    case Outcome.Ambiguous:
      return ambiguousResult(body, failure);
  }
  throw new Error("invalid failure outcome");
}

export function claimHeaders(claimIdB64: string, epoch: number): Record<string, string> {
  return {
    "licoarc-claim-id": claimIdB64,
    "licoarc-claim-epoch": String(epoch),
  };
}
