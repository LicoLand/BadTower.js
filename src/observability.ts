/**
 * Privacy-minimal structured observability.
 *
 * Only the allowlisted fields below are ever emitted. No token, digest
 * derived from a client, handle, item or claim identifier, packet byte or
 * size, header, URL, error text, stack trace, or stable client identifier
 * may appear in an emitted record.
 */

import { OPERATIONS } from "./transport/candidate";
import type { Operation } from "./transport/candidate";

export const EVENT_SCHEMA_VERSION = 1;

export type EventCode = "admission" | "operation" | "management" | "liveness";
export type EventOutcome = "accepted" | "rejected" | "transient" | "completed";
export type EventFailure =
  | "invalidRequest"
  | "unsupportedProfile"
  | "unauthorized"
  | "rateLimited"
  | "capacityUnavailable"
  | "targetUnavailable"
  | "packetTooLarge"
  | "conflict"
  | "internalUnavailable";

const ALLOWED_KEYS: ReadonlySet<string> = new Set([
  "schemaVersion",
  "event",
  "operation",
  "outcome",
  "failure",
  "count",
]);

export interface OperationEvent {
  event: EventCode;
  operation?: Operation;
  outcome: EventOutcome;
  failure?: EventFailure;
  /** A coarse aggregate only; individual byte and item sizes are forbidden. */
  count?: number;
}

const EVENTS: ReadonlySet<string> = new Set<EventCode>(["admission", "operation", "management", "liveness"]);
const OUTCOMES: ReadonlySet<string> = new Set<EventOutcome>(["accepted", "rejected", "transient", "completed"]);
const FAILURES: ReadonlySet<string> = new Set<EventFailure>([
  "invalidRequest",
  "unsupportedProfile",
  "unauthorized",
  "rateLimited",
  "capacityUnavailable",
  "targetUnavailable",
  "packetTooLarge",
  "conflict",
  "internalUnavailable",
]);
const OPERATION_CODES: ReadonlySet<string> = new Set(OPERATIONS);

export function emitEvent(record: OperationEvent): void {
  if (
    record === null ||
    typeof record !== "object" ||
    !EVENTS.has(record.event) ||
    !OUTCOMES.has(record.outcome) ||
    (record.operation !== undefined && !OPERATION_CODES.has(record.operation)) ||
    (record.failure !== undefined && !FAILURES.has(record.failure))
  ) {
    throw new TypeError("invalid observability event");
  }
  const out: Record<string, string | number> = {
    schemaVersion: EVENT_SCHEMA_VERSION,
    event: record.event,
    outcome: record.outcome,
  };
  if (record.operation !== undefined) out.operation = record.operation;
  if (record.failure !== undefined) out.failure = record.failure;
  if (record.count !== undefined) {
    if (!Number.isSafeInteger(record.count) || record.count < 0 || record.count > 10_000) {
      throw new TypeError("invalid observability aggregate");
    }
    out.count = record.count;
  }
  // Keys are construction-controlled; the allowlist guard is a final defense.
  for (const key of Object.keys(out)) {
    if (!ALLOWED_KEYS.has(key)) throw new Error("forbidden observability key");
  }
  console.log(JSON.stringify(out));
}
