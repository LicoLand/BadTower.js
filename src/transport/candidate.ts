/**
 * Pinned LicoArc Candidate transport contract.
 *
 * This module is the single immutable source of wire identity, lifecycle,
 * operation, enum, label, media type, header, and bound facts for the
 * access-gated Candidate transport surface. It reproduces only constants and closed
 * schemas from the reviewed Candidate sources; it never imports or copies
 * sibling runtime source (LicoArc, Go BadTower, or any other repository).
 */

export const WIRE_ID = "licoarc.protocol-line.v1";
export const PROTOCOL_LINE_ID = "licoarc.v1";
export const TRANSPORT_PROFILE_ID = "licoarc.https-transport.v1";
export const LIFECYCLE = "Candidate";
export const PROTOCOL_MANIFEST_SHA256 =
  "96688cc20ea8bcd4726fa33ced35a10ea12349e0a6d5abc23fb585197b06c503";
export const TRANSPORT_SOURCE_DIGEST =
  "6d4636c983606fb266443a3ce05171a8af7ab5284e0ce301be7024ce16592cb5";

export const CONTROL_MEDIA_TYPE = "application/licoarc-transport+cbor";
export const PROTECTED_PACKET_MEDIA_TYPE = "application/licoarc-protected-packet";

export const OPERATION_ID_HEADER = "licoarc-operation-id";
/** Fixed preview-level retry value for transient responses (ms). */
export const RETRY_AFTER_MS_HEADER_VALUE = 1000;
export const OUTCOME_HEADER = "licoarc-outcome";
export const FAILURE_CLASS_HEADER = "licoarc-failure-class";
export const RETRY_AFTER_MS_HEADER = "licoarc-retry-after-ms";
export const CLAIM_ID_HEADER = "licoarc-claim-id";
export const CLAIM_EPOCH_HEADER = "licoarc-claim-epoch";

export const OPERATION_ID_HEX_LENGTH = 32; // 16 bytes, lowercase hex
/** Fixed Candidate numeric bounds (spec/v1/transport/bounds.json). */
export const MAX_PACKET_BYTES = 524288;
export const MAX_CONTROL_BODY_BYTES = 16384;
export const MAX_CONTROL_RESPONSE_BYTES = 16384;
export const MAX_CLAIM_RESPONSE_BYTES = 33554432;
export const MAX_OPERATION_ID_BYTES = 16;
export const MAX_DELIVERY_HANDLE_BYTES = 32;
export const MAX_CLAIM_ID_BYTES = 32;
export const MAX_ITEM_ID_BYTES = 32;
export const MAX_QUEUE_ITEMS_PER_HANDLE = 128;
export const MAX_QUEUE_BYTES_PER_HANDLE = 67108864;
export const MAX_CLAIM_ITEMS = 64;
export const MAX_CLAIM_BYTES = 33554432;
export const MAX_SETTLEMENT_ITEMS = 64;
export const MAX_SETTLEMENT_ATTEMPTS = 8;
export const MAX_RETRY_AFTER_MS = 60000;
export const STORAGE_WINDOW_SECONDS = 3600;
export const IDEMPOTENCY_WINDOW_SECONDS = 300;
export const CLAIM_WINDOW_SECONDS = 300;

/** Preview-owned operation replay quotas (not part of the Candidate wire). */
export const MAX_OPERATION_RECORDS_PER_AFFILIATION = 256;
export const MAX_OPERATION_RECORDS_PER_HANDLE = 256;
export const MAX_CACHED_RESPONSE_BYTES_PER_HANDLE = 67108864;
export const CLEANUP_BATCH_ROWS = 64;

export enum Operation {
  AFFILIATE = "AFFILIATE",
  RESERVE = "RESERVE",
  SUBMIT = "SUBMIT",
  RETRIEVE = "RETRIEVE",
  CLAIM = "CLAIM",
  SETTLE = "SETTLE",
}

export const OPERATIONS: readonly Operation[] = [
  Operation.AFFILIATE,
  Operation.RESERVE,
  Operation.SUBMIT,
  Operation.RETRIEVE,
  Operation.CLAIM,
  Operation.SETTLE,
];

export interface OperationShape {
  method: string;
  pathPrefix: string;
  handleBound: boolean;
  requestMediaType: string;
  acceptedStatus: number;
  maxBodyBytes: number;
}

const HANDLE_PATH = "/v1/handles/";

export const OPERATION_SHAPES: Record<Operation, OperationShape> = {
  [Operation.AFFILIATE]: {
    method: "POST",
    pathPrefix: "/v1/affiliate",
    handleBound: false,
    requestMediaType: CONTROL_MEDIA_TYPE,
    acceptedStatus: 201,
    maxBodyBytes: MAX_CONTROL_BODY_BYTES,
  },
  [Operation.RESERVE]: {
    method: "POST",
    pathPrefix: "/v1/reserve",
    handleBound: false,
    requestMediaType: CONTROL_MEDIA_TYPE,
    acceptedStatus: 201,
    maxBodyBytes: MAX_CONTROL_BODY_BYTES,
  },
  [Operation.SUBMIT]: {
    method: "POST",
    pathPrefix: HANDLE_PATH,
    handleBound: true,
    requestMediaType: PROTECTED_PACKET_MEDIA_TYPE,
    acceptedStatus: 202,
    maxBodyBytes: MAX_PACKET_BYTES,
  },
  [Operation.RETRIEVE]: {
    method: "POST",
    pathPrefix: HANDLE_PATH,
    handleBound: true,
    requestMediaType: CONTROL_MEDIA_TYPE,
    acceptedStatus: 200,
    maxBodyBytes: MAX_CONTROL_BODY_BYTES,
  },
  [Operation.CLAIM]: {
    method: "POST",
    pathPrefix: HANDLE_PATH,
    handleBound: true,
    requestMediaType: CONTROL_MEDIA_TYPE,
    acceptedStatus: 200,
    maxBodyBytes: MAX_CONTROL_BODY_BYTES,
  },
  [Operation.SETTLE]: {
    method: "POST",
    pathPrefix: HANDLE_PATH,
    handleBound: true,
    requestMediaType: CONTROL_MEDIA_TYPE,
    acceptedStatus: 200,
    maxBodyBytes: MAX_CONTROL_BODY_BYTES,
  },
};

export function operationSuffix(operation: Operation): string {
  return `/${operation.toLowerCase()}`;
}

export enum Outcome {
  Accepted = 0,
  Rejected = 1,
  Transient = 2,
  Ambiguous = 3,
}

export const OUTCOME_NAMES: Record<Outcome, string> = {
  [Outcome.Accepted]: "accepted",
  [Outcome.Rejected]: "rejected",
  [Outcome.Transient]: "transient",
  [Outcome.Ambiguous]: "ambiguous",
};

export enum FailureClass {
  InvalidRequest = 0,
  UnsupportedProfile = 1,
  TargetUnavailable = 2,
  PacketTooLarge = 3,
  CapacityUnavailable = 4,
  RateLimited = 5,
  Conflict = 6,
  InternalUnavailable = 7,
}

export const FAILURE_CLASS_NAMES: Record<FailureClass, string> = {
  [FailureClass.InvalidRequest]: "invalidRequest",
  [FailureClass.UnsupportedProfile]: "unsupportedProfile",
  [FailureClass.TargetUnavailable]: "targetUnavailable",
  [FailureClass.PacketTooLarge]: "packetTooLarge",
  [FailureClass.CapacityUnavailable]: "capacityUnavailable",
  [FailureClass.RateLimited]: "rateLimited",
  [FailureClass.Conflict]: "conflict",
  [FailureClass.InternalUnavailable]: "internalUnavailable",
};

export enum HandleClass {
  Async = 0,
  FirstContact = 1,
}

export enum SettleAction {
  Complete = 0,
  Release = 1,
}

export enum SettleOutcome {
  Completed = 0,
  Released = 1,
  StaleClaim = 2,
  AttemptLimit = 3,
}

/** Deterministic-CBOR map labels (spec/v1/transport/labels.json). */
export const LABELS = {
  affiliateRequest: { stationDescriptorDigest: 0, affiliationCommitment: 1 },
  reserveRequest: {
    stationDescriptorDigest: 0,
    affiliationCommitment: 1,
    transportProfileId: 2,
    handleClass: 3,
  },
  retrieveRequest: { claimId: 0, claimEpoch: 1, itemId: 2 },
  claimRequest: { maxItems: 0 },
  settleRequest: { claimId: 0, claimEpoch: 1, settlements: 2 },
  settlement: { itemId: 0, settleAction: 1 },
  affiliateResponse: {
    outcome: 0,
    affiliationNotAfter: 1,
    stationAffiliationSignature: 2,
    failureClass: 3,
    retryAfterMs: 4,
  },
  reserveResponse: {
    outcome: 0,
    deliveryHandle: 1,
    handleClass: 2,
    serviceUntil: 3,
    stationServiceSignature: 4,
    failureClass: 5,
    retryAfterMs: 6,
  },
  submitResponse: { outcome: 0, failureClass: 1, retryAfterMs: 2 },
  claimResponse: {
    outcome: 0,
    claimId: 1,
    claimEpoch: 2,
    items: 3,
    failureClass: 4,
    retryAfterMs: 5,
  },
  claimedItem: { itemId: 0, protectedPacket: 1 },
  settleResponse: {
    outcome: 0,
    settlementResults: 1,
    failureClass: 2,
    retryAfterMs: 3,
  },
  settlementResult: { itemId: 0, settleOutcome: 1 },
} as const;

/** Admitted TLS 1.3 cipher suites (TLS names and Cloudflare OpenSSL names). */
export const ADMITTED_CIPHERS: readonly string[] = [
  "TLS_AES_128_GCM_SHA256",
  "TLS_AES_256_GCM_SHA384",
  "TLS_CHACHA20_POLY1305_SHA256",
  "AEAD-AES128-GCM-SHA256",
  "AEAD-AES256-GCM-SHA384",
  "AEAD-CHACHA20-POLY1305-SHA256",
];

export const MAX_PATH_BYTES = 128;
export const MAX_HEADER_BYTES = 2048;
