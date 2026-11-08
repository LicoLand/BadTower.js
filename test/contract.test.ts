/**
 * AC-001 Candidate contract: byte-exact corpus vectors, closed grammar,
 * fixed limits, and the pinned identity/digest/label/outcome constants.
 * Every malformed or over-bound vector must fail before any state callback
 * (these parsers are pure; a throw means no state was touched).
 */

import { describe, expect, it } from "vitest";
import { CborWriter, CborError, CborReader } from "../src/transport/cbor";
import {
  parseAffiliate,
  parseReserve,
  parseRetrieve,
  parseClaim,
  parseSettle,
  encodeSubmitAcceptedBody,
  encodeClaimAcceptedBody,
  encodeSettleAcceptedBody,
  encodeAffiliateFailureBody,
  encodeSubmitFailureBody,
  encodeReserveFailureBody,
  encodeClaimFailureBody,
  encodeSettleFailureBody,
} from "../src/transport/codec";
import {
  CLAIM_ID_HEADER,
  CLAIM_EPOCH_HEADER,
  CONTROL_MEDIA_TYPE,
  FAILURE_CLASS_HEADER,
  FAILURE_CLASS_NAMES,
  FailureClass,
  LIFECYCLE,
  MAX_CLAIM_ITEMS,
  MAX_CLAIM_RESPONSE_BYTES,
  MAX_CONTROL_BODY_BYTES,
  MAX_CONTROL_RESPONSE_BYTES,
  MAX_PACKET_BYTES,
  MAX_RETRY_AFTER_MS,
  MAX_SETTLEMENT_ITEMS,
  OPERATION_ID_HEADER,
  OPERATION_ID_HEX_LENGTH,
  OPERATIONS,
  OPERATION_SHAPES,
  OUTCOME_HEADER,
  OUTCOME_NAMES,
  Operation,
  Outcome,
  PROTOCOL_LINE_ID,
  PROTOCOL_MANIFEST_SHA256,
  PROTECTED_PACKET_MEDIA_TYPE,
  RETRY_AFTER_MS_HEADER,
  RETRY_AFTER_MS_HEADER_VALUE,
  TRANSPORT_PROFILE_ID,
  TRANSPORT_SOURCE_DIGEST,
  WIRE_ID,
} from "../src/transport/candidate";
import { statusFor } from "../src/durable/rpc";
import { fromHex, patternBytes, toHex } from "./helpers";

type Value =
  | { kind: "uint"; value: number }
  | { kind: "bytes"; value: Uint8Array }
  | { kind: "array"; values: Value[] }
  | { kind: "map"; entries: Array<[number, Value]> };

function u(value: number): Value {
  return { kind: "uint", value };
}

function b(value: Uint8Array): Value {
  return { kind: "bytes", value };
}

function arr(values: Value[]): Value {
  return { kind: "array", values };
}

function map(entries: Array<[number, Value]>): Value {
  return { kind: "map", entries };
}

function sizeOf(value: Value): number {
  switch (value.kind) {
    case "uint":
      return CborWriter.uintSize(value.value);
    case "bytes":
      return CborWriter.bytesSize(value.value);
    case "array": {
      let total = CborWriter.uintSize(value.values.length);
      for (const item of value.values) total += sizeOf(item);
      return total;
    }
    case "map": {
      let total = CborWriter.uintSize(value.entries.length);
      for (const [label, item] of value.entries) {
        total += CborWriter.uintSize(label) + sizeOf(item);
      }
      return total;
    }
  }
}

function write(writer: CborWriter, value: Value): void {
  switch (value.kind) {
    case "uint":
      writer.uint(value.value);
      return;
    case "bytes":
      writer.bytes(value.value);
      return;
    case "array":
      writer.arrayHeader(value.values.length);
      for (const item of value.values) write(writer, item);
      return;
    case "map":
      writer.mapHeader(value.entries.length);
      for (const [label, item] of value.entries) {
        writer.uint(label);
        write(writer, item);
      }
      return;
  }
}

function encodeControl(value: Value): Uint8Array {
  const writer = new CborWriter(sizeOf(value));
  write(writer, value);
  return writer.finish();
}

const ONES = patternBytes(0x01, 32);
const TWOS = patternBytes(0x02, 32);
const THREES = patternBytes(0x03, 32);
const FOURS = patternBytes(0x04, 32);
const FIVES = patternBytes(0x05, 32);

const VECTORS: Array<{ id: string; value: Value; expectedHex: string }> = [
  {
    id: "affiliate-control",
    value: map([[0, b(ONES)], [1, b(TWOS)]]),
    expectedHex:
      "a200582001010101010101010101010101010101010101010101010101010101010101010158200202020202020202020202020202020202020202020202020202020202020202",
  },
  {
    id: "reserve-control",
    value: map([[0, b(ONES)], [1, b(TWOS)], [2, b(THREES)], [3, u(0)]]),
    expectedHex:
      "a40058200101010101010101010101010101010101010101010101010101010101010101015820020202020202020202020202020202020202020202020202020202020202020202582003030303030303030303030303030303030303030303030303030303030303030300",
  },
  {
    id: "retrieve-control",
    value: map([[0, b(FOURS)], [1, u(1)], [2, b(FIVES)]]),
    expectedHex:
      "a3005820040404040404040404040404040404040404040404040404040404040404040401010258200505050505050505050505050505050505050505050505050505050505050505",
  },
  {
    id: "claim-control",
    value: map([[0, u(2)]]),
    expectedHex: "a10002",
  },
  {
    id: "settle-control",
    value: map([
      [0, b(FOURS)],
      [1, u(1)],
      [2, arr([map([[0, b(FIVES)], [1, u(0)]])])],
    ]),
    expectedHex:
      "a3005820040404040404040404040404040404040404040404040404040404040404040401010281a200582005050505050505050505050505050505050505050505050505050505050505050100",
  },
];

describe("corpus byte-exact request vectors", () => {
  it("encodes every valid control vector to the corpus hex", () => {
    for (const vector of VECTORS) {
      expect(toHex(encodeControl(vector.value))).toBe(vector.expectedHex);
    }
  });

  it("parses every valid vector into typed fields", () => {
    const affiliate = parseAffiliate(encodeControl(VECTORS[0]!.value));
    expect(toHex(affiliate.stationDescriptorDigest)).toBe(toHex(ONES));
    expect(toHex(affiliate.affiliationCommitment)).toBe(toHex(TWOS));

    const reserve = parseReserve(encodeControl(VECTORS[1]!.value));
    expect(toHex(reserve.transportProfileId)).toBe(toHex(THREES));
    expect(reserve.handleClass).toBe(0);

    const retrieve = parseRetrieve(encodeControl(VECTORS[2]!.value));
    expect(retrieve.claimEpoch).toBe(1);
    expect(toHex(retrieve.itemId)).toBe(toHex(FIVES));

    const claim = parseClaim(encodeControl(VECTORS[3]!.value));
    expect(claim.maxItems).toBe(2);

    const settle = parseSettle(encodeControl(VECTORS[4]!.value));
    expect(settle.settlements.length).toBe(1);
    expect(settle.settlements[0]!.action).toBe(0);
  });

  it("round-trips parse then re-encode to identical bytes", () => {
    for (const vector of VECTORS) {
      const raw = encodeControl(vector.value);
      let reparsed: Value;
      switch (vector.id) {
        case "affiliate-control": {
          const request = parseAffiliate(raw);
          reparsed = map([[0, b(request.stationDescriptorDigest)], [1, b(request.affiliationCommitment)]]);
          break;
        }
        case "reserve-control": {
          const request = parseReserve(raw);
          reparsed = map([
            [0, b(request.stationDescriptorDigest)],
            [1, b(request.affiliationCommitment)],
            [2, b(request.transportProfileId)],
            [3, u(request.handleClass)],
          ]);
          break;
        }
        case "retrieve-control": {
          const request = parseRetrieve(raw);
          reparsed = map([[0, b(request.claimId)], [1, u(request.claimEpoch)], [2, b(request.itemId)]]);
          break;
        }
        case "claim-control": {
          reparsed = map([[0, u(parseClaim(raw).maxItems)]]);
          break;
        }
        default: {
          const request = parseSettle(raw);
          reparsed = map([
            [0, b(request.claimId)],
            [1, u(request.claimEpoch)],
            [
              2,
              arr(request.settlements.map((item) => map([[0, b(item.itemId)], [1, u(item.action)]]))),
            ],
          ]);
          break;
        }
      }
      expect(toHex(encodeControl(reparsed))).toBe(vector.expectedHex);
    }
  });
});

describe("closed deterministic-CBOR grammar", () => {
  const malformed: Array<{ id: string; hex: string }> = [
    { id: "non-shortest-integer", hex: "a100180a" },
    { id: "duplicate-label", hex: "a200010002" },
    { id: "unknown-label", hex: "a200010202" },
    { id: "unordered-labels", hex: "a201020001" },
    { id: "trailing-bytes", hex: "a10002ff" },
    { id: "tag", hex: "c0a10002" },
    { id: "text-value", hex: "a1006101" },
    { id: "float-value", hex: "a100f93c00" },
    { id: "indefinite-map", hex: "bf0001ff" },
    { id: "truncated-map", hex: "a2" },
    { id: "unsafe-integer", hex: "1b001fffff00000000" },
    { id: "negative-integer", hex: "a10020" },
  ];

  it("rejects every malformed grammar vector with CborError", () => {
    for (const vector of malformed) {
      expect(() => parseAffiliate(fromHex(vector.hex)), vector.id).toThrow(CborError);
      expect(() => parseReserve(fromHex(vector.hex)), vector.id).toThrow(CborError);
      expect(() => parseClaim(fromHex(vector.hex)), vector.id).toThrow(CborError);
    }
  });

  it("rejects wrong field sizes and out-of-bound enums", () => {
    const wrongSize = map([[0, b(new Uint8Array(31))], [1, b(TWOS)]]);
    expect(() => parseAffiliate(encodeControl(wrongSize))).toThrow(CborError);
    const badClass = map([[0, b(ONES)], [1, b(TWOS)], [2, b(THREES)], [3, u(2)]]);
    expect(() => parseReserve(encodeControl(badClass))).toThrow(CborError);
    const badAction = map([[0, b(FOURS)], [1, u(1)], [2, arr([map([[0, b(FIVES)], [1, u(2)]])])]]);
    expect(() => parseSettle(encodeControl(badAction))).toThrow(CborError);
  });

  it("enforces claim and settlement bounds before any state callback", () => {
    expect(() => parseClaim(encodeControl(map([[0, u(0)]])))).toThrow(CborError);
    expect(() => parseClaim(encodeControl(map([[0, u(MAX_CLAIM_ITEMS + 1)]])))).toThrow(CborError);
    expect(() => parseSettle(encodeControl(map([[0, b(FOURS)], [1, u(1)], [2, arr([])]])))).toThrow(
      CborError,
    );
    expect(() =>
      parseSettle(
        encodeControl(
          map([[0, b(FOURS)], [1, u(1)], [2, arr(new Array(MAX_SETTLEMENT_ITEMS + 1).fill(map([[0, b(FIVES)], [1, u(0)]])))]]),
        ),
      ),
    ).toThrow(CborError);
    const duplicate = map([
      [0, b(FOURS)],
      [1, u(1)],
      [2, arr([map([[0, b(FIVES)], [1, u(0)]]), map([[0, b(FIVES)], [1, u(1)]])])],
    ]);
    expect(() => parseSettle(encodeControl(duplicate))).toThrow(CborError);
  });

  it("rejects trailing garbage inside settlement arrays", () => {
    const valid = encodeControl(
      map([
        [0, b(FOURS)],
        [1, u(1)],
        [2, arr([map([[0, b(FIVES)], [1, u(0)]])])],
      ]),
    );
    const withTrailingByte = new Uint8Array(valid.length + 1);
    withTrailingByte.set(valid);
    withTrailingByte[valid.length] = 0x00;
    expect(() => parseSettle(withTrailingByte)).toThrow(CborError);
  });
});

describe("response encoders are byte-exact and bounded", () => {
  it("encodes the accepted submit response", () => {
    expect(toHex(encodeSubmitAcceptedBody())).toBe("a10000");
  });

  it("encodes a claim response with claim id, epoch, and items", () => {
    const body = encodeClaimAcceptedBody(FOURS, 1, [{ itemId: FIVES, protectedPacket: fromHex("aabbccdd") }]);
    expect(body.length).toBeLessThanOrEqual(MAX_CLAIM_RESPONSE_BYTES);
    const parsed = new CborReader(body);
    expect(parsed.mapEntries().length).toBe(4);
  });

  it("encodes failure bodies with the failure class label", () => {
    expect(toHex(encodeSubmitFailureBody(Outcome.Rejected, { failureClass: FailureClass.Conflict }))).toBe(
      "a200010106",
    );
    expect(
      toHex(
        encodeSubmitFailureBody(Outcome.Transient, {
          failureClass: FailureClass.InternalUnavailable,
          retryAfterMs: RETRY_AFTER_MS_HEADER_VALUE,
        }),
      ),
    ).toBe("a300020107021903e8");
  });

  it("bounds every response body at 16384 bytes", () => {
    const oversized = patternBytes(0xaa, MAX_CLAIM_RESPONSE_BYTES + 1);
    expect(() => encodeClaimAcceptedBody(FOURS, 1, [{ itemId: FIVES, protectedPacket: oversized }])).toThrow(
      CborError,
    );
  });

  it("rejects out-of-bound retry values", () => {
    expect(() =>
      encodeSubmitFailureBody(Outcome.Transient, {
        failureClass: FailureClass.RateLimited,
        retryAfterMs: MAX_RETRY_AFTER_MS + 1,
      }),
    ).toThrow(CborError);
  });

  it("exposes every operation failure encoder shape without throwing", () => {
    expect(() =>
      encodeAffiliateFailureBody(Outcome.Rejected, { failureClass: FailureClass.UnsupportedProfile }),
    ).not.toThrow();
    expect(() =>
      encodeReserveFailureBody(Outcome.Rejected, { failureClass: FailureClass.UnsupportedProfile }),
    ).not.toThrow();
    expect(() =>
      encodeClaimFailureBody(Outcome.Rejected, { failureClass: FailureClass.TargetUnavailable }),
    ).not.toThrow();
    expect(() =>
      encodeSettleFailureBody(Outcome.Rejected, { failureClass: FailureClass.InternalUnavailable }),
    ).not.toThrow();
  });
});

describe("pinned identity, labels, and closed enums", () => {
  it("pins the Candidate wire identity and digests", () => {
    expect(WIRE_ID).toBe("licoarc.protocol-line.v1");
    expect(PROTOCOL_LINE_ID).toBe("licoarc.v1");
    expect(TRANSPORT_PROFILE_ID).toBe("licoarc.https-transport.v1");
    expect(LIFECYCLE).toBe("Candidate");
    expect(PROTOCOL_MANIFEST_SHA256).toBe("96688cc20ea8bcd4726fa33ced35a10ea12349e0a6d5abc23fb585197b06c503");
    expect(TRANSPORT_SOURCE_DIGEST).toBe("6d4636c983606fb266443a3ce05171a8af7ab5284e0ce301be7024ce16592cb5");
  });

  it("pins media types and header names", () => {
    expect(CONTROL_MEDIA_TYPE).toBe("application/licoarc-transport+cbor");
    expect(PROTECTED_PACKET_MEDIA_TYPE).toBe("application/licoarc-protected-packet");
    expect(OPERATION_ID_HEADER).toBe("licoarc-operation-id");
    expect(OUTCOME_HEADER).toBe("licoarc-outcome");
    expect(FAILURE_CLASS_HEADER).toBe("licoarc-failure-class");
    expect(RETRY_AFTER_MS_HEADER).toBe("licoarc-retry-after-ms");
    expect(CLAIM_ID_HEADER).toBe("licoarc-claim-id");
    expect(CLAIM_EPOCH_HEADER).toBe("licoarc-claim-epoch");
  });

  it("pins the six-operation surface with no alternate wire", () => {
    expect(OPERATIONS).toEqual([
      Operation.AFFILIATE,
      Operation.RESERVE,
      Operation.SUBMIT,
      Operation.RETRIEVE,
      Operation.CLAIM,
      Operation.SETTLE,
    ]);
    expect(Object.keys(OPERATION_SHAPES)).toEqual([
      "AFFILIATE",
      "RESERVE",
      "SUBMIT",
      "RETRIEVE",
      "CLAIM",
      "SETTLE",
    ]);
    const expected: Array<{ status: number; media: string; max: number }> = [
      { status: 201, media: CONTROL_MEDIA_TYPE, max: MAX_CONTROL_BODY_BYTES },
      { status: 201, media: CONTROL_MEDIA_TYPE, max: MAX_CONTROL_BODY_BYTES },
      { status: 202, media: PROTECTED_PACKET_MEDIA_TYPE, max: MAX_PACKET_BYTES },
      { status: 200, media: CONTROL_MEDIA_TYPE, max: MAX_CONTROL_BODY_BYTES },
      { status: 200, media: CONTROL_MEDIA_TYPE, max: MAX_CONTROL_BODY_BYTES },
      { status: 200, media: CONTROL_MEDIA_TYPE, max: MAX_CONTROL_BODY_BYTES },
    ];
    OPERATIONS.forEach((operation, index) => {
      const shape = OPERATION_SHAPES[operation];
      const want = expected[index]!;
      expect(shape.method).toBe("POST");
      expect(shape.acceptedStatus).toBe(want.status);
      expect(shape.requestMediaType).toBe(want.media);
      expect(shape.maxBodyBytes).toBe(want.max);
    });
  });

  it("pins outcome and failure name vocabularies", () => {
    expect(Object.keys(OUTCOME_NAMES)).toEqual(["0", "1", "2", "3"]);
    expect(OUTCOME_NAMES[Outcome.Accepted]).toBe("accepted");
    expect(OUTCOME_NAMES[Outcome.Rejected]).toBe("rejected");
    expect(OUTCOME_NAMES[Outcome.Transient]).toBe("transient");
    expect(OUTCOME_NAMES[Outcome.Ambiguous]).toBe("ambiguous");
    expect(Object.keys(FAILURE_CLASS_NAMES)).toEqual(["0", "1", "2", "3", "4", "5", "6", "7"]);
    expect(FAILURE_CLASS_NAMES[FailureClass.InvalidRequest]).toBe("invalidRequest");
    expect(FAILURE_CLASS_NAMES[FailureClass.UnsupportedProfile]).toBe("unsupportedProfile");
    expect(FAILURE_CLASS_NAMES[FailureClass.TargetUnavailable]).toBe("targetUnavailable");
    expect(FAILURE_CLASS_NAMES[FailureClass.PacketTooLarge]).toBe("packetTooLarge");
    expect(FAILURE_CLASS_NAMES[FailureClass.CapacityUnavailable]).toBe("capacityUnavailable");
    expect(FAILURE_CLASS_NAMES[FailureClass.RateLimited]).toBe("rateLimited");
    expect(FAILURE_CLASS_NAMES[FailureClass.Conflict]).toBe("conflict");
    expect(FAILURE_CLASS_NAMES[FailureClass.InternalUnavailable]).toBe("internalUnavailable");
  });

  it("maps outcomes to the fixed status vocabulary", () => {
    expect(statusFor(Outcome.Rejected, FailureClass.TargetUnavailable)).toBe(404);
    expect(statusFor(Outcome.Rejected, FailureClass.UnsupportedProfile)).toBe(406);
    expect(statusFor(Outcome.Rejected, FailureClass.Conflict)).toBe(409);
    expect(statusFor(Outcome.Rejected, FailureClass.PacketTooLarge)).toBe(413);
    expect(statusFor(Outcome.Rejected, FailureClass.InvalidRequest)).toBe(400);
    expect(statusFor(Outcome.Transient, FailureClass.RateLimited)).toBe(429);
    expect(statusFor(Outcome.Transient, FailureClass.CapacityUnavailable)).toBe(429);
    expect(statusFor(Outcome.Transient, FailureClass.InternalUnavailable)).toBe(503);
    expect(statusFor(Outcome.Ambiguous, FailureClass.InternalUnavailable)).toBe(504);
  });

  it("pins fixed bounds and the operation id shape", () => {
    expect(OPERATION_ID_HEX_LENGTH).toBe(32);
    expect(MAX_PACKET_BYTES).toBe(524288);
    expect(MAX_CONTROL_BODY_BYTES).toBe(16384);
    expect(MAX_CONTROL_RESPONSE_BYTES).toBe(16384);
    expect(MAX_CLAIM_RESPONSE_BYTES).toBe(33554432);
    expect(MAX_RETRY_AFTER_MS).toBe(60000);
    expect(RETRY_AFTER_MS_HEADER_VALUE).toBe(1000);
  });
});
