import { afterEach, describe, expect, it, vi } from "vitest";
import { emitEvent } from "../src/observability";
import { Operation } from "../src/transport/candidate";

afterEach(() => vi.restoreAllMocks());

describe("closed observability schema", () => {
  it("emits only closed categorical fields and coarse counts", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    emitEvent({
      event: "operation",
      operation: Operation.CLAIM,
      outcome: "completed",
      count: 2,
    });
    expect(JSON.parse(String(log.mock.calls[0]?.[0]))).toEqual({
      schemaVersion: 1,
      event: "operation",
      operation: "CLAIM",
      outcome: "completed",
      count: 2,
    });
  });

  it.each([-1, 1.5, 10_001])("rejects unsafe aggregate %s", (count) => {
    expect(() => emitEvent({ event: "admission", outcome: "rejected", count })).toThrow();
  });

  it("rejects values outside every closed category", () => {
    expect(() => emitEvent({ event: "request-derived" as never, outcome: "rejected" })).toThrow();
    expect(() => emitEvent({ event: "operation", operation: "request-derived" as never, outcome: "completed" })).toThrow();
    expect(() => emitEvent({ event: "operation", outcome: "request-derived" as never })).toThrow();
    expect(() => emitEvent({ event: "operation", outcome: "rejected", failure: "request-derived" as never })).toThrow();
  });
});
