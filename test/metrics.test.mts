/**
 * The cost-metrics registry itself: bounded labels by construction,
 * deterministic text export, and a storage gauge whose internal
 * per-mailbox keys can never become a label.
 */
import { describe, expect, it } from "vitest";
import { CostMetrics } from "@badtower/station-core";

describe("CostMetrics", () => {
  it("exports recorded aggregates in closed label sets", () => {
    const m = new CostMetrics();
    m.workerRequest("submit", "free");
    m.workerRequest("submit", "free");
    m.doRequest("claim", "free");
    m.doActiveMs("claim", "free", 12);
    m.wsMessageIn("free");
    m.rowsRead("claim", 3, "free");
    m.rowsWritten("submit", 1, "free");
    m.observeStorage("mailbox-internal-key-a", 100);
    m.observeStorage("mailbox-internal-key-b", 50);
    m.observeStorage("mailbox-internal-key-a", 120); // replaces, does not add
    const text = m.export("free");
    expect(text).toContain('badtower_worker_requests_total{operation="submit",plan="free"} 2');
    expect(text).toContain('badtower_do_requests_total{operation="claim",plan="free"} 1');
    expect(text).toContain('badtower_do_active_ms_total{operation="claim",plan="free"} 12');
    expect(text).toContain('badtower_ws_messages_total{direction="in",plan="free"} 1');
    expect(text).toContain('badtower_rows_read_total{operation="claim",plan="free"} 3');
    expect(text).toContain('badtower_rows_written_total{operation="submit",plan="free"} 1');
    expect(text).toContain('badtower_sqlite_bytes{plan="free"} 170');
  });

  it("drops store operations outside the closed enumeration", () => {
    const m = new CostMetrics();
    m.rowsRead("a-mailbox-id-hex-is-not-an-operation", 5, "free");
    m.rowsWritten("192.0.2.1", 5, "free");
    const text = m.export("free");
    expect(text).not.toContain("a-mailbox-id-hex-is-not-an-operation");
    expect(text).not.toContain("192.0.2.1");
    expect(text).not.toContain("mailbox-internal-key");
  });
});
