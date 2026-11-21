/**
 * The composed Mailbox durable object: one permanent mailbox per station
 * mailbox id. Storage, queue and ownership semantics live in the core
 * store; the `licoarc.mailbox.v1` listener lives in the plugin session
 * hosted here. This class is the only place that wires the two together —
 * core never sees a frame, the plugin never sees a table.
 *
 * Every public operation is metered into the shared aggregate registry:
 * request counts, active milliseconds and store row/storage figures —
 * never a mailbox id, handle, subject or any content.
 */
import { DurableObject } from "cloudflare:workers";
import {
  MailboxStore,
  METRICS,
  emptyNoStore,
  hexToBytes,
  resolvePlan,
  toHex,
  type Operation,
  type Packet,
  type PlanName,
  type ReserveResult,
  type StoreMeter,
  type SubmitResult,
} from "@badtower/station-core";
import { LicoArcMailbox } from "@badtower/plugin-licoarc-mailbox";

const BIND_NOT_AFTER_HEADER = "x-badtower-bind-not-after";

export class Mailbox extends DurableObject<Env> {
  private readonly store: MailboxStore;
  private readonly licoarc: LicoArcMailbox;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // An unsafe plan/capacity combination refuses the object outright;
    // the configured capacity is re-read lazily so it cannot go stale
    // inside a long-lived object.
    resolvePlan(env);
    const meter: StoreMeter = {
      rowsRead: (operation, count) =>
        METRICS.rowsRead(operation, count, this.planName()),
      rowsWritten: (operation, count) =>
        METRICS.rowsWritten(operation, count, this.planName()),
      observeStorage: (bytes) =>
        METRICS.observeStorage(this.ctx.id.toString(), bytes),
    };
    this.store = new MailboxStore(ctx, {
      capacityBytes: () => resolvePlan(this.env).mailboxCapacityBytes,
      meter,
    });
    this.licoarc = new LicoArcMailbox({
      ctx,
      store: this.store,
      mailboxId: () => this.mailboxId(),
      submitTo: (target, handle, body) => this.submitToMailbox(target, handle, body),
    });
  }

  private planName(): PlanName {
    return resolvePlan(this.env).name;
  }

  /** Record a Durable Object request and the active time it spent. */
  private async timed<T>(operation: Operation, fn: () => Promise<T> | T): Promise<T> {
    const started = Date.now();
    METRICS.doRequest(operation, this.planName());
    try {
      return await fn();
    } finally {
      METRICS.doActiveMs(operation, this.planName(), Date.now() - started);
    }
  }

  private mailboxId(): Uint8Array {
    const id = hexToBytes(this.ctx.id.name ?? "");
    if (id === null || id.length !== 16) throw new Error("mailbox id mismatch");
    return id;
  }

  private submitToMailbox(
    target: Uint8Array,
    handle: Uint8Array,
    body: Uint8Array,
  ): Promise<SubmitResult> {
    return this.env.MAILBOX.getByName(toHex(target)).submit(handle, body);
  }

  override async fetch(request: Request): Promise<Response> {
    return this.timed("mailbox_ws", async () => {
      const raw = Number(request.headers.get(BIND_NOT_AFTER_HEADER) ?? "0");
      // A malformed bind deadline fails safe: an unbound mailbox refuses;
      // a bound subject still only faces its subject check.
      const notAfter = Number.isFinite(raw) ? raw : 0;
      if (this.store.canBind(notAfter) === "closed") return emptyNoStore(403);
      return this.licoarc.accept(notAfter);
    });
  }

  override async webSocketMessage(
    ws: WebSocket,
    message: string | ArrayBuffer,
  ): Promise<void> {
    const started = Date.now();
    METRICS.wsMessageIn(this.planName());
    try {
      await this.licoarc.onMessage(ws, message);
    } finally {
      METRICS.doActiveMs("mailbox_ws", this.planName(), Date.now() - started);
    }
  }

  /** Station→station RPC: store one packet in this mailbox. */
  async submit(handle: Uint8Array, body: Uint8Array): Promise<SubmitResult> {
    return this.timed("submit", () => {
      const result = this.store.submit(handle, body);
      if (result.outcome === "accepted") this.licoarc.notifyStored();
      return result;
    });
  }

  /** Native binding RPC: reserve this mailbox for an opaque subject. */
  async reserve(subject: Uint8Array, notAfter: number): Promise<ReserveResult> {
    return this.timed("reserve", () => this.store.reserve(subject, notAfter, "native"));
  }

  /** Native binding RPC: claim stored packets in replay order. */
  async claim(excludeSequences: number[], limit: number): Promise<Packet[] | null> {
    return this.timed("claim", () => this.store.nativeClaim(excludeSequences, limit));
  }

  /** Native binding RPC: settle stored packets by sequence. */
  async settle(sequences: number[]): Promise<boolean> {
    return this.timed("settle", () => this.store.nativeSettle(sequences));
  }

  /** Native binding RPC: capacity usage for this mailbox. */
  async capacityInfo(): Promise<{
    bound: boolean;
    capacityBytes: number;
    databaseBytes: number;
  }> {
    return this.timed("capacity", () => this.store.nativeCapacityInfo());
  }

  /** Ops RPC: destroy the mailbox and refuse it forever. */
  async revoke(): Promise<void> {
    return this.timed("revoke", async () => {
      await this.store.revoke();
      this.licoarc.revoked();
    });
  }
}
