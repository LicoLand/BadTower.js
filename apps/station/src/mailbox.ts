/**
 * The composed Mailbox durable object: one permanent mailbox per station
 * mailbox id. Storage, queue and ownership semantics live in the core
 * store; the `licoarc.mailbox.v1` listener lives in the plugin session
 * hosted here. This class is the only place that wires the two together —
 * core never sees a frame, the plugin never sees a table.
 */
import { DurableObject } from "cloudflare:workers";
import {
  MailboxStore,
  emptyNoStore,
  hexToBytes,
  toHex,
  type Packet,
  type ReserveResult,
  type SubmitResult,
} from "@badtower/station-core";
import { LicoArcMailbox } from "@badtower/plugin-licoarc-mailbox";

const BIND_NOT_AFTER_HEADER = "x-badtower-bind-not-after";

export class Mailbox extends DurableObject<Env> {
  private readonly store: MailboxStore;
  private readonly licoarc: LicoArcMailbox;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.store = new MailboxStore(ctx, {
      capacityBytes: () => this.capacityBytes(),
    });
    this.licoarc = new LicoArcMailbox({
      ctx,
      store: this.store,
      mailboxId: () => this.mailboxId(),
      submitTo: (target, handle, body) => this.submitToMailbox(target, handle, body),
    });
  }

  private capacityBytes(): number {
    return Number(this.env.BADTOWER_MAILBOX_CAPACITY_BYTES ?? "1000000000");
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
    const raw = Number(request.headers.get(BIND_NOT_AFTER_HEADER) ?? "0");
    // A malformed bind deadline fails safe: an unbound mailbox refuses;
    // a bound subject still only faces its subject check.
    const notAfter = Number.isFinite(raw) ? raw : 0;
    if (this.store.canBind(notAfter) === "closed") return emptyNoStore(403);
    return this.licoarc.accept();
  }

  override async webSocketMessage(
    ws: WebSocket,
    message: string | ArrayBuffer,
  ): Promise<void> {
    await this.licoarc.onMessage(ws, message);
  }

  /** Station→station RPC: store one packet in this mailbox. */
  async submit(handle: Uint8Array, body: Uint8Array): Promise<SubmitResult> {
    const result = this.store.submit(handle, body);
    if (result.outcome === "accepted") this.licoarc.notifyStored();
    return result;
  }

  /** Native binding RPC: reserve this mailbox for an opaque subject. */
  async reserve(subject: Uint8Array, notAfter: number): Promise<ReserveResult> {
    return this.store.reserve(subject, notAfter);
  }

  /** Native binding RPC: claim stored packets in replay order. */
  async claim(excludeSequences: number[], limit: number): Promise<Packet[] | null> {
    return this.store.claim(excludeSequences, limit);
  }

  /** Native binding RPC: settle stored packets by sequence. */
  async settle(sequences: number[]): Promise<boolean> {
    return this.store.settle(sequences);
  }

  /** Native binding RPC: capacity usage for this mailbox. */
  async capacityInfo(): Promise<{
    bound: boolean;
    capacityBytes: number;
    databaseBytes: number;
  }> {
    return this.store.capacityInfo();
  }

  /** Ops RPC: destroy the mailbox and refuse it forever. */
  async revoke(): Promise<void> {
    await this.store.revoke();
    this.licoarc.revoked();
  }
}
