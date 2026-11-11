/**
 * The `licoarc.mailbox.v1` WebSocket listener: exactly one protocol line,
 * no negotiation, no translation. The session owns the wire grammar —
 * CHALLENGE/HELLO/READY, SEND/RESULT, DELIVER/ACK, DRAINED — the Ed25519
 * device-signature binding, and its close codes; every storage decision
 * goes through the core store API and nothing else.
 *
 * All per-socket state lives in the WebSocket attachment so the object
 * stays hibernatable.
 */
import { CborError } from "./transport/cbor";
import {
  decodeClientFrame,
  encodeStationFrame,
  type ClientFrame,
  type StationFrame,
} from "./frames";
import {
  IN_FLIGHT_WINDOW,
  type MailboxStore,
  type SubmitResult,
} from "@badtower/station-core";

export const SUBPROTOCOL = "licoarc.mailbox.v1";
const HELLO_CONTEXT = "licoarc-mailbox-hello-v1";
const MAX_OUTSTANDING_SENDS = 16;
const CLOSE_MALFORMED = 1002;
const CLOSE_POLICY = 1008;
const CLOSE_SUPERSEDED = 4000;
const CLOSE_REVOKED = 4001;
const CLOSE_SUBJECT_MISMATCH = 4003;

const OUTCOME_ACCEPTED = 0;
const OUTCOME_REJECTED = 1;
const OUTCOME_TRANSIENT = 2;
const FAIL_TARGET_UNAVAILABLE = 1;
const FAIL_MAILBOX_FULL = 3;
const FAIL_INTERNAL_UNAVAILABLE = 4;

type Attachment =
  | { state: "challenged"; nonce: Uint8Array }
  | { state: "ready"; inflight: number[] };

export type LicoArcMailboxDeps = {
  ctx: DurableObjectState;
  store: MailboxStore;
  mailboxId(): Uint8Array;
  /** Route one packet to its target mailbox (first 16 handle bytes). */
  submitTo(target: Uint8Array, handle: Uint8Array, body: Uint8Array): Promise<SubmitResult>;
};

/** Whether a request is this listener's `/v1/mailbox` upgrade. */
export function isMailboxUpgrade(request: Request): boolean {
  if (request.headers.get("Upgrade") !== "websocket") return false;
  const protocols = request.headers.get("Sec-WebSocket-Protocol") ?? "";
  return protocols.split(",").map((part) => part.trim()).includes(SUBPROTOCOL);
}

function resultFrame(requestId: number, result: SubmitResult): StationFrame {
  const frame: StationFrame = {
    kind: "result",
    requestId,
    outcome: result.outcome === "accepted"
      ? OUTCOME_ACCEPTED
      : result.outcome === "rejected"
        ? OUTCOME_REJECTED
        : OUTCOME_TRANSIENT,
  };
  if (result.outcome !== "accepted") {
    frame.failureClass = result.reason === "target-unavailable"
      ? FAIL_TARGET_UNAVAILABLE
      : result.reason === "mailbox-full"
        ? FAIL_MAILBOX_FULL
        : FAIL_INTERNAL_UNAVAILABLE;
  }
  return frame;
}

export class LicoArcMailbox {
  private pendingSends = 0;

  constructor(private readonly deps: LicoArcMailboxDeps) {}

  private attachment(ws: WebSocket): Attachment {
    return ws.deserializeAttachment() as Attachment;
  }

  private send(ws: WebSocket, frame: StationFrame): void {
    try {
      ws.send(encodeStationFrame(frame));
    } catch {
      // A stale socket in getWebSockets() must not abort the caller (e.g.
      // a transient result after a durable insert); the undelivered
      // packet stays stored for the next live connection.
      this.close(ws, 1011);
    }
  }

  private close(ws: WebSocket, code: number): void {
    try {
      ws.close(code, "");
    } catch {
      // Already closed.
    }
  }

  /** Accept an admitted upgrade: issue the challenge on the new socket. */
  accept(): Response {
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.deps.ctx.acceptWebSocket(server, [SUBPROTOCOL]);
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    server.serializeAttachment({ state: "challenged", nonce } satisfies Attachment);
    this.send(server, { kind: "challenge", nonce });
    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: { "Sec-WebSocket-Protocol": SUBPROTOCOL },
    });
  }

  /** A packet landed in the mailbox: fill every ready socket's window. */
  notifyStored(): void {
    for (const ws of this.deps.ctx.getWebSockets()) {
      const attachment = this.attachment(ws);
      if (attachment.state === "ready") this.fill(ws, attachment);
    }
  }

  /** The mailbox was revoked: close every socket with the revoked code. */
  revoked(): void {
    for (const ws of this.deps.ctx.getWebSockets()) {
      this.close(ws, CLOSE_REVOKED);
    }
  }

  async onMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message === "string") {
      this.close(ws, CLOSE_MALFORMED);
      return;
    }
    let frame: ClientFrame;
    try {
      frame = decodeClientFrame(new Uint8Array(message));
    } catch (error) {
      this.close(ws, error instanceof CborError ? CLOSE_MALFORMED : CLOSE_POLICY);
      return;
    }
    const attachment = this.attachment(ws);
    try {
      if (attachment.state === "challenged") {
        await this.onChallenged(ws, attachment, frame);
      } else {
        await this.onReady(ws, attachment, frame);
      }
    } catch {
      this.close(ws, CLOSE_POLICY);
    }
  }

  private async onChallenged(
    ws: WebSocket,
    attachment: Attachment & { state: "challenged" },
    frame: ClientFrame,
  ): Promise<void> {
    if (frame.kind !== "hello") {
      this.close(ws, CLOSE_POLICY);
      return;
    }
    const payload = new Uint8Array(HELLO_CONTEXT.length + attachment.nonce.length);
    payload.set(new TextEncoder().encode(HELLO_CONTEXT), 0);
    payload.set(attachment.nonce, HELLO_CONTEXT.length);
    const key = await crypto.subtle.importKey(
      "raw",
      frame.deviceKey as BufferSource,
      "Ed25519",
      false,
      ["verify"],
    );
    const valid = await crypto.subtle.verify(
      "Ed25519",
      key,
      frame.signature as BufferSource,
      payload,
    );
    if (!valid) {
      this.close(ws, CLOSE_POLICY);
      return;
    }
    // The upgrade gate already proved the bind window; HELLO binds the
    // verified device key as this mailbox's opaque subject.
    const reserved = this.deps.store.reserve(
      frame.deviceKey,
      Number.MAX_SAFE_INTEGER,
    );
    if (reserved === "subject-mismatch") {
      this.close(ws, CLOSE_SUBJECT_MISMATCH);
      return;
    }
    if (reserved === "revoked") {
      this.close(ws, CLOSE_REVOKED);
      return;
    }
    if (reserved !== "bound") {
      this.close(ws, CLOSE_POLICY);
      return;
    }
    ws.serializeAttachment({ state: "ready", inflight: [] } satisfies Attachment);
    for (const other of this.deps.ctx.getWebSockets()) {
      if (other !== ws && this.attachment(other).state === "ready") {
        this.close(other, CLOSE_SUPERSEDED);
      }
    }
    this.send(ws, { kind: "ready", mailboxId: this.deps.mailboxId() });
    this.fill(ws, { state: "ready", inflight: [] });
  }

  private async onReady(
    ws: WebSocket,
    attachment: Attachment & { state: "ready" },
    frame: ClientFrame,
  ): Promise<void> {
    switch (frame.kind) {
      case "send": {
        // The object stays active while awaiting the store RPC, so an
        // in-memory counter bounds outstanding SENDs exactly.
        const pending = this.pendingSends++;
        if (pending >= MAX_OUTSTANDING_SENDS) {
          this.pendingSends -= 1;
          this.close(ws, CLOSE_POLICY);
          return;
        }
        try {
          const result = await this.deps.submitTo(
            frame.handle.slice(0, 16),
            frame.handle,
            frame.packet,
          );
          this.send(ws, resultFrame(frame.requestId, result));
        } catch {
          this.send(ws, {
            kind: "result",
            requestId: frame.requestId,
            outcome: OUTCOME_TRANSIENT,
            failureClass: FAIL_INTERNAL_UNAVAILABLE,
          });
        } finally {
          this.pendingSends -= 1;
        }
        return;
      }
      case "ack": {
        this.deps.store.settle([frame.sequence]);
        attachment.inflight = attachment.inflight.filter(
          (sequence) => sequence !== frame.sequence,
        );
        ws.serializeAttachment(attachment);
        this.fill(ws, attachment);
        return;
      }
      default:
        this.close(ws, CLOSE_POLICY);
    }
  }

  private fill(ws: WebSocket, attachment: Attachment & { state: "ready" }): void {
    const room = IN_FLIGHT_WINDOW - attachment.inflight.length;
    if (room > 0) {
      const packets = this.deps.store.claim(attachment.inflight, room) ?? [];
      for (const packet of packets) {
        this.send(ws, {
          kind: "deliver",
          sequence: packet.sequence,
          handle: packet.handle,
          packet: packet.body,
        });
        attachment.inflight.push(packet.sequence);
      }
      if (attachment.inflight.length > 0) ws.serializeAttachment(attachment);
    }
    if (attachment.inflight.length === 0 && !this.deps.store.hasPending()) {
      this.send(ws, { kind: "drained" });
    }
  }
}
