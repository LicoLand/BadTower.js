/**
 * Core-only verification harness: a minimal station Worker composed of
 * station-core and nothing else — no compatibility listener, no frames,
 * no subprotocol strings. It exists to prove the native contract
 * (Reserve → Submit → Claim → Settle, health, capacity, revoke) is
 * usable end to end without any plugin.
 */
import { DurableObject } from "cloudflare:workers";
import {
  MailboxStore,
  REVOKE_BODY_BYTES,
  StationCredentials,
  emptyNoStore,
  handleNativeRequest,
  readBoundedBody,
  resolvePlan,
  secureResponse,
  toHex,
  type Packet,
  type ReserveResult,
  type SubmitResult,
} from "@badtower/station-core";

export type HarnessEnv = {
  BADTOWER_STATION_KEY: string;
  BADTOWER_MAILBOX_CAPACITY_BYTES: string;
  BADTOWER_ALLOW_PLAINTEXT: string;
  BADTOWER_PLAN?: string;
  MAILBOX: DurableObjectNamespace<CoreMailbox>;
};

export class CoreMailbox extends DurableObject<HarnessEnv> {
  private readonly store = new MailboxStore(this.ctx, {
    capacityBytes: () => resolvePlan(this.env).mailboxCapacityBytes,
  });

  constructor(ctx: DurableObjectState, env: HarnessEnv) {
    super(ctx, env);
    resolvePlan(env); // refuse an unsafe plan/capacity pair at startup
  }

  async submit(handle: Uint8Array, body: Uint8Array): Promise<SubmitResult> {
    return this.store.submit(handle, body);
  }

  async reserve(subject: Uint8Array, notAfter: number): Promise<ReserveResult> {
    return this.store.reserve(subject, notAfter);
  }

  async claim(excludeSequences: number[], limit: number): Promise<Packet[] | null> {
    return this.store.claim(excludeSequences, limit);
  }

  async settle(sequences: number[]): Promise<boolean> {
    return this.store.settle(sequences);
  }

  async capacityInfo(): Promise<{
    bound: boolean;
    capacityBytes: number;
    databaseBytes: number;
  }> {
    return this.store.capacityInfo();
  }

  async revoke(): Promise<void> {
    await this.store.revoke();
  }
}

let credentials: StationCredentials | null = null;

function admission(env: HarnessEnv): StationCredentials {
  credentials ??= new StationCredentials(env.BADTOWER_STATION_KEY);
  return credentials;
}

export default {
  async fetch(request: Request, env: HarnessEnv): Promise<Response> {
    const url = new URL(request.url);
    try {
      resolvePlan(env);
    } catch {
      return secureResponse("station misconfigured\n", {
        status: 500,
        headers: { "Content-Type": "text/plain" },
      });
    }
    const allowPlaintext = String(env.BADTOWER_ALLOW_PLAINTEXT);
    if (url.protocol !== "https:" && allowPlaintext !== "true") {
      return emptyNoStore(403);
    }
    if (request.method === "GET" && url.pathname === "/healthz") {
      return secureResponse("ok\n", { headers: { "Content-Type": "text/plain" } });
    }
    if (request.method === "POST" && url.pathname === "/v1/revoke") {
      if (request.headers.get("Content-Type") !== "application/octet-stream") {
        return emptyNoStore(400);
      }
      const body = await readBoundedBody(request, REVOKE_BODY_BYTES + 1);
      if (body.kind !== "ok") return emptyNoStore(401);
      const mailboxId = await admission(env).verifyRevocation(body.bytes);
      if (mailboxId === null) return emptyNoStore(401);
      await env.MAILBOX.getByName(toHex(mailboxId)).revoke();
      return emptyNoStore(204);
    }
    if (url.pathname.startsWith("/v1/native/")) {
      const seen = await admission(env).verifyBearer(
        request.headers.get("Authorization"),
      );
      if (seen.kind === "bad") return emptyNoStore(401);
      const res = await handleNativeRequest(request, seen, (mailboxId) =>
        env.MAILBOX.getByName(toHex(mailboxId)));
      return res ?? emptyNoStore(404);
    }
    return emptyNoStore(404);
  },
} satisfies ExportedHandler<HarnessEnv>;
