/**
 * BadTower Station Worker: the mailbox relay's public edge. It terminates
 * TLS, verifies the station admission credential in constant time, and
 * routes: the plugin listener on `/v1/mailbox`, the native mailbox
 * contract on `/v1/native/…`, revocation on `/v1/revoke`, the operator's
 * aggregate cost meters on `/v1/metrics`, and `/healthz`.
 * No request reaches a Durable Object before verification, and every
 * failure answers a bare status with the shared security headers.
 */
import {
  METRICS,
  REVOKE_BODY_BYTES,
  StationCredentials,
  emptyNoStore,
  handleNativeRequest,
  readBoundedBody,
  resolvePlan,
  secureResponse,
  toHex,
  type Operation,
  type PlanName,
} from "@badtower/station-core";
import { isMailboxUpgrade } from "@badtower/plugin-licoarc-mailbox";

export { Mailbox } from "./mailbox";

const BIND_NOT_AFTER_HEADER = "x-badtower-bind-not-after";

let credentials: StationCredentials | null = null;

function admission(env: Env): StationCredentials {
  credentials ??= new StationCredentials(
    env.BADTOWER_STATION_KEY,
    env.BADTOWER_METRICS_KEY,
  );
  return credentials;
}

function upgradeRequest(request: Request, notAfter: number): Request {
  const headers = new Headers(request.headers);
  headers.delete(BIND_NOT_AFTER_HEADER);
  headers.set(BIND_NOT_AFTER_HEADER, String(notAfter));
  return new Request(request.url, { method: request.method, headers });
}

/** The closed operation label every inbound request is metered under. */
function operationFor(method: string, pathname: string): Operation {
  if (method === "GET" && pathname === "/healthz") return "healthz";
  if (method === "GET" && pathname === "/v1/mailbox") return "mailbox_ws";
  if (method === "POST" && pathname === "/v1/revoke") return "revoke";
  if (method === "GET" && pathname === "/v1/metrics") return "metrics";
  const native = /^\/v1\/native\/(\w+)$/.exec(pathname)?.[1];
  if (
    native === "reserve" ||
    native === "submit" ||
    native === "claim" ||
    native === "settle" ||
    native === "capacity" ||
    native === "version"
  ) {
    return native;
  }
  return "other";
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    let plan: PlanName;
    try {
      // A plan/capacity combination the platform cannot honor fails
      // closed at the edge, not silently inside a mailbox.
      plan = resolvePlan(env).name;
    } catch {
      return secureResponse("station misconfigured\n", {
        status: 500,
        headers: { "Content-Type": "text/plain" },
      });
    }
    METRICS.workerRequest(operationFor(request.method, url.pathname), plan);
    const allowPlaintext = String(env.BADTOWER_ALLOW_PLAINTEXT);
    if (url.protocol !== "https:" && allowPlaintext !== "true") {
      return emptyNoStore(403);
    }
    if (request.method === "GET" && url.pathname === "/healthz") {
      return secureResponse("ok\n", { headers: { "Content-Type": "text/plain" } });
    }
    if (request.method === "GET" && url.pathname === "/v1/metrics") {
      if (!admission(env).verifyOperator(request.headers.get("Authorization"))) {
        return emptyNoStore(401);
      }
      return secureResponse(METRICS.export(plan), {
        headers: { "Content-Type": "text/plain; version=0.0.4" },
      });
    }
    if (request.method === "GET" && url.pathname === "/v1/mailbox") {
      if (!isMailboxUpgrade(request)) return emptyNoStore(400);
      const seen = await admission(env).verifyBearer(
        request.headers.get("Authorization"),
      );
      if (seen.kind === "bad") return emptyNoStore(401);
      const stub = env.MAILBOX.getByName(toHex(seen.mailboxId));
      const res = await stub.fetch(upgradeRequest(request, seen.notAfter));
      return res.status === 101 ? res : emptyNoStore(res.status);
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
} satisfies ExportedHandler<Env>;
