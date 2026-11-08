import { handleOperatorServiceRequest } from "./access/operator-service";
import { emptyNoStore } from "./http";
import { emitEvent } from "./observability";

const GRANT_PATH = /^\/v1\/operator\/grants\/[A-Za-z0-9_-]{22}$/;

function operatorPath(path: string): boolean {
  return path === "/readyz" || path === "/v1/operator/invitations" || GRANT_PATH.test(path);
}

/** Consume only a fixed edge allow result; never retain upstream identity. */
function edgeAuthorized(request: Request, env: Env): boolean {
  const url = new URL(request.url);
  if (
    String(env.BADTOWER_RUNTIME_MODE) === "local" &&
    url.protocol === "http:" &&
    (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]")
  ) {
    return true;
  }
  const configured = (env as unknown as { BADTOWER_EDGE_AUTHORIZATION?: unknown })
    .BADTOWER_EDGE_AUTHORIZATION;
  if (configured !== "mtls") return false;
  const tls = (request as Request & {
    cf?: {
      tlsClientAuth?: {
        certPresented?: unknown;
        certVerified?: unknown;
        certRevoked?: unknown;
      };
    };
  }).cf?.tlsClientAuth;
  return (
    tls !== null &&
    typeof tls === "object" &&
    tls.certPresented === "1" &&
    tls.certVerified === "SUCCESS" &&
    tls.certRevoked === "0"
  );
}

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.search !== "" || url.hash !== "" || !operatorPath(url.pathname)) {
    emitEvent({ event: "management", outcome: "rejected", failure: "invalidRequest" });
    return emptyNoStore(404);
  }
  if (!edgeAuthorized(request, env)) {
    emitEvent({ event: "management", outcome: "rejected", failure: "unauthorized" });
    return emptyNoStore(404);
  }
  const response = await handleOperatorServiceRequest(request, env);
  if (response === null) {
    emitEvent({ event: "management", outcome: "rejected", failure: "invalidRequest" });
    return emptyNoStore(404);
  }
  emitEvent({
    event: "management",
    outcome: response.ok ? "completed" : "rejected",
    ...(response.status === 401 || response.status === 404 ? { failure: "unauthorized" as const } : {}),
  });
  return response;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handleRequest(request, env);
    } catch {
      emitEvent({ event: "management", outcome: "transient", failure: "internalUnavailable" });
      return emptyNoStore(503);
    }
  },
};
