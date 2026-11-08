export type BodyRead =
  | { kind: "ok"; bytes: Uint8Array }
  | { kind: "too-large" }
  | { kind: "read-error" };

const SECURITY_HEADERS = {
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
} as const;

/**
 * Construct the only kind of response that may cross a BadTower Worker
 * ingress. Callers may add closed protocol headers, but cannot weaken the
 * cache, referrer, content-sniffing, or CORS boundary.
 */
export function secureResponse(
  body: BodyInit | null,
  init: ResponseInit = {},
): Response {
  const headers = new Headers(init.headers);
  headers.delete("Access-Control-Allow-Origin");
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    headers.set(name, value);
  }
  return new Response(body, { ...init, headers });
}

export async function readBoundedBody(request: Request, maxBytes: number): Promise<BodyRead> {
  if (request.body === null) return { kind: "ok", bytes: new Uint8Array(0) };
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxBytes) {
        await reader.cancel();
        return { kind: "too-large" };
      }
      chunks.push(value);
    }
  } catch {
    try {
      await reader.cancel();
    } catch {
      // The request already failed; cancellation is best-effort.
    }
    return { kind: "read-error" };
  }
  const bytes = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, at);
    at += chunk.length;
  }
  return { kind: "ok", bytes };
}

export function jsonNoStore(value: unknown, status = 200): Response {
  return secureResponse(JSON.stringify(value), {
    status,
    headers: {
      "Content-Type": "application/json",
    },
  });
}

export function emptyNoStore(status: number): Response {
  return secureResponse(null, { status });
}
