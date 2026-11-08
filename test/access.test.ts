import { env } from "cloudflare:workers";
import { runDurableObjectAlarm } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";
import {
  formatOperatorToken,
  formatInvitationToken,
  parseCapabilityKeyring,
  randomBytes,
  sha256,
} from "../src/access/token";
import { toBase64Url } from "../src/encoding";
import { CONTROL_MEDIA_TYPE, OPERATION_ID_HEADER } from "../src/transport/candidate";
import { HandleClass } from "../src/transport/candidate";
import {
  encodeReserveRequest,
  generateClientProofKey,
  opRequest,
  randomOpId,
  registerProofKey,
  VALID_CF,
} from "./helpers";

import dataHandler from "../src/data-entry";
import operatorHandler from "../src/operator-entry";

function jsonRequest(path: string, body: unknown): Request {
  const text = JSON.stringify(body);
  return new Request(`https://station.invalid${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "content-length": String(new TextEncoder().encode(text).length),
    },
    body: text,
  });
}

async function invitation(): Promise<{
  token: string;
  selector: string;
}> {
  const selectorBytes = randomBytes(16);
  const selector = toBase64Url(selectorBytes);
  const now = Date.now();
  const expiresAt = now + 60 * 60 * 1000;
  const keyring = parseCapabilityKeyring((env as unknown as Record<string, unknown>).BADTOWER_CAPABILITY_KEYS);
  if (keyring === null) throw new Error("missing synthetic capability keyring");
  const token = await formatInvitationToken(selectorBytes, expiresAt, keyring);
  const initialized = await env.ACCESS_GRANTS.getByName(selector).initialize(
    await sha256(new TextEncoder().encode(token)),
    expiresAt,
    24 * 60 * 60 * 1000,
  );
  expect(initialized).toBe(true);
  return { token, selector };
}

function operatorRequest(path: string, authorization: string, init: RequestInit = {}): Request {
  return new Request(`http://localhost${path}`, {
    ...init,
    headers: { ...Object.fromEntries(new Headers(init.headers).entries()), authorization },
  });
}

describe("public access lifecycle", () => {
  it("requires a verified, unrevoked mTLS client certificate in production", async () => {
    const operatorSecret = randomBytes(32);
    const authorization = `Bearer ${formatOperatorToken(operatorSecret)}`;
    const record = env as unknown as Record<string, unknown>;
    const realDigest = record.BADTOWER_OPERATOR_TOKEN_DIGEST;
    const realMode = record.BADTOWER_RUNTIME_MODE;
    const realEdge = record.BADTOWER_EDGE_AUTHORIZATION;
    record.BADTOWER_RUNTIME_MODE = "production";
    record.BADTOWER_EDGE_AUTHORIZATION = "mtls";
    record.BADTOWER_OPERATOR_TOKEN_DIGEST = Array.from(
      await sha256(operatorSecret),
      (byte) => byte.toString(16).padStart(2, "0"),
    ).join("");
    const request = (tlsClientAuth?: Record<string, string>) => new Request(
      "https://operator.invalid/readyz",
      {
        headers: { authorization },
        ...(tlsClientAuth === undefined ? {} : { cf: { tlsClientAuth } }),
      },
    );
    try {
      const allowed = await operatorHandler.fetch(request({
        certPresented: "1",
        certVerified: "SUCCESS",
        certRevoked: "0",
      }), env);
      expect(allowed.status).toBe(200);
      expect((await operatorHandler.fetch(request(), env)).status).toBe(404);
      expect((await operatorHandler.fetch(request({
        certPresented: "1",
        certVerified: "SUCCESS",
        certRevoked: "1",
      }), env)).status).toBe(404);
    } finally {
      record.BADTOWER_OPERATOR_TOKEN_DIGEST = realDigest;
      record.BADTOWER_RUNTIME_MODE = realMode;
      record.BADTOWER_EDGE_AUTHORIZATION = realEdge;
    }
  });

  it("lets the operator create, inspect, and revoke one invitation without listing grants", async () => {
    const operatorSecret = randomBytes(32);
    const record = env as unknown as Record<string, unknown>;
    const realDigest = record.BADTOWER_OPERATOR_TOKEN_DIGEST;
    const realMode = record.BADTOWER_RUNTIME_MODE;
    // Operator digests are lowercase hexadecimal.
    record.BADTOWER_RUNTIME_MODE = "local";
    record.BADTOWER_OPERATOR_TOKEN_DIGEST = Array.from(
      await sha256(operatorSecret),
      (byte) => byte.toString(16).padStart(2, "0"),
    ).join("");
    const authorization = `Bearer ${formatOperatorToken(operatorSecret)}`;
    try {
      const created = await operatorHandler.fetch(
        operatorRequest("/v1/operator/invitations", authorization, {
          method: "POST",
          headers: {
            authorization,
            "content-type": "application/json",
            "content-length": "2",
          },
          body: "{}",
        }),
        env,
      );
      expect(created.status).toBe(201);
      const body = await created.json<{ invitation: string; invitationId: string }>();
      expect(body.invitation).toMatch(/^bti2\.[A-Za-z0-9_-]+$/);

      const status = await operatorHandler.fetch(
        operatorRequest(`/v1/operator/grants/${body.invitationId}`, authorization),
        env,
      );
      expect(status.status).toBe(200);
      expect(await status.json()).toMatchObject({ state: "invited" });

      const revoked = await operatorHandler.fetch(
        operatorRequest(`/v1/operator/grants/${body.invitationId}`, authorization, {
          method: "DELETE",
        }),
        env,
      );
      expect(revoked.status).toBe(204);

      const client = generateClientProofKey();
      const denied = await dataHandler.fetch(
        jsonRequest("/v1/invitations/exchange", {
          invitation: body.invitation,
          clientPublicKey: toBase64Url(client.publicKey),
        }),
        env,
      );
      expect(denied.status).toBe(401);
    } finally {
      record.BADTOWER_OPERATOR_TOKEN_DIGEST = realDigest;
      record.BADTOWER_RUNTIME_MODE = realMode;
    }
  });

  it("exchanges an invitation once and returns a retry-stable access token", async () => {
    const invite = await invitation();
    const client = generateClientProofKey();
    const clientPublicKey = toBase64Url(client.publicKey);
    const sensitiveKeys: string[] = [];
    const isolated = new Proxy(env, {
      get(target, property, receiver) {
        if (property === "SENSITIVE_RATE_LIMITER") {
          return { limit: async ({ key }: { key: string }) => {
            sensitiveKeys.push(key);
            return { success: true };
          } };
        }
        return Reflect.get(target, property, receiver);
      },
    });
    const unauthenticated = await dataHandler.fetch(
      jsonRequest("/v1/invitations/exchange", {
        invitation: "malformed",
        clientPublicKey,
      }),
      isolated,
    );
    expect(unauthenticated.status).toBe(401);
    expect(sensitiveKeys).toEqual([]);
    const first = await dataHandler.fetch(
      jsonRequest("/v1/invitations/exchange", {
        invitation: invite.token,
        clientPublicKey,
      }),
      isolated,
    );
    expect(first.status).toBe(200);
    expect(sensitiveKeys).toEqual([`exchange:${invite.selector}`]);
    expect(first.headers.get("cache-control")).toBe("no-store");
    const firstBody = await first.json<{ accessToken: string; expiresAt: string }>();
    expect(firstBody.accessToken).toMatch(/^bta2\.[A-Za-z0-9_-]+$/);
    expect(Number.isNaN(Date.parse(firstBody.expiresAt))).toBe(false);

    const retry = await dataHandler.fetch(
      jsonRequest("/v1/invitations/exchange", {
        invitation: invite.token,
        clientPublicKey,
      }),
      env,
    );
    expect(retry.status).toBe(200);
    const retryBody = await retry.json<{ accessToken: string }>();
    expect(retryBody.accessToken).toBe(firstBody.accessToken);

    const secondClient = await dataHandler.fetch(
      jsonRequest("/v1/invitations/exchange", {
        invitation: invite.token,
        clientPublicKey: toBase64Url(generateClientProofKey().publicKey),
      }),
      env,
    );
    expect(secondClient.status).toBe(401);
    expect((await secondClient.arrayBuffer()).byteLength).toBe(0);

    registerProofKey(firstBody.accessToken, client.privateKey);
    const reserve = await dataHandler.fetch(
      opRequest("/v1/reserve", {
        token: firstBody.accessToken,
        headers: {
          "content-type": CONTROL_MEDIA_TYPE,
          [OPERATION_ID_HEADER]: randomOpId(),
        },
        body: encodeReserveRequest(
          randomBytes(32),
          randomBytes(32),
          randomBytes(32),
          HandleClass.FirstContact,
        ),
        cf: VALID_CF,
      }),
      env,
    );
    expect(reserve.status).not.toBe(401);
  });

  it("denies malformed, unknown, expired, and revoked grants identically", async () => {
    const invite = await invitation();
    const client = generateClientProofKey();
    const exchanged = await dataHandler.fetch(
      jsonRequest("/v1/invitations/exchange", { invitation: invite.token, clientPublicKey: toBase64Url(client.publicKey) }),
      env,
    );
    const { accessToken } = await exchanged.json<{ accessToken: string }>();
    registerProofKey(accessToken, client.privateKey);
    await env.ACCESS_GRANTS.getByName(invite.selector).revoke();

    const reserveBody = encodeReserveRequest(randomBytes(32), randomBytes(32), randomBytes(32), HandleClass.FirstContact);
    const requestFor = (token: string) => opRequest("/v1/reserve", {
      token,
      headers: { "content-type": CONTROL_MEDIA_TYPE, [OPERATION_ID_HEADER]: randomOpId() },
      body: reserveBody,
      cf: VALID_CF,
    });
    const requests = [
      requestFor("malformed"),
      requestFor(`${accessToken.slice(0, -1)}${accessToken.endsWith("A") ? "B" : "A"}`),
      requestFor(accessToken),
    ];
    for (const request of requests) {
      const response = await dataHandler.fetch(request, env);
      expect(response.status).toBe(401);
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect((await response.arrayBuffer()).byteLength).toBe(0);
    }
  });

  it("expires invitations and removes their Durable Object storage", async () => {
    const selectorBytes = randomBytes(16);
    const selector = toBase64Url(selectorBytes);
    const secret = randomBytes(32);
    const now = Date.now();
    const grant = env.ACCESS_GRANTS.getByName(selector);
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    try {
      expect(await grant.initialize(
        await sha256(secret),
        now + 5 * 60 * 1000,
        60 * 60 * 1000,
      )).toBe(true);
      clock.mockReturnValue(now + 5 * 60 * 1000);
      const expiredStatus = await grant.status();
      expect(expiredStatus.state).toBe("absent");
      expect(await runDurableObjectAlarm(grant)).toBe(false);
    } finally {
      clock.mockRestore();
    }
  });

  it("health is public while readiness fails closed on invalid secret shape", async () => {
    const health = await dataHandler.fetch(new Request("https://station.invalid/healthz"), env);
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ status: "ok" });

    const operatorSecret = randomBytes(32);
    const authorization = `Bearer ${formatOperatorToken(operatorSecret)}`;
    const record = env as unknown as Record<string, unknown>;
    const realDigest = record.BADTOWER_OPERATOR_TOKEN_DIGEST;
    const realKeys = record.BADTOWER_CAPABILITY_KEYS;
    const realMode = record.BADTOWER_RUNTIME_MODE;
    record.BADTOWER_RUNTIME_MODE = "local";
    record.BADTOWER_OPERATOR_TOKEN_DIGEST = Array.from(await sha256(operatorSecret), (byte) => byte.toString(16).padStart(2, "0")).join("");
    record.BADTOWER_CAPABILITY_KEYS = "invalid";
    try {
      const ready = await operatorHandler.fetch(operatorRequest("/readyz", authorization), env);
      expect(ready.status).toBe(503);
      expect(await ready.json()).toEqual({ status: "unavailable" });
    } finally {
      record.BADTOWER_OPERATOR_TOKEN_DIGEST = realDigest;
      record.BADTOWER_CAPABILITY_KEYS = realKeys;
      record.BADTOWER_RUNTIME_MODE = realMode;
    }
  });
});
