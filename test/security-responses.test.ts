import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import dataHandler from "../src/data-entry";
import operatorHandler from "../src/operator-entry";
import { emptyNoStore, jsonNoStore, secureResponse } from "../src/http";

const EXPECTED = {
  "cache-control": "no-store",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
};

describe("secure response boundary", () => {
  it.each([
    emptyNoStore(404),
    emptyNoStore(429),
    jsonNoStore({ status: "ok" }),
    secureResponse("opaque", {
      status: 503,
      headers: { "Access-Control-Allow-Origin": "*", "Cache-Control": "public" },
    }),
  ])("applies invariant headers without wildcard CORS", (response) => {
    for (const [name, value] of Object.entries(EXPECTED)) {
      expect(response.headers.get(name)).toBe(value);
    }
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("maps pre-dispatch configuration exceptions through the secure boundary", async () => {
    const broken = new Proxy(env, {
      get(target, property, receiver) {
        if (property === "BADTOWER_CAPABILITY_KEYS") throw new Error("sensitive canary");
        return Reflect.get(target, property, receiver);
      },
    });
    const response = await dataHandler.fetch(
      new Request("https://station.invalid/v1/reserve", {
        method: "POST",
        headers: { authorization: "Bearer malformed" },
      }),
      broken,
    );
    expect(response.status).toBe(503);
    for (const [name, value] of Object.entries(EXPECTED)) {
      expect(response.headers.get(name)).toBe(value);
    }
    expect(await response.text()).not.toContain("sensitive canary");

    const brokenOperator = new Proxy(env, {
      get(target, property, receiver) {
        if (property === "BADTOWER_RUNTIME_MODE") throw new Error("operator canary");
        return Reflect.get(target, property, receiver);
      },
    });
    const operatorResponse = await operatorHandler.fetch(
      new Request("https://operator.invalid/readyz"),
      brokenOperator,
    );
    expect(operatorResponse.status).toBe(503);
    for (const [name, value] of Object.entries(EXPECTED)) {
      expect(operatorResponse.headers.get(name)).toBe(value);
    }
    expect(await operatorResponse.text()).not.toContain("operator canary");
  });
});
