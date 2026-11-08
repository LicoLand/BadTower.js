import { describe, expect, it } from "vitest";
import {
  encodeRequestProof,
  formatAccessToken,
  formatInvitationToken,
  parseAccessToken,
  parseInvitationToken,
  sha256,
  verifyRequestProof,
  type CapabilityKeyring,
} from "../src/access/token";

function keyring(): CapabilityKeyring {
  return { activeKeyId: 7, keys: new Map([[7, new Uint8Array(32).fill(0x41)]]) };
}

describe("v2 capability authentication", () => {
  it("authenticates fixed canonical invitation and access capabilities and rejects mutation", async () => {
    const keys = keyring();
    const selector = new Uint8Array(16).fill(0x21);
    const publicKey = new Uint8Array(32).fill(0x31);
    const now = 1_900_000_000_000;
    const invitation = await formatInvitationToken(selector, now + 60_000, keys);
    expect(invitation.startsWith("bti2.")).toBe(true);
    expect((await parseInvitationToken(invitation, keys, now))?.selectorBytes).toEqual(selector);
    const tail = invitation.at(-1)!;
    expect(await parseInvitationToken(`${invitation.slice(0, -1)}${tail === "A" ? "B" : "A"}`, keys, now)).toBeNull();
    expect(await parseInvitationToken(invitation, keys, now + 60_000)).toBeNull();

    const access = await formatAccessToken(selector, publicKey, 3, now + 60_000, keys);
    const parsed = await parseAccessToken(access, keys, now);
    expect(access.startsWith("bta2.")).toBe(true);
    expect(parsed?.publicKey).toEqual(publicKey);
    expect(parsed?.epoch).toBe(3);
    const unknownKeys: CapabilityKeyring = { activeKeyId: 8, keys: new Map([[8, new Uint8Array(32).fill(1)]]) };
    expect(await parseAccessToken(access, unknownKeys, now)).toBeNull();
  });

  it("binds Ed25519 proof to every canonical field", async () => {
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const exported = await crypto.subtle.exportKey("raw", pair.publicKey) as ArrayBuffer;
    const publicKey = new Uint8Array(exported);
    const fields = {
      capabilityDigest: await sha256(new TextEncoder().encode("capability")),
      method: "POST",
      path: "/v1/reserve",
      mediaType: "application/cbor",
      contentLength: 3,
      operationId: new Uint8Array(16).fill(2),
      bodyDigest: await sha256(new Uint8Array([1, 2, 3])),
      issuedAt: 1_900_000_000_000,
      counter: 9n,
    };
    const transcript = encodeRequestProof(fields);
    const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, transcript));
    expect(await verifyRequestProof(publicKey, transcript, signature)).toBe(true);
    expect(await verifyRequestProof(publicKey, encodeRequestProof({ ...fields, path: "/v1/affiliate" }), signature)).toBe(false);
    expect(await verifyRequestProof(publicKey, encodeRequestProof({ ...fields, counter: 10n }), signature)).toBe(false);
  });
});
