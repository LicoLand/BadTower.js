/**
 * Station admission credentials: offline-minted HMAC-SHA256 proofs over
 * fixed binary fields, verified in constant time. The station key never
 * leaves the verifier; every failure is indistinguishable.
 *
 *   btm1.<base64url> = mailboxId(16) ‖ notAfter(u64 BE) ‖
 *                      HMAC(key, "btm1" ‖ mailboxId ‖ notAfter)
 *   revoke body      = mailboxId(16) ‖ HMAC(key, "btr1" ‖ mailboxId)
 */
import { decodeBase64Url } from "./encoding";

const CREDENTIAL_PREFIX = "btm1.";
const CREDENTIAL_BYTES = 56; // mailboxId(16) || notAfter(8) || hmac(32)
const REVOKE_BYTES = 48; // mailboxId(16) || hmac(32)

export const ADMISSION_CREDENTIAL_BYTES = CREDENTIAL_BYTES;
export const REVOKE_BODY_BYTES = REVOKE_BYTES;
export const MAILBOX_ID_BYTES = 16;

export type Admission =
  | { kind: "ok"; mailboxId: Uint8Array; notAfter: number }
  | { kind: "bad" };

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  const left = new Uint8Array(a).buffer as ArrayBuffer;
  const right = new Uint8Array(b).buffer as ArrayBuffer;
  return crypto.subtle.timingSafeEqual(left, right);
}

export class StationCredentials {
  private imported: Promise<CryptoKey> | null = null;

  constructor(private readonly encodedKey: string) {}

  private key(): Promise<CryptoKey> {
    this.imported ??= (async () => {
      const raw = decodeBase64Url(this.encodedKey);
      if (raw === null || raw.length !== 32) throw new Error("invalid station key");
      return crypto.subtle.importKey(
        "raw",
        raw as BufferSource,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"],
      );
    })();
    return this.imported;
  }

  private async hmac(parts: Uint8Array[]): Promise<Uint8Array> {
    const total = parts.reduce((sum, part) => sum + part.length, 0);
    const input = new Uint8Array(total);
    let at = 0;
    for (const part of parts) {
      input.set(part, at);
      at += part.length;
    }
    return new Uint8Array(await crypto.subtle.sign("HMAC", await this.key(), input));
  }

  /**
   * Verify an `Authorization: Bearer btm1.<…>` header. `notAfter` bounds
   * only the first binding; the caller decides what a deadline means for
   * its session type.
   */
  async verifyBearer(header: string | null): Promise<Admission> {
    const token = header?.startsWith("Bearer ") ? header.slice(7).trim() : "";
    if (!token.startsWith(CREDENTIAL_PREFIX)) return { kind: "bad" };
    const raw = decodeBase64Url(token.slice(CREDENTIAL_PREFIX.length));
    if (raw === null || raw.length !== CREDENTIAL_BYTES) return { kind: "bad" };
    const mailboxId = raw.slice(0, MAILBOX_ID_BYTES);
    const notAfter = new DataView(raw.buffer, raw.byteOffset + 16, 8).getBigUint64(0, false);
    const expected = await this.hmac([
      new TextEncoder().encode("btm1"),
      mailboxId,
      raw.slice(16, 24),
    ]);
    if (!equalBytes(expected, raw.slice(24))) return { kind: "bad" };
    return { kind: "ok", mailboxId, notAfter: Number(notAfter) };
  }

  /**
   * Verify a revocation body (mailboxId ‖ HMAC(key,"btr1"‖mailboxId)).
   * Returns the mailbox id the body destroys, or null on any mismatch.
   */
  async verifyRevocation(body: Uint8Array): Promise<Uint8Array | null> {
    if (body.length !== REVOKE_BYTES) return null;
    const mailboxId = body.slice(0, MAILBOX_ID_BYTES);
    const expected = await this.hmac([new TextEncoder().encode("btr1"), mailboxId]);
    if (!equalBytes(expected, body.slice(MAILBOX_ID_BYTES))) return null;
    return mailboxId;
  }
}
