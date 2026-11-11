const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE64URL_LOOKUP = new Map<string, number>(
  Array.from(BASE64URL_ALPHABET, (character, index) => [character, index]),
);

export function toBase64Url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2]! : 0;
    out += BASE64URL_ALPHABET[b0 >> 2];
    out += BASE64URL_ALPHABET[((b0 & 3) << 4) | (b1 >> 4)];
    if (i + 1 < bytes.length) out += BASE64URL_ALPHABET[((b1 & 15) << 2) | (b2 >> 6)];
    if (i + 2 < bytes.length) out += BASE64URL_ALPHABET[b2 & 63];
  }
  return out;
}

export function decodeBase64Url(encoded: string): Uint8Array | null {
  if (encoded.length === 0) return null;
  const bytes: number[] = [];
  for (let i = 0; i < encoded.length; i += 4) {
    const c0 = BASE64URL_LOOKUP.get(encoded[i]!);
    const c1 = BASE64URL_LOOKUP.get(encoded[i + 1]!);
    if (c0 === undefined || c1 === undefined) return null;
    const c2 = i + 2 < encoded.length ? BASE64URL_LOOKUP.get(encoded[i + 2]!) : undefined;
    const c3 = i + 3 < encoded.length ? BASE64URL_LOOKUP.get(encoded[i + 3]!) : undefined;
    bytes.push((c0 << 2) | (c1 >> 4));
    if (c2 !== undefined) {
      bytes.push(((c1 & 15) << 4) | (c2 >> 2));
      if (c3 !== undefined) bytes.push(((c2 & 3) << 6) | c3);
    }
  }
  const out = new Uint8Array(bytes);
  return toBase64Url(out) === encoded ? out : null;
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

export function hexToBytes(hex: string): Uint8Array | null {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function requireSqliteBlob(value: unknown): ArrayBuffer {
  if (!(value instanceof ArrayBuffer)) throw new Error("invalid durable blob");
  return value;
}

export function fromSqliteBlob(value: unknown): Uint8Array {
  return new Uint8Array(requireSqliteBlob(value));
}
