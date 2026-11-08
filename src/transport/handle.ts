import { decodeBase64Url } from "../encoding";

export const RELAY_HANDLE_BYTES = 32;
export const RELAY_HANDLE_VERSION = 1;
export const RELAY_HANDLE_RANDOM_BYTES = 16;
export const RELAY_HANDLE_TAG_BYTES = 14;
export const MAX_HANDLE_KEY_SLOTS = 4;

const HANDLE_PREFIX_BYTES = 2 + RELAY_HANDLE_RANDOM_BYTES;
const HANDLE_KEY_BYTES = 32;
const HANDLE_DOMAIN = new TextEncoder().encode("badtower-js-relay-handle-v1\0");

export interface HandleKeySlot {
  readonly id: number;
  readonly key: Uint8Array;
  /** Exclusive epoch-millisecond deadline. Null is valid only for the current slot. */
  readonly notAfter: number | null;
}

export interface HandleKeyRing {
  readonly currentSlot: number;
  readonly slots: readonly HandleKeySlot[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function canonicalSlot(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 255
    ? value
    : null;
}

function parseCurrentSlot(value: unknown): number | null {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,2})$/.test(value)) return null;
  return canonicalSlot(Number(value));
}

function parseNotAfter(value: unknown): number | null | undefined {
  if (value === null) return null;
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value <= 0
  ) {
    return undefined;
  }
  return value;
}

/** Parses the closed, bounded handle-key configuration without accepting aliases. */
export function parseHandleKeyRing(
  rawKeys: unknown,
  rawCurrentSlot: unknown,
): HandleKeyRing | null {
  const currentSlot = parseCurrentSlot(rawCurrentSlot);
  if (currentSlot === null || typeof rawKeys !== "string") return null;

  let decoded: unknown;
  try {
    decoded = JSON.parse(rawKeys) as unknown;
  } catch {
    return null;
  }
  if (!Array.isArray(decoded) || decoded.length === 0 || decoded.length > MAX_HANDLE_KEY_SLOTS) {
    return null;
  }

  const slots: HandleKeySlot[] = [];
  const seen = new Set<number>();
  for (const value of decoded) {
    if (!isRecord(value)) return null;
    const names = Object.keys(value).sort();
    if (names.length !== 3 || names[0] !== "id" || names[1] !== "key" || names[2] !== "notAfter") {
      return null;
    }
    const id = canonicalSlot(value.id);
    const notAfter = parseNotAfter(value.notAfter);
    if (
      id === null ||
      notAfter === undefined ||
      seen.has(id) ||
      typeof value.key !== "string" ||
      value.key.length !== 43
    ) {
      return null;
    }
    const key = decodeBase64Url(value.key);
    if (key === null || key.length !== HANDLE_KEY_BYTES) return null;
    seen.add(id);
    slots.push({ id, key, notAfter });
  }

  const current = slots.find((slot) => slot.id === currentSlot);
  if (
    current === undefined ||
    slots.some((slot) => slot.id !== currentSlot && slot.notAfter === null)
  ) {
    return null;
  }
  return { currentSlot, slots };
}

function slotFor(ring: HandleKeyRing, id: number): HandleKeySlot | null {
  let found: HandleKeySlot | null = null;
  for (const slot of ring.slots) {
    if (slot.id !== id) continue;
    if (found !== null) return null;
    found = slot;
  }
  return found;
}

function usable(slot: HandleKeySlot, nowMs: number): boolean {
  return slot.notAfter === null || nowMs < slot.notAfter;
}

async function tag(prefix: Uint8Array, keyBytes: Uint8Array): Promise<Uint8Array> {
  const message = new Uint8Array(HANDLE_DOMAIN.length + prefix.length);
  message.set(HANDLE_DOMAIN);
  message.set(prefix, HANDLE_DOMAIN.length);
  const keyMaterial = new Uint8Array(keyBytes.length);
  keyMaterial.set(keyBytes);
  const key = await crypto.subtle.importKey(
    "raw",
    keyMaterial.buffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, message.buffer));
}

/** Issues a fixed-size opaque handle using only the configured current slot. */
export async function createRelayHandle(
  ring: HandleKeyRing,
  nowMs = Date.now(),
): Promise<Uint8Array | null> {
  const current = slotFor(ring, ring.currentSlot);
  if (current === null || !usable(current, nowMs) || current.key.length !== HANDLE_KEY_BYTES) {
    return null;
  }
  const handle = new Uint8Array(RELAY_HANDLE_BYTES);
  handle[0] = RELAY_HANDLE_VERSION;
  handle[1] = current.id;
  crypto.getRandomValues(handle.subarray(2, HANDLE_PREFIX_BYTES));
  const authenticationTag = await tag(handle.subarray(0, HANDLE_PREFIX_BYTES), current.key);
  handle.set(authenticationTag.subarray(0, RELAY_HANDLE_TAG_BYTES), HANDLE_PREFIX_BYTES);
  return handle;
}

/** Authenticates version, slot lifetime and tag without consulting Durable Objects. */
export async function verifyRelayHandle(
  handle: Uint8Array,
  ring: HandleKeyRing,
  nowMs = Date.now(),
): Promise<boolean> {
  if (handle.length !== RELAY_HANDLE_BYTES || handle[0] !== RELAY_HANDLE_VERSION) return false;
  const slot = slotFor(ring, handle[1]!);
  if (slot === null || !usable(slot, nowMs) || slot.key.length !== HANDLE_KEY_BYTES) return false;

  const expected = await tag(handle.subarray(0, HANDLE_PREFIX_BYTES), slot.key);
  let difference = 0;
  for (let index = 0; index < RELAY_HANDLE_TAG_BYTES; index += 1) {
    difference |= handle[HANDLE_PREFIX_BYTES + index]! ^ expected[index]!;
  }
  return difference === 0;
}
