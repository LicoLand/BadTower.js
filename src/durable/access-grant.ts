import { DurableObject } from "cloudflare:workers";
import { digestEqual } from "../access/token";

const STORAGE_KEY = "grant";
const EXCHANGE_RETRY_WINDOW_MS = 10 * 60 * 1000;
const MAX_INVITATION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const MIN_ACCESS_TTL_MS = 60 * 60 * 1000;
const MAX_ACCESS_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const REPLAY_WINDOW_BITS = 128;
const REQUEST_CAPACITY = 120;
const REQUEST_REFILL_PER_MS = 2 / 1000;
const BYTE_CAPACITY = 16 * 1024 * 1024;
const BYTE_REFILL_PER_MS = 1024 * 1024 / 1000;
const WEIGHT_CAPACITY = 240;
const WEIGHT_REFILL_PER_MS = 4 / 1000;
const CREATION_CAPACITY = 32;
const MAX_CONCURRENCY = 8;
const MAX_LEASE_MS = 60_000;

interface Bucket { balance: number; updatedAt: number }
interface Lease { counter: string; expiresAt: number }
interface InvitedGrant { state: "invited"; invitationDigest: Uint8Array; invitationExpiresAt: number; accessTtlMs: number }
interface ActiveGrant {
  state: "active";
  publicKey: Uint8Array;
  epoch: number;
  credentialExpiresAt: number;
  highestCounter: string | null;
  replayBitmap: Uint8Array;
  requestBucket: Bucket;
  byteBucket: Bucket;
  weightBucket: Bucket;
  creationsUsed: number;
  leases: Lease[];
  invitationDigest?: Uint8Array;
  exchangeRetryUntil?: number;
}
type StoredGrant = InvitedGrant | ActiveGrant;

export interface GrantExchangeResult { ok: boolean; credentialExpiresAt?: number; epoch?: number }
export interface GrantStatus { state: "absent" | "invited" | "active"; expiresAt?: number; epoch?: number; exchangeRetryUntil?: number }
export interface GrantCharge {
  epoch: number;
  publicKey: Uint8Array;
  counter: string;
  requestCost: number;
  byteCost: number;
  operationWeight: number;
  creationCost: number;
  concurrencyCost: 0 | 1;
  leaseTtlMs: number;
}
export interface GrantChargeResult { ok: boolean; leaseCounter?: string }

function isDigest(value: Uint8Array): boolean { return value.length === 32 }
function validCounter(value: string): bigint | null {
  if (!/^(0|[1-9][0-9]{0,19})$/.test(value)) return null;
  const counter = BigInt(value);
  return counter <= 0xffff_ffff_ffff_ffffn ? counter : null;
}
function refill(bucket: Bucket, now: number, capacity: number, rate: number): Bucket {
  const updatedAt = Math.max(now, bucket.updatedAt);
  const elapsed = updatedAt - bucket.updatedAt;
  return { balance: Math.min(capacity, bucket.balance + elapsed * rate), updatedAt };
}
function bitmapUsed(bitmap: Uint8Array, offset: number): boolean { return (bitmap[offset >>> 3]! & (1 << (offset & 7))) !== 0 }
function bitmapSet(bitmap: Uint8Array, offset: number): void { bitmap[offset >>> 3] = bitmap[offset >>> 3]! | (1 << (offset & 7)); }
function shiftBitmap(bitmap: Uint8Array, shift: number): Uint8Array {
  const next = new Uint8Array(REPLAY_WINDOW_BITS / 8);
  if (shift >= REPLAY_WINDOW_BITS) return next;
  for (let old = 0; old < REPLAY_WINDOW_BITS - shift; old += 1) if (bitmapUsed(bitmap, old)) bitmapSet(next, old + shift);
  return next;
}

export class AccessGrant extends DurableObject<Env> {
  async initialize(invitationDigest: Uint8Array, invitationExpiresAt: number, accessTtlMs: number): Promise<boolean> {
    if (!isDigest(invitationDigest) || !Number.isSafeInteger(invitationExpiresAt) || !Number.isSafeInteger(accessTtlMs) || accessTtlMs < MIN_ACCESS_TTL_MS || accessTtlMs > MAX_ACCESS_TTL_MS) return false;
    return this.ctx.storage.transaction(async (transaction) => {
      const now = Date.now();
      // The operator service enforces the minimum requested TTL before this
      // RPC. Here, use only the local clock to reject expired or overlong
      // absolute deadlines without making a minimum TTL race the RPC delay.
      if (invitationExpiresAt <= now || invitationExpiresAt - now > MAX_INVITATION_TTL_MS) return false;
      if (await transaction.get<StoredGrant>(STORAGE_KEY) !== undefined) return false;
      await transaction.put(STORAGE_KEY, { state: "invited", invitationDigest, invitationExpiresAt, accessTtlMs } satisfies InvitedGrant);
      await transaction.setAlarm(invitationExpiresAt);
      return true;
    });
  }

  async exchange(invitationDigest: Uint8Array, publicKey: Uint8Array): Promise<GrantExchangeResult> {
    if (!isDigest(invitationDigest) || publicKey.length !== 32) return { ok: false };
    return this.ctx.storage.transaction(async (transaction) => {
      const now = Date.now();
      const grant = await transaction.get<StoredGrant>(STORAGE_KEY);
      if (grant === undefined) return { ok: false };
      if (grant.state === "active") {
        if (now >= grant.credentialExpiresAt) {
          await transaction.delete(STORAGE_KEY);
          await transaction.deleteAlarm();
          return { ok: false };
        }
        const retry = grant.invitationDigest !== undefined && grant.exchangeRetryUntil !== undefined && now <= grant.exchangeRetryUntil && now < grant.credentialExpiresAt && digestEqual(invitationDigest, grant.invitationDigest) && crypto.subtle.timingSafeEqual(publicKey, grant.publicKey);
        return retry ? { ok: true, credentialExpiresAt: grant.credentialExpiresAt, epoch: grant.epoch } : { ok: false };
      }
      if (now >= grant.invitationExpiresAt) {
        await transaction.delete(STORAGE_KEY);
        await transaction.deleteAlarm();
        return { ok: false };
      }
      if (!digestEqual(invitationDigest, grant.invitationDigest)) return { ok: false };
      const credentialExpiresAt = Math.min(now + grant.accessTtlMs, now + MAX_ACCESS_TTL_MS);
      const exchangeRetryUntil = Math.min(now + EXCHANGE_RETRY_WINDOW_MS, credentialExpiresAt);
      const active: ActiveGrant = {
        state: "active", publicKey, epoch: 1, credentialExpiresAt, highestCounter: null,
        replayBitmap: new Uint8Array(REPLAY_WINDOW_BITS / 8),
        requestBucket: { balance: REQUEST_CAPACITY, updatedAt: now },
        byteBucket: { balance: BYTE_CAPACITY, updatedAt: now },
        weightBucket: { balance: WEIGHT_CAPACITY, updatedAt: now },
        creationsUsed: 0, leases: [], invitationDigest, exchangeRetryUntil,
      };
      await transaction.put(STORAGE_KEY, active);
      await transaction.setAlarm(exchangeRetryUntil);
      return { ok: true, credentialExpiresAt, epoch: active.epoch };
    });
  }

  async authorizeAndCharge(charge: GrantCharge): Promise<GrantChargeResult> {
    const counter = validCounter(charge.counter);
    if (counter === null || charge.publicKey.length !== 32 || !Number.isInteger(charge.epoch) || charge.epoch < 1 || !Number.isInteger(charge.requestCost) || charge.requestCost < 1 || !Number.isSafeInteger(charge.byteCost) || charge.byteCost < 0 || !Number.isInteger(charge.operationWeight) || charge.operationWeight < 0 || !Number.isInteger(charge.creationCost) || charge.creationCost < 0 || (charge.concurrencyCost !== 0 && charge.concurrencyCost !== 1) || !Number.isInteger(charge.leaseTtlMs) || charge.leaseTtlMs < 0 || charge.leaseTtlMs > MAX_LEASE_MS) return { ok: false };
    return this.ctx.storage.transaction(async (transaction) => {
      const grant = await transaction.get<StoredGrant>(STORAGE_KEY);
      if (grant === undefined || grant.state !== "active") return { ok: false };
      const now = Math.max(
        Date.now(),
        grant.requestBucket.updatedAt,
        grant.byteBucket.updatedAt,
        grant.weightBucket.updatedAt,
      );
      if (now >= grant.credentialExpiresAt) {
        await transaction.delete(STORAGE_KEY);
        await transaction.deleteAlarm();
        return { ok: false };
      }
      if (charge.epoch !== grant.epoch || !crypto.subtle.timingSafeEqual(charge.publicKey, grant.publicKey)) return { ok: false };
      let bitmap: Uint8Array<ArrayBufferLike> = new Uint8Array(grant.replayBitmap);
      let highest = grant.highestCounter === null ? null : BigInt(grant.highestCounter);
      if (highest === null || counter > highest) {
        bitmap = shiftBitmap(bitmap, highest === null ? REPLAY_WINDOW_BITS : Number(counter - highest > BigInt(REPLAY_WINDOW_BITS) ? BigInt(REPLAY_WINDOW_BITS) : counter - highest));
        highest = counter;
      } else {
        const offset = Number(highest - counter);
        if (offset >= REPLAY_WINDOW_BITS || bitmapUsed(bitmap, offset)) return { ok: false };
      }
      bitmapSet(bitmap, Number(highest - counter));
      const requestBucket = refill(grant.requestBucket, now, REQUEST_CAPACITY, REQUEST_REFILL_PER_MS);
      const byteBucket = refill(grant.byteBucket, now, BYTE_CAPACITY, BYTE_REFILL_PER_MS);
      const weightBucket = refill(grant.weightBucket, now, WEIGHT_CAPACITY, WEIGHT_REFILL_PER_MS);
      const leases = grant.leases.filter((lease) => lease.expiresAt > now);
      if (requestBucket.balance < charge.requestCost || byteBucket.balance < charge.byteCost || weightBucket.balance < charge.operationWeight || grant.creationsUsed + charge.creationCost > CREATION_CAPACITY || leases.length + charge.concurrencyCost > MAX_CONCURRENCY) return { ok: false };
      requestBucket.balance -= charge.requestCost;
      byteBucket.balance -= charge.byteCost;
      weightBucket.balance -= charge.operationWeight;
      if (charge.concurrencyCost === 1) leases.push({ counter: charge.counter, expiresAt: now + charge.leaseTtlMs });
      const next: ActiveGrant = { ...grant, highestCounter: highest.toString(), replayBitmap: bitmap, requestBucket, byteBucket, weightBucket, creationsUsed: grant.creationsUsed + charge.creationCost, leases };
      await transaction.put(STORAGE_KEY, next);
      return charge.concurrencyCost === 1 ? { ok: true, leaseCounter: charge.counter } : { ok: true };
    });
  }

  async releaseLease(epoch: number, counter: string): Promise<boolean> {
    if (!Number.isInteger(epoch) || validCounter(counter) === null) return false;
    return this.ctx.storage.transaction(async (transaction) => {
      const grant = await transaction.get<StoredGrant>(STORAGE_KEY);
      if (grant === undefined || grant.state !== "active" || grant.epoch !== epoch) return false;
      const leases = grant.leases.filter((lease) => lease.counter !== counter);
      if (leases.length === grant.leases.length) return false;
      await transaction.put(STORAGE_KEY, { ...grant, leases });
      return true;
    });
  }

  async status(): Promise<GrantStatus> {
    const now = Date.now();
    const grant = await this.ctx.storage.get<StoredGrant>(STORAGE_KEY);
    if (grant === undefined) return { state: "absent" };
    const expiresAt = grant.state === "invited" ? grant.invitationExpiresAt : grant.credentialExpiresAt;
    if (now >= expiresAt) { await this.clear(); return { state: "absent" }; }
    return grant.state === "invited" ? { state: "invited", expiresAt } : { state: "active", expiresAt, epoch: grant.epoch, ...(grant.exchangeRetryUntil === undefined ? {} : { exchangeRetryUntil: grant.exchangeRetryUntil }) };
  }
  async revoke(): Promise<boolean> { if (await this.ctx.storage.get(STORAGE_KEY) === undefined) return false; await this.clear(); return true; }
  override async alarm(): Promise<void> {
    const now = Date.now();
    const grant = await this.ctx.storage.get<StoredGrant>(STORAGE_KEY);
    if (grant === undefined) return;
    const expiry = grant.state === "invited" ? grant.invitationExpiresAt : grant.credentialExpiresAt;
    if (now >= expiry) { await this.clear(); return; }
    if (grant.state === "active" && grant.exchangeRetryUntil !== undefined && now >= grant.exchangeRetryUntil) {
      const { invitationDigest: _invitationDigest, exchangeRetryUntil: _exchangeRetryUntil, ...minimized } = grant;
      await this.ctx.storage.put(STORAGE_KEY, minimized);
    }
    await this.ctx.storage.setAlarm(expiry);
  }
  private async clear(): Promise<void> { await this.ctx.storage.deleteAlarm(); await this.ctx.storage.deleteAll(); }
}
