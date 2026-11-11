/**
 * Minimal deterministic-CBOR codec for the mailbox transport v1 frame
 * grammar.
 *
 * Admitted: definite shortest unsigned integers, definite byte strings,
 * definite arrays, and unsigned-key maps in strictly ascending label order.
 * Rejected: tags, text, floats, indefinite lengths, non-shortest integers,
 * duplicate or unordered labels, unsafe integers, and trailing bytes.
 */

export class CborError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CborError";
  }
}

const MAX_SAFE = Number.MAX_SAFE_INTEGER;

export class CborReader {
  readonly buf: Uint8Array;
  pos = 0;

  constructor(buf: Uint8Array) {
    this.buf = buf;
  }

  get remaining(): number {
    return this.buf.length - this.pos;
  }

  private head(): { major: number; info: number } {
    if (this.pos >= this.buf.length) throw new CborError("truncated head");
    const b = this.buf[this.pos];
    if (b === undefined) throw new CborError("truncated head");
    this.pos += 1;
    return { major: b >> 5, info: b & 0x1f };
  }

  private argument(info: number): number {
    if (info < 24) return info;
    if (info === 24) {
      const v = this.buf[this.pos];
      if (v === undefined) throw new CborError("truncated argument");
      if (v < 24) throw new CborError("non-shortest integer");
      this.pos += 1;
      return v;
    }
    if (info === 25) {
      if (this.pos + 2 > this.buf.length) throw new CborError("truncated argument");
      const v = (this.buf[this.pos]! << 8) | this.buf[this.pos + 1]!;
      if (v < 256) throw new CborError("non-shortest integer");
      this.pos += 2;
      return v;
    }
    if (info === 26) {
      if (this.pos + 4 > this.buf.length) throw new CborError("truncated argument");
      const v =
        ((this.buf[this.pos]! << 24) |
          (this.buf[this.pos + 1]! << 16) |
          (this.buf[this.pos + 2]! << 8) |
          this.buf[this.pos + 3]!) >>>
        0;
      if (v < 65536) throw new CborError("non-shortest integer");
      this.pos += 4;
      return v;
    }
    if (info === 27) {
      if (this.pos + 8 > this.buf.length) throw new CborError("truncated argument");
      const hi =
        ((this.buf[this.pos]! << 24) |
          (this.buf[this.pos + 1]! << 16) |
          (this.buf[this.pos + 2]! << 8) |
          this.buf[this.pos + 3]!) >>>
        0;
      const lo =
        ((this.buf[this.pos + 4]! << 24) |
          (this.buf[this.pos + 5]! << 16) |
          (this.buf[this.pos + 6]! << 8) |
          this.buf[this.pos + 7]!) >>>
        0;
      if (hi > 0x001fffff) throw new CborError("unsafe integer");
      const v = hi * 4294967296 + lo;
      if (v > MAX_SAFE) throw new CborError("unsafe integer");
      if (v < 4294967296) throw new CborError("non-shortest integer");
      this.pos += 8;
      return v;
    }
    throw new CborError("reserved or indefinite length");
  }

  uint(): number {
    const { major, info } = this.head();
    if (major !== 0) throw new CborError("expected unsigned integer");
    return this.argument(info);
  }

  bytes(): Uint8Array {
    const { major, info } = this.head();
    if (major !== 2) throw new CborError("expected byte string");
    const len = this.argument(info);
    if (len > this.remaining) throw new CborError("truncated byte string");
    const out = this.buf.subarray(this.pos, this.pos + len);
    this.pos += len;
    return out;
  }

  /**
   * Reads one definite map whose keys are unsigned integers in strictly
   * ascending order. Values are returned as copy-free slices of the buffer.
   */
  mapEntries(): Array<{ key: number; value: Uint8Array }> {
    const { major, info } = this.head();
    if (major !== 5) throw new CborError("expected map");
    const count = this.argument(info);
    const entries: Array<{ key: number; value: Uint8Array }> = [];
    let previous = -1;
    for (let i = 0; i < count; i += 1) {
      const key = this.uint();
      if (key <= previous) throw new CborError("unordered or duplicate label");
      previous = key;
      const start = this.pos;
      // Walk one complete value without copying.
      this.skipValue();
      entries.push({ key, value: this.buf.subarray(start, this.pos) });
    }
    return entries;
  }

  /** Advances past exactly one value without decoding it. */
  skipValue(): void {
    const { major, info } = this.head();
    const len = this.argument(info);
    if (major === 2) {
      if (len > this.remaining) throw new CborError("truncated byte string");
      this.pos += len;
      return;
    }
    if (major === 4) {
      for (let i = 0; i < len; i += 1) this.skipValue();
      return;
    }
    if (major === 5) {
      for (let i = 0; i < len * 2; i += 1) this.skipValue();
      return;
    }
    if (major === 0) return;
    throw new CborError("disallowed major type");
  }

  end(): void {
    if (this.remaining !== 0) throw new CborError("trailing bytes");
  }
}

export class CborWriter {
  readonly out: Uint8Array;
  pos = 0;

  constructor(size: number) {
    this.out = new Uint8Array(size);
  }

  private headWithMajor(major: number, n: number): void {
    if (!Number.isSafeInteger(n) || n < 0) throw new CborError("invalid integer");
    const at = this.pos;
    if (n < 24) {
      this.out[at] = (major << 5) | n;
      this.pos = at + 1;
    } else if (n < 256) {
      this.out[at] = (major << 5) | 24;
      this.out[at + 1] = n;
      this.pos = at + 2;
    } else if (n < 65536) {
      this.out[at] = (major << 5) | 25;
      this.out[at + 1] = n >> 8;
      this.out[at + 2] = n & 0xff;
      this.pos = at + 3;
    } else if (n < 4294967296) {
      this.out[at] = (major << 5) | 26;
      this.out[at + 1] = (n >>> 24) & 0xff;
      this.out[at + 2] = (n >>> 16) & 0xff;
      this.out[at + 3] = (n >>> 8) & 0xff;
      this.out[at + 4] = n & 0xff;
      this.pos = at + 5;
    } else {
      this.out[at] = (major << 5) | 27;
      const hi = Math.floor(n / 4294967296);
      const lo = n >>> 0;
      this.out[at + 1] = (hi >>> 24) & 0xff;
      this.out[at + 2] = (hi >>> 16) & 0xff;
      this.out[at + 3] = (hi >>> 8) & 0xff;
      this.out[at + 4] = hi & 0xff;
      this.out[at + 5] = (lo >>> 24) & 0xff;
      this.out[at + 6] = (lo >>> 16) & 0xff;
      this.out[at + 7] = (lo >>> 8) & 0xff;
      this.out[at + 8] = lo & 0xff;
      this.pos = at + 9;
    }
  }

  uint(n: number): void {
    this.headWithMajor(0, n);
  }

  bytes(b: Uint8Array): void {
    this.bytesHeader(b.length);
    this.out.set(b, this.pos);
    this.pos += b.length;
  }

  bytesHeader(length: number): void {
    this.headWithMajor(2, length);
  }

  mapHeader(count: number): void {
    this.headWithMajor(5, count);
  }

  finish(): Uint8Array {
    return this.out.subarray(0, this.pos);
  }
}
