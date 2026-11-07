/**
 * SandboxProtocol v1 (ADR-0002 §17.1): length-prefixed envelopes whose body is a strict CBOR array
 * `[frameType, fields…]`. Mirrors the app's SandboxCbor.kt / SandboxProtocol.kt so the CLI's test
 * harness can later speak to the app's `sandbox-core` WASM guest unchanged.
 *
 * CBOR subset: unsigned integers, byte and text strings, arrays, false/true/null; definite lengths,
 * shortest encodings only. Integers are limited to 2^53 − 1 here (JavaScript numbers); the app
 * accepts up to Long.MAX_VALUE, which no real frame uses.
 */

import { decodeUtf8, utf8 } from "./bytes.ts";

export const PROTOCOL_VERSION = 1;
export const MAX_FRAME_BYTES = 1 << 20;
export const CHUNK_PAYLOAD_BYTES = MAX_FRAME_BYTES - 16;

export class SandboxProtocolError extends Error {}

export const FRAME_CODES = {
  CHUNK: 0,
  INIT: 1,
  INVOKE: 2,
  CANCEL: 3,
  BRIDGE_RESULT: 4,
  ASYNC_BRIDGE_RESULT: 5,
  ASYNC_CANCEL: 6,
  READY: 16,
  BRIDGE_CALL: 17,
  ASYNC_BRIDGE_CALL: 18,
  RESULT: 19,
  FAILURE: 20,
  LOG: 21,
  LIMIT_EXCEEDED: 22,
} as const;
export type FrameTypeName = keyof typeof FRAME_CODES;

export const ERROR_CODES = {
  SCRIPT_ERROR: 1, LIMIT_MEMORY: 2, LIMIT_STACK: 3, LIMIT_TIME: 4, LIMIT_BRIDGE: 5, LIMIT_RESULT: 6,
  CANCELLED: 7, NO_SUCH_HOOK: 8, PROMISE_STALLED: 9, INTERNAL: 10, BAD_ARGUMENT: 11,
  UNSUPPORTED_PROTOCOL: 32, PERMISSION_DENIED: 33, UNKNOWN_OPERATION: 34, HOST_FAILURE: 35,
  NETWORK_FAILED: 36, REVOKED: 37,
} as const;
const KNOWN_ERROR_CODES = new Set<number>(Object.values(ERROR_CODES));

/** Host-owned source failure markers (SourceFailureMarker.kt); 0 = none. */
export const SOURCE_FAILURES = {
  HTTP_CHALLENGE: 1, HTTP_BLOCKED: 2, HTTP_FORBIDDEN: 3, HTTP_UNAVAILABLE: 4, QUOTA_EXCEEDED: 5,
} as const;

export const LIMIT_KINDS = {
  MEMORY: 1, STACK: 2, TIME: 3, BRIDGE_CALLS: 4, RESULT_SIZE: 5, ASYNC_QUEUE: 6, DOM_NODES: 7, DOM_DEPTH: 8, LOG: 9,
} as const;

export const LIMITS_FIELD_COUNT = 10;

export type Frame =
  | { type: "INIT"; callId: number; protocolVersion: number; apiLevel: number; limits: number[]; script: string }
  | { type: "INVOKE"; callId: number; method: string; argsJson: string }
  | { type: "CANCEL"; callId: number }
  | { type: "BRIDGE_RESULT"; seq: number; ok: true; json: string | null }
  | { type: "BRIDGE_RESULT"; seq: number; ok: false; code: number }
  | { type: "ASYNC_BRIDGE_RESULT"; opId: number; ok: true; json: string | null }
  | { type: "ASYNC_BRIDGE_RESULT"; opId: number; ok: false; code: number }
  | { type: "ASYNC_CANCEL"; opId: number }
  | { type: "READY"; callId: number; protocolVersion: number }
  | { type: "BRIDGE_CALL"; callId: number; seq: number; op: string; argsJson: string }
  | { type: "ASYNC_BRIDGE_CALL"; callId: number; opId: number; op: string; argsJson: string }
  | { type: "RESULT"; callId: number; valueJson: string }
  | { type: "FAILURE"; callId: number; code: number; sourceFailure: number }
  | { type: "LOG"; bytes: Uint8Array }
  | { type: "LIMIT_EXCEEDED"; callId: number; kind: number };

/** Which side is reading; each side accepts only the other side's frame types. */
export type Peer = "host" | "sandbox";
const ACCEPTS: Record<Peer, Set<number>> = {
  host: new Set([16, 17, 18, 19, 20, 21, 22]),
  sandbox: new Set([1, 2, 3, 4, 5, 6]),
};

export interface FieldLimits {
  maxScriptBytes: number;
  maxMethodBytes: number;
  maxJsonBytes: number;
  maxLogBytes: number;
}
export const DEFAULT_FIELD_LIMITS: FieldLimits = {
  maxScriptBytes: 8 << 20,
  maxMethodBytes: 256,
  maxJsonBytes: 4 << 20,
  maxLogBytes: 16 * 1024,
};

// ---------------------------------------------------------------------------------------------
// CBOR subset

const MAJOR_UINT = 0;
const MAJOR_BYTES = 2;
const MAJOR_TEXT = 3;
const MAJOR_ARRAY = 4;
const FALSE = 0xf4;
const TRUE = 0xf5;
const NULL = 0xf6;

export class CborWriter {
  private buf = new Uint8Array(64);
  private size = 0;

  uint(v: number): this {
    if (!Number.isSafeInteger(v) || v < 0) throw new SandboxProtocolError("CBOR subset has only non-negative safe integers");
    this.head(MAJOR_UINT, v);
    return this;
  }
  bool(v: boolean): this {
    this.put(v ? TRUE : FALSE);
    return this;
  }
  nul(): this {
    this.put(NULL);
    return this;
  }
  bytes(v: Uint8Array): this {
    this.head(MAJOR_BYTES, v.length);
    this.putAll(v);
    return this;
  }
  text(v: string): this {
    const b = utf8(v);
    this.head(MAJOR_TEXT, b.length);
    this.putAll(b);
    return this;
  }
  textOrNull(v: string | null): this {
    return v === null ? this.nul() : this.text(v);
  }
  array(n: number): this {
    this.head(MAJOR_ARRAY, n);
    return this;
  }
  toBytes(): Uint8Array {
    return this.buf.slice(0, this.size);
  }

  private head(major: number, v: number): void {
    const m = major << 5;
    if (v < 24) this.put(m | v);
    else if (v <= 0xff) { this.put(m | 24); this.be(v, 1); }
    else if (v <= 0xffff) { this.put(m | 25); this.be(v, 2); }
    else if (v <= 0xffffffff) { this.put(m | 26); this.be(v, 4); }
    else { this.put(m | 27); this.be(v, 8); }
  }
  private be(v: number, n: number): void {
    const big = BigInt(v);
    for (let i = n - 1; i >= 0; i--) this.put(Number((big >> BigInt(8 * i)) & 0xffn));
  }
  private ensure(extra: number): void {
    const need = this.size + extra;
    if (need <= this.buf.length) return;
    let cap = Math.max(this.buf.length, 16);
    while (cap < need) cap *= 2;
    const next = new Uint8Array(cap);
    next.set(this.buf.subarray(0, this.size));
    this.buf = next;
  }
  private put(b: number): void {
    this.ensure(1);
    this.buf[this.size++] = b;
  }
  private putAll(b: Uint8Array): void {
    this.ensure(b.length);
    this.buf.set(b, this.size);
    this.size += b.length;
  }
}

export class CborReader {
  constructor(private readonly data: Uint8Array, private pos = 0, private readonly end = data.length) {}

  get remaining(): number {
    return this.end - this.pos;
  }
  requireEnd(): void {
    if (this.pos !== this.end) this.fail("trailing bytes after frame");
  }
  uint(max = Number.MAX_SAFE_INTEGER): number {
    const v = this.head(MAJOR_UINT);
    if (v > max) this.fail(`integer ${v} above ${max}`);
    return v;
  }
  bool(): boolean {
    const b = this.next();
    if (b === FALSE) return false;
    if (b === TRUE) return true;
    return this.fail(`expected boolean, got 0x${b.toString(16)}`);
  }
  nullNext(): boolean {
    if (this.pos >= this.end) this.fail("truncated");
    if (this.data[this.pos] !== NULL) return false;
    this.pos++;
    return true;
  }
  bytes(maxBytes: number): Uint8Array {
    const n = this.length(MAJOR_BYTES, maxBytes);
    const out = this.data.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  text(maxBytes: number): string {
    const n = this.length(MAJOR_TEXT, maxBytes);
    let s: string;
    try {
      s = decodeUtf8(this.data.subarray(this.pos, this.pos + n));
    } catch {
      return this.fail("text is not valid UTF-8");
    }
    this.pos += n;
    return s;
  }
  textOrNull(maxBytes: number): string | null {
    return this.nullNext() ? null : this.text(maxBytes);
  }
  array(maxCount = Number.MAX_SAFE_INTEGER): number {
    const n = this.head(MAJOR_ARRAY);
    if (n > maxCount) this.fail(`array of ${n} elements above ${maxCount}`);
    if (n > this.remaining) this.fail(`array count ${n} exceeds remaining bytes`);
    return n;
  }

  private length(major: number, maxBytes: number): number {
    const n = this.head(major);
    if (n > maxBytes) this.fail(`string of ${n} bytes above ${maxBytes}`);
    if (n > this.remaining) this.fail(`string length ${n} exceeds remaining bytes`);
    return n;
  }
  private head(expectedMajor: number): number {
    const initial = this.next();
    const major = initial >>> 5;
    if (major !== expectedMajor) this.fail(`expected major type ${expectedMajor}, got ${major}`);
    const info = initial & 0x1f;
    let v: bigint;
    let min: bigint;
    if (info < 24) return info;
    else if (info === 24) { v = this.be(1); min = 24n; }
    else if (info === 25) { v = this.be(2); min = 0x100n; }
    else if (info === 26) { v = this.be(4); min = 0x10000n; }
    else if (info === 27) { v = this.be(8); min = 0x100000000n; }
    else return this.fail(`unsupported additional info ${info} (indefinite or reserved)`);
    if (v < min) this.fail("non-shortest integer encoding");
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) this.fail("integer above 2^53 - 1");
    return Number(v);
  }
  private be(n: number): bigint {
    if (this.remaining < n) this.fail("truncated");
    let v = 0n;
    for (let i = 0; i < n; i++) v = (v << 8n) | BigInt(this.data[this.pos++]);
    return v;
  }
  private next(): number {
    if (this.pos >= this.end) this.fail("truncated");
    return this.data[this.pos++];
  }
  private fail(msg: string): never {
    throw new SandboxProtocolError(msg);
  }
}

// ---------------------------------------------------------------------------------------------
// Frames

export function encodeBody(frame: Frame): Uint8Array {
  const w = new CborWriter();
  const t = FRAME_CODES[frame.type];
  switch (frame.type) {
    case "INIT":
      if (frame.limits.length !== LIMITS_FIELD_COUNT) throw new SandboxProtocolError("limits must have 10 fields");
      if (frame.limits.some((v) => v <= 0)) throw new SandboxProtocolError("sandbox limits must be positive");
      w.array(6).uint(t).uint(frame.callId).uint(frame.protocolVersion).uint(frame.apiLevel).array(LIMITS_FIELD_COUNT);
      frame.limits.forEach((v) => w.uint(v));
      w.text(frame.script);
      break;
    case "INVOKE": w.array(4).uint(t).uint(frame.callId).text(frame.method).text(frame.argsJson); break;
    case "CANCEL": w.array(2).uint(t).uint(frame.callId); break;
    case "BRIDGE_RESULT":
      w.array(4).uint(t).uint(frame.seq);
      if (frame.ok) w.bool(true).textOrNull(frame.json); else w.bool(false).uint(errorCode(frame.code));
      break;
    case "ASYNC_BRIDGE_RESULT":
      w.array(4).uint(t).uint(frame.opId);
      if (frame.ok) w.bool(true).textOrNull(frame.json); else w.bool(false).uint(errorCode(frame.code));
      break;
    case "ASYNC_CANCEL": w.array(2).uint(t).uint(frame.opId); break;
    case "READY": w.array(3).uint(t).uint(frame.callId).uint(frame.protocolVersion); break;
    case "BRIDGE_CALL": w.array(5).uint(t).uint(frame.callId).uint(frame.seq).text(frame.op).text(frame.argsJson); break;
    case "ASYNC_BRIDGE_CALL": w.array(5).uint(t).uint(frame.callId).uint(frame.opId).text(frame.op).text(frame.argsJson); break;
    case "RESULT": w.array(3).uint(t).uint(frame.callId).text(frame.valueJson); break;
    case "FAILURE":
      checkFailure(frame.code, frame.sourceFailure);
      w.array(4).uint(t).uint(frame.callId).uint(frame.code).uint(frame.sourceFailure);
      break;
    case "LOG": w.array(2).uint(t).bytes(frame.bytes); break;
    case "LIMIT_EXCEEDED":
      if (!Object.values(LIMIT_KINDS).includes(frame.kind as never)) throw new SandboxProtocolError("unknown limit kind");
      w.array(3).uint(t).uint(frame.callId).uint(frame.kind);
      break;
  }
  return w.toBytes();
}

function errorCode(code: number): number {
  if (!KNOWN_ERROR_CODES.has(code)) throw new SandboxProtocolError("unknown error code");
  return code;
}

function checkFailure(code: number, marker: number): void {
  errorCode(code);
  if (marker !== 0 && !Object.values(SOURCE_FAILURES).includes(marker as never)) {
    throw new SandboxProtocolError("unknown source failure marker");
  }
  if (marker !== 0 && code !== ERROR_CODES.SCRIPT_ERROR) throw new SandboxProtocolError("source failure marker without SCRIPT_ERROR");
}

export function decodeBody(body: Uint8Array, peer: Peer, limits: FieldLimits = DEFAULT_FIELD_LIMITS): Frame {
  const r = new CborReader(body);
  const n = r.array(8);
  if (n < 1) throw new SandboxProtocolError("empty frame");
  const code = r.uint();
  const type = (Object.keys(FRAME_CODES) as FrameTypeName[]).find((k) => FRAME_CODES[k] === code);
  if (type === undefined) throw new SandboxProtocolError("unknown frame type");
  if (type === "CHUNK") throw new SandboxProtocolError("chunk inside a reassembled frame");
  if (!ACCEPTS[peer].has(code)) throw new SandboxProtocolError(`frame ${type} not accepted by ${peer}`);
  const arity = (want: number) => {
    if (n !== want) throw new SandboxProtocolError(`frame ${type} has ${n} fields, expected ${want}`);
  };
  const outcome = (): { ok: true; json: string | null } | { ok: false; code: number } =>
    r.bool() ? { ok: true, json: r.textOrNull(limits.maxJsonBytes) } : { ok: false, code: errorCode(r.uint(0xffff)) };
  let frame: Frame;
  switch (type) {
    case "INIT": {
      arity(6);
      const callId = r.uint();
      const protocolVersion = r.uint(0xffff);
      const apiLevel = r.uint(0xffff);
      if (r.array(LIMITS_FIELD_COUNT) !== LIMITS_FIELD_COUNT) throw new SandboxProtocolError("limits must have 10 fields");
      const values = Array.from({ length: LIMITS_FIELD_COUNT }, () => r.uint());
      if (values.some((v) => v <= 0)) throw new SandboxProtocolError("limits must be positive");
      frame = { type, callId, protocolVersion, apiLevel, limits: values, script: r.text(limits.maxScriptBytes) };
      break;
    }
    case "INVOKE": arity(4); frame = { type, callId: r.uint(), method: r.text(limits.maxMethodBytes), argsJson: r.text(limits.maxJsonBytes) }; break;
    case "CANCEL": arity(2); frame = { type, callId: r.uint() }; break;
    case "BRIDGE_RESULT": arity(4); frame = { type, seq: r.uint(), ...outcome() }; break;
    case "ASYNC_BRIDGE_RESULT": arity(4); frame = { type, opId: r.uint(), ...outcome() }; break;
    case "ASYNC_CANCEL": arity(2); frame = { type, opId: r.uint() }; break;
    case "READY": arity(3); frame = { type, callId: r.uint(), protocolVersion: r.uint(0xffff) }; break;
    case "BRIDGE_CALL":
      arity(5);
      frame = { type, callId: r.uint(), seq: r.uint(), op: r.text(limits.maxMethodBytes), argsJson: r.text(limits.maxJsonBytes) };
      break;
    case "ASYNC_BRIDGE_CALL":
      arity(5);
      frame = { type, callId: r.uint(), opId: r.uint(), op: r.text(limits.maxMethodBytes), argsJson: r.text(limits.maxJsonBytes) };
      break;
    case "RESULT": arity(3); frame = { type, callId: r.uint(), valueJson: r.text(limits.maxJsonBytes) }; break;
    case "FAILURE": {
      arity(4);
      const callId = r.uint();
      const c = errorCode(r.uint(0xffff));
      const marker = r.uint(0xff);
      checkFailure(c, marker);
      frame = { type, callId, code: c, sourceFailure: marker };
      break;
    }
    case "LOG": arity(2); frame = { type, bytes: r.bytes(limits.maxLogBytes) }; break;
    case "LIMIT_EXCEEDED": {
      arity(3);
      const callId = r.uint();
      const kind = r.uint(0xff);
      if (!Object.values(LIMIT_KINDS).includes(kind as never)) throw new SandboxProtocolError("unknown limit kind");
      frame = { type, callId, kind };
      break;
    }
  }
  r.requireEnd();
  return frame;
}

function envelope(body: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + body.length);
  new DataView(out.buffer).setUint32(0, body.length, false);
  out.set(body, 4);
  return out;
}

/** One envelope, or a canonical CHUNK sequence when the body exceeds [MAX_FRAME_BYTES]. */
export function encodeFrame(frame: Frame): Uint8Array[] {
  const body = encodeBody(frame);
  if (body.length <= MAX_FRAME_BYTES) return [envelope(body)];
  const out: Uint8Array[] = [];
  for (let off = 0; off < body.length; off += CHUNK_PAYLOAD_BYTES) {
    const n = Math.min(CHUNK_PAYLOAD_BYTES, body.length - off);
    const more = off + n < body.length;
    const chunk = new CborWriter().array(3).uint(0).bool(more).bytes(body.subarray(off, off + n)).toBytes();
    if (chunk.length > MAX_FRAME_BYTES) throw new SandboxProtocolError("chunk above frame limit");
    out.push(envelope(chunk));
  }
  return out;
}

/**
 * Streaming reader: accepts arbitrary byte slices, yields complete frames, reassembles CHUNK
 * sequences up to [maxMessageBytes] with the same canonical-split rules as the app.
 */
export class FrameStreamReader {
  private pending = new Uint8Array(0);
  private chunks: Uint8Array[] | null = null;
  private chunkBytes = 0;

  constructor(
    private readonly peer: Peer,
    private readonly maxMessageBytes = 16 << 20,
    private readonly limits: FieldLimits = DEFAULT_FIELD_LIMITS,
  ) {}

  get idle(): boolean {
    return this.pending.length === 0 && this.chunks === null;
  }

  push(bytes: Uint8Array): Frame[] {
    const merged = new Uint8Array(this.pending.length + bytes.length);
    merged.set(this.pending);
    merged.set(bytes, this.pending.length);
    const frames: Frame[] = [];
    let off = 0;
    while (merged.length - off >= 4) {
      const n = new DataView(merged.buffer, merged.byteOffset + off).getUint32(0, false);
      if (n > MAX_FRAME_BYTES) throw new SandboxProtocolError(`envelope of ${n} bytes above ${MAX_FRAME_BYTES}`);
      if (n === 0) throw new SandboxProtocolError("empty envelope");
      if (merged.length - off - 4 < n) break;
      const body = merged.subarray(off + 4, off + 4 + n);
      off += 4 + n;
      const frame = this.onBody(body);
      if (frame) frames.push(frame);
    }
    this.pending = merged.slice(off);
    return frames;
  }

  private onBody(body: Uint8Array): Frame | null {
    if (body[0] === 0x83 && body[1] === 0x00) {
      const r = new CborReader(body);
      if (r.array(3) !== 3) throw new SandboxProtocolError("chunk must have 3 fields");
      r.uint();
      const more = r.bool();
      const part = r.bytes(CHUNK_PAYLOAD_BYTES);
      r.requireEnd();
      if (part.length === 0) throw new SandboxProtocolError("empty chunk");
      if (more && part.length !== CHUNK_PAYLOAD_BYTES) throw new SandboxProtocolError(`non-final chunk of ${part.length} bytes`);
      if (this.chunkBytes + part.length > this.maxMessageBytes) throw new SandboxProtocolError(`message above ${this.maxMessageBytes} bytes`);
      (this.chunks ??= []).push(part);
      this.chunkBytes += part.length;
      if (more) return null;
      const whole = new Uint8Array(this.chunkBytes);
      let o = 0;
      for (const c of this.chunks) { whole.set(c, o); o += c.length; }
      this.chunks = null;
      this.chunkBytes = 0;
      if (whole.length <= MAX_FRAME_BYTES) throw new SandboxProtocolError("needlessly chunked frame");
      return decodeBody(whole, this.peer, this.limits);
    }
    if (this.chunks !== null) throw new SandboxProtocolError("frame interleaved with a chunk sequence");
    return decodeBody(body, this.peer, this.limits);
  }
}
