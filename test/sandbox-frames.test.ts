import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { decode as cborXDecode } from "cbor-x";
import { fromHex, toHex } from "../src/core/bytes.ts";
import {
  CHUNK_PAYLOAD_BYTES,
  decodeBody,
  encodeBody,
  encodeFrame,
  FrameStreamReader,
  MAX_FRAME_BYTES,
  PROTOCOL_VERSION,
  SandboxProtocolError,
  type Frame,
  type Peer,
} from "../src/core/sandbox-protocol.ts";

const vectors = JSON.parse(readFileSync(new URL("./fixtures/contract-v1/sandbox-frames.json", import.meta.url), "utf8"));

function frameFromVector(f: Record<string, unknown>): Frame {
  if (f.type === "LOG") return { type: "LOG", bytes: fromHex(f.bytesHex as string) };
  return f as unknown as Frame;
}

function frameToVector(f: Frame): Record<string, unknown> {
  if (f.type === "LOG") return { type: "LOG", bytesHex: toHex(f.bytes) };
  return f as unknown as Record<string, unknown>;
}

const readerOf = (direction: string): Peer => (direction === "host-to-sandbox" ? "sandbox" : "host");

test("protocol constants match the vectors", () => {
  assert.equal(vectors.protocolVersion, PROTOCOL_VERSION);
  assert.equal(vectors.maxFrameBytes, MAX_FRAME_BYTES);
  assert.equal(vectors.chunkPayloadBytes, CHUNK_PAYLOAD_BYTES);
});

for (const v of vectors.frames) {
  test(`frame ${v.name} round-trips exactly`, () => {
    const frame = frameFromVector(v.frame);
    const body = encodeBody(frame);
    assert.equal(toHex(body), v.bodyHex, "encoded body");
    const envelopes = encodeFrame(frame);
    assert.equal(envelopes.length, 1);
    assert.equal(toHex(envelopes[0]), v.envelopeHex, "envelope");

    const peer = readerOf(v.direction);
    const decoded = decodeBody(fromHex(v.bodyHex), peer);
    assert.deepEqual(frameToVector(decoded), v.frame, "decoded frame");
    assert.equal(toHex(encodeBody(decoded)), v.bodyHex, "re-encoded body");

    // Stream reader, fed one byte at a time.
    const reader = new FrameStreamReader(peer);
    const out: Frame[] = [];
    for (const b of fromHex(v.envelopeHex)) out.push(...reader.push(Uint8Array.of(b)));
    assert.equal(out.length, 1);
    assert.deepEqual(frameToVector(out[0]), v.frame);
    assert.ok(reader.idle);

    // The opposite side must refuse it.
    assert.throws(() => decodeBody(fromHex(v.bodyHex), peer === "host" ? "sandbox" : "host"), SandboxProtocolError);

    // An independent CBOR decoder agrees on the structure.
    const generic = cborXDecode(Buffer.from(fromHex(v.bodyHex)));
    assert.ok(Array.isArray(generic));
  });
}

test("rejects non-shortest integers, maps, negatives, floats, indefinite lengths and trailing bytes", () => {
  const bad = [
    "83181001", // READY type 16 spelled 0x18 0x10 (non-shortest)
    "a0", // map
    "8320", // negative
    "f97e00", // float
    "9f10ff", // indefinite array
    "83100101ff", // trailing byte
    "8310011801", // non-shortest 1
  ];
  for (const hex of bad) assert.throws(() => decodeBody(fromHex(hex), "host"), SandboxProtocolError, hex);
});

test("FAILURE marker requires SCRIPT_ERROR", () => {
  assert.throws(() => encodeBody({ type: "FAILURE", callId: 1, code: 4, sourceFailure: 1 }), SandboxProtocolError);
  assert.throws(() => decodeBody(fromHex("8414020401"), "host"), SandboxProtocolError);
  assert.throws(() => decodeBody(fromHex("8414020109"), "host"), SandboxProtocolError);
});

test("large frames are chunked canonically and reassembled", () => {
  const script = "x".repeat(MAX_FRAME_BYTES * 2 + 123);
  const frame: Frame = { type: "INIT", callId: 9, protocolVersion: 1, apiLevel: 1, limits: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], script };
  const envelopes = encodeFrame(frame);
  assert.equal(envelopes.length, 3);
  for (const e of envelopes) assert.ok(e.length - 4 <= MAX_FRAME_BYTES);
  const reader = new FrameStreamReader("sandbox", 8 << 20);
  const frames = envelopes.flatMap((e) => reader.push(e));
  assert.equal(frames.length, 1);
  assert.deepEqual(frames[0], frame);
});

test("rejects needless chunking and frames interleaved with a chunk sequence", () => {
  const small = new Uint8Array(10);
  const chunk = (more: boolean, part: Uint8Array) => {
    const body = Buffer.concat([Buffer.from([0x83, 0x00, more ? 0xf5 : 0xf4, 0x4a]), Buffer.from(part)]);
    const env = Buffer.alloc(4 + body.length);
    env.writeUInt32BE(body.length);
    body.copy(env, 4);
    return new Uint8Array(env);
  };
  assert.throws(() => new FrameStreamReader("sandbox").push(chunk(true, small)), SandboxProtocolError);
  assert.throws(() => new FrameStreamReader("sandbox").push(chunk(false, small)), SandboxProtocolError);
});
