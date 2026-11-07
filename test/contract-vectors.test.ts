// Shared byte-level contract with the Shinsou X app (fixtures copied from
// shinsoux/fixtures/plugin-contract/v1). A failure here means the wire protocol changed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { base64UrlEncode, fromHex, toHex, utf8 } from "../src/core/bytes.ts";
import { canonicalJson, parseStrictJson, type JsonObject, type JsonValue } from "../src/core/canonical-json.ts";
import { displayFingerprint, fingerprint, publicKeyFromSeed, sha256Hex } from "../src/core/crypto.ts";
import { SIGNATURE_DOMAIN, signEnvelope, signingMessage, TrustError, verifyEnvelope, type PayloadType } from "../src/core/envelope.ts";
import { ROTATION_DOMAIN, rotationPayload, rotationStatement, verifyRotationPayload } from "../src/core/publisher.ts";

const dir = new URL("./fixtures/contract-v1/", import.meta.url);
const load = (name: string) => JSON.parse(readFileSync(new URL(name, dir), "utf8"));
const keys = load("keys.json");
const canonical = load("canonical-json.json");
const envelopes = load("envelopes.json");

const keyByName = new Map<string, { seed: Uint8Array; publicKey: string; fingerprint: string }>();
for (const k of keys.keys) keyByName.set(k.name, { seed: fromHex(k.seedHex), publicKey: k.publicKey, fingerprint: k.fingerprint });

test("test seeds are SHA-256 of their labels", () => {
  for (const k of keys.keys) assert.equal(sha256Hex(utf8(k.seedLabel)), k.seedHex);
});

test("public keys, full fingerprints and display fingerprints match", () => {
  for (const k of keys.keys) {
    const pk = publicKeyFromSeed(fromHex(k.seedHex));
    assert.equal(base64UrlEncode(pk), k.publicKey, k.name);
    assert.equal(fingerprint(pk), k.fingerprint, k.name);
    assert.equal(displayFingerprint(pk), k.displayFingerprint, k.name);
  }
});

for (const c of canonical.valid) {
  test(`canonical JSON accepts ${c.name}`, () => {
    const out = canonicalJson(parseStrictJson(c.json));
    assert.equal(out, c.canonical);
    assert.equal(sha256Hex(utf8(out)), c.sha256Hex);
  });
}

for (const c of canonical.invalid) {
  test(`canonical JSON rejects ${c.name}`, () => {
    assert.throws(() => canonicalJson(parseStrictJson(c.json)));
  });
}

test("canonical JSON rejects -0 and fractions given as JS numbers", () => {
  assert.throws(() => canonicalJson(-0));
  assert.throws(() => canonicalJson(1.5));
  assert.throws(() => canonicalJson(2 ** 53));
});

for (const v of envelopes.valid) {
  test(`envelope ${v.name} is reproduced byte for byte`, () => {
    const signer = keyByName.get(v.signer)!;
    const payload = v.envelope.payload as JsonValue;
    const message = signingMessage({
      repository: v.repository,
      payloadType: v.payloadType,
      documentId: v.documentId,
      sequence: v.sequence,
      keyFingerprint: signer.fingerprint,
      payload,
    });
    assert.equal(Buffer.from(message).toString("base64"), Buffer.from(v.signingMessageBase64, "base64").toString("base64"));
    assert.equal(sha256Hex(message), v.signingMessageSha256Hex);
    assert.equal(sha256Hex(utf8(canonicalJson(payload))), v.payloadCanonicalSha256Hex);

    if (v.payloadType === "publisher-key-rotation") {
      // Rebuild the payload from the seeds too: newKeySignature must be reproducible.
      const rebuilt = rotationPayload({
        publisherId: (payload as JsonObject).publisherId as string,
        oldKeyFingerprint: signer.fingerprint,
        newSeed: keyByName.get(envelopes.rotationStatement.newKey)!.seed,
        effectiveSequence: (payload as JsonObject).effectiveSequence as number,
      });
      assert.deepEqual(rebuilt, payload);
      assert.deepEqual(Object.keys(rebuilt), Object.keys(payload as JsonObject));
    }

    const env = signEnvelope({
      seed: signer.seed,
      repository: v.repository,
      payloadType: v.payloadType,
      documentId: v.documentId,
      sequence: v.sequence,
      payload,
    });
    assert.deepEqual(Object.keys(env), Object.keys(v.envelope), "field order");
    assert.equal(canonicalJson(env as unknown as JsonValue), canonicalJson(v.envelope));
    assert.equal(JSON.stringify(env), JSON.stringify(v.envelope));

    const verified = verifyEnvelope({
      envelope: v.envelope,
      repository: v.repository,
      payloadType: v.payloadType,
      documentId: v.documentId,
      pinned: { publicKey: signer.publicKey, fingerprint: signer.fingerprint },
    });
    assert.equal(verified.sequence, v.sequence);
  });
}

for (const v of envelopes.invalid) {
  test(`envelope ${v.name} is rejected as ${v.expectedError}`, () => {
    const pinned = keyByName.get(v.pinnedKey)!;
    assert.throws(
      () =>
        verifyEnvelope({
          envelope: v.envelope,
          repository: v.repository,
          payloadType: v.payloadType as PayloadType,
          documentId: v.documentId,
          pinned: { publicKey: pinned.publicKey, fingerprint: pinned.fingerprint },
        }),
      (err: unknown) => err instanceof TrustError && err.category === v.expectedError,
    );
  });
}

test("rotation statement matches the vector", () => {
  const r = envelopes.rotationStatement;
  const b = keyByName.get(r.newKey)!;
  const message = rotationStatement({
    publisherId: r.publisherId,
    oldKeyFingerprint: r.oldKeyFingerprint,
    newPublicKey: b.publicKey,
    newKeyFingerprint: b.fingerprint,
    effectiveSequence: r.effectiveSequence,
  });
  assert.equal(base64UrlEncode(message), r.messageBase64.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_"));
  assert.equal(toHex(message), toHex(new Uint8Array(Buffer.from(r.messageBase64, "base64"))));
  const rotation = envelopes.valid.find((v: { payloadType: string }) => v.payloadType === "publisher-key-rotation");
  assert.ok(verifyRotationPayload(rotation.envelope.payload, r.oldKeyFingerprint));
});

test("domain separators match the vectors", () => {
  // The fixture spells the NUL separator as the six characters `\u0000`.
  const nul = (s: string) => s.replace("\\u0000", "\u0000");
  assert.equal(nul(envelopes.signatureDomain), SIGNATURE_DOMAIN);
  assert.equal(nul(envelopes.rotationDomain), ROTATION_DOMAIN);
});
