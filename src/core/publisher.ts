/** Publisher documents (ADR-0002 §8.3–§8.4, §20.2): rotation, revocations, key self-revocation. */

import { base64UrlDecodeCanonical, base64UrlEncode, concatBytes, utf8 } from "./bytes.ts";
import { canonicalJson, type JsonObject } from "./canonical-json.ts";
import { fingerprint, publicKeyFromSeed, signEd25519, verifyEd25519 } from "./crypto.ts";

export const ROTATION_DOMAIN = "dev.shinsou.publisher.rotation.v1\u0000";
export const SHA256_HEX = /^[0-9a-f]{64}$/;
export const MAX_REVOKED_ARTIFACTS = 4096;
export const DEFAULT_REVOCATIONS_TTL_SECONDS = 30 * 24 * 60 * 60;

export function rotationStatement(args: {
  publisherId: string;
  oldKeyFingerprint: string;
  newPublicKey: string;
  newKeyFingerprint: string;
  effectiveSequence: number;
}): Uint8Array {
  if (!Number.isSafeInteger(args.effectiveSequence) || args.effectiveSequence < 0) {
    throw new Error("effectiveSequence must be a non-negative integer");
  }
  const body: JsonObject = {
    effectiveSequence: args.effectiveSequence,
    newKeyFingerprint: args.newKeyFingerprint,
    newPublicKey: args.newPublicKey,
    oldKeyFingerprint: args.oldKeyFingerprint,
    publisherId: args.publisherId,
  };
  return concatBytes(utf8(ROTATION_DOMAIN), utf8(canonicalJson(body)));
}

/**
 * The rotation payload: the envelope around it is signed by the OLD key; `newKeySignature` is the
 * NEW key's signature over [rotationStatement], proving it agreed to take over.
 */
export function rotationPayload(args: {
  publisherId: string;
  oldKeyFingerprint: string;
  newSeed: Uint8Array;
  effectiveSequence: number;
}): JsonObject {
  const newPublicKeyBytes = publicKeyFromSeed(args.newSeed);
  const newPublicKey = base64UrlEncode(newPublicKeyBytes);
  const newKeyFingerprint = fingerprint(newPublicKeyBytes);
  const statement = rotationStatement({
    publisherId: args.publisherId,
    oldKeyFingerprint: args.oldKeyFingerprint,
    newPublicKey,
    newKeyFingerprint,
    effectiveSequence: args.effectiveSequence,
  });
  return {
    publisherId: args.publisherId,
    newPublicKey,
    newKeyFingerprint,
    effectiveSequence: args.effectiveSequence,
    newKeySignature: base64UrlEncode(signEd25519(statement, args.newSeed)),
  };
}

export function verifyRotationPayload(payload: JsonObject, oldKeyFingerprint: string): boolean {
  const newPublicKey = base64UrlDecodeCanonical(String(payload.newPublicKey), 32);
  if (fingerprint(newPublicKey) !== payload.newKeyFingerprint) return false;
  const statement = rotationStatement({
    publisherId: String(payload.publisherId),
    oldKeyFingerprint,
    newPublicKey: String(payload.newPublicKey),
    newKeyFingerprint: String(payload.newKeyFingerprint),
    effectiveSequence: Number(payload.effectiveSequence),
  });
  return verifyEd25519(base64UrlDecodeCanonical(String(payload.newKeySignature), 64), statement, newPublicKey);
}

export function revocationsPayload(args: { publisherId: string; revokedArtifacts: string[]; expiresAt: number }): JsonObject {
  const artifacts = [...new Set(args.revokedArtifacts)];
  for (const a of artifacts) if (!SHA256_HEX.test(a)) throw new Error(`Revoked artifact must be lowercase SHA-256 hex: ${a}`);
  if (artifacts.length > MAX_REVOKED_ARTIFACTS) throw new Error(`At most ${MAX_REVOKED_ARTIFACTS} revoked artifacts`);
  if (!Number.isSafeInteger(args.expiresAt) || args.expiresAt <= 0) throw new Error("expiresAt must be Unix seconds");
  return { publisherId: args.publisherId, revokedArtifacts: artifacts, expiresAt: args.expiresAt };
}

export function keyRevokedPayload(args: { publisherId: string; revokedKeyFingerprint: string }): JsonObject {
  return { publisherId: args.publisherId, revokedKeyFingerprint: args.revokedKeyFingerprint };
}
