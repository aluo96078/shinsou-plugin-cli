/** Ed25519 + SHA-256 primitives and the publisher fingerprint formats. */

import * as ed from "@noble/ed25519";
import { sha256 as nobleSha256, sha512 } from "@noble/hashes/sha2.js";
import { base64UrlEncode, toHex } from "./bytes.ts";

ed.hashes.sha512 = sha512;

export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

export function sha256Hex(data: Uint8Array): string {
  return toHex(sha256(data));
}

export function publicKeyFromSeed(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new Error("Ed25519 seed must be 32 bytes");
  return ed.getPublicKey(seed);
}

export function signEd25519(message: Uint8Array, seed: Uint8Array): Uint8Array {
  return ed.sign(message, seed);
}

/** Strict verification (no ZIP-215 leniency), like libsodium's `crypto_sign_verify_detached`. */
export function verifyEd25519(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

export function randomSeed(): Uint8Array {
  return ed.utils.randomSecretKey();
}

/** Full fingerprint: `sha256:` + unpadded base64url of SHA-256(publicKey). Compare with this value. */
export function fingerprint(publicKey: Uint8Array): string {
  return "sha256:" + base64UrlEncode(sha256(publicKey));
}

/** Display form: first 16 bytes of SHA-256(publicKey), uppercase hex, groups of 4 characters. */
export function displayFingerprint(publicKey: Uint8Array): string {
  const hex = toHex(sha256(publicKey).subarray(0, 16)).toUpperCase();
  return hex.match(/.{4}/g)!.join(" ");
}
