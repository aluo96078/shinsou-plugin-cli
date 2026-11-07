/**
 * `shinsou-signed-envelope-v1`: byte-for-byte the format verified by the app's
 * `RepositorySignedDocumentVerifier` (RepositoryTrust.kt) and fixed by the shared contract vectors.
 */

import { base64UrlDecodeCanonical, base64UrlEncode, bytesEqual, concatBytes, utf8 } from "./bytes.ts";
import { canonicalJson, type JsonObject, type JsonValue } from "./canonical-json.ts";
import { fingerprint, publicKeyFromSeed, signEd25519, verifyEd25519 } from "./crypto.ts";

export const ENVELOPE_FORMAT = "shinsou-signed-envelope-v1";
export const SIGNATURE_DOMAIN = "dev.shinsou.repository.signature.v1\u0000";

export const PAYLOAD_TYPES = [
  "repository-meta",
  "repository-index",
  "repository-legacy-index",
  "plugin-sidecar",
  "publisher-key-rotation",
  "publisher-revocations",
  "publisher-key-revoked",
] as const;
export type PayloadType = (typeof PAYLOAD_TYPES)[number];

/** Fixed document ids; sidecars use their repository-relative path, e.g. `sidecars/example.novel.json`. */
export const DOCUMENT_IDS = {
  repo: "repo.json",
  index: "index.json",
  legacyIndex: "index.min.json",
  rotation: "publisher-key-rotation.json",
  revocations: "publisher-revocations.json",
  keyRevoked: "publisher-key-revoked.json",
} as const;

const ENVELOPE_FIELDS = ["format", "algorithm", "keyFingerprint", "publicKey", "payloadType", "sequence", "payload", "signature"];

export interface SignedEnvelope {
  format: typeof ENVELOPE_FORMAT;
  algorithm: "Ed25519";
  keyFingerprint: string;
  publicKey: string;
  payloadType: PayloadType;
  sequence: number;
  payload: JsonValue;
  signature: string;
}

/** Error categories shared with the app (`RepositoryTrustException` subclasses). */
export type TrustErrorCategory = "Malformed" | "KeySubstitution" | "InvalidSignature";

export class TrustError extends Error {
  constructor(readonly category: TrustErrorCategory, message: string) {
    super(`${category}: ${message}`);
  }
}

/**
 * Same normalization as the app's repository client: trim, drop trailing `/`, no query or fragment,
 * scheme + host lower-cased by URL parsing, path kept as-is.
 */
export function normalizeRepositoryUrl(value: string, { allowHttp = false } = {}): string {
  const trimmed = value.trim().replace(/\/+$/, "");
  if (trimmed.includes("?") || trimmed.includes("#")) throw new Error(`Repository URL must not have a query or fragment: ${value}`);
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`Invalid repository URL: ${value}`);
  }
  if (parsed.protocol !== "https:" && !(allowHttp && parsed.protocol === "http:")) {
    throw new Error(`Repository URL must use HTTPS: ${value}`);
  }
  if (parsed.username || parsed.password) throw new Error(`Repository URL must not contain credentials: ${value}`);
  const path = parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/+$/, "");
  if (path.split("/").some((s) => s === "." || s === "..")) throw new Error(`Repository URL must not contain dot segments: ${value}`);
  return parsed.origin + path;
}

export function signingMessage(args: {
  repository: string;
  payloadType: PayloadType;
  documentId: string;
  sequence: number;
  keyFingerprint: string;
  payload: JsonValue;
}): Uint8Array {
  if (!Number.isSafeInteger(args.sequence) || args.sequence < 0) throw new Error("Repository sequence must be non-negative");
  if (!args.documentId.trim() || args.documentId.length > 512) throw new Error("Invalid repository document id");
  const statement: JsonObject = {
    algorithm: "Ed25519",
    documentId: args.documentId,
    format: ENVELOPE_FORMAT,
    keyFingerprint: args.keyFingerprint,
    payload: args.payload,
    payloadType: args.payloadType,
    repository: args.repository,
    sequence: args.sequence,
  };
  return concatBytes(utf8(SIGNATURE_DOMAIN), utf8(canonicalJson(statement)));
}

export function signEnvelope(args: {
  seed: Uint8Array;
  repository: string;
  payloadType: PayloadType;
  documentId: string;
  sequence: number;
  payload: JsonValue;
}): SignedEnvelope {
  const publicKey = publicKeyFromSeed(args.seed);
  const keyFingerprint = fingerprint(publicKey);
  if (args.payloadType === "repository-meta") {
    const advertised = metaFingerprint(args.payload);
    if (advertised !== keyFingerprint) {
      throw new Error("repo.json meta.signingKeyFingerprint must equal the signing key fingerprint");
    }
  }
  const message = signingMessage({ ...args, keyFingerprint });
  return {
    format: ENVELOPE_FORMAT,
    algorithm: "Ed25519",
    keyFingerprint,
    publicKey: base64UrlEncode(publicKey),
    payloadType: args.payloadType,
    sequence: args.sequence,
    payload: args.payload,
    signature: base64UrlEncode(signEd25519(message, args.seed)),
  };
}

function metaFingerprint(payload: JsonValue): string | undefined {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return undefined;
  const meta = (payload as JsonObject).meta;
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) return undefined;
  const fp = (meta as JsonObject).signingKeyFingerprint;
  return typeof fp === "string" ? fp : undefined;
}

export interface PinnedKey {
  publicKey: string;
  fingerprint: string;
}

/**
 * Verifies [envelope] the way the app does, in the same order, so a broken envelope fails with the
 * same category: shape → pinned key → repo.json fingerprint binding → signature.
 */
export function verifyEnvelope(args: {
  envelope: unknown;
  repository: string;
  payloadType: PayloadType;
  documentId: string;
  pinned: PinnedKey;
}): { payload: JsonValue; sequence: number } {
  const env = args.envelope;
  const malformed = (msg: string): never => {
    throw new TrustError("Malformed", msg);
  };
  if (!env || typeof env !== "object" || Array.isArray(env)) return malformed("Envelope is not an object");
  const e = env as Record<string, unknown>;
  const keys = Object.keys(e);
  if (keys.length !== ENVELOPE_FIELDS.length || !ENVELOPE_FIELDS.every((k) => keys.includes(k))) {
    malformed("Unknown or missing signed-envelope field");
  }
  const str = (k: string): string => {
    const v = e[k];
    if (typeof v !== "string" || !v.trim()) malformed(`Missing '${k}'`);
    return v as string;
  };
  if (str("format") !== ENVELOPE_FORMAT) malformed("Unexpected envelope format");
  if (str("algorithm") !== "Ed25519") malformed("Unexpected algorithm");
  if (str("payloadType") !== args.payloadType) malformed("Unexpected payload type");
  const sequence = e.sequence;
  if (typeof sequence !== "number" || !Number.isSafeInteger(sequence)) malformed("Missing signed-envelope sequence");
  if ((sequence as number) < 0) malformed("Repository sequence must be non-negative");
  let wirePublicKey: Uint8Array, wireSignature: Uint8Array, pinnedPublicKey: Uint8Array;
  try {
    wirePublicKey = base64UrlDecodeCanonical(str("publicKey"), 32);
    wireSignature = base64UrlDecodeCanonical(str("signature"), 64);
    pinnedPublicKey = base64UrlDecodeCanonical(args.pinned.publicKey, 32);
  } catch (err) {
    if (err instanceof TrustError) throw err;
    return malformed((err as Error).message);
  }
  const wireFingerprint = str("keyFingerprint");
  const calculated = fingerprint(pinnedPublicKey);
  if (args.pinned.fingerprint !== calculated || wireFingerprint !== calculated || !bytesEqual(wirePublicKey, pinnedPublicKey)) {
    throw new TrustError("KeySubstitution", "Repository signing key does not match its pinned trust root");
  }
  const payload = e.payload as JsonValue;
  if (args.payloadType === "repository-meta" && metaFingerprint(payload) !== wireFingerprint) {
    malformed("Repository metadata signing fingerprint does not match the authenticated key");
  }
  let message: Uint8Array;
  try {
    message = signingMessage({
      repository: args.repository,
      payloadType: args.payloadType,
      documentId: args.documentId,
      sequence: sequence as number,
      keyFingerprint: wireFingerprint,
      payload,
    });
  } catch (err) {
    return malformed((err as Error).message);
  }
  if (!verifyEd25519(wireSignature, message, pinnedPublicKey)) {
    throw new TrustError("InvalidSignature", "Invalid repository author signature");
  }
  return { payload, sequence: sequence as number };
}
