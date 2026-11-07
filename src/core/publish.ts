/**
 * `sign`, `rotate`, `revoke`, `revoke-key`, `refresh`: produce signed repositories, one per mirror.
 *
 * Signatures bind the repository URL, so every mirror gets its own copy under
 * `<out>/<mirror-slug>/`. Sequences are per document and shared by all mirrors (the app keeps one
 * watermark per publisher), recorded in `.shinsou/state.json`.
 */

import { copyFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { JsonObject, JsonValue } from "./canonical-json.ts";
import { buildProject } from "./build.ts";
import { DOCUMENT_IDS, normalizeRepositoryUrl, signEnvelope, verifyEnvelope, type PayloadType } from "./envelope.ts";
import type { LoadedKey } from "./keystore.ts";
import { loadManifest, repoMetaDocument, scriptUrl, sidecarUrl } from "./manifest.ts";
import { DEFAULT_REVOCATIONS_TTL_SECONDS, keyRevokedPayload, revocationsPayload, rotationPayload, SHA256_HEX } from "./publisher.ts";
import { loadState, nextSequence, saveState, type PublishState } from "./state.ts";

export const DEFAULT_PUBLIC_DIR = "public";

interface Doc {
  documentId: string;
  payloadType: PayloadType;
  payload: JsonValue;
}

export interface SignedOutput {
  mirror: string;
  dir: string;
  documents: { documentId: string; sequence: number }[];
}

export function mirrorSlug(normalizedUrl: string): string {
  return normalizedUrl.replace(/^https:\/\//, "").replace(/[^A-Za-z0-9.-]+/g, "_");
}

export function resolveMirrors(projectDir: string, mirrors: string[] | undefined): string[] {
  const list = mirrors?.length ? mirrors : loadManifest(projectDir).repository.mirrors;
  if (!list.length) throw new Error("No mirror URL: pass --mirror <https://…> or set repository.mirrors in shinsou.plugin.json");
  return [...new Set(list.map((m) => normalizeRepositoryUrl(m)))];
}

/** Adopt [key] as the publisher key on first use; afterwards only the state's current key may sign. */
function requireSigningKey(state: PublishState, key: LoadedKey): void {
  if (!state.publisherId || !state.currentKey) {
    state.publisherId = key.fingerprint;
    state.currentKey = { name: key.name, publicKey: key.publicKey, fingerprint: key.fingerprint };
    return;
  }
  if (state.keyRevoked) throw new Error("The publisher key was revoked; publish under a new key (users must trust it again)");
  if (state.currentKey.fingerprint !== key.fingerprint) {
    const retired = state.retiredKeys.some((k) => k.fingerprint === key.fingerprint);
    throw new Error(
      `${key.name} (${key.fingerprint}) is ${retired ? "a retired key" : "not this repository's key"}; ` +
        `the current key is '${state.currentKey.name}' (${state.currentKey.fingerprint}). Use 'rotate' to change keys.`,
    );
  }
}

function revocationsDoc(state: PublishState, opts: { refresh: boolean; ttlSeconds: number; now: number }): Doc {
  const previous = state.documents[DOCUMENT_IDS.revocations];
  const half = Math.floor(opts.ttlSeconds / 2);
  // Keep the current expiry unless asked to refresh or it is past half its lifetime.
  const keep = !opts.refresh && previous?.expiresAt !== undefined && previous.expiresAt - opts.now > half;
  const expiresAt = keep ? previous!.expiresAt! : opts.now + opts.ttlSeconds;
  return {
    documentId: DOCUMENT_IDS.revocations,
    payloadType: "publisher-revocations",
    payload: revocationsPayload({ publisherId: state.publisherId!, revokedArtifacts: state.revokedArtifacts, expiresAt }),
  };
}

function signDocs(args: {
  state: PublishState;
  key: LoadedKey;
  mirrors: string[];
  docs: Doc[];
  outDir: string;
  copy?: Record<string, string>;
}): SignedOutput[] {
  const sequences = args.docs.map((d) => nextSequence(args.state, d.documentId, d.payload));
  const outputs: SignedOutput[] = [];
  for (const mirror of args.mirrors) {
    const dir = join(args.outDir, mirrorSlug(mirror));
    const documents: SignedOutput["documents"] = [];
    args.docs.forEach((d, i) => {
      const envelope = signEnvelope({
        seed: args.key.seed,
        repository: mirror,
        payloadType: d.payloadType,
        documentId: d.documentId,
        sequence: sequences[i],
        payload: d.payload,
      });
      // Self-check with the same verifier the tests hold to the app's vectors.
      verifyEnvelope({
        envelope,
        repository: mirror,
        payloadType: d.payloadType,
        documentId: d.documentId,
        pinned: { publicKey: args.key.publicKey, fingerprint: args.key.fingerprint },
      });
      const target = join(dir, d.documentId);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, JSON.stringify(envelope, null, 2) + "\n");
      documents.push({ documentId: d.documentId, sequence: sequences[i] });
    });
    for (const [rel, from] of Object.entries(args.copy ?? {})) {
      const target = join(dir, rel);
      mkdirSync(dirname(target), { recursive: true });
      copyFileSync(from, target);
    }
    outputs.push({ mirror, dir, documents });
  }
  if (args.docs.some((d) => d.documentId === DOCUMENT_IDS.revocations)) {
    const rev = args.docs.find((d) => d.documentId === DOCUMENT_IDS.revocations)!.payload as JsonObject;
    args.state.documents[DOCUMENT_IDS.revocations].expiresAt = rev.expiresAt as number;
  }
  return outputs;
}

export async function signRepository(args: {
  projectDir: string;
  key: LoadedKey;
  mirrors?: string[];
  outDir?: string;
  ttlSeconds?: number;
  now?: number;
}): Promise<SignedOutput[]> {
  const state = loadState(args.projectDir);
  requireSigningKey(state, args.key);
  saveState(args.projectDir, state); // build embeds the fingerprint in repo.json
  const built = await buildProject(args.projectDir);
  const mirrors = resolveMirrors(args.projectDir, args.mirrors);
  const m = built.manifest;
  const docs: Doc[] = [
    { documentId: DOCUMENT_IDS.repo, payloadType: "repository-meta", payload: repoMetaDocument(m, args.key.fingerprint) },
    { documentId: DOCUMENT_IDS.index, payloadType: "repository-index", payload: built.index },
    { documentId: sidecarUrl(m), payloadType: "plugin-sidecar", payload: built.sidecar },
    revocationsDoc(state, { refresh: false, ttlSeconds: args.ttlSeconds ?? DEFAULT_REVOCATIONS_TTL_SECONDS, now: args.now ?? nowSeconds() }),
  ];
  const outputs = signDocs({
    state,
    key: args.key,
    mirrors,
    docs,
    outDir: join(args.projectDir, args.outDir ?? DEFAULT_PUBLIC_DIR),
    copy: { [scriptUrl(m)]: join(built.outDir, scriptUrl(m)) },
  });
  saveState(args.projectDir, state);
  return outputs;
}

/** Re-sign `publisher-revocations.json` (new expiry, current list). For CI: no build needed. */
export function refreshRevocations(args: {
  projectDir: string;
  key: LoadedKey;
  mirrors?: string[];
  outDir?: string;
  ttlSeconds?: number;
  now?: number;
  add?: string[];
}): SignedOutput[] {
  const state = loadState(args.projectDir);
  if (!state.publisherId) throw new Error("Nothing signed yet: run 'shinsou-plugin sign' first");
  requireSigningKey(state, args.key);
  for (const raw of args.add ?? []) {
    const digest = raw.toLowerCase().replace(/^sha256:/, "");
    if (!SHA256_HEX.test(digest)) throw new Error(`Not a SHA-256 hex digest: ${raw}`);
    if (!state.revokedArtifacts.includes(digest)) state.revokedArtifacts.push(digest);
  }
  const outputs = signDocs({
    state,
    key: args.key,
    mirrors: resolveMirrors(args.projectDir, args.mirrors),
    docs: [revocationsDoc(state, { refresh: true, ttlSeconds: args.ttlSeconds ?? DEFAULT_REVOCATIONS_TTL_SECONDS, now: args.now ?? nowSeconds() })],
    outDir: join(args.projectDir, args.outDir ?? DEFAULT_PUBLIC_DIR),
  });
  saveState(args.projectDir, state);
  return outputs;
}

/**
 * Key rotation: the OLD key signs the envelope, the NEW key signs the rotation statement
 * (`newKeySignature`). Then everything is re-signed with the new key.
 */
export async function rotateKey(args: {
  projectDir: string;
  oldKey: LoadedKey;
  newKey: LoadedKey;
  mirrors?: string[];
  outDir?: string;
  now?: number;
}): Promise<{ rotation: SignedOutput[]; resigned: SignedOutput[]; effectiveSequence: number }> {
  const state = loadState(args.projectDir);
  if (!state.publisherId || !state.currentKey) throw new Error("Nothing signed yet: run 'shinsou-plugin sign' first");
  requireSigningKey(state, args.oldKey);
  if (args.newKey.fingerprint === args.oldKey.fingerprint) throw new Error("The new key is the current key");
  if (state.retiredKeys.some((k) => k.fingerprint === args.newKey.fingerprint)) throw new Error("The new key was already retired");
  const effectiveSequence = state.rotationSequence + 1;
  const payload = rotationPayload({
    publisherId: state.publisherId,
    oldKeyFingerprint: args.oldKey.fingerprint,
    newSeed: args.newKey.seed,
    effectiveSequence,
  });
  const mirrors = resolveMirrors(args.projectDir, args.mirrors);
  const outDir = join(args.projectDir, args.outDir ?? DEFAULT_PUBLIC_DIR);
  const rotation = signDocs({
    state,
    key: args.oldKey,
    mirrors,
    docs: [{ documentId: DOCUMENT_IDS.rotation, payloadType: "publisher-key-rotation", payload }],
    outDir,
  });
  state.retiredKeys.push({ ...state.currentKey, retiredAt: new Date().toISOString() });
  state.currentKey = { name: args.newKey.name, publicKey: args.newKey.publicKey, fingerprint: args.newKey.fingerprint };
  state.rotationSequence = effectiveSequence;
  saveState(args.projectDir, state);
  const resigned = await signRepository({ projectDir: args.projectDir, key: args.newKey, mirrors, outDir: args.outDir, now: args.now });
  return { rotation, resigned, effectiveSequence };
}

/** Key self-revocation, signed by the revoked key itself (current or retired). */
export function revokeKey(args: { projectDir: string; key: LoadedKey; mirrors?: string[]; outDir?: string }): SignedOutput[] {
  const state = loadState(args.projectDir);
  if (!state.publisherId) throw new Error("Nothing signed yet");
  const isCurrent = state.currentKey?.fingerprint === args.key.fingerprint;
  const isRetired = state.retiredKeys.some((k) => k.fingerprint === args.key.fingerprint);
  if (!isCurrent && !isRetired) throw new Error(`${args.key.name} is not a key of this publisher`);
  const outputs = signDocs({
    state,
    key: args.key,
    mirrors: resolveMirrors(args.projectDir, args.mirrors),
    docs: [
      {
        documentId: DOCUMENT_IDS.keyRevoked,
        payloadType: "publisher-key-revoked",
        payload: keyRevokedPayload({ publisherId: state.publisherId, revokedKeyFingerprint: args.key.fingerprint }),
      },
    ],
    outDir: join(args.projectDir, args.outDir ?? DEFAULT_PUBLIC_DIR),
  });
  if (isCurrent) state.keyRevoked = true;
  saveState(args.projectDir, state);
  return outputs;
}

export function publicDirHas(projectDir: string, outDir = DEFAULT_PUBLIC_DIR): boolean {
  return existsSync(join(projectDir, outDir));
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
