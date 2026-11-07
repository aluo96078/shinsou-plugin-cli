/**
 * `.shinsou/state.json`: publishing state that must be committed with the repository (no secrets).
 * It keeps every signed document's sequence strictly increasing across machines and CI runs.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { sha256Hex } from "./crypto.ts";
import { utf8 } from "./bytes.ts";
import { canonicalJson, type JsonValue } from "./canonical-json.ts";

export const STATE_FORMAT = "shinsou-plugin-state-v1";

export interface KeyRef {
  name: string;
  publicKey: string;
  fingerprint: string;
}

export interface PublishState {
  format: typeof STATE_FORMAT;
  /** Fingerprint of the publisher's first key; never changes across rotations. */
  publisherId: string | null;
  currentKey: KeyRef | null;
  retiredKeys: (KeyRef & { retiredAt: string })[];
  /** Last applied rotation `effectiveSequence` (0 = never rotated). */
  rotationSequence: number;
  /** True once the current key published a self-revocation; signing is then refused. */
  keyRevoked: boolean;
  revokedArtifacts: string[];
  documents: Record<string, { sequence: number; payloadSha256: string; expiresAt?: number }>;
}

export function statePath(projectDir: string): string {
  return join(projectDir, ".shinsou", "state.json");
}

export function emptyState(): PublishState {
  return {
    format: STATE_FORMAT,
    publisherId: null,
    currentKey: null,
    retiredKeys: [],
    rotationSequence: 0,
    keyRevoked: false,
    revokedArtifacts: [],
    documents: {},
  };
}

export function loadState(projectDir: string): PublishState {
  const path = statePath(projectDir);
  if (!existsSync(path)) return emptyState();
  const s = JSON.parse(readFileSync(path, "utf8")) as PublishState;
  if (s.format !== STATE_FORMAT) throw new Error(`${path}: unsupported state format`);
  return { ...emptyState(), ...s };
}

export function saveState(projectDir: string, state: PublishState): void {
  const path = statePath(projectDir);
  mkdirSync(dirname(path), { recursive: true });
  const tmp = path + ".tmp";
  writeFileSync(tmp, JSON.stringify(state, null, 2) + "\n");
  renameSync(tmp, path);
}

/**
 * The sequence to sign [payload] with for [documentId]: unchanged content keeps its sequence (so a
 * new mirror or a re-run signs identical bytes), changed content gets the next one. The app rejects
 * a lower sequence (replay) and the same sequence with different content (equivocation).
 */
export function nextSequence(state: PublishState, documentId: string, payload: JsonValue): number {
  const digest = sha256Hex(utf8(canonicalJson(payload)));
  const current = state.documents[documentId];
  if (current && current.payloadSha256 === digest) return current.sequence;
  const sequence = current ? current.sequence + 1 : 1;
  state.documents[documentId] = { sequence, payloadSha256: digest };
  return sequence;
}
