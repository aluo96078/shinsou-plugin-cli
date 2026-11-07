/**
 * Index ↔ sidecar ↔ script agreement, ported from the community repository's
 * `test/v2-migration-smoke.js` (generic rules only; its package-specific assertions are dropped).
 * `build` runs this on the files it just wrote and fails on any disagreement.
 */

import { isDeepStrictEqual } from "node:util";
import { Script } from "node:vm";
import { decodeUtf8 } from "./bytes.ts";
import { sha256Hex } from "./crypto.ts";
import type { JsonObject, JsonValue } from "./canonical-json.ts";
import {
  CONTENT_CONTRACT,
  CONTENT_KINDS,
  EVENT_IDS,
  EVENTS_PROTOCOL,
  HOST_PERMISSIONS,
  INDEX_FORMAT,
  RUNTIME_PERMISSIONS,
  SIDECAR_FORMAT,
} from "./manifest.ts";

export const EXECUTABLE_DECLARATION = /var __shinsouExtensionV2 = (\{[^\n]+\});/;

export function readExecutableMetadata(scriptText: string): JsonObject | null {
  const m = EXECUTABLE_DECLARATION.exec(scriptText);
  if (!m) return null;
  try {
    return JSON.parse(m[1]);
  } catch {
    return null;
  }
}

export function checkPackageConsistency(args: {
  index: JsonObject;
  pkg: JsonObject;
  sidecar: JsonObject;
  scriptBytes: Uint8Array;
}): string[] {
  const problems: string[] = [];
  const expect = (cond: unknown, msg: string) => {
    if (!cond) problems.push(msg);
  };
  const same = (a: unknown, b: unknown, msg: string) => expect(isDeepStrictEqual(a, b), msg);
  const { index, pkg, sidecar, scriptBytes } = args;
  const id = String(pkg.id);

  expect(index.format === INDEX_FORMAT, "unexpected repository index format");
  expect(index.contractVersion === 2, "unexpected v2 contract version");
  expect(index.contentContract === CONTENT_CONTRACT, "unexpected v2 content contract");
  expect(pkg.contractVersion === undefined || pkg.contractVersion === 2, `${id} contract version`);
  expect(typeof pkg.id === "string" && pkg.id.length > 0, "package id");
  expect(!("hostPermissions" in pkg), `${id} must not self-grant host permissions`);
  noTraversal(pkg.scriptUrl, `${id} scriptUrl`, expect);
  noTraversal(pkg.sidecarUrl, `${id} sidecarUrl`, expect);
  expect(String(pkg.scriptUrl).startsWith("plugins/"), `${id} scriptUrl must be under plugins`);
  expect(String(pkg.sidecarUrl).startsWith("sidecars/"), `${id} sidecarUrl must be under sidecars`);
  const kinds = pkg.contentKinds as string[];
  expect(Array.isArray(kinds) && kinds.length > 0, `${id} content kinds`);
  for (const k of kinds ?? []) expect(CONTENT_KINDS.includes(k as never), `${id} unknown content kind ${k}`);
  checkEvents(pkg.systemEvents, `${id} package events`, expect);
  checkList(pkg.requestedHostPermissions, HOST_PERMISSIONS, `${id} requestedHostPermissions`, expect);
  checkList(pkg.runtimePermissions, RUNTIME_PERMISSIONS, `${id} runtimePermissions`, expect);
  const sources = (pkg.sources as JsonObject[]) ?? [];
  for (const s of sources) checkBrowserSessionOrigins(s.browserSessionOrigins ?? [], `${id} source browserSessionOrigins`, expect);

  expect(scriptBytes.length === pkg.byteSize, `${id} index byteSize mismatch`);
  expect(sha256Hex(scriptBytes) === pkg.sha256, `${id} index sha256 mismatch`);
  let scriptText = "";
  try {
    scriptText = decodeUtf8(scriptBytes);
    new Script(scriptText, { filename: String(pkg.scriptUrl) });
  } catch (err) {
    problems.push(`${id} script does not parse as a classic script: ${(err as Error).message}`);
  }
  expect(scriptText.includes("source.v2 = __shinsouExtensionV2"), `${id} missing v2 metadata export`);
  const meta = readExecutableMetadata(scriptText);
  expect(meta, `${id} missing executable v2 declaration`);
  if (meta) {
    expect(meta.contractVersion === 2, `${id} executable contract version`);
    expect(meta.contentContract === CONTENT_CONTRACT, `${id} executable content contract`);
    expect(meta.packageId === pkg.id, `${id} executable package identity`);
    same(meta.contentType, pkg.contentType, `${id} executable content type`);
    same(meta.contentKinds, pkg.contentKinds, `${id} executable content kinds`);
    same(meta.systemEvents, pkg.systemEvents, `${id} executable event declaration`);
    same(meta.requestedHostPermissions, pkg.requestedHostPermissions, `${id} executable requested permissions`);
  }

  expect(sidecar.format === SIDECAR_FORMAT, `${id} sidecar format`);
  expect(sidecar.contractVersion === 2, `${id} sidecar contract version`);
  expect(sidecar.packageId === pkg.id, `${id} sidecar package identity`);
  expect(sidecar.version === pkg.version && sidecar.versionCode === pkg.versionCode, `${id} sidecar version identity`);
  expect(sidecar.runtime === undefined || sidecar.runtime === pkg.runtime, `${id} sidecar runtime binding`);
  expect(!("hostPermissions" in sidecar), `${id} sidecar must not self-grant host permissions`);
  const artifact = (sidecar.artifact ?? {}) as JsonObject;
  expect(artifact.scriptUrl === pkg.scriptUrl, `${id} sidecar artifact binding`);
  expect(artifact.sha256 === pkg.sha256 && artifact.byteSize === pkg.byteSize, `${id} sidecar artifact metadata`);
  const content = (sidecar.content ?? {}) as JsonObject;
  expect(content.contract === CONTENT_CONTRACT && content.contractVersion === 2, `${id} sidecar content contract`);
  expect(content.type === pkg.contentType, `${id} sidecar content type`);
  same(content.kinds, pkg.contentKinds, `${id} sidecar content kinds`);
  same(sidecar.capabilities, pkg.capabilities, `${id} sidecar capabilities`);
  checkEvents(sidecar.systemEvents, `${id} sidecar events`, expect);
  same(sidecar.systemEvents, pkg.systemEvents, `${id} sidecar package events`);
  same(sidecar.requestedHostPermissions, pkg.requestedHostPermissions, `${id} sidecar requested permissions`);
  same(sidecar.runtimePermissions, pkg.runtimePermissions, `${id} sidecar runtime permissions`);
  const sidecarSources = (sidecar.sources as JsonObject[]) ?? [];
  expect(sidecarSources.length === sources.length, `${id} sidecar source count`);
  for (const s of sources) {
    const match = sidecarSources.find((e) => e.sourceId === s.sourceId);
    if (!match) {
      problems.push(`${id} sidecar is missing source ${String(s.sourceId)}`);
      continue;
    }
    const key = (match.sourceKey ?? {}) as JsonObject;
    expect(key.packageId === pkg.id && key.sourceId === s.sourceId && key.contractVersion === 2, `${id} sourceKey binding`);
    expect(key.legacyLongId === s.legacyLongId, `${id} sourceKey legacyLongId`);
    for (const field of ["name", "lang", "baseUrl", "requestOrigins", "credentialOrigins", "contentOrigins", "browserSessionOrigins", "contentHostSuffixes"]) {
      same(match[field] ?? null, s[field] ?? null, `${id} source ${String(s.sourceId)} ${field} binding`);
    }
    expect("contentKinds" in match, `${id} sidecar source contentKinds must be explicit`);
    same(match.contentKinds, s.contentKinds ?? pkg.contentKinds, `${id} source contentKinds binding`);
    same(match.capabilities, pkg.capabilities, `${id} source capabilities binding`);
    same(match.systemEvents, pkg.systemEvents, `${id} source events binding`);
    same(match.requestedHostPermissions, pkg.requestedHostPermissions, `${id} source requested permissions binding`);
    same(match.runtimePermissions, pkg.runtimePermissions, `${id} source runtime permissions binding`);
  }

  const events = (pkg.systemEvents ?? {}) as JsonObject;
  const declared = [...((events.required as string[]) ?? []), ...((events.optional as string[]) ?? [])];
  if (declared.includes("command.auth.login.request")) {
    expect(/bridge\.system\.requestLogin\s*\(/.test(scriptText), `${id} must use the native system login helper`);
    const systemCall = scriptText.indexOf("bridge.system.requestLogin");
    const legacyCall = scriptText.indexOf("bridge.requestLogin");
    expect(legacyCall < 0 || systemCall < legacyCall, `${id} legacy login callback may only be a fallback`);
  }
  const caps = (pkg.capabilities as string[]) ?? [];
  if (/supportsLogin\s*:\s*true/.test(scriptText)) expect(caps.includes("LOGIN"), `${id} script supports login but LOGIN capability is not declared`);
  if (caps.includes("LOGIN")) expect(/supportsLogin\s*:\s*true/.test(scriptText), `${id} declares LOGIN but the script does not set supportsLogin: true`);
  return problems;
}

function noTraversal(value: JsonValue | undefined, label: string, expect: (c: unknown, m: string) => void) {
  expect(typeof value === "string" && value.length > 0, `${label} must be a non-empty string`);
  expect(typeof value === "string" && !value.split("/").includes(".."), `${label} must not traverse outside the repository root`);
}

function checkEvents(events: JsonValue | undefined, label: string, expect: (c: unknown, m: string) => void) {
  const e = (events ?? {}) as JsonObject;
  expect(e.protocol === EVENTS_PROTOCOL, `${label} protocol`);
  expect(e.minVersion === 1 && e.maxVersion === 1, `${label} version range`);
  expect(Array.isArray(e.required) && Array.isArray(e.optional), `${label} event arrays`);
  const required = new Set((e.required as string[]) ?? []);
  const optional = new Set((e.optional as string[]) ?? []);
  for (const id of required) expect(EVENT_IDS.includes(id as never), `${label} unknown required event ${id}`);
  for (const id of optional) expect(EVENT_IDS.includes(id as never), `${label} unknown optional event ${id}`);
  for (const id of required) expect(!optional.has(id), `${label} event is both required and optional: ${id}`);
}

function checkList(list: JsonValue | undefined, allowed: readonly string[], label: string, expect: (c: unknown, m: string) => void) {
  expect(Array.isArray(list), `${label} must be an array`);
  for (const p of (list as string[]) ?? []) expect(allowed.includes(p), `${label} contains unknown permission ${p}`);
}

function checkBrowserSessionOrigins(origins: JsonValue, label: string, expect: (c: unknown, m: string) => void) {
  expect(Array.isArray(origins), `${label} must be an array`);
  const list = (origins as string[]) ?? [];
  expect(list.length <= 4, `${label} must remain bounded`);
  for (const origin of list) {
    try {
      const parsed = new URL(origin);
      expect(parsed.protocol === "https:", `${label} must use HTTPS`);
      expect(parsed.origin === origin && parsed.pathname === "/", `${label} must contain exact origins only`);
    } catch {
      expect(false, `${label} contains an invalid origin ${origin}`);
    }
  }
}
