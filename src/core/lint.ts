/**
 * `lint`: static policy checks on top of build's consistency checks (ADR-0002 §6, §8.1).
 */

import { isIP } from "node:net";
import type { BuildResult } from "./build.ts";
import { MAX_SCRIPT_BYTES } from "./build.ts";
import { TIER_CEILING_HOST_PERMISSIONS, type PluginManifest, type SourceManifest } from "./manifest.ts";
import { misleadingTerm } from "./names.ts";
import { registrableDomain } from "./psl.ts";

export interface Finding {
  rule: string;
  message: string;
}
export interface LintReport {
  errors: Finding[];
  warnings: Finding[];
}

interface OpRule {
  runtime?: string[];
  host?: string[];
  events?: string[];
}

/** Bridge op (as called from the script) → declarations the host will require (§5.1, §17.2). */
export const BRIDGE_OPS: Record<string, OpRule> = {
  httpGet: { runtime: ["NETWORK"] },
  httpGetWithHeaders: { runtime: ["NETWORK"] },
  httpGetResponse: { runtime: ["NETWORK"] },
  httpPost: { runtime: ["NETWORK"] },
  httpPostResponse: { runtime: ["NETWORK"] },
  httpPostBatch: { runtime: ["NETWORK"] },
  "net.fetch": { runtime: ["NETWORK"] },
  browserSessionRequest: { runtime: ["BROWSER_CHALLENGE"] },
  getCredentialUsername: { runtime: ["CREDENTIAL_ACCESS"] },
  hasCredential: { runtime: ["CREDENTIAL_ACCESS"] },
  getCredentialPassword: { runtime: ["CREDENTIAL_ACCESS"] },
  setCredential: { runtime: ["CREDENTIAL_ACCESS"] },
  clearCredential: { runtime: ["CREDENTIAL_ACCESS"] },
  getCookie: { runtime: ["COOKIE_STORAGE", "COOKIE_READ"] },
  getCookies: { runtime: ["COOKIE_STORAGE", "COOKIE_READ"] },
  setCookie: { runtime: ["COOKIE_STORAGE"] },
  deleteCookie: { runtime: ["COOKIE_STORAGE"] },
  clearCookies: { runtime: ["COOKIE_STORAGE"] },
  requestLogin: { runtime: ["LOGIN_PROMPT"], host: ["REQUEST_LOGIN_UI"] },
  "system.requestLogin": { host: ["REQUEST_LOGIN_UI"], events: ["command.auth.login.request"] },
  "system.requestRefresh": { host: ["REQUEST_SOURCE_REFRESH"], events: ["command.source.refresh.request"] },
  "system.requestLogout": { host: ["REQUEST_LOGOUT"], events: ["command.auth.logout.request"] },
  "system.reportMessage": { host: ["REPORT_DIAGNOSTIC"], events: ["event.diagnostic.message.report"] },
  "system.submit": {},
  requestHostEvent: {},
  getHostEventContext: {},
  getHostEventCapabilities: {},
  getPreference: {},
  setPreference: {},
  log: {},
  parseHtml: {},
  domRelease: {},
  domReleaseAll: {},
};

const EVENT_HOST_PERMISSION: Record<string, string> = {
  "command.auth.login.request": "REQUEST_LOGIN_UI",
  "command.source.refresh.request": "REQUEST_SOURCE_REFRESH",
  "command.auth.logout.request": "REQUEST_LOGOUT",
  "event.diagnostic.message.report": "REPORT_DIAGNOSTIC",
};

const CAPABILITY_HOOKS: Record<string, string> = {
  CATALOGUE: "getPopularManga",
  LATEST: "getLatestUpdates",
  SEARCH: "getSearchManga",
  METADATA: "getMangaDetails",
  UNITS: "getChapterList",
  CONTENT: "getPageList",
};

/** Bridge ops the script calls, e.g. `httpGet`, `system.requestLogin`, `net.fetch`. */
export function usedBridgeOps(code: string): Set<string> {
  const ops = new Set<string>();
  for (const m of code.matchAll(/\bbridge\s*\.\s*(system|net)\s*\.\s*([A-Za-z_$][\w$]*)\s*\(/g)) ops.add(`${m[1]}.${m[2]}`);
  for (const m of code.matchAll(/\bbridge\s*\.\s*([A-Za-z_$][\w$]*)\s*\(/g)) ops.add(m[1]);
  return ops;
}

export function lintBuild(result: BuildResult): LintReport {
  const report: LintReport = { errors: [], warnings: [] };
  const err = (rule: string, message: string) => report.errors.push({ rule, message });
  const warn = (rule: string, message: string) => report.warnings.push({ rule, message });
  const m = result.manifest;
  const code = result.bundledCode;

  // Names: no package, source or publisher may claim to be official.
  const names: [string, string][] = [
    ["packageId", m.packageId],
    ["name", m.name],
    ["repository.name", m.repository.name],
    ["repository.shortName", m.repository.shortName],
    ...m.sources.flatMap((s, i): [string, string][] => [[`sources[${i}].name`, s.name], [`sources[${i}].sourceId`, s.sourceId]]),
  ];
  for (const [field, value] of names) {
    const term = misleadingTerm(value);
    if (term) err("misleading-name", `${field} "${value}" contains the misleading word "${term}": Shinsou has no official plugins`);
  }

  if (result.byteSize > MAX_SCRIPT_BYTES) err("script-size", `script is ${result.byteSize} bytes (limit 2 MiB)`);
  if (!m.runtimePermissions.includes("EXECUTE_SCRIPT")) err("permissions", "runtimePermissions must include EXECUTE_SCRIPT");

  // Bridge ops ↔ declared permissions.
  const ops = usedBridgeOps(code);
  const neededRuntime = new Set<string>(["EXECUTE_SCRIPT"]);
  const neededHost = new Set<string>();
  const declaredEvents = new Set([...m.systemEvents.required, ...m.systemEvents.optional]);
  for (const op of ops) {
    const rule = BRIDGE_OPS[op];
    if (!rule) {
      err("bridge-op", `bridge.${op}() is not a bridge operation the sandbox provides (it would fail with UNKNOWN_OPERATION)`);
      continue;
    }
    for (const p of rule.runtime ?? []) {
      neededRuntime.add(p);
      if (!m.runtimePermissions.includes(p)) err("bridge-permission", `bridge.${op}() requires runtime permission ${p}`);
    }
    for (const p of rule.host ?? []) {
      neededHost.add(p);
      if (!m.requestedHostPermissions.includes(p)) err("bridge-permission", `bridge.${op}() requires host permission ${p}`);
    }
    for (const e of rule.events ?? []) {
      if (!declaredEvents.has(e)) err("bridge-permission", `bridge.${op}() requires systemEvents to declare ${e}`);
    }
    if (op === "system.submit" || op === "requestHostEvent") {
      warn("bridge-dynamic", `bridge.${op}() submits arbitrary events: make sure systemEvents and requestedHostPermissions cover them`);
    }
  }
  if (/\bbridge\s*\[/.test(code)) warn("bridge-dynamic", "bridge[...] dynamic access cannot be checked statically");
  for (const p of m.runtimePermissions) {
    if (!neededRuntime.has(p) && p !== "FAVORITE_MUTATION") warn("least-privilege", `runtime permission ${p} is declared but no bridge call needs it`);
  }

  // Events ↔ host permissions.
  for (const e of declaredEvents) {
    const p = EVENT_HOST_PERMISSION[e];
    if (p && !m.requestedHostPermissions.includes(p)) err("events", `systemEvents declares ${e}, which needs host permission ${p}`);
  }
  const usedHost = new Set([...neededHost, ...[...declaredEvents].map((e) => EVENT_HOST_PERMISSION[e]).filter(Boolean)]);
  for (const p of m.requestedHostPermissions) {
    if (TIER_CEILING_HOST_PERMISSIONS.includes(p)) err("tier-ceiling", `${p} is never granted to third-party packages (ADR-0002 §6.2)`);
    else if (!usedHost.has(p)) warn("least-privilege", `host permission ${p} is declared but nothing uses it`);
  }

  // Capabilities ↔ hooks.
  for (const cap of m.capabilities) {
    const hook = CAPABILITY_HOOKS[cap];
    const found = (h: string) => new RegExp(`\\b${h}\\b`).test(code);
    // CONTENT is served by getPageList (images) or getChapterText (PLAIN_TEXT sources).
    if (hook && !found(hook) && !(cap === "CONTENT" && found("getChapterText"))) warn("capabilities", `capability ${cap} is declared but no ${hook} hook was found`);
  }
  if (m.capabilities.includes("LOGIN") && !m.runtimePermissions.includes("CREDENTIAL_ACCESS")) {
    warn("capabilities", "LOGIN normally needs CREDENTIAL_ACCESS to store the account");
  }

  for (const [i, s] of m.sources.entries()) {
    const kinds = s.contentKinds ?? m.contentKinds;
    if (kinds.includes("PLAIN_TEXT") && !/\bgetChapterText\b/.test(code)) {
      warn("capabilities", `sources[${i}] serves PLAIN_TEXT but no getChapterText hook was found (the app reads chapter text from getChapterText(chapter), which returns a string)`);
    }
  }
  for (const [i, s] of m.sources.entries()) lintSource(m, s, `sources[${i}]`, code, err, warn);
  lintUrlLiterals(m, code, warn);
  return report;
}

function lintSource(
  m: PluginManifest,
  s: SourceManifest,
  label: string,
  code: string,
  err: (r: string, msg: string) => void,
  warn: (r: string, msg: string) => void,
) {
  if (!/^\d{1,19}$/.test(s.sourceId) || BigInt(s.sourceId) > 0x7fffffffffffffffn) {
    err("source-id", `${label}.sourceId must be a decimal 64-bit integer string (the app stores it as a Long)`);
  }
  if (s.legacyLongId !== null && s.legacyLongId !== s.sourceId) warn("source-id", `${label}.legacyLongId differs from sourceId`);
  for (const field of ["requestOrigins", "credentialOrigins", "contentOrigins", "browserSessionOrigins"] as const) {
    for (const origin of s[field]) {
      const problem = exactHttpsOriginProblem(origin);
      if (problem) err("origin", `${label}.${field}: ${origin} ${problem}`);
    }
  }
  const base = exactHttpsOriginProblem(safeOrigin(s.baseUrl) ?? s.baseUrl);
  if (base) err("origin", `${label}.baseUrl ${s.baseUrl} ${base}`);
  const baseOrigin = safeOrigin(s.baseUrl);
  if (m.runtimePermissions.includes("NETWORK") && s.requestOrigins.length === 0) {
    err("origin", `${label}.requestOrigins is empty: the app denies every request of a v2 source without declared origins`);
  }
  if (baseOrigin && s.requestOrigins.length && !s.requestOrigins.includes(baseOrigin) && !s.contentOrigins.includes(baseOrigin)) {
    warn("origin", `${label}.baseUrl origin ${baseOrigin} is neither a request nor a content origin`);
  }
  if (s.requestOrigins.length && !m.runtimePermissions.includes("NETWORK")) {
    warn("origin", `${label}.requestOrigins is declared but NETWORK is not requested`);
  }
  for (const o of s.credentialOrigins) {
    if (!s.requestOrigins.includes(o)) err("origin", `${label}.credentialOrigins ${o} must also be a request origin`);
  }
  if (s.browserSessionOrigins.length > 4) err("origin", `${label}.browserSessionOrigins allows at most 4 origins`);
  if (s.browserSessionOrigins.length && !m.runtimePermissions.includes("BROWSER_CHALLENGE")) {
    err("origin", `${label}.browserSessionOrigins needs runtime permission BROWSER_CHALLENGE`);
  }
  if (/\bbridge\s*\.\s*browserSessionRequest\s*\(/.test(code) && s.browserSessionOrigins.length === 0) {
    err("origin", `${label}: browserSessionRequest is used but browserSessionOrigins is empty`);
  }
  for (const suffix of s.contentHostSuffixes) {
    const problem = contentHostSuffixProblem(suffix);
    if (problem) err("content-host-suffix", `${label}.contentHostSuffixes ${suffix}: ${problem}`);
  }
  if (s.contentHostSuffixes.length > MAX_CONTENT_HOST_SUFFIXES) {
    err("content-host-suffix", `${label}.contentHostSuffixes allows at most ${MAX_CONTENT_HOST_SUFFIXES} entries`);
  }
}

function lintUrlLiterals(m: PluginManifest, code: string, warn: (r: string, msg: string) => void) {
  const allowed = new Set(m.sources.flatMap((s) => [...s.requestOrigins, ...s.contentOrigins, ...s.browserSessionOrigins]));
  const seen = new Set<string>();
  for (const match of code.matchAll(/\bhttps?:\/\/[A-Za-z0-9.-]+(?::\d+)?/g)) {
    const origin = safeOrigin(match[0]);
    if (!origin || seen.has(origin)) continue;
    seen.add(origin);
    if (origin.startsWith("http:")) warn("origin", `script contains a plain-HTTP URL (${origin}); third-party packages may only use HTTPS`);
    else if (!allowed.has(origin)) warn("origin", `script mentions ${origin}, which is not a declared request/content origin`);
  }
}

function safeOrigin(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/** Null when [origin] is an exact public HTTPS origin, else why not (§6.2 tier ceiling). */
export function exactHttpsOriginProblem(origin: string): string | null {
  let u: URL;
  try {
    u = new URL(origin);
  } catch {
    return "is not a valid URL";
  }
  if (u.protocol !== "https:") return "must use HTTPS";
  if (u.origin !== origin) return `must be an exact origin (expected ${u.origin})`;
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (isIP(host)) return "must not be an IP address";
  if (host === "localhost" || /\.(localhost|local|internal|lan|home|test|invalid|example)$/.test(host) || !host.includes(".")) {
    return "must be a public host name (private, loopback and LAN hosts are never granted)";
  }
  return null;
}

/** Appended to a declared suffix, allows the non-privileged port range too (like the app). */
export const CONTENT_HOST_SUFFIX_HIGH_PORTS = ":1024-65535";
/** Most `contentHostSuffixes` one source may declare (app: MAX_CONTENT_HOST_SUFFIXES). */
export const MAX_CONTENT_HOST_SUFFIXES = 8;

/** Null when the app grants [declared] (`isGrantableContentHostSuffix`), else why not. */
export function contentHostSuffixProblem(declared: string): string | null {
  const s = declared.endsWith(CONTENT_HOST_SUFFIX_HIGH_PORTS) ? declared.slice(0, -CONTENT_HOST_SUFFIX_HIGH_PORTS.length) : declared;
  if (s !== s.toLowerCase()) return "must be lower-case";
  if (s.startsWith(".") || s.startsWith("*")) return "write the bare suffix (example.com), without a leading dot or wildcard";
  if (s.endsWith(".")) return "must not end with a dot";
  if (s.length > 253 || !/^[a-z0-9.-]+$/.test(s)) {
    return `must be lower-case ASCII host name characters; the only allowed port suffix is ${CONTENT_HOST_SUFFIX_HIGH_PORTS}`;
  }
  const labels = s.split(".");
  if (labels.length < 2 || labels.some((l) => !l || l.length > 63 || l.startsWith("-") || l.endsWith("-"))) {
    return "is not a valid host name with at least two labels";
  }
  if (/^\d+$/.test(labels[labels.length - 1]) || isIP(s)) return "must not be an IP address";
  if (registrableDomain(s) === null) return "is a public suffix; it must be at least a registrable domain (e.g. cdn.example.com)";
  return null;
}
