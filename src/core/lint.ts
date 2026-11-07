/**
 * `lint`: static policy checks on top of build's consistency checks (ADR-0002 §6, §8.1).
 */

import { isIP } from "node:net";
import type { BuildResult } from "./build.ts";
import { MAX_SCRIPT_BYTES } from "./build.ts";
import { TIER_CEILING_HOST_PERMISSIONS, type PluginManifest, type SourceManifest } from "./manifest.ts";
import { misleadingTerm } from "./names.ts";

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
  getCookie: { runtime: ["COOKIE_READ"] },
  getCookies: { runtime: ["COOKIE_READ"] },
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
    if (rule.runtime?.includes("COOKIE_READ")) {
      warn("app-support", "COOKIE_READ (ADR-0002 §5.1) is not yet a runtime permission in the current app; cookie reads will be denied");
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
    if (hook && !new RegExp(`\\b${hook}\\b`).test(code)) warn("capabilities", `capability ${cap} is declared but no ${hook} hook was found`);
  }
  if (m.capabilities.includes("LOGIN") && !m.runtimePermissions.includes("CREDENTIAL_ACCESS")) {
    warn("capabilities", "LOGIN normally needs CREDENTIAL_ACCESS to store the account");
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
  if (s.contentHostSuffixes.length) {
    warn(
      "app-support",
      `${label}.contentHostSuffixes is a sensitive permission (ADR-0002 D11) that the current app does not yet accept from third-party manifests`,
    );
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

/**
 * Minimal public-suffix guard for `contentHostSuffixes`.
 * TODO(PSL): replace with the full Mozilla Public Suffix List (bundled, periodically updated), the
 * same list the app must adopt for D11 (ADR-0002 §6.2, §12 S6). Until then this list only catches
 * the most common mistakes and lint cannot prove a suffix is at least a registrable domain.
 */
const KNOWN_PUBLIC_SUFFIXES = new Set([
  "com", "net", "org", "io", "co", "me", "app", "dev", "info", "biz", "xyz", "top", "cc", "tv", "jp", "cn", "tw", "hk", "kr",
  "co.jp", "ne.jp", "or.jp", "com.cn", "net.cn", "com.tw", "net.tw", "org.tw", "com.hk", "co.kr", "co.uk", "org.uk", "com.au",
  "github.io", "gitlab.io", "pages.dev", "workers.dev", "netlify.app", "vercel.app", "herokuapp.com", "appspot.com",
  "cloudfront.net", "azurewebsites.net", "blogspot.com", "firebaseapp.com", "web.app", "r2.dev", "b-cdn.net",
]);

export function isPublicSuffix(suffix: string): boolean {
  return KNOWN_PUBLIC_SUFFIXES.has(suffix.toLowerCase());
}

export function contentHostSuffixProblem(suffix: string): string | null {
  const s = suffix.toLowerCase();
  if (s !== suffix) return "must be lower-case";
  if (s.startsWith(".") || s.startsWith("*")) return "write the bare suffix (example.com), without a leading dot or wildcard";
  if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(s)) {
    return "is not a valid host name with at least two labels";
  }
  if (isIP(s)) return "must not be an IP address";
  if (isPublicSuffix(s)) return "is a public suffix; it must be at least a registrable domain (e.g. cdn.example.com)";
  return null;
}
