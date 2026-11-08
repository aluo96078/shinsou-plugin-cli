/**
 * `shinsou.plugin.json`: the single source of truth for one plugin package. The index entry, the
 * sidecar and the script's executable metadata are all generated from it, so they cannot drift.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseStrictJson, type JsonObject, type JsonValue } from "./canonical-json.ts";

export const MANIFEST_FILE = "shinsou.plugin.json";
export const INDEX_FORMAT = "shinsou-extension-v2";
export const SIDECAR_FORMAT = "shinsou-extension-sidecar-v2";
export const CONTENT_CONTRACT = "extension-content-v2";
export const CONTRACT_VERSION = 2;
export const EVENTS_PROTOCOL = "dev.shinsou.system";

export const CONTENT_KINDS = ["IMAGE_SEQUENCE", "PLAIN_TEXT", "EPUB_SPINE"] as const;
export const CONTENT_TYPES = ["manga", "novel", "both"] as const;
export const CAPABILITIES = [
  "CATALOGUE", "LATEST", "BROWSE", "METADATA", "UNITS", "CONTENT", "SEARCH", "PREFERENCES", "LOGIN", "FAVORITE",
] as const;
export const RUNTIME_PERMISSIONS = [
  "EXECUTE_SCRIPT", "NETWORK", "COOKIE_STORAGE", "CREDENTIAL_ACCESS", "LOGIN_PROMPT", "FAVORITE_MUTATION", "BROWSER_CHALLENGE",
  // ADR-0002 §5.1: reading cookie values (getCookie/getCookies also need COOKIE_STORAGE in the app).
  "COOKIE_READ",
  // Loading the source's browserImageOrigins in an isolated browser (macOS/iOS).
  "BROWSER_IMAGES",
] as const;
export const HOST_PERMISSIONS = [
  "REQUEST_LOGIN_UI", "REQUEST_SOURCE_REFRESH", "REQUEST_LOGOUT", "REPORT_DIAGNOSTIC", "REPORT_USER_MESSAGE", "REQUEST_BROWSER_CHALLENGE",
] as const;
/** ADR-0002 §6.2 tier ceiling: never granted to third-party packages. */
export const TIER_CEILING_HOST_PERMISSIONS = ["REPORT_USER_MESSAGE"];
export const EVENT_IDS = [
  "command.auth.login.request",
  "command.source.refresh.request",
  "command.auth.logout.request",
  "event.diagnostic.message.report",
] as const;

export interface SourceManifest {
  sourceId: string;
  legacyLongId: string | null;
  name: string;
  lang: string;
  baseUrl: string;
  contentType?: string;
  contentKinds?: string[];
  requestOrigins: string[];
  credentialOrigins: string[];
  contentOrigins: string[];
  browserSessionOrigins: string[];
  /** ADR-0002 §6.2 / D11: sensitive dynamic CDN suffixes (content plane only). */
  contentHostSuffixes: string[];
  /** Exact HTTPS content origins (port 443) whose images the app may load in an isolated browser (BROWSER_IMAGES). */
  browserImageOrigins: string[];
}

export interface RepositoryManifest {
  name: string;
  shortName: string;
  website: string;
  /** Every base URL the repository is published under; each gets its own signatures. */
  mirrors: string[];
}

export interface PluginManifest {
  manifestVersion: 1;
  packageId: string;
  name: string;
  version: string;
  versionCode: number;
  lang: string;
  nsfw: boolean;
  description?: string;
  contract: string;
  runtime: string;
  contentType: string;
  contentKinds: string[];
  capabilities: string[];
  runtimePermissions: string[];
  requestedHostPermissions: string[];
  systemEvents: { required: string[]; optional: string[] };
  entry: string;
  sources: SourceManifest[];
  repository: RepositoryManifest;
  test?: { cases?: string; fixtures?: string };
}

export class ManifestError extends Error {}

export function loadManifest(projectDir: string): PluginManifest {
  const path = join(projectDir, MANIFEST_FILE);
  let raw: JsonValue;
  try {
    raw = parseStrictJson(readFileSync(path, "utf8"));
  } catch (err) {
    throw new ManifestError(`${MANIFEST_FILE}: ${(err as Error).message}`);
  }
  return validateManifest(raw);
}

/** Structural validation; policy checks (names, origins, permissions) live in lint. */
export function validateManifest(raw: JsonValue): PluginManifest {
  const errors: string[] = [];
  const o = obj(raw, "manifest", errors);
  const str = (v: JsonValue | undefined, label: string) => {
    if (typeof v !== "string" || !v.trim()) errors.push(`${label} must be a non-empty string`);
    return typeof v === "string" ? v : "";
  };
  const strList = (v: JsonValue | undefined, label: string, allowed?: readonly string[]) => {
    if (v === undefined) return [];
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
      errors.push(`${label} must be an array of strings`);
      return [];
    }
    const list = v as string[];
    if (new Set(list).size !== list.length) errors.push(`${label} must not contain duplicates`);
    if (allowed) for (const x of list) if (!allowed.includes(x)) errors.push(`${label}: unknown value ${x}`);
    return list;
  };
  if (o.manifestVersion !== 1) errors.push("manifestVersion must be 1");
  const packageId = str(o.packageId, "packageId");
  if (packageId && !/^[a-z0-9][a-z0-9._-]{0,127}$/.test(packageId)) {
    errors.push("packageId must be lowercase [a-z0-9._-], 1–128 characters, e.g. 'zh.example'");
  }
  const versionCode = o.versionCode;
  if (typeof versionCode !== "number" || !Number.isInteger(versionCode) || versionCode < 0 || versionCode > 2147483647) {
    errors.push("versionCode must be a non-negative 32-bit integer");
  }
  if (typeof o.nsfw !== "boolean") errors.push("nsfw must be a boolean");
  const contentType = str(o.contentType, "contentType");
  if (contentType && !CONTENT_TYPES.includes(contentType as never)) errors.push(`contentType must be one of ${CONTENT_TYPES.join(", ")}`);
  const contentKinds = strList(o.contentKinds, "contentKinds", CONTENT_KINDS);
  if (contentKinds.length === 0) errors.push("contentKinds must not be empty");
  const events = obj(o.systemEvents ?? {}, "systemEvents", errors);
  const repo = obj(o.repository, "repository", errors);
  const sourcesRaw = Array.isArray(o.sources) ? o.sources : (errors.push("sources must be an array"), []);
  if (sourcesRaw.length === 0) errors.push("sources must contain at least one source");
  const sources: SourceManifest[] = sourcesRaw.map((s, i) => {
    const so = obj(s, `sources[${i}]`, errors);
    const label = `sources[${i}]`;
    const legacy = so.legacyLongId;
    if (legacy !== undefined && legacy !== null && typeof legacy !== "string") errors.push(`${label}.legacyLongId must be a string or null`);
    const source: SourceManifest = {
      sourceId: str(so.sourceId, `${label}.sourceId`),
      legacyLongId: typeof legacy === "string" ? legacy : null,
      name: str(so.name, `${label}.name`),
      lang: str(so.lang, `${label}.lang`),
      baseUrl: str(so.baseUrl, `${label}.baseUrl`),
      requestOrigins: strList(so.requestOrigins, `${label}.requestOrigins`),
      credentialOrigins: strList(so.credentialOrigins, `${label}.credentialOrigins`),
      contentOrigins: strList(so.contentOrigins, `${label}.contentOrigins`),
      browserSessionOrigins: strList(so.browserSessionOrigins, `${label}.browserSessionOrigins`),
      contentHostSuffixes: strList(so.contentHostSuffixes, `${label}.contentHostSuffixes`),
      browserImageOrigins: strList(so.browserImageOrigins, `${label}.browserImageOrigins`),
    };
    if (so.contentType !== undefined) source.contentType = str(so.contentType, `${label}.contentType`);
    if (so.contentKinds !== undefined) source.contentKinds = strList(so.contentKinds, `${label}.contentKinds`, CONTENT_KINDS);
    return source;
  });
  const ids = sources.map((s) => s.sourceId);
  if (new Set(ids).size !== ids.length) errors.push("sourceId values must be unique");
  const manifest: PluginManifest = {
    manifestVersion: 1,
    packageId,
    name: str(o.name, "name"),
    version: str(o.version, "version"),
    versionCode: typeof versionCode === "number" ? versionCode : 0,
    lang: str(o.lang, "lang"),
    nsfw: o.nsfw === true,
    contract: typeof o.contract === "string" ? o.contract : "shinsou",
    runtime: typeof o.runtime === "string" ? o.runtime : "legacy-shinsou-adapter-v2",
    contentType,
    contentKinds,
    capabilities: strList(o.capabilities, "capabilities", CAPABILITIES),
    runtimePermissions: strList(o.runtimePermissions, "runtimePermissions", RUNTIME_PERMISSIONS),
    requestedHostPermissions: strList(o.requestedHostPermissions, "requestedHostPermissions", HOST_PERMISSIONS),
    systemEvents: {
      required: strList(events.required, "systemEvents.required", EVENT_IDS),
      optional: strList(events.optional, "systemEvents.optional", EVENT_IDS),
    },
    entry: str(o.entry, "entry"),
    sources,
    repository: {
      name: str(repo.name, "repository.name"),
      shortName: typeof repo.shortName === "string" ? repo.shortName : str(repo.name, "repository.name"),
      website: str(repo.website, "repository.website"),
      mirrors: strList(repo.mirrors, "repository.mirrors"),
    },
  };
  if (typeof o.description === "string") manifest.description = o.description;
  if (o.test && typeof o.test === "object" && !Array.isArray(o.test)) {
    const t = o.test as JsonObject;
    manifest.test = {
      cases: typeof t.cases === "string" ? t.cases : undefined,
      fixtures: typeof t.fixtures === "string" ? t.fixtures : undefined,
    };
  }
  if (errors.length) throw new ManifestError(`${MANIFEST_FILE} is invalid:\n  - ${errors.join("\n  - ")}`);
  return manifest;
}

function obj(v: JsonValue | undefined, label: string, errors: string[]): JsonObject {
  if (!v || typeof v !== "object" || Array.isArray(v)) {
    errors.push(`${label} must be an object`);
    return {};
  }
  return v as JsonObject;
}

// ---------------------------------------------------------------------------------------------
// Generated documents

export function scriptUrl(m: PluginManifest): string {
  return `plugins/${m.packageId}.js`;
}

export function sidecarUrl(m: PluginManifest): string {
  return `sidecars/${m.packageId}.json`;
}

export function eventDeclaration(m: PluginManifest): JsonObject {
  return {
    protocol: EVENTS_PROTOCOL,
    minVersion: 1,
    maxVersion: 1,
    required: [...m.systemEvents.required],
    optional: [...m.systemEvents.optional],
  };
}

/** The one-line `var __shinsouExtensionV2 = {...};` declaration embedded in the script. */
export function executableMetadata(m: PluginManifest): JsonObject {
  return {
    contractVersion: CONTRACT_VERSION,
    contentContract: CONTENT_CONTRACT,
    packageId: m.packageId,
    contentType: m.contentType,
    contentKinds: [...m.contentKinds],
    systemEvents: eventDeclaration(m),
    requestedHostPermissions: [...m.requestedHostPermissions],
  };
}

function originFields(s: SourceManifest): JsonObject {
  const out: JsonObject = {
    requestOrigins: [...s.requestOrigins],
    credentialOrigins: [...s.credentialOrigins],
    contentOrigins: [...s.contentOrigins],
    browserSessionOrigins: [...s.browserSessionOrigins],
  };
  // Sensitive (ADR-0002 D11): only emitted when declared; lint validates it like the app does.
  if (s.contentHostSuffixes.length) out.contentHostSuffixes = [...s.contentHostSuffixes];
  if (s.browserImageOrigins.length) out.browserImageOrigins = [...s.browserImageOrigins];
  return out;
}

export function indexEntry(m: PluginManifest, artifact: { sha256: string; byteSize: number }): JsonObject {
  const entry: JsonObject = {
    id: m.packageId,
    name: m.name,
    version: m.version,
    versionCode: m.versionCode,
    lang: m.lang,
    nsfw: m.nsfw,
    contract: m.contract,
    runtime: m.runtime,
    contentType: m.contentType,
    contentKinds: [...m.contentKinds],
    scriptUrl: scriptUrl(m),
    sidecarUrl: sidecarUrl(m),
    sha256: artifact.sha256,
    byteSize: artifact.byteSize,
    capabilities: [...m.capabilities],
    runtimePermissions: [...m.runtimePermissions],
    requestedHostPermissions: [...m.requestedHostPermissions],
    systemEvents: eventDeclaration(m),
    sources: m.sources.map((s) => {
      const src: JsonObject = {
        sourceId: s.sourceId,
        legacyLongId: s.legacyLongId,
        name: s.name,
        lang: s.lang,
        baseUrl: s.baseUrl,
      };
      if (s.contentType) src.contentType = s.contentType;
      src.contentKinds = [...(s.contentKinds ?? m.contentKinds)];
      return { ...src, ...originFields(s) };
    }),
  };
  if (m.description) entry.description = m.description;
  return entry;
}

export function indexDocument(m: PluginManifest, entries: JsonObject[]): JsonObject {
  return {
    format: INDEX_FORMAT,
    contractVersion: CONTRACT_VERSION,
    contentContract: CONTENT_CONTRACT,
    contentContractVersion: CONTRACT_VERSION,
    repository: { name: m.repository.name, source: "index.json" },
    systemEvents: {
      protocol: EVENTS_PROTOCOL,
      minVersion: 1,
      maxVersion: 1,
      knownPermissions: HOST_PERMISSIONS.filter((p) => !TIER_CEILING_HOST_PERMISSIONS.includes(p)),
    },
    packages: entries,
  };
}

export function sidecarDocument(m: PluginManifest, artifact: { sha256: string; byteSize: number }): JsonObject {
  return {
    format: SIDECAR_FORMAT,
    contractVersion: CONTRACT_VERSION,
    packageId: m.packageId,
    name: m.name,
    version: m.version,
    versionCode: m.versionCode,
    contract: m.contract,
    runtime: m.runtime,
    lang: m.lang,
    nsfw: m.nsfw,
    installable: true,
    artifact: { scriptUrl: scriptUrl(m), sha256: artifact.sha256, byteSize: artifact.byteSize },
    content: { contract: CONTENT_CONTRACT, contractVersion: CONTRACT_VERSION, type: m.contentType, kinds: [...m.contentKinds] },
    capabilities: [...m.capabilities],
    systemEvents: eventDeclaration(m),
    requestedHostPermissions: [...m.requestedHostPermissions],
    runtimePermissions: [...m.runtimePermissions],
    sources: m.sources.map((s) => {
      const src: JsonObject = {
        sourceKey: { contractVersion: CONTRACT_VERSION, packageId: m.packageId, sourceId: s.sourceId, legacyLongId: s.legacyLongId },
        sourceId: s.sourceId,
        name: s.name,
        lang: s.lang,
        baseUrl: s.baseUrl,
      };
      if (s.contentType) src.contentType = s.contentType;
      return {
        ...src,
        capabilities: [...m.capabilities],
        contentKinds: [...(s.contentKinds ?? m.contentKinds)],
        systemEvents: eventDeclaration(m),
        requestedHostPermissions: [...m.requestedHostPermissions],
        runtimePermissions: [...m.runtimePermissions],
        ...originFields(s),
      };
    }),
  };
}

export function repoMetaDocument(m: PluginManifest, signingKeyFingerprint: string): JsonObject {
  return {
    meta: {
      name: m.repository.name,
      shortName: m.repository.shortName,
      website: m.repository.website,
      signingKeyFingerprint,
    },
  };
}

/** Deterministic numeric source id (the app parses `sourceId` as a lossless Long). */
export function defaultSourceId(digest: Uint8Array): string {
  let v = 0n;
  for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(digest[i]);
  return String(v & 0x7fffffffffffffffn);
}
