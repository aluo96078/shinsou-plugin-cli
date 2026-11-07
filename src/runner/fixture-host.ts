/**
 * A bridge host that answers network calls from recorded HTTP fixtures and enforces the same
 * declaration-based rules as the app's SandboxBridgeDispatcher (runtime permissions, exact request
 * origins), so a test fails locally where the app would deny.
 */

import { ERROR_CODES } from "../core/sandbox-protocol.ts";
import type { PluginManifest, SourceManifest } from "../core/manifest.ts";
import type { BridgeHost, BridgeOutcome } from "./sandbox.ts";

export interface HttpFixture {
  request: { method: string; url: string; body?: string };
  response: { status: number; headers?: Record<string, string>; body: string };
}

export interface HostEvent {
  kind: "denied" | "missing-fixture" | "unknown-op" | "log";
  op: string;
  detail: string;
}

const CREDENTIAL_RESPONSE_HEADERS = new Set([
  "set-cookie", "set-cookie2", "cookie", "authorization", "proxy-authorization", "www-authenticate", "proxy-authenticate",
]);

export function fixtureKey(method: string, url: string, body = ""): string {
  return `${method.toUpperCase()} ${url}${method.toUpperCase() === "GET" ? "" : `\n${body}`}`;
}

export class FixtureBridgeHost implements BridgeHost {
  readonly events: HostEvent[] = [];
  readonly misses: { method: string; url: string; body: string; headers: Record<string, string> }[] = [];
  readonly logs: string[] = [];
  private readonly fixtures = new Map<string, HttpFixture>();
  private readonly prefs = new Map<string, string>();
  private readonly cookies = new Map<string, string>();

  constructor(
    private readonly manifest: PluginManifest,
    private readonly source: SourceManifest,
    fixtures: HttpFixture[],
    opts: { preferences?: Record<string, string>; credential?: { username: string; password: string } | null } = {},
  ) {
    for (const f of fixtures) this.fixtures.set(fixtureKey(f.request.method, f.request.url, f.request.body ?? ""), f);
    for (const [k, v] of Object.entries(opts.preferences ?? {})) this.prefs.set(k, v);
    this.credential = opts.credential ?? null;
  }
  private credential: { username: string; password: string } | null;

  log(message: string): void {
    this.logs.push(message);
  }

  call(op: string, argsJson: string): BridgeOutcome {
    let args: unknown[];
    try {
      args = JSON.parse(argsJson);
      if (!Array.isArray(args)) return fail(ERROR_CODES.BAD_ARGUMENT);
    } catch {
      return fail(ERROR_CODES.BAD_ARGUMENT);
    }
    const s = (i: number) => (typeof args[i] === "string" ? (args[i] as string) : args[i] == null ? "" : String(args[i]));
    const map = (i: number) => (args[i] && typeof args[i] === "object" ? (args[i] as Record<string, string>) : {});
    switch (op) {
      case "httpGet":
      case "httpGetWithHeaders":
      case "httpGetResponse": {
        const r = this.http(op, "GET", s(0), "", map(1));
        if (!r.ok) return r;
        return value(op === "httpGetResponse" ? { status: r.response.status, body: r.response.body } : r.response.body);
      }
      case "httpPost":
      case "httpPostResponse": {
        const r = this.http(op, "POST", s(0), s(1), map(2));
        if (!r.ok) return r;
        return value(op === "httpPostResponse" ? { status: r.response.status, body: r.response.body } : r.response.body);
      }
      case "httpPostBatch": {
        const urls = Array.isArray(args[0]) ? (args[0] as string[]) : [];
        const bodies = Array.isArray(args[1]) ? (args[1] as string[]) : [];
        const out: (string | null)[] = [];
        for (let i = 0; i < urls.length; i++) {
          const r = this.http(op, "POST", String(urls[i]), String(bodies[i] ?? ""), map(2));
          if (!r.ok && r.code === ERROR_CODES.PERMISSION_DENIED) return r;
          out.push(r.ok ? r.response.body : null);
        }
        return value(JSON.stringify(out));
      }
      case "browserSessionRequest": {
        if (!this.has("BROWSER_CHALLENGE")) return this.deny(op, "BROWSER_CHALLENGE not declared");
        const target = origin(s(0));
        if (!target || !this.source.browserSessionOrigins.includes(target)) return this.deny(op, `${s(0)} is not a browserSessionOrigin`);
        const r = this.http(op, s(1) || "GET", s(0), s(2), map(3), true);
        return r.ok ? value({ status: r.response.status, body: r.response.body }) : r;
      }
      case "getPreference":
        return value(this.prefs.has(s(0)) ? this.prefs.get(s(0))! : null);
      case "setPreference":
        this.prefs.set(s(0), s(1));
        return value(null);
      case "getCredentialUsername":
        return this.has("CREDENTIAL_ACCESS") ? value(this.credential?.username ?? null) : this.deny(op, "CREDENTIAL_ACCESS not declared");
      case "hasCredential":
        return this.has("CREDENTIAL_ACCESS") ? value(!!this.credential?.username) : this.deny(op, "CREDENTIAL_ACCESS not declared");
      case "getCredentialPassword":
      case "setCredential":
      case "clearCredential":
        // Only inside a host-started login invocation (ADR-0002 §6.4); tests never are one.
        return this.deny(op, "credential secrets are only available during a host-started login");
      case "getCookie":
      case "getCookies":
        return this.has("COOKIE_STORAGE") && this.has("COOKIE_READ") ? value(op === "getCookie" ? this.cookies.get(s(0)) ?? null : Object.fromEntries(this.cookies)) : this.deny(op, "COOKIE_STORAGE and COOKIE_READ are both required");
      case "setCookie":
        if (!this.has("COOKIE_STORAGE")) return this.deny(op, "COOKIE_STORAGE not declared");
        this.cookies.set(s(0), s(1));
        return value(true);
      case "deleteCookie":
        if (!this.has("COOKIE_STORAGE")) return this.deny(op, "COOKIE_STORAGE not declared");
        this.cookies.delete(s(0));
        return value(null);
      case "clearCookies":
        if (!this.has("COOKIE_STORAGE")) return this.deny(op, "COOKIE_STORAGE not declared");
        this.cookies.clear();
        return value(null);
      case "requestLogin":
        return value(false);
      case "requestHostEvent":
        return value(JSON.stringify({ messageId: "", disposition: "UNSUPPORTED" }));
      case "getHostEventContext":
        return value(null);
      case "getHostEventCapabilities":
        return value({ enabled: false, protocol: "dev.shinsou.system", version: null, grantedCapabilities: [], hardLimits: null });
      case "log":
        this.logs.push(s(0));
        return value(null);
      // DOM bookkeeping calls made by the bootstrap's in-sandbox parser.
      case "domParse":
        return value({ maxNodes: 200_000, maxDepth: 512 });
      case "domSelect":
      case "domParsed":
      case "domDepth":
      case "domRelease":
      case "domReleaseAll":
        return value(null);
      default:
        this.events.push({ kind: "unknown-op", op, detail: "not a sandbox bridge operation" });
        return fail(ERROR_CODES.UNKNOWN_OPERATION);
    }
  }

  async callAsync(op: string, argsJson: string): Promise<BridgeOutcome> {
    if (op !== "net.fetch") return fail(ERROR_CODES.UNKNOWN_OPERATION);
    let args: unknown[];
    try {
      args = JSON.parse(argsJson);
    } catch {
      return fail(ERROR_CODES.BAD_ARGUMENT);
    }
    const options = (args[1] && typeof args[1] === "object" ? args[1] : {}) as { method?: string; body?: string; headers?: Record<string, string> };
    const method = (options.method ?? "GET").toUpperCase();
    if (method !== "GET" && method !== "POST") return fail(ERROR_CODES.BAD_ARGUMENT);
    if (method === "GET" && options.body) return fail(ERROR_CODES.BAD_ARGUMENT);
    const r = this.http(op, method, String(args[0]), options.body ?? "", options.headers ?? {});
    if (!r.ok) return r;
    const headers = Object.fromEntries(
      Object.entries(r.response.headers ?? {})
        .filter(([k]) => !CREDENTIAL_RESPONSE_HEADERS.has(k.toLowerCase()))
        .map(([k, v]) => [k.toLowerCase(), v]),
    );
    return value({ status: r.response.status, headers, body: r.response.body });
  }

  private has(permission: string): boolean {
    return this.manifest.runtimePermissions.includes(permission);
  }

  private deny(op: string, detail: string): BridgeOutcome {
    this.events.push({ kind: "denied", op, detail });
    return fail(ERROR_CODES.PERMISSION_DENIED);
  }

  private http(
    op: string,
    method: string,
    url: string,
    body: string,
    headers: Record<string, string>,
    browserSession = false,
  ): { ok: true; response: HttpFixture["response"] } | { ok: false; code: number } {
    if (!this.has("NETWORK")) return this.deny(op, "NETWORK not declared") as { ok: false; code: number };
    const o = origin(url);
    if (!o || !o.startsWith("https:")) return this.deny(op, `${url} is not an HTTPS URL`) as { ok: false; code: number };
    if (!browserSession && !this.source.requestOrigins.includes(o)) {
      return this.deny(op, `${o} is not in requestOrigins`) as { ok: false; code: number };
    }
    const f = this.fixtures.get(fixtureKey(method, url, body));
    if (!f) {
      this.events.push({ kind: "missing-fixture", op, detail: `${method} ${url}` });
      this.misses.push({ method: method.toUpperCase(), url, body, headers });
      return { ok: false, code: ERROR_CODES.NETWORK_FAILED };
    }
    return { ok: true, response: f.response };
  }
}

function origin(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

function value(v: unknown): BridgeOutcome {
  return { ok: true, json: v === null || v === undefined ? null : JSON.stringify(v) };
}

function fail(code: number): BridgeOutcome {
  return { ok: false, code };
}
