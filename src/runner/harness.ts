/**
 * `shinsou-plugin test`: run hooks from `test/cases.json` against recorded HTTP fixtures.
 * With `--record`, missing responses are fetched for real, saved, and the hook re-run.
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import type { PluginManifest } from "../core/manifest.ts";
import { FixtureBridgeHost, fixtureKey, type HostEvent, type HttpFixture } from "./fixture-host.ts";
import { QuickJsEngine } from "./quickjs.ts";
import type { SandboxEngine } from "./sandbox.ts";

export interface TestCase {
  name: string;
  hook: string;
  args?: unknown[];
  sourceId?: string;
  preferences?: Record<string, string>;
  credential?: { username: string; password: string };
  expect?: {
    /** Dot path into the result, e.g. `mangas` or `0.imageUrl`; defaults to the whole result. */
    path?: string;
    minItems?: number;
    notEmpty?: boolean;
    /** Every key given must deep-equal the value at that key of the result (subset match). */
    matches?: Record<string, unknown>;
    /** Compare with (or with --update, write) `test/snapshots/<name>.json`. */
    snapshot?: boolean;
    /** The whole result (or the value at `path`) deep-equals this; handy for `getChapterText` strings. */
    equals?: unknown;
    /** The result (a string, or an array/object serialised to JSON) contains this text. */
    contains?: string;
  };
}

export interface CaseResult {
  name: string;
  ok: boolean;
  problems: string[];
  events: HostEvent[];
  logs: string[];
  value?: unknown;
}

export const DEFAULT_CASES = "test/cases.json";
export const DEFAULT_FIXTURES = "test/fixtures";

export function loadFixtures(dir: string): HttpFixture[] {
  if (!existsSync(dir)) return [];
  const out: HttpFixture[] = [];
  for (const name of readdirSync(dir).filter((n) => n.endsWith(".json")).sort()) {
    const data = JSON.parse(readFileSync(join(dir, name), "utf8"));
    out.push(...(Array.isArray(data) ? data : data.entries ?? []));
  }
  return out;
}

export async function runTests(args: {
  projectDir: string;
  manifest: PluginManifest;
  script: string;
  record?: boolean;
  update?: boolean;
  only?: string;
  engine?: SandboxEngine;
  fetchImpl?: typeof fetch;
}): Promise<CaseResult[]> {
  const { projectDir, manifest } = args;
  const casesPath = join(projectDir, manifest.test?.cases ?? DEFAULT_CASES);
  const fixturesDir = join(projectDir, manifest.test?.fixtures ?? DEFAULT_FIXTURES);
  if (!existsSync(casesPath)) throw new Error(`No test cases: ${casesPath}`);
  const cases = (JSON.parse(readFileSync(casesPath, "utf8")) as TestCase[]).filter((c) => !args.only || c.name.includes(args.only));
  const engine = args.engine ?? new QuickJsEngine();
  const results: CaseResult[] = [];
  for (const c of cases) {
    const source = manifest.sources.find((s) => s.sourceId === (c.sourceId ?? manifest.sources[0].sourceId));
    if (!source) {
      results.push({ name: c.name, ok: false, problems: [`unknown sourceId ${c.sourceId}`], events: [], logs: [] });
      continue;
    }
    let result: CaseResult | undefined;
    for (let round = 0; round < 20; round++) {
      const fixtures = loadFixtures(fixturesDir);
      const host = new FixtureBridgeHost(manifest, source, fixtures, { preferences: c.preferences, credential: c.credential });
      const problems: string[] = [];
      let value: unknown;
      try {
        const instance = await engine.create({ script: args.script, sourceId: source.sourceId, host });
        try {
          const out = await instance.invoke(c.hook, JSON.stringify(c.args ?? []));
          if (out.ok) value = JSON.parse(out.valueJson);
          else problems.push(`hook threw: ${out.error}`);
        } finally {
          instance.dispose();
        }
      } catch (err) {
        problems.push(`script failed to load: ${(err as Error).message}`);
      }
      if (args.record && host.misses.length) {
        await recordMisses(fixturesDir, c.name, host.misses, args.fetchImpl ?? fetch);
        continue;
      }
      for (const e of host.events) if (e.kind !== "log") problems.push(`${e.kind}: bridge.${e.op} — ${e.detail}`);
      if (problems.length === 0) problems.push(...checkExpectations(projectDir, c, value, !!args.update));
      result = { name: c.name, ok: problems.length === 0, problems, events: host.events, logs: host.logs, value };
      break;
    }
    results.push(result ?? { name: c.name, ok: false, problems: ["recording did not converge after 20 rounds"], events: [], logs: [] });
  }
  return results;
}

async function recordMisses(
  dir: string,
  caseName: string,
  misses: FixtureBridgeHost["misses"],
  fetchImpl: typeof fetch,
): Promise<void> {
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${caseName.replace(/[^\w.-]+/g, "_")}.json`);
  const existing: HttpFixture[] = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : [];
  const keys = new Set(existing.map((f) => fixtureKey(f.request.method, f.request.url, f.request.body ?? "")));
  for (const miss of misses) {
    const key = fixtureKey(miss.method, miss.url, miss.body);
    if (keys.has(key)) continue;
    keys.add(key);
    const res = await fetchImpl(miss.url, {
      method: miss.method,
      headers: miss.headers,
      body: miss.method === "GET" ? undefined : miss.body,
      redirect: "follow",
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      if (!["set-cookie", "authorization", "cookie"].includes(k)) headers[k] = v;
    });
    existing.push({
      request: { method: miss.method, url: miss.url, ...(miss.method === "GET" ? {} : { body: miss.body }) },
      response: { status: res.status, headers, body: await res.text() },
    });
  }
  writeFileSync(file, JSON.stringify(existing, null, 2) + "\n");
}

function at(value: unknown, path?: string): unknown {
  if (!path) return value;
  return path.split(".").reduce<unknown>((v, k) => (v && typeof v === "object" ? (v as Record<string, unknown>)[k] : undefined), value);
}

/** The app accepts a non-empty string (or `{ text }`) of at most 4 MiB from getChapterText. */
export const MAX_CHAPTER_TEXT_BYTES = 4 * 1024 * 1024;
function chapterTextProblems(result: unknown): string[] {
  const text = typeof result === "string" ? result : result && typeof result === "object" ? (result as { text?: unknown }).text : undefined;
  if (typeof text !== "string") return ["getChapterText must return a string (or { text }); the app ignores anything else"];
  if (text.length === 0) return ["getChapterText returned an empty string (the app treats it as no text)"];
  if (Buffer.byteLength(text, "utf8") > MAX_CHAPTER_TEXT_BYTES) return ["getChapterText result exceeds the 4 MiB result limit"];
  return [];
}

function checkExpectations(projectDir: string, c: TestCase, result: unknown, update: boolean): string[] {
  const problems: string[] = [];
  if (c.hook === "getChapterText") problems.push(...chapterTextProblems(result));
  const e = c.expect;
  if (!e) return problems;
  const v = at(result, e.path);
  const label = e.path ? `result.${e.path}` : "result";
  if (e.notEmpty && (v === null || v === undefined || v === "" || (Array.isArray(v) && v.length === 0))) problems.push(`${label} is empty`);
  if (e.minItems !== undefined) {
    if (!Array.isArray(v)) problems.push(`${label} is not an array`);
    else if (v.length < e.minItems) problems.push(`${label} has ${v.length} items, expected at least ${e.minItems}`);
  }
  if ("equals" in e && !isDeepStrictEqual(v, e.equals)) problems.push(`${label} = ${JSON.stringify(v)}, expected ${JSON.stringify(e.equals)}`);
  if (e.contains !== undefined && !(typeof v === "string" ? v : JSON.stringify(v) ?? "").includes(e.contains)) {
    problems.push(`${label} does not contain ${JSON.stringify(e.contains)}`);
  }
  for (const [k, want] of Object.entries(e.matches ?? {})) {
    const got = at(v, k);
    if (!isDeepStrictEqual(got, want)) problems.push(`${label}.${k} = ${JSON.stringify(got)}, expected ${JSON.stringify(want)}`);
  }
  if (e.snapshot) {
    const dir = join(projectDir, "test", "snapshots");
    const file = join(dir, `${c.name.replace(/[^\w.-]+/g, "_")}.json`);
    if (update || !existsSync(file)) {
      mkdirSync(dir, { recursive: true });
      writeFileSync(file, JSON.stringify(result, null, 2) + "\n");
    } else if (!isDeepStrictEqual(JSON.parse(readFileSync(file, "utf8")), result)) {
      problems.push(`result differs from snapshot ${file} (run with --update to accept)`);
    }
  }
  return problems;
}
