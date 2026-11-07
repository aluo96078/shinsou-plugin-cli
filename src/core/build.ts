/**
 * `build`: bundle the entry into one classic script, embed the executable metadata, compute
 * SHA-256 / byte size, generate the index entry and sidecar from `shinsou.plugin.json`, then
 * re-read what was produced and fail on any disagreement.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { build as esbuild } from "esbuild";
import { isDeepStrictEqual } from "node:util";
import { utf8 } from "./bytes.ts";
import { sha256Hex } from "./crypto.ts";
import type { JsonObject } from "./canonical-json.ts";
import { checkPackageConsistency, readExecutableMetadata } from "./consistency.ts";
import {
  executableMetadata,
  indexDocument,
  indexEntry,
  loadManifest,
  repoMetaDocument,
  scriptUrl,
  sidecarDocument,
  sidecarUrl,
  type PluginManifest,
} from "./manifest.ts";
import { loadState } from "./state.ts";

export const DEFAULT_OUT_DIR = "build/repo";
export const MAX_SCRIPT_BYTES = 2 * 1024 * 1024;

export interface BuildResult {
  manifest: PluginManifest;
  /** Script text as published (what the app hashes). */
  script: string;
  scriptBytes: Uint8Array;
  /** The author's bundled code, before the generated header/footer. */
  bundledCode: string;
  sha256: string;
  byteSize: number;
  index: JsonObject;
  pkg: JsonObject;
  sidecar: JsonObject;
  repoMeta: JsonObject;
  outDir: string;
  files: Record<string, string | Uint8Array>;
}

export class BuildError extends Error {}

export async function bundleEntry(projectDir: string, manifest: PluginManifest): Promise<string> {
  const result = await esbuild({
    absWorkingDir: projectDir,
    entryPoints: [manifest.entry],
    bundle: true,
    write: false,
    // ESM output without exports is a plain top-level script: `var source = {...}` stays global.
    format: "esm",
    // Nothing is "used" from the host's point of view; keep every top-level declaration.
    treeShaking: false,
    platform: "neutral",
    target: "es2020",
    charset: "utf8",
    legalComments: "inline",
    logLevel: "silent",
    mainFields: ["module", "main"],
  }).catch((err: { errors?: { text: string; location?: { file: string; line: number } }[] }) => {
    const msgs = (err.errors ?? []).map((e) => `${e.location ? `${e.location.file}:${e.location.line}: ` : ""}${e.text}`);
    throw new BuildError(`esbuild failed:\n  ${msgs.join("\n  ") || String(err)}`);
  });
  const code = result.outputFiles[0].text;
  if (/^\s*export\s/m.test(code) || /^\s*import\s/m.test(code)) {
    throw new BuildError(
      `${manifest.entry} must not export anything: declare \`var source = {...}\` (or \`var sources = [...]\`) at top level instead`,
    );
  }
  if (!/^(?:var\s+sources?\b|globalThis\.sources?\s*=)/m.test(code)) {
    throw new BuildError(
      `${manifest.entry} must declare \`var source = {...}\` (or \`var sources = [...]\`) at top level; ` +
        "let/const do not become globals and the host looks the source up on the global object",
    );
  }
  return code;
}

export function assembleScript(manifest: PluginManifest, bundled: string): string {
  const generated = executableMetadata(manifest);
  const existing = readExecutableMetadata(bundled);
  if (existing) {
    // Migrated scripts may carry their own declaration: it must agree with the manifest exactly.
    if (!isDeepStrictEqual(existing, generated)) {
      throw new BuildError(
        "The script's own __shinsouExtensionV2 declaration disagrees with shinsou.plugin.json.\n" +
          `  script:   ${JSON.stringify(existing)}\n  manifest: ${JSON.stringify(generated)}\n` +
          "Remove the declaration from the source; build generates it.",
      );
    }
  }
  const header =
    `/* ${manifest.packageId} ${manifest.version} (${manifest.versionCode}) — built by @shinsou/plugin from shinsou.plugin.json */\n` +
    (existing ? "" : `var __shinsouExtensionV2 = ${JSON.stringify(generated)};\n`);
  const hasExport = bundled.includes("source.v2 = __shinsouExtensionV2");
  const footer = hasExport
    ? ""
    : "\n// Bounded, host-audited v2 metadata (generated).\n" +
      'if (typeof source === "object" && source) {\n  source.v2 = __shinsouExtensionV2;\n}\n' +
      'if (typeof sources === "object" && sources) {\n' +
      "  (Array.isArray(sources) ? sources : Object.keys(sources).map(function (k) { return sources[k]; }))\n" +
      "    .forEach(function (s) { if (s && typeof s === \"object\") s.v2 = __shinsouExtensionV2; });\n}\n";
  return header + bundled.replace(/\s*$/, "\n") + footer;
}

export async function buildProject(projectDir: string, opts: { outDir?: string; write?: boolean } = {}): Promise<BuildResult> {
  const manifest = loadManifest(projectDir);
  const bundledCode = await bundleEntry(projectDir, manifest);
  const script = assembleScript(manifest, bundledCode);
  const scriptBytes = utf8(script);
  if (scriptBytes.length > MAX_SCRIPT_BYTES) {
    throw new BuildError(`Script is ${scriptBytes.length} bytes; the limit is ${MAX_SCRIPT_BYTES} (2 MiB)`);
  }
  const artifact = { sha256: sha256Hex(scriptBytes), byteSize: scriptBytes.length };
  const pkg = indexEntry(manifest, artifact);
  const index = indexDocument(manifest, [pkg]);
  const sidecar = sidecarDocument(manifest, artifact);
  const state = loadState(projectDir);
  const repoMeta = repoMetaDocument(manifest, state.currentKey?.fingerprint ?? "");

  // Re-parse the serialized documents, exactly as a client would read them.
  const files: Record<string, string | Uint8Array> = {
    [scriptUrl(manifest)]: scriptBytes,
    [sidecarUrl(manifest)]: JSON.stringify(sidecar, null, 2) + "\n",
    "index.json": JSON.stringify(index, null, 2) + "\n",
    "repo.json": JSON.stringify(repoMeta, null, 2) + "\n",
  };
  const reIndex = JSON.parse(files["index.json"] as string) as JsonObject;
  const reSidecar = JSON.parse(files[sidecarUrl(manifest)] as string) as JsonObject;
  const rePkg = (reIndex.packages as JsonObject[]).find((p) => p.id === manifest.packageId)!;
  const problems = checkPackageConsistency({ index: reIndex, pkg: rePkg, sidecar: reSidecar, scriptBytes });
  if (problems.length) throw new BuildError(`Script metadata / index / sidecar disagree:\n  - ${problems.join("\n  - ")}`);

  const outDir = join(projectDir, opts.outDir ?? DEFAULT_OUT_DIR);
  if (opts.write !== false) {
    for (const [rel, content] of Object.entries(files)) {
      const target = join(outDir, rel);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, content);
    }
  }
  return { manifest, script, scriptBytes, bundledCode, ...artifact, index, pkg, sidecar, repoMeta, outDir, files };
}
