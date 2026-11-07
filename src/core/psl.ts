/**
 * Public Suffix List lookup, a port of the app's `PublicSuffixList` (ICANN + private sections).
 * The pinned list in `data/public_suffix_list.dat` is the same file the app bundles; hosts are
 * compared as lower-case ASCII (internationalized rules are converted to punycode on load).
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { domainToASCII } from "node:url";

export function dataDir(): string {
  // Bundled: dist/cli.js → ../data. From source: src/core/psl.ts → ../../data.
  const here = fileURLToPath(new URL(".", import.meta.url));
  for (const candidate of [join(here, "..", "data"), join(here, "..", "..", "data")]) {
    if (existsSync(join(candidate, "public_suffix_list.dat"))) return candidate;
  }
  throw new Error("data/public_suffix_list.dat not found next to the CLI");
}

interface Rules {
  normal: Set<string>;
  wildcards: Set<string>;
  exceptions: Set<string>;
}

let cached: Rules | undefined;

export function parsePublicSuffixList(text: string): Rules {
  const normal = new Set<string>();
  const wildcards = new Set<string>();
  const exceptions = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const rule = line.split(/[ \t]/)[0].trim();
    if (!rule || rule.startsWith("//")) continue;
    const prefix = rule.startsWith("!") ? "!" : rule.startsWith("*.") ? "*." : "";
    const ascii = domainToASCII(rule.slice(prefix.length)).toLowerCase();
    if (!/^[a-z0-9.-]+$/.test(ascii)) throw new Error(`Unexpected public suffix rule '${rule}'`);
    if (prefix === "!") exceptions.add(ascii);
    else if (prefix === "*.") wildcards.add(ascii);
    else normal.add(ascii);
  }
  if (normal.size + wildcards.size + exceptions.size < 5000) throw new Error("Public Suffix List looks truncated");
  return { normal, wildcards, exceptions };
}

function rules(): Rules {
  return (cached ??= parsePublicSuffixList(readFileSync(join(dataDir(), "public_suffix_list.dat"), "utf8")));
}

function normalizedLabels(host: string): string[] | null {
  const n = host.trim().replace(/\.+$/, "").toLowerCase();
  if (!n || n.length > 253 || !/^[a-z0-9.-]+$/.test(n)) return null;
  const labels = n.split(".");
  if (labels.some((l) => !l || l.length > 63)) return null;
  return labels;
}

/** The public suffix of [host], or null for an unusable host. A lone label is its own suffix. */
export function publicSuffixOf(host: string): string | null {
  const labels = normalizedLabels(host);
  if (!labels) return null;
  const r = rules();
  for (let start = 0; start < labels.length; start++) {
    const candidate = labels.slice(start).join(".");
    if (r.exceptions.has(candidate)) return labels.slice(start + 1).join(".");
    if (r.normal.has(candidate)) return candidate;
    if (start + 1 < labels.length && r.wildcards.has(labels.slice(start + 1).join("."))) return candidate;
  }
  return labels[labels.length - 1];
}

/** Public suffix plus one label, or null when [host] is itself a public suffix (or unusable). */
export function registrableDomain(host: string): string | null {
  const labels = normalizedLabels(host);
  const suffix = publicSuffixOf(host);
  if (!labels || !suffix) return null;
  const suffixLabels = suffix.split(".").length;
  if (labels.length <= suffixLabels) return null;
  return labels.slice(labels.length - suffixLabels - 1).join(".");
}
