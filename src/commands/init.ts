/** `init`: scaffold a plugin project whose single source of truth is `shinsou.plugin.json`. */

import { cpSync, existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { utf8 } from "../core/bytes.ts";
import { sha256 } from "../core/crypto.ts";
import { defaultSourceId, MANIFEST_FILE } from "../core/manifest.ts";

export const TEMPLATES = ["manga", "novel", "async"] as const;
export type TemplateName = (typeof TEMPLATES)[number];

export function templatesDir(): string {
  // Bundled: dist/cli.js → ../templates. From source: src/commands/init.ts → ../../templates.
  const here = fileURLToPath(new URL(".", import.meta.url));
  for (const candidate of [join(here, "..", "templates"), join(here, "..", "..", "templates")]) {
    if (existsSync(join(candidate, "manga"))) return candidate;
  }
  throw new Error("templates directory not found next to the CLI");
}

export function initProject(args: {
  dir: string;
  template: TemplateName;
  packageId?: string;
  name?: string;
  lang?: string;
  cliVersion: string;
}): string[] {
  const dir = resolve(args.dir);
  if (!TEMPLATES.includes(args.template)) throw new Error(`Unknown template '${args.template}' (manga | novel | async)`);
  mkdirSync(dir, { recursive: true });
  if (existsSync(join(dir, MANIFEST_FILE))) throw new Error(`${join(dir, MANIFEST_FILE)} already exists`);
  const leftovers = readdirSync(dir).filter((n) => !n.startsWith("."));
  if (leftovers.includes("src") || leftovers.includes("test")) throw new Error(`${dir} already has src/ or test/; use an empty directory`);

  const lang = args.lang ?? "zh";
  const slug = basename(dir).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "plugin";
  const packageId = args.packageId ?? `${lang}.${slug.replace(/-/g, "")}`;
  const name = args.name ?? slug;
  const sourceId = defaultSourceId(sha256(utf8(`${packageId}/${lang}/1`)));
  const t = templatesDir();
  cpSync(join(t, args.template), dir, { recursive: true });
  cpSync(join(t, "common", ".github"), join(dir, ".github"), { recursive: true });
  cpSync(join(t, "common", "gitignore"), join(dir, ".gitignore"));

  const profile = {
    manga: {
      contentType: "manga",
      contentKinds: ["IMAGE_SEQUENCE"],
      capabilities: ["CATALOGUE", "LATEST", "BROWSE", "METADATA", "UNITS", "CONTENT", "SEARCH"],
      baseUrl: "https://example.com",
      requestOrigins: ["https://example.com"],
      contentOrigins: ["https://example.com"],
    },
    novel: {
      contentType: "novel",
      contentKinds: ["PLAIN_TEXT"],
      capabilities: ["CATALOGUE", "LATEST", "BROWSE", "METADATA", "UNITS", "CONTENT", "SEARCH"],
      baseUrl: "https://example.com",
      requestOrigins: ["https://example.com"],
      contentOrigins: [],
    },
    async: {
      contentType: "manga",
      contentKinds: ["IMAGE_SEQUENCE"],
      capabilities: ["CATALOGUE", "BROWSE", "METADATA", "UNITS", "CONTENT", "SEARCH"],
      baseUrl: "https://example.com",
      requestOrigins: ["https://api.example.com"],
      contentOrigins: ["https://example.com", "https://cdn.example.com"],
    },
  }[args.template];

  const manifest = {
    manifestVersion: 1,
    packageId,
    name,
    version: "0.1.0",
    versionCode: 1,
    lang,
    nsfw: false,
    contract: "shinsou",
    runtime: "legacy-shinsou-adapter-v2",
    contentType: profile.contentType,
    contentKinds: profile.contentKinds,
    capabilities: profile.capabilities,
    runtimePermissions: ["EXECUTE_SCRIPT", "NETWORK"],
    requestedHostPermissions: [],
    systemEvents: { required: [], optional: [] },
    entry: "src/index.js",
    sources: [
      {
        sourceId,
        legacyLongId: null,
        name,
        lang,
        baseUrl: profile.baseUrl,
        requestOrigins: profile.requestOrigins,
        credentialOrigins: [],
        contentOrigins: profile.contentOrigins,
        browserSessionOrigins: [],
        contentHostSuffixes: [],
      },
    ],
    repository: {
      name: "My Shinsou Plugins",
      shortName: "My Plugins",
      website: "https://github.com/you/your-plugins",
      mirrors: ["https://you.github.io/your-plugins"],
    },
    test: { cases: "test/cases.json", fixtures: "test/fixtures" },
  };
  writeFileSync(join(dir, MANIFEST_FILE), JSON.stringify(manifest, null, 2) + "\n");
  if (!existsSync(join(dir, "package.json"))) {
    const pkg = {
      name: slug,
      private: true,
      type: "module",
      scripts: {
        build: "shinsou-plugin build",
        lint: "shinsou-plugin lint",
        test: "shinsou-plugin test",
        dev: "shinsou-plugin serve",
        sign: "shinsou-plugin sign",
      },
      devDependencies: { "@shinsou/plugin": `^${args.cliVersion}` },
    };
    writeFileSync(join(dir, "package.json"), JSON.stringify(pkg, null, 2) + "\n");
  }
  return [MANIFEST_FILE, "package.json", "src/", "test/", ".github/workflows/shinsou-refresh.yml", ".gitignore"];
}
